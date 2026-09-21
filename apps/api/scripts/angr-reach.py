#!/usr/bin/env python3
"""
angr-reach — FirmLab's symbolic-reachability probe.

One question, asked once per sink: *is this dangerous call site reachable from the binary's entry point under
attacker-controlled input?* That is the question that turns a `binary-pwnable-candidate` lead (an unbounded-copy
import with no stack canary — a precondition, not a bug) into evidence that the sink is actually on a live path.

What this script deliberately does NOT claim:

  * Reaching `strcpy` is not proof of an overflow. It proves the sink is on a feasible path from the entry point
    with a concrete input that gets there. That is a real, checkable upgrade over "this binary imports strcpy" —
    and it is the whole claim. Exploitability is out of scope by design (FirmLab drafts disclosure, not PoCs).
  * NOT reaching a sink is never reported as "unreachable". Symbolic exploration here is bounded — wall-clock
    budget, step cap, and active-state pruning — and indirect jumps/unmodelled syscalls routinely hide real paths.
    An exhausted search is `not_reached_in_budget`, an honest inconclusive, and the caller must keep the original
    `needs_runtime_reproduction` proof state. The JSON says exactly which budget ran out and whether states were
    pruned, so the inconclusive can be read for what it is.

**Two start states, one search.** A program is explored from its entry point. A shared object has none — it is
entered through an exported function — so `mode: "library"` builds a `call_state` at each exported function
instead and asks the same question from there. What that proves is strictly less, and the wording has to carry it:
the arguments of an export are UNCONSTRAINED, so a path found from one says the branch conditions along it can be
satisfied by *some* argument values, not that any caller can produce them. It is more than the control-flow route
`angr-cfgreach.py` reports (that one checks no condition at all) and less than an entry-point `reached`.

**And it is expensive, measured.** A symbolic `call_state` at an export was tried on the real `NetUSB.ko` against
a target 0x51c INSIDE the function being explored: 5925 steps and 123 seconds without reaching it, because the
search fans out through memory it cannot constrain. So library mode is bounded on a second axis — how many
exports it starts from at all — and every count travels in the result: exports declared, exports considered,
exports actually attempted per sink, and how many of those searches ended by exhausting their state space rather
than by running into a bound. A sink not reached under any of that is inconclusive, never unreachable.

Input : argv[1] = path to a JSON spec, argv[2] = path to write the JSON result to.
        spec = {"binary": str, "sinks": [str], "budgetSeconds": int, "maxSteps": int, "maxActive": int,
                "mode": "entry" | "library", "maxEntryPoints": int}
Output: always a JSON object (a crash is reported as {"ok": false, "error": ...}), so the caller never has to
        distinguish "the tool broke" from "the tool found nothing".
"""

import json
import sys
import time

# 40 printable bytes is enough to recognise a path-triggering input without dumping a payload into the findings.
PREVIEW_BYTES = 40


def preview(raw):
    """Render a concrete byte string as a bounded, printable preview (never the full payload)."""
    if not raw:
        return ""
    shown = raw[:PREVIEW_BYTES]
    text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in shown)
    suffix = f"…(+{len(raw) - PREVIEW_BYTES} B)" if len(raw) > PREVIEW_BYTES else ""
    return text + suffix


def sink_addresses(proj, name):
    """
    Every address that entering `name` can look like: the PLT thunk (dynamically linked, the common firmware case)
    and the symbol itself (statically linked). Reaching any of them means the sink is called on that path.
    """
    addrs = []
    plt = getattr(proj.loader.main_object, "plt", {}) or {}
    if name in plt:
        addrs.append(plt[name])
    try:
        sym = proj.loader.find_symbol(name)
        if sym is not None and sym.rebased_addr:
            addrs.append(sym.rebased_addr)
    except Exception:
        pass
    # dedupe, order-stable
    return list(dict.fromkeys(addrs))


def explore_one(angr, claripy, proj, name, addrs, budget_s, max_steps, max_active, start_state=None):
    """
    Bounded search for a path to any address of one sink. Returns the per-sink result dict.

    With no `start_state` the search begins at the program's ENTRY POINT, seeded with symbolic argv[1] and
    symbolic stdin — the two input channels a firmware CLI daemon actually reads — so a path that depends on
    attacker input can be found rather than being cut off by a concrete-zero default.

    `start_state` is library mode's `call_state` at an exported function. It carries no argv and no stdin because
    nothing here models the process that would supply them; `completed` in the returned dict says whether the
    search ended by running out of states or by running into a bound, which is the difference between "this start
    state cannot reach the sink" and "this start state was not explored far enough to say".
    """
    argv1 = None
    if start_state is not None:
        state = start_state
    else:
        try:
            argv1 = claripy.BVS("argv1", 8 * 128)
            state = proj.factory.entry_state(args=[proj.filename, argv1])
        except Exception:
            # A binary whose entry state cannot take argv (unusual loaders) still gets a stdin-only attempt.
            state = proj.factory.entry_state()
            argv1 = None

    simgr = proj.factory.simulation_manager(state)
    # DFS keeps the active set narrow: without it, a firmware daemon's branchiness exhausts memory long before
    # the step budget, and every run would report a pruned, useless inconclusive.
    try:
        simgr.use_technique(angr.exploration_techniques.DFS())
    except Exception:
        pass

    deadline = time.time() + budget_s
    steps = 0
    pruned = False
    # Set only where the loop runs out of work inside its bounds; every `break` below is a bound being hit.
    completed = False
    errors = 0
    first_error = ""
    exhausted_reason = "search space exhausted"
    # angr's libc SimProcedure models are imperfect on real firmware (its `sscanf` model raises a raw TypeError on a
    # symbolic position, for one). Such a crash belongs to ONE state, so tolerate a handful: drop the offending
    # state and let the search continue down the other paths. Only give up when they dominate the run.
    max_errors = 12

    def has_work():
        """DFS parks everything but the head state in `deferred`; an empty active stash is not an empty search."""
        return bool(simgr.active) or bool(simgr.stashes.get("deferred"))

    while has_work() and steps < max_steps:
        if time.time() >= deadline:
            exhausted_reason = f"wall-clock budget ({budget_s}s) reached"
            break
        if not simgr.active:
            simgr.active.append(simgr.stashes["deferred"].pop())
        try:
            simgr.explore(find=addrs, n=1)
        except Exception as exc:
            errors += 1
            if not first_error:
                first_error = f"{type(exc).__name__}: {exc}"
            if simgr.active:
                simgr.active = simgr.active[1:]  # discard the state angr choked on, keep the rest
            if errors > max_errors:
                exhausted_reason = f"angr-internal errors dominated the search ({errors}); first was {first_error}"
                break
            continue
        steps += 1
        if simgr.found:
            break
        if len(simgr.active) > max_active:
            simgr.active = simgr.active[:max_active]
            pruned = True
    else:
        if steps >= max_steps:
            exhausted_reason = f"step budget ({max_steps} steps) reached"
            completed = False
        else:
            # No work left inside the bounds — but "exhausted" only counts when no path was thrown away on the way.
            # Pruning drops active states to stay inside the memory bound, and an angr-internal error discards the
            # state it happened on; either way the search walked less than the whole space and cannot say so.
            # Measured on /bin/cat: 8 states lost to a SimFileDescriptorDuplex TypeError in a run that would
            # otherwise have reported itself complete.
            completed = not pruned and errors == 0

    if errors and "angr-internal errors" not in exhausted_reason:
        # The budget is still the headline reason, but a reader must know the search also lost paths to tool bugs.
        exhausted_reason = f"{exhausted_reason}; {errors} state(s) also lost to angr-internal errors ({first_error})"

    result = {
        "sink": name,
        "addresses": [hex(a) for a in addrs],
        "steps": steps,
        "pruned": pruned,
        "errors": errors,
        "completed": completed,
    }

    if simgr.found:
        found = simgr.found[0]
        result["outcome"] = "reached"
        try:
            result["stdin"] = preview(found.posix.dumps(0))
        except Exception:
            result["stdin"] = ""
        if argv1 is not None:
            try:
                result["argv1"] = preview(found.solver.eval(argv1, cast_to=bytes))
            except Exception:
                result["argv1"] = ""
        try:
            # The call chain that got here — the evidence a reader can follow back into the disassembly.
            result["path"] = [hex(a) for a in found.history.bbl_addrs.hardcopy[-12:]]
        except Exception:
            result["path"] = []
    else:
        result["outcome"] = "not_reached_in_budget"
        result["reason"] = exhausted_reason

    return result


def exported_functions(proj, max_entries):
    """
    The functions an outsider can enter a shared object through, deduped by address and ordered by it.

    `is_export` is the dynamic symbol table saying "callers may bind to this", which is exactly the set a library's
    users can call. Local statics are excluded: nothing outside the object can name them. Where a stripped object
    declares none, the GLOBAL function symbols are the fallback — a name something outside can resolve — and the
    result says which of the two produced the list, because "no export table" and "no exported function" are
    different facts about the object.
    """
    exports, globals_ = [], []
    for sym in proj.loader.main_object.symbols:
        try:
            if not sym.is_function or not sym.rebased_addr:
                continue
            if getattr(sym, "is_export", False):
                exports.append(sym)
            elif not getattr(sym, "is_local", True):
                globals_.append(sym)
        except Exception:
            continue
    chosen, source = (exports, "dynsym-export") if exports else (globals_, "global-symbol")
    seen, uniq = set(), []
    for sym in sorted(chosen, key=lambda s: (s.rebased_addr, s.name or "")):
        if sym.rebased_addr in seen:
            continue
        seen.add(sym.rebased_addr)
        uniq.append((sym.name or f"sub_{sym.rebased_addr:x}", sym.rebased_addr))
    return len(uniq), uniq[:max_entries], source


def explore_from_exports(angr, claripy, proj, name, addrs, entries, deadline, max_steps, max_active):
    """
    One sink, asked from each exported function in turn until it is reached or the sink's slice of wall-clock runs
    out. Returns the per-sink dict, with the accounting that keeps its silence readable.

    `entryPointsAttempted` is how many exports the search actually started from and `entryPointsCompleted` how many
    of those ran out of states inside their bounds having thrown none away — the only ones about which anything was
    settled. Everything else is a bound that was hit, so a `not_reached_in_budget` here says "not found from the
    exports we got through", which is not a statement about the exports we did not.
    """
    attempted = 0
    completed = 0
    steps = 0
    errors = 0
    pruned = False
    first_reason = ""
    for index, (export_name, addr) in enumerate(entries):
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        # Split what is left across the exports still unasked, with a floor: a slice too small to take a single
        # step would spend the budget proving nothing about every one of them.
        slice_s = max(3.0, remaining / max(1, len(entries) - index))
        try:
            state = proj.factory.call_state(addr)
        except Exception as exc:
            attempted += 1
            if not first_reason:
                first_reason = f"call_state at {export_name} failed: {type(exc).__name__}: {exc}"
            continue
        r = explore_one(angr, claripy, proj, name, addrs, slice_s, max_steps, max_active, start_state=state)
        attempted += 1
        steps += r.get("steps", 0)
        errors += r.get("errors", 0)
        pruned = pruned or bool(r.get("pruned"))
        if r.get("completed"):
            completed += 1
        if not first_reason:
            first_reason = r.get("reason", "")
        if r.get("outcome") == "reached":
            out = dict(r)
            out.update(
                {
                    "outcome": "reached",
                    "reachedFrom": export_name,
                    "entryPointsAttempted": attempted,
                    "entryPointsCompleted": completed,
                    "steps": steps,
                    "errors": errors,
                    "pruned": pruned,
                }
            )
            # Nothing supplied argv or stdin to a library call, so no concrete input is claimed for one.
            out.pop("argv1", None)
            out.pop("stdin", None)
            return out
    if attempted == 0:
        reason = "no export was reached before the run budget was spent"
    else:
        reason = (
            f"not found from {attempted} of {len(entries)} export(s) asked; {completed} of those searches ran out "
            f"of states inside their bounds. {first_reason}"
        ).strip()
    return {
        "sink": name,
        "outcome": "not_reached_in_budget",
        "addresses": [hex(a) for a in addrs],
        "entryPointsAttempted": attempted,
        "entryPointsCompleted": completed,
        "steps": steps,
        "errors": errors,
        "pruned": pruned,
        "completed": False,
        "reason": reason,
    }


def run_library(angr, claripy, proj, spec, sinks, budget_s, max_steps, max_active):
    """Library mode: the same bounded search, started at each export instead of at an entry point there is none of."""
    max_entries = int(spec.get("maxEntryPoints", 16))
    total, entries, source = exported_functions(proj, max_entries)
    out = {
        "mode": "library",
        "entryPointsTotal": total,
        "entryPointsConsidered": len(entries),
        "maxEntryPoints": max_entries,
        "entryPointSource": source,
        "entryPointsNamed": [n for n, _ in entries],
    }
    if total == 0:
        # Nothing to start from. Reporting the sinks as not-reached here would report a bound as an answer.
        out["results"] = []
        return out
    per_sink = max(5, budget_s // max(1, len(sinks))) if sinks else budget_s
    overall_deadline = time.time() + budget_s
    results = []
    for name in sinks:
        addrs = sink_addresses(proj, name)
        if not addrs:
            results.append({"sink": name, "outcome": "absent", "reason": "no PLT/symbol address in this object"})
            continue
        if time.time() >= overall_deadline:
            results.append({"sink": name, "outcome": "skipped", "reason": "run budget spent on earlier sinks"})
            continue
        deadline = min(time.time() + per_sink, overall_deadline)
        results.append(explore_from_exports(angr, claripy, proj, name, addrs, entries, deadline, max_steps, max_active))
    out["results"] = results
    return out


def main():
    if len(sys.argv) != 3:
        print(json.dumps({"ok": False, "error": "usage: angr-reach.py <spec.json> <out.json>"}))
        return 2
    spec_path, out_path = sys.argv[1], sys.argv[2]

    try:
        with open(spec_path, "r", encoding="utf-8") as fh:
            spec = json.load(fh)
    except Exception as exc:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump({"ok": False, "error": f"unreadable spec: {exc}"}, fh)
        return 1

    out = {"ok": False, "error": "unknown"}
    try:
        import logging

        import angr
        import claripy

        # angr is extremely chatty on firmware binaries (every unresolved jump is a warning); the caller wants the
        # JSON, not a log flood down the job stream.
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
        logging.getLogger("pyvex").setLevel(logging.ERROR)

        binary = spec["binary"]
        sinks = spec.get("sinks", [])
        budget_s = int(spec.get("budgetSeconds", 60))
        max_steps = int(spec.get("maxSteps", 400))
        max_active = int(spec.get("maxActive", 24))

        proj = angr.Project(binary, auto_load_libs=False)
        out["arch"] = proj.arch.name
        out["entry"] = hex(proj.entry)

        if spec.get("mode") == "library":
            lib = run_library(angr, claripy, proj, spec, sinks, budget_s, max_steps, max_active)
            out = {"ok": True, "arch": out["arch"], "entry": out["entry"], **lib}
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(out, fh)
            return 0

        results = []
        # The budget is per-run, not per-sink: a binary with six sinks must not take six times as long. Each sink
        # gets an equal slice, and a sink that never got its slice is reported as skipped rather than unreachable.
        per_sink = max(5, budget_s // max(1, len(sinks))) if sinks else budget_s
        overall_deadline = time.time() + budget_s
        for name in sinks:
            addrs = sink_addresses(proj, name)
            if not addrs:
                results.append({"sink": name, "outcome": "absent", "reason": "no PLT/symbol address in this binary"})
                continue
            if time.time() >= overall_deadline:
                results.append({"sink": name, "outcome": "skipped", "reason": "run budget spent on earlier sinks"})
                continue
            results.append(explore_one(angr, claripy, proj, name, addrs, per_sink, max_steps, max_active))

        out = {"ok": True, "arch": out["arch"], "entry": out["entry"], "results": results}
    except ImportError as exc:
        out = {"ok": False, "error": f"angr not importable: {exc}"}
    except Exception as exc:
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
