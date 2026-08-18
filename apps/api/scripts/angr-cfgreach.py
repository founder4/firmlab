#!/usr/bin/env python3
"""
angr-cfgreach — FirmLab's export-reachability probe, for the objects that have no entry point.

**The question `symreach` cannot ask.** `angr-reach.py` explores symbolically from a program's entry point. A
shared object and a kernel module have no entry point: a `.so` is entered through an exported function and a
`.ko` through a handler the kernel calls. Both were therefore *permanently unasked* — a vulnerable library or
module stayed a candidate nothing would ever settle.

**Why this is a CFG query and not symbolic execution, measured rather than assumed.** The obvious extension is a
symbolic `call_state` at an exported symbol. It was tried first, on the real `NetUSB.ko` from the corpus's
WDR3600, against a target that is provably INSIDE the function being explored (`__kmalloc`'s call site, 0x51c
into `SoftwareBus_dispatchNormalEPMsgOut`): **5925 steps and 123 seconds, and it never got there.** An exported
function's arguments are symbolic pointers into unconstrained memory, so the search fans out through data it
cannot constrain and never converges on the target. The same question over the recovered CFG is answered in
**microseconds**, after a one-off graph build of about two seconds.

**So the claim is deliberately weaker, and its wording has to carry that.** A path in the control-flow graph is
NOT a feasible path: nothing here checks that the branch conditions along it can be satisfied together. It says
that the code contains a route from an entry an outsider can invoke to the sink — which is a real, checkable
upgrade over "this object imports `__kmalloc`", and is emphatically not what `symreach`'s `reached` means. The
caller must never merge the two.

**A negative is worth even less, and there are three of them.** `not_reached` here means only that the RECOVERED
graph shows no route. CFGFast does not resolve indirect calls, and both target classes are built on them — a
kernel module registers a handler and the kernel calls it through a pointer, which is exactly why `init_module`
reaches almost nothing in the measured run. `no_functions_recovered` is a third state again: some stripped
shared objects on this corpus yield a graph with zero functions, and reporting that as "no sink reachable" would
turn a total failure to analyse into a clean bill of health.

Input : argv[1] = path to a JSON spec, argv[2] = path to write the JSON result to.
        spec = {"binary": str, "sinks": [str], "budgetSeconds": int, "maxExports": int}
Output: always a JSON object (a crash is reported as {"ok": false, "error": ...}), so the caller never has to
        distinguish "the tool broke" from "the tool found nothing".
"""

import json
import sys
import time

# Exported functions listed per sink in the result. The full count always travels beside it, so the list being
# bounded can never be read as the whole set.
NAMED_EXPORTS = 40


def load_spec(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def entry_symbols(proj, mo):
    """
    The functions an outsider can enter this object through.

    A `.so` declares them: `is_export` is the dynamic symbol table saying "callers may bind to this". A `.ko` has
    no dynamic table at all, so the equivalent is its GLOBAL function symbols — the names the kernel module
    loader resolves for other modules, plus the ones the module itself registers. Local statics are excluded from
    both: nothing outside the object can name them, so they are not entry points even though they are functions.
    """
    out = []
    for sym in mo.symbols:
        try:
            if not sym.is_function or not sym.rebased_addr:
                continue
            if getattr(sym, "is_export", False):
                out.append(sym)
                continue
            # ET_REL carries no dynamic exports at all, so fall back to binding: a GLOBAL function symbol is a
            # name something outside this object can resolve. A local static is not an entry point even though
            # it is a function, so it is excluded from both classes.
            if not getattr(sym, "is_local", True):
                out.append(sym)
        except Exception:
            continue
    # Stable order, deduped by address: two names for one address are one entry point.
    seen = set()
    uniq = []
    for s in sorted(out, key=lambda s: (s.rebased_addr, s.name or "")):
        if s.rebased_addr in seen:
            continue
        seen.add(s.rebased_addr)
        uniq.append(s)
    return uniq


def sink_holder_functions(cfg, proj, name):
    """
    Which functions contain a call to `name`.

    The sink is an UNRESOLVED symbol in both target classes, so CLE parks it in its synthetic extern object and
    every call site shows up as a graph predecessor of that address. That is more precise than scanning for the
    name: it is the set of blocks whose control flow actually leaves for the sink.
    """
    sym = proj.loader.find_symbol(name)
    if sym is None:
        return None
    node = cfg.model.get_any_node(sym.rebased_addr)
    if node is None:
        return None
    holders = set()
    for pred in cfg.model.get_predecessors(node):
        if pred.function_address is not None:
            holders.add(pred.function_address)
    return holders


def callers_of(callgraph, holders, nx):
    """
    Every function that can reach one of `holders` through the call graph, including the holders themselves.

    ONE reverse traversal per sink, not one forward traversal per export. A C library exports ~1600 functions and
    a forward `descendants()` for each is quadratic in practice; reversing the question makes the cost
    proportional to the number of sinks, which is a handful.
    """
    reaching = set()
    for h in holders:
        if h not in callgraph:
            continue
        reaching.add(h)
        try:
            reaching |= nx.ancestors(callgraph, h)
        except Exception:
            continue
    return reaching


def main():
    spec = load_spec(sys.argv[1])
    out_path = sys.argv[2]
    started = time.time()
    result = {"ok": False, "binary": spec.get("binary", "")}

    try:
        import angr
        import networkx as nx
    except Exception as exc:  # pragma: no cover - import failure is a deployment fact, not a code path
        result["error"] = f"angr import failed: {type(exc).__name__}: {exc}"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
        return

    import logging

    for noisy in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)

    try:
        proj = angr.Project(spec["binary"], auto_load_libs=False)
    except Exception as exc:
        result["error"] = f"could not load the object: {type(exc).__name__}: {exc}"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
        return

    mo = proj.loader.main_object
    result["arch"] = proj.arch.name
    result["objectType"] = type(mo).__name__

    t0 = time.time()
    try:
        cfg = proj.analyses.CFGFast(normalize=True)
    except Exception as exc:
        result["error"] = f"CFG recovery failed: {type(exc).__name__}: {exc}"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
        return
    result["cfgSeconds"] = round(time.time() - t0, 2)

    callgraph = cfg.functions.callgraph
    result["functionsRecovered"] = callgraph.number_of_nodes()
    result["callEdges"] = callgraph.number_of_edges()

    # A graph with no functions is a FAILURE TO ANALYSE, and it is a real state on this corpus: some stripped
    # shared objects yield exactly this. Returning it as "no sink reachable" would convert a total analysis
    # failure into a clean result, which is the one reading this whole provider exists to prevent.
    if result["functionsRecovered"] == 0:
        result["ok"] = True
        result["outcome"] = "no_functions_recovered"
        result["entryPoints"] = 0
        result["sinks"] = []
        result["elapsedSeconds"] = round(time.time() - started, 2)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
        return

    entries = entry_symbols(proj, mo)
    max_exports = int(spec.get("maxExports", 4000))
    result["entryPoints"] = len(entries)
    result["entryPointsConsidered"] = min(len(entries), max_exports)
    entries = entries[:max_exports]
    entry_by_addr = {s.rebased_addr: (s.name or f"sub_{s.rebased_addr:x}") for s in entries}

    budget = float(spec.get("budgetSeconds", 300))
    sinks_out = []
    for name in spec.get("sinks", []):
        if time.time() - started > budget:
            sinks_out.append({"sink": name, "outcome": "budget_exhausted"})
            continue
        holders = sink_holder_functions(cfg, proj, name)
        if holders is None:
            sinks_out.append({"sink": name, "outcome": "absent", "holders": 0})
            continue
        if not holders:
            # The symbol exists but no recovered block calls it — distinct from the symbol not being there.
            sinks_out.append({"sink": name, "outcome": "no_call_site", "holders": 0})
            continue
        reaching = callers_of(callgraph, holders, nx)
        hits = sorted(
            (entry_by_addr[a] for a in entry_by_addr if a in reaching),
            key=lambda n: (len(n), n),
        )
        sinks_out.append(
            {
                "sink": name,
                "outcome": "reachable" if hits else "not_reached",
                "holders": len(holders),
                "reachableFrom": len(hits),
                "entryPointsNamed": hits[:NAMED_EXPORTS],
                "namedTruncated": max(0, len(hits) - NAMED_EXPORTS),
            }
        )

    result["ok"] = True
    result["sinks"] = sinks_out
    result["elapsedSeconds"] = round(time.time() - started, 2)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover - the caller must never see a bare traceback as "no findings"
        try:
            with open(sys.argv[2], "w", encoding="utf-8") as fh:
                json.dump({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, fh)
        except Exception:
            pass
        sys.exit(1)
