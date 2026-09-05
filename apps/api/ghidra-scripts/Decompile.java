// Decompile.java — FirmLab Ghidra headless post-script.
//
// Runs after analyzeHeadless has imported and auto-analyzed a single binary. Decompiles up to MAX functions to
// C pseudocode and writes JSON to the path given as the first script argument. Defensive throughout: a failure
// on one function must not abort the whole run.
//
// The cap bounds the DECOMPILATION, not the walk. It used to `break` out of the function loop, so nothing ever
// learned how many functions the binary had: the provider then reported `functionCount: functions.length`, the
// two could not differ, and the workbench's coverage widget could only ever read "40 of 40" for a binary with
// thousands of functions — the first forty by ADDRESS, at that. Iterating the function manager is cheap and
// decompiling is not, so the loop now runs to the end and only stops calling the decompiler, which is the same
// shape as the fix applied to `scanSignatures` in packages/core.
//
// Output is therefore an object, not a bare array:
//   {"functionTotal":N,"eligible":M,"decompiled":K,"functions":[{name,signature,pseudocode},...]}
// `functionTotal` counts every function Ghidra knows about; `eligible` excludes thunks and externals, which this
// script never decompiles, and is the honest denominator for K.
//
// Invoked by the API provider as:
//   analyzeHeadless <proj> firmlabproj -import <bin> -scriptPath <dir> -postScript Decompile.java <outJson> -deleteProject
//
// @category FirmLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class Decompile extends GhidraScript {

  private static final int MAX_FUNCTIONS = 40;
  private static final int MAX_PSEUDOCODE = 8000;

  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 1) {
      println("Decompile.java: missing output path argument");
      return;
    }
    String outPath = args[0];

    DecompInterface decomp = new DecompInterface();
    decomp.openProgram(currentProgram);

    FunctionManager fm = currentProgram.getFunctionManager();
    List<String> objects = new ArrayList<>();
    int count = 0;
    int total = 0;
    int eligible = 0;

    for (Function fn : fm.getFunctions(true)) {
      total++;
      if (fn.isThunk() || fn.isExternal()) {
        continue;
      }
      eligible++;
      // Past the cap the walk keeps counting and stops decompiling. Breaking here is what made the total
      // unknowable, and an unknowable total is what let the coverage widget claim completeness it never had.
      if (count >= MAX_FUNCTIONS) {
        continue;
      }
      try {
        DecompileResults res = decomp.decompileFunction(fn, 60, monitor);
        String code = "";
        if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
          code = res.getDecompiledFunction().getC();
        }
        if (code == null) {
          code = "";
        }
        if (code.length() > MAX_PSEUDOCODE) {
          code = code.substring(0, MAX_PSEUDOCODE);
        }
        objects.add(
            "{\"name\":" + jsonString(fn.getName())
                + ",\"signature\":" + jsonString(fn.getPrototypeString(false, false))
                + ",\"pseudocode\":" + jsonString(code) + "}");
        count++;
      } catch (Exception e) {
        // Skip a function that fails to decompile; keep going.
      }
    }

    decomp.dispose();

    StringBuilder sb = new StringBuilder();
    sb.append("{\"functionTotal\":").append(total);
    sb.append(",\"eligible\":").append(eligible);
    sb.append(",\"decompiled\":").append(count);
    sb.append(",\"functions\":[");
    for (int i = 0; i < objects.size(); i++) {
      if (i > 0) {
        sb.append(",");
      }
      sb.append(objects.get(i));
    }
    sb.append("]}");

    try (FileWriter w = new FileWriter(outPath)) {
      w.write(sb.toString());
    }
    println(
        "Decompile.java: decompiled " + count + " of " + eligible + " eligible function(s) (" + total
            + " total, thunks and externals excluded) to " + outPath);
  }

  /** Minimal JSON string escaper (quotes, backslashes, control chars). */
  private String jsonString(String s) {
    if (s == null) {
      return "\"\"";
    }
    StringBuilder b = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"':
          b.append("\\\"");
          break;
        case '\\':
          b.append("\\\\");
          break;
        case '\n':
          b.append("\\n");
          break;
        case '\r':
          b.append("\\r");
          break;
        case '\t':
          b.append("\\t");
          break;
        default:
          if (c < 0x20) {
            b.append(String.format("\\u%04x", (int) c));
          } else {
            b.append(c);
          }
      }
    }
    b.append("\"");
    return b.toString();
  }
}
