// Decompile.java — FirmLab Ghidra headless post-script.
//
// Runs after analyzeHeadless has imported and auto-analyzed a single binary. Decompiles up to MAX functions to
// C pseudocode and writes a JSON array of {name, signature, pseudocode} to the path given as the first script
// argument. Defensive throughout: a failure on one function must not abort the whole run.
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

    for (Function fn : fm.getFunctions(true)) {
      if (count >= MAX_FUNCTIONS) {
        break;
      }
      if (fn.isThunk() || fn.isExternal()) {
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
    sb.append("[");
    for (int i = 0; i < objects.size(); i++) {
      if (i > 0) {
        sb.append(",");
      }
      sb.append(objects.get(i));
    }
    sb.append("]");

    try (FileWriter w = new FileWriter(outPath)) {
      w.write(sb.toString());
    }
    println("Decompile.java: wrote " + count + " functions to " + outPath);
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
