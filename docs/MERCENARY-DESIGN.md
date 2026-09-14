# FirmLab — Mercenary (el agente 100 % autónomo, opt-in)

Este apartado es **arm C de [`AUTONOMOUS-WORKERS.md`](AUTONOMOUS-WORKERS.md), productizado**. Aquel documento
midió, sobre 18 imágenes y cuatro pasadas, un agente 100 % autónomo con la toolchain cruda y sin FirmLab, y lo
rechazó *como producto por defecto* por una razón concreta: reintroduce la confabulación que el proyecto entero
combate — un `[]` de findings no distingue "corrió todo y limpio" de "nunca llegó al rootfs", y §7.5/§9 de ese
doc registran las sobreafirmaciones reales que produjo (un titular "cleartext cloud pairing secret" que era una
clave **pública**; un `miio_token_seed` declarado "0 veces" cuando aparecía dos).

Esa decisión sigue en pie para el flujo normal. El mercenario la revierte **solo para los casos más difíciles y
solo detrás de un muro**. La revierte porque el mismo §11 midió que arm C **gana** justo donde el pipeline
determinista es ciego: lee dentro de ficheros que los scanners no abren (una clave privada dentro de
`usr/bin/httpd`, el instruction-stream de un módulo del kernel, 57 variables UEFI frente a 1), resuelve retos
completos (los 6 flags del RP2350, §7.6), recupera credenciales que la imagen lleva en claro, y —la sorpresa—
**rechaza findings bien** (declinó un CVE tras leer el bounds-check del vendor en los bytes). FirmLab ya está lo
bastante maduro como para incorporar esa amplitud sin perder la honestidad, si —y solo si— la salida del
mercenario nunca puede contaminar el ledger honesto.

## El invariante que rompe, y el que no

- **Rompe** determinismo y reproducibilidad. Cada run es irrepetible: modelo, proveedor, temperatura y las
  decisiones del propio agente cambian el recorrido. Eso es deliberado; es el precio de la adaptatividad que
  arm A no tiene.
- **No rompe** la honestidad del ledger. Es la línea que no se cruza. Un finding del mercenario **jamás** escribe
  un `ProofState` disciplinado (`static_confirmed`, `confirmed_in_emulation`, `confirmed_full_system`) en la tabla
  `findings`. Vive en un almacén en cuarentena, aparte, y la ÚNICA puerta al ledger honesto es la reconciliación
  (abajo): un provider determinista re-deriva la afirmación y es el CÓDIGO quien le estampa el proof-state, como
  para cualquier otro finding. Sin esa re-derivación, la afirmación del mercenario se queda fuera del censo, de
  `coverage.ts` y de la vista de calidad — existe, se lee, pero no cuenta como algo que FirmLab defiende.

Dicho de otro modo: el mercenario aporta **hipótesis**, no veredictos. La disciplina de proof-state se preserva
moviendo el agente a un lado del muro donde sus afirmaciones no pueden hacerse pasar por pruebas.

## Arquitectura

Aditivo, junto al pipeline actual — no lo sustituye. Reutiliza los seams que ya existen.

1. **Almacén en cuarentena (no la tabla `findings`).** Tablas nuevas en `store.ts`: `mercenary_runs`
   (id, imageId, provider, model, objetivo, presupuesto, coste real, estado, narrativa) y `mercenary_claims`
   (runId, título, clase-de-bug, ruta/evidencia citada, **confianza autoevaluada por el agente** — nunca un
   `ProofState`, un campo distinto y así nombrado, `mercenary_confidence`). Estructuralmente separado para que
   nada del mercenario pueda colarse en coverage/calidad/census. Es la misma lección que `mcp/format.ts`: la
   honestidad se hace la forma del dato, no una nota al pie.

2. **Modelo/proveedor configurable por run.** Reutiliza `agent/llm.ts` (raw `fetch`, ya soporta DeepSeek /
   OpenAI-compat / Anthropic; añadir `baseURL` libre para modelos locales/otros). Selección por run
   `{ provider, baseURL, model, apiKeyRef }`; la clave se resuelve vía `config-store` y **nunca** se persiste en
   la fila del run. Este es el "cualquier modelo al que le configure la API de un proveedor" del encargo.

3. **Governor como techo configurable, no fijo.** El agente gobernado (arm B) tiene caps duros
   (8 pasos / 120k tok / $0.50 / 300 s). El mercenario los expone como **techos que fija el operador** por run —
   siguen siendo un límite (coste/tiempo acotado, nunca infinito), pero el operador los sube para los casos que
   lo justifican. `governor.ts` se generaliza a ceilings paramétricos.

4. **Modo de objetivo + clasificación de artefacto.** El run declara `objective ∈ { assess, ctf, free }`, y el
   agente emite además su lectura del artefacto: *"reto CTF"*, *"target de investigación"*, *"dispositivo de
   producción"*. En `ctf` el objetivo es resolver (extraer flags/credenciales, como el RP2350 de §7.6); en
   `assess` es el análisis de seguridad estilo-galert; en `free` el operador da la consigna.

5. **Aislamiento y ROE.** Corre en el contenedor de tools bajo `isolate.ts` (rlimits + namespace de red opcional,
   reportado como parcial, no como sandbox). Egress OFF salvo `FIRMLAB_RESEARCH` (para el CVE-lookup y la
   adquisición de imagen hermana — item (a) del backlog). Toda acción activa/saliente pasa por `approval.ts`.
   Se mantiene el límite FSTM-9 por defecto (FirmLab prueba alcanzabilidad y redacta disclosure; no envía PoC
   armados); la excepción natural es `objective=ctf`, donde producir el flag ES el resultado legítimo.

6. **Salida.** Tres cosas, en este orden de valor: (1) la **narrativa** (el producto real de arm C — la
   cadena source→sink→privilegio→ruta que la UI de filas planas no tiene); (2) las **claims en cuarentena** con
   su confianza autoevaluada; (3) la **cola de reconciliación**.

7. **Reconciliación (arm C → arm A).** El puente. Cada claim que nombra algo re-derivable se entrega al provider
   determinista que corresponde (`webtaint`/`symreach`/`binvuln`/`credmatch`/`component-cve`…). Si el provider la
   reproduce, entra en `findings` con `syncFindings` bajo un source `reconciled:mercenary:<run>` y un
   `ProofState` **decidido por el código**. Si no, la claim se queda en cuarentena, etiquetada como no
   verificada. Así se capturan las ganancias de arm C sin ninguna de sus sobreafirmaciones — es exactamente la
   síntesis que la "tercera disposición" (§10) argumentaba, pero con el agente libre en vez del agente sobre MCP.

## UI

Nuevo apartado **Mercenary** (junto a los actuales, feature-gated por su propio flag, p. ej.
`FIRMLAB_MERCENARY=1`): elegir proveedor/modelo, objetivo y presupuesto; lanzar; ver el **reasoning trace en
streaming** (sobre el mismo primitivo de `jobs.ts`); y una lista de claims en cuarentena con un botón
**"Verificar con los providers"** (dispara la reconciliación). Un banner permanente declara que esta salida
**no** tiene disciplina de proof-state hasta reconciliarse — el equivalente al banner de coverage, porque un
agente no tiene banner propio y ese es precisamente el fallo que §10 documenta.

## Lo que NO es

- No es el flujo por defecto ni sustituye a `opacidad`; es opt-in para lo difícil.
- No cuenta en `coverage.ts` ni en la vista de calidad hasta que una claim se reconcilia.
- No arma exploits por defecto (límite FSTM-9), salvo el flag de un CTF.

## Tests de aceptación

Contra el corpus real, en contenedor, como manda el proyecto:

1. **RP2350 CTF** (`objective=ctf`): clasifica `baremetal-riscv` + "reto CTF", extrae los 6 flags y la password
   de arranque (§7.6). arm A no puede tocarlo; el mercenario sí.
2. **GE800 cifrada** (`objective=assess`): nombra el cifrado (AES-128 CBC/CTR, IV@0x116); con
   `FIRMLAB_RESEARCH=1` intenta la adquisición-hermana + recuperación de clave (backlog item (a)); sin él, emite
   el bloqueo honesto con la ruta de recuperación. Nunca un vacío silencioso.
3. **BE3600 producción** (`objective=assess`): narrativa estilo-galert de la cadena
   `rpc/tor replace_country os.execute → uci → root RCE`; la claim se entrega a `webtaint.ts`, que la confirma, y
   **solo entonces** entra en `findings` como `static_confirmed` con source `reconciled:mercenary:<run>`.
4. **Invariante (el test load-bearing):** ninguna fila de `findings` lleva jamás un source `mercenary:*` con
   `ProofState ∈ { static_confirmed, confirmed_in_emulation, confirmed_full_system }`. Las claims del mercenario
   viven solo en `mercenary_claims`; el único camino a `findings` es la reconciliación, que estampa un
   proof-state decidido por código y un source `reconciled:*`.

## Fases

1. **Almacén + runner esqueleto** — tablas de cuarentena, wiring sobre `jobs.ts`, reusando `llm.ts` + `isolate.ts`
   + governor-como-techo. Un run produce narrativa + claims en cuarentena. Sin reconciliación todavía.
2. **Config proveedor/modelo por run + modos de objetivo + clasificación de artefacto.**
3. **Puente de reconciliación** — claim → provider determinista → ledger honesto. Aquí es donde el apartado se
   gana el derecho a existir dentro de FirmLab.
4. **UI** — el apartado Mercenary con streaming del trace y el botón de verificación.

Deferidos y dependencias se anotan en [`BACKLOG.md`](BACKLOG.md) (sección "Mercenario").
