# FirmLab — plan de trabajo: motor de firmware con autonomía consciente

Plan completo para llevar FirmLab de un banco de análisis operado por clics a un **motor de firmware
especializado**: aísla un solo dominio y lo perfecciona al máximo — más datos, más control, más profundidad, y
autonomía igual o mayor que un generalista pero **con consciencia** (razonamiento acotado, auditable y
determinista por debajo).

Este documento reemplaza el borrador anterior, cuya premisa —un agente LLM que decide libremente el siguiente
paso— quedó desmentida por la evidencia: la plataforma madre (Galert, ver §1) eligió lo contrario, y por buenas
razones. Es un plan; cada fase se envía por separado.

---

## 1. Encuadre: por qué firmware-only, y qué aprendemos de Galert

FirmLab se talló del dominio firmware de **Galert**, una plataforma de pentest autónomo de siete dominios
(Claude Agent SDK + Temporal). Compartir capacidades con Galert de entrada no es duplicar por error: es el punto
de partida para **superarlo en firmware**, algo que un generalista no puede permitirse. El dominio firmware de
Galert es un v1 naciente (8 agentes que comparten maquinaria genérica, emulación frágil, sin memoria entre
scans). Un dominio aislado y perfeccionado gana en profundidad, robustez y datos.

Lecciones de Galert, incorporadas a este plan:

- **Su orquestador no es un LLM autónomo, es código determinista** (un DAG de Temporal). La IA solo razona
  *dentro* de cada nodo. Es la decisión correcta: la autonomía ciega es frágil e inauditable.
- **Su emulación la conduce el LLM a mano → es su mayor fragilidad** (los shims de NVRAM son "el bloqueador
  #1"; un qemu colgado "ha parado un scan entero"). La convertimos en providers deterministas.
- **Su disciplina de prueba es excelente**: `audita → preflight → reproduce → prueba o degrada honestamente`,
  con una máquina de proof-states que se niega a llamar "RCE en el dispositivo" a una shell de qemu-user. La
  adoptamos como ciudadano de primera clase.
- **Es stateless**: cada scan empieza de cero. Nuestro diferenciador estructural es lo contrario — un **corpus
  persistente** que aprende del dominio.

Diferenciadores de FirmLab que se preservan y amplían: determinista, local, sin coste y sin red en su base;
**visual e interactivo** (Galert produce markdown); entropía y firmas como primitivas de primera clase.

---

## 2. Principio rector: autonomía con consciencia

> **El agente razona sobre un esqueleto determinista, no sobre un lienzo en blanco.** Su libertad está en la
> interpretación, la priorización y la elección de rama — nunca en la mecánica. Extracción, bring-up de
> emulación y captura de prueba son *providers deterministas*. El agente decide **qué** hacer y **qué
> significa** el resultado; no teclea el `mknod` ni el `LD_PRELOAD`.

Dos corolarios que no se violan:

- **La verdad de base es determinista.** `@firmlab/core` y los providers producen los hechos; el agente los
  cita, no los inventa. Cada hallazgo se sostiene en su propia evidencia per-imagen.
- **El corpus da priors y referencias cruzadas, nunca conclusiones.** Una clave vista antes *levanta una
  bandera para comprobar*, no afirma el hallazgo. Si el corpus concluyera, reintroduciríamos la alucinación a
  nivel de base de datos y mataríamos la reproducibilidad.

Todo lo que sea LLM va detrás de `FIRMLAB_AGENT`. Con el flag apagado: sin red, sin coste, comportamiento
determinista idéntico al actual. La "consciencia" es que cada decisión de agente tiene entradas estructuradas,
salida registrada y justificación auditable — y la máquina de proof-states como conciencia moral.

---

## 3. Arquitectura: el esqueleto y los nodos de agente

Todo el flujo mecánico es determinista. El agente vive en cinco puntos de juicio.

```
DETERMINISTA (código)              NODO DE AGENTE (juicio, registrado)
─────────────────────              ──────────────────────────────────
intake + análisis estático
  (entropía/firmas/estructura/id)
        │
        ▼
                              ①  Triaje: clase ambigua, ¿merece extracción?,
                                 qué cascada, prioriza superficie de ataque
        │
        ▼
extracción + walk + arch modal
        │
        ▼
preflight de capacidades
  (qué es emulable — determinista)
        │
        ▼
SBOM · secrets · triaje binario
        │
        ▼
                              ②  Selección de objetivo: qué binarios/servicios
                                 valen profundidad; qué rung de emulación
                                 (acotado por el preflight)
        │
        ▼
escalera de emulación
  (providers robustos, scriptados)
        │
        ▼
                              ③  Interpretación + proof-state: ¿prueba o
                                 downgrade? — la conciencia
        │
        ▼
                              ④  Zero-day: sink decompilado + source
                                 alcanzable → ¿vuln?, construye el trigger
        │
        ▼
captura de prueba (determinista)
        │
        ▼
                              ⑤  Síntesis: narrativa sobre hallazgos citados
```

Cada nodo consume datos estructurados de las etapas deterministas y emite una decisión + rationale a la tabla
de sesión. Entre nodos, todo es código que no falla de formas creativas.

---

## 4. La escalera de emulación como providers deterministas

El punto donde más superamos a Galert. Su escalera la conduce el LLM a mano; aquí es código robusto con panel
de control. El agente elige el peldaño (nodo ②) e interpreta el resultado (nodo ③); la mecánica es determinista.

| Rung | Provider determinista | El agente decide |
|---|---|---|
| 1 · qemu-user binario | `qemu-<arch>-static -L rootfs`, env CGI, captura canary/SIGSEGV | qué binario, qué input |
| 2 · servicio en chroot | qemu-static copiado al rootfs, `mknod /dev/{nvram,mtd,watchdog}`, `LD_PRELOAD=libnvram-<arch>.so`, arranque como el init | qué servicio, cuándo escalar |
| 3 · full-system | `qemu-system-<arch>` + kernels firmadyne, rootfs→ext2, `hostfwd` | cuándo el rung-2 no basta |
| fuzz · AFL++ | `afl-qemu-trace-<arch>`, dict de `rabin2 -z`, desock | qué target, cuándo vale la pena |
| RTOS · Renode | boot Cortex-M en la plataforma MCU | clase rtos/baremetal |

El bloqueador NVRAM de Galert se resuelve **una vez, en código**, y no vuelve. El teardown (que a ellos les
rompe scans) es determinista y garantizado. La captura de prueba es un provider, no un prompt.

---

## 5. La máquina de proof-states (la conciencia)

Cada hallazgo lleva un estado de prueba explícito, calculado con disciplina, no asumido:

- `needs_runtime_reproduction` — plausible, sin reproducir. El default de todo lo estático.
- `static_confirmed` — reproducible desde los bytes del firmware (p.ej. taint sink→source decompilado).
- `confirmed_in_emulation` — probado bajo qemu-user/chroot. **Prueba el sandbox, no el dispositivo.**
- `confirmed_full_system` — probado en boot completo.
- `blocked_by_platform` — la arch/blob no es emulable aquí; necesita hardware.
- `blocked_by_security` — un control válido lo detiene.
- `false_positive` — la evidencia lo contradice, o pura especulación por clase de dispositivo.

El **preflight determinista** (§3) pone un suelo honesto: si la arch no es emulable en contenedor, el nodo ③ no
puede fabricar una ejecución — se le fuerza a `static_confirmed`/`blocked_by_platform`. Nunca se sube qemu-user
a "RCE en el dispositivo". Todo downgrade queda registrado con su rationale.

---

## 6. El corpus persistente: el diferenciador estructural

Galert es stateless. FirmLab acumula conocimiento del dominio. El modelo pasa de por-imagen a un grafo
cross-imagen que **referencia**, nunca concluye.

```
POR-IMAGEN (existe)          CROSS-IMAGEN (nuevo — índices consultables)
images ──────────────────►   device_family    agrupa imágenes por identidad
binaries ────────────────►   artifact          hash → en qué imágenes aparece
secrets ─────────────────►   credential        hash → seen-in set
sbom components ─────────►   component_obs      versión → imágenes + CVEs alcanzables
findings ────────────────►   reachability_prior componente+sink+familia → confirmado antes
```

Son unas tablas más en el SQLite actual, con índices — no infraestructura nueva. Ninguna decide nada; el
finding vive en la imagen.

Tres niveles de "aprendizaje", de menor a mayor riesgo:

- **Nivel 0 — Acumulación determinista (el 80% del valor).** Sin ML. Matching por hash: mismo BusyBox entre
  imágenes, misma clave, memoria de alcanzabilidad de CVEs, diff cross-versión (regresiones). Puro y
  reproducible.
- **Nivel 1 — Promoción de reglas (curada por humano).** Un patrón recurrente (layout de vendor, credencial
  por defecto) se promueve a firma de primera clase tras N observaciones o confirmación humana. Aprendizaje
  como curación auditable. Ej.: el SquashFS Broadcom que a Galert le tocó parchear a mano → aquí se aprende y
  se promueve a receta try-first.
- **Nivel 2 — Priors asistidos por el agente (después, acotado).** El nodo LLM usa estadísticas del corpus para
  priorizar e hipotetizar, pero sigue obligado a producir evidencia per-imagen.

**Advertencia de diseño**: entrenar un modelo sobre el corpus (aprendizaje continuo en sentido ML) es lo que NO
queremos de entrada — pelea contra la identidad determinista y los corpus de firmware son pequeños y
heterogéneos. El win es una base de conocimiento disciplinada con matching determinista + reglas curadas.

---

## 7. Superficies nuevas: el dossier y los paneles

El dossier por-imagen y las vistas de corpus son el mismo dato a dos zooms.

**Panel-dossier** — vista única que se rellena en vivo conforme completan los jobs (aprovecha el polling
actual). Secciones que se encienden por etapa: identidad · entropía · estructura · árbol de extracción · **tabla
de binarios** (ruta, arch, hardening NX/canary/PIC, imports, network-facing, estado de emulación, hallazgos) ·
componentes/SBOM · secretos · runs de emulación · hallazgos. Dos reglas de honestidad:

1. **Indicador de cobertura**: dice qué se corrió y qué falta; nunca aparenta completitud.
2. **Cada dato lleva su proof-state**: no es "lo encontrado" sino "lo encontrado y cuánto lo creemos".

Los badges de corpus aparecen inline ("esta clave vista en 3 imágenes", "este BusyBox tiene CVE alcanzable en
esta familia") y enlazan a las vistas de corpus.

**Otros paneles**: control de emulación (rungs como controles, harness visible, traza en vivo) · tablero de
proof-states · vistas de corpus (timeline por device-family, grafo de reutilización de credenciales, diff
cross-firmware) · vista de sesión del agente (qué eligió en cada nodo y por qué — la auditabilidad en pantalla).

---

## 8. Roadmap por fases

Las Fases 0–1 entregan valor **sin ningún LLM** — respetan la identidad determinista y baten a Galert antes de
introducir riesgo de agente. Las Fases 2–4 añaden la autonomía consciente sobre esa base sólida.

### Fase 0 — Fundaciones deterministas (sin agente)
- **Tabla de binarios de primera clase**: persistir el triaje r2/ghidra (hoy en jobs sueltos) como entidad.
- **Panel-dossier**: la vista única compuesta, con indicador de cobertura y proof-state por dato.
- **Escalera de emulación endurecida**: rung-2 (chroot + libnvram + `/dev`) y rung-3 (qemu-system+firmadyne)
  como providers robustos; teardown garantizado. Arregla el bloqueador NVRAM de Galert de una vez.
- **Preflight de capacidades** determinista (`runtime_capabilities`).
- **Esquema de proof-states** como ciudadano de primera clase en el modelo de datos.

### Fase 1 — Corpus persistente (sin agente)
- Las 5 tablas cross-imagen + índices.
- **Nivel 0** de aprendizaje: matching determinista (huellas, credenciales seen-in, component_obs, diff
  cross-versión).
- Badges de corpus en el dossier + vistas de corpus.
- **Nivel 1**: promoción de reglas curada por humano.

### Fase 2 — Copiloto (primer LLM, solo lectura)
- Nodos **③** (interpretación/proof-state) y **⑤** (síntesis) — los de menor riesgo.
- Lee dossier + corpus, produce análisis, priorización y siguientes pasos con la disciplina de proof-states.
- Detrás de `FIRMLAB_AGENT`; Claude Agent SDK; tiers de modelo (small/medium/large).

### Fase 3 — Nodos de decisión (agente en el esqueleto)
- Nodos **①** (triaje) y **②** (selección de objetivo): el agente elige rama e interpreta; la mecánica sigue
  determinista.
- Governor (presupuesto de pasos/tokens/dinero/tiempo), tabla de sesiones, transcript auditable.
- Emulación con aprobación humana (aún sin aislamiento de Fase 4).

### Fase 4 — Zero-day + profundidad + aislamiento
- Nodo **④**: razonamiento sink→source, construcción de trigger.
- Fuzzing AFL++ como provider; RTOS/Renode; UEFI/chipsec — cobertura de clases que Galert tiene nacientes.
- **Aislamiento por sesión**: contenedor efímero (como Galert, pero firmware-only y con límites de CPU/RAM que
  a ellos les faltan). Emulación sin aprobación manual porque el radio de daño ya está contenido.
- **Nivel 2** de aprendizaje (priors asistidos).

---

## 9. Qué no cambia · riesgos · decisiones abiertas

**No cambia**: `@firmlab/core` permanece puro y determinista; con `FIRMLAB_AGENT` apagado, sin red y sin coste;
los providers no se reescriben, se envuelven; binding loopback por defecto.

**Riesgos reconocidos**:
- La emulación es intrínsecamente frágil (Galert lo demuestra). Mitigación: providers deterministas +
  preflight honesto + degradar a `static_confirmed` sin vergüenza. No prometemos que todo firmware arranque.
- El corpus podría tentar a "concluir". Mitigación: el principio priors-no-conclusiones, aplicado en revisión.
- Coste de agente. Mitigación: governor con topes duros; Fases 0–1 no cuestan nada.
- Aislamiento (Fase 4) es el trabajo grande y donde Galert tiene grietas (socket Docker, `seccomp=unconfined`,
  sin límites de recursos). Lo abordamos con esas grietas ya identificadas.

**Decisiones abiertas** (a cerrar al empezar cada fase):
- Modelo de datos exacto de las 5 tablas cross-imagen (claves, qué indexa, qué dispara un badge). *(Cerrado en
  Fase 1.)*
- Contrato preciso de entrada/salida de cada nodo de agente.
- Formato del transcript de sesión (auditable y reanudable).
- Coordinación retención↔sesiones: una imagen con sesión activa no debe ser desalojable (bug latente actual).

---

## 10. Fase 2 — El copiloto (implementado): configuración de proveedores

La Fase 2 (nodos ③ interpretación y ⑤ síntesis, solo lectura) está construida: el **copiloto** lee los
resultados deterministas ya calculados de una imagen y devuelve un análisis priorizado y citado, con la
disciplina de proof-states codificada en el system prompt. No ejecuta nada y no inventa nada.

**Orientación DeepSeek-first, multi-proveedor.** La capa LLM (`apps/api/src/llm.ts`) usa `fetch` crudo (sin
SDK, coherente con el zero-dep del core). Toda ella va detrás de `FIRMLAB_AGENT`: con el flag apagado,
`loadLlmConfig()` devuelve `null` y **nada toca la red** — el workbench sigue local-only, sin coste.

Variables de entorno:

| Variable | Default | Qué hace |
|---|---|---|
| `FIRMLAB_AGENT` | (sin poner) | Gate maestro. `=1` habilita el copiloto; ausente = sin red, sin coste. |
| `FIRMLAB_LLM_PROVIDER` | `deepseek` | `deepseek` \| `openai` \| `anthropic`. |
| `FIRMLAB_LLM_API_KEY` | — | Clave genérica. Fallbacks: `DEEPSEEK_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`. |
| `FIRMLAB_LLM_MODEL` | según proveedor | deepseek→`deepseek-v4-flash`; anthropic→`claude-opus-4-8`; openai→**obligatorio**. |
| `FIRMLAB_LLM_BASE_URL` | según proveedor | Override. Apunta aquí un servidor OpenAI-compatible local (Ollama/vLLM). |
| `FIRMLAB_LLM_MAX_TOKENS` | `4096` | Tope de salida. |

Ejemplos:

```bash
# DeepSeek (por defecto)
FIRMLAB_AGENT=1 DEEPSEEK_API_KEY=sk-...              node apps/api/dist/index.js

# Anthropic (Claude)
FIRMLAB_AGENT=1 FIRMLAB_LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-... node apps/api/dist/index.js

# Servidor local OpenAI-compatible (Ollama), sin salir a internet
FIRMLAB_AGENT=1 FIRMLAB_LLM_PROVIDER=openai FIRMLAB_LLM_BASE_URL=http://127.0.0.1:11434/v1 \
  FIRMLAB_LLM_MODEL=llama3 OPENAI_API_KEY=ollama                      node apps/api/dist/index.js
```

Notas de implementación: DeepSeek/OpenAI comparten el adaptador `/chat/completions` (Bearer, `temperature`
0.2); Anthropic usa `/v1/messages` (`x-api-key` + `anthropic-version`, **sin** `temperature` — los modelos 4.x
lo rechazan con 400). El `reasoning_content` de los modelos thinking de DeepSeek se descarta: solo se toma la
respuesta final, nunca la cadena de pensamiento. El copiloto corre como job (las llamadas LLM son lentas); la
web muestra el panel solo si `/api/agent/status` reporta `enabled`.

**Principio, reafirmado**: el copiloto es la capa que *interpreta*, nunca la fuente de un hallazgo. Cada
afirmación se cita de un finding con su proof-state; los cross-refs de corpus son priors, no conclusiones. Es
el nodo ③/⑤ del esqueleto, no un agente que conduce el pipeline (eso es Fase 3).

---

## 11. Fase 3 — Los nodos de decisión (implementado)

La Fase 3 pone al agente **a elegir rama** sobre el esqueleto determinista. Cierra los contratos abiertos del §9
(entrada/salida de cada nodo, formato del transcript, coordinación retención↔sesiones). Todo tras `FIRMLAB_AGENT`.

**El orquestador es código, no el LLM** (`apps/api/src/agent/session.ts`). Conduce el flujo determinista:

```
triaje ①  →  extracción determinista (si el agente la eligió, vía el MISMO job que pulsa el usuario)
          →  preflight determinista (el techo honesto)
          →  selección de objetivo ②  →  pausa para APROBACIÓN HUMANA antes de cualquier emulación
```

El LLM solo actúa dentro de los dos nodos, y devuelve **JSON estructurado** (no prosa) que se valida y coacciona
con defaults seguros (`nodes.ts`). Contratos:

- **Nodo ① Triaje** — entrada: identidad, resumen de entropía, firmas, conteo de secretos por tipo, priors de
  corpus (familia vista, credenciales reusadas). Salida: `{resolvedClass, classConfidence, shouldExtract,
  extractionCascade, attackSurface, rationale}`.
- **Nodo ② Selección de objetivo** — entrada: tabla de binarios (hardening, network-facing, imports), findings, y
  **el preflight** (la cota dura). Salida: `{targets:[{path, rung, priority, reason}], emulationPlan, rationale}`.
  Cada `rung` solicitado se **recorta** (`clampRung`) al techo del preflight: un despliegue `static-only` baja todo
  a `none`; un techo `qemu-user` no se puede subir a `full-system` por decisión del agente. La honestidad se
  impone en código, no en la buena voluntad del modelo.

**El governor** (`agent/governor.ts`) es la correa: topes duros de pasos/tokens/dinero/tiempo, evaluados como
función pura antes de cada nodo; el primer techo alcanzado detiene la sesión y su razón queda registrada. Env:
`FIRMLAB_AGENT_MAX_STEPS` (8), `FIRMLAB_AGENT_MAX_TOKENS` (120000), `FIRMLAB_AGENT_MAX_USD` (0.5),
`FIRMLAB_AGENT_MAX_SECONDS` (300). El coste USD se estima por modelo (tabla de precios; fallback conservador).

**El transcript** (tablas `agent_session` + `agent_step`) es la auditabilidad: cada paso guarda la entrada
estructurada que vio el nodo, la decisión, el rationale, el modelo y los tokens — reproducible y reanudable. Al
arranque, `reconcileSessions()` marca como `error` cualquier sesión `running` interrumpida por un reinicio;
las `awaiting_approval` son una pausa durable legítima y sobreviven.

**Aprobación humana + retención.** La emulación propuesta por ② espera una aprobación explícita
(`POST /agent/sessions/:id/approve|decline`); al aprobar, la mecánica es el provider de emulación determinista
existente, corrido vía el sistema de jobs, y su proof-state queda acotado por el techo del preflight. Una sesión
activa (`running`/`awaiting_approval`) **fija** su imagen: `sweepRetention` la salta (cierra el bug latente del
§9). Sin aislamiento por sesión todavía — eso es Fase 4.

**Web**: la pestaña **Agent** muestra el transcript en vivo (cada nodo, su decisión y su porqué, con un expander
de auditoría del JSON de entrada/salida), el medidor del governor, y el gate de aprobar/rechazar emulación.

**Validado de extremo a extremo** en la imagen firmware (un mock LLM OpenAI-compatible sustituye la clave ausente,
así se ejercita toda la maquinaria determinista de forma reproducible): flag apagado inerte; ciclo completo de
sesión; recorte de rung en vivo (el `full-system` pedido cae a `qemu-user`); extracción real con binwalk y
emulación real con qemu-user; y la guarda de retención. Los tests unitarios cubren el governor y las funciones
puras de los nodos (parseo, clamping) sin tocar `node:sqlite`, coherente con la convención del repo.

---

## 12. Fase 4 — Zero-day, aislamiento y profundidad (implementado)

La Fase 4 añade el nodo de mayor valor y el trabajo grande (el aislamiento), sobre el esqueleto de las Fases 3.
Todo sigue tras `FIRMLAB_AGENT`; los tooling pesados (AFL++) son opt-in con degradación honesta.

**Nodo ④ — zero-day (`agent/zeroday.ts`).** Razona sink→source sobre un **scaffold de taint determinista**
(`providers/taint.ts`): de la triage de radare2 de un binario, se listan los *sinks* peligrosos que importa
(`system`/`popen`/`strcpy`/`sprintf`/`printf`…), las *fuentes* controlables (`recv`/`getenv`/`nvram_get`…) y las
pistas CGI/HTTP en sus strings. El agente hipotetiza un camino, clasifica la vuln y construye un **trigger** — pero
está atado por la máquina de proof-states: node ④ **solo produce candidatos** (`needs_runtime_reproduction`);
nunca declara un hallazgo confirmado. Solo la ejecución determinista del trigger (emulación aislada) puede subir un
candidato, y esa decisión es de código. **Nivel-2 de aprendizaje**: el contexto de ④ se enriquece con priors del
corpus (componentes vulnerables vistos en la familia, reachability confirmada antes) — banderas a comprobar, no
conclusiones.

**Aislamiento por sesión (`providers/isolate.ts`) — el trabajo grande, donde Galert falla.** En vez de un
contenedor anidado (socket Docker, seccomp abierto, sin límites — las grietas de Galert), FirmLab acota el radio de
daño con **primitivas del SO**: `prlimit` (topes duros de CPU/RAM/tamaño-de-fichero/FDs, aplicados por el kernel,
sin shell), `unshare -n` (namespace de red vacío, sin salida a internet) y un workdir efímero con teardown
garantizado en un `finally`. Se componen **sin shell** (execFile directo de `unshare`/`prlimit`), así una ruta de
rootfs con caracteres raros no puede inyectar. Niveles: `full` (netns + rlimits) → **la emulación se auto-ejecuta
sin aprobación humana**, porque el radio ya está contenido; `partial` (solo rlimits) o `none` → se conserva el gate
de aprobación de la Fase 3. Degradación honesta: `unshare -n` necesita `CAP_SYS_ADMIN`; sin él, `partial`.

**Fuzzing AFL++ (`providers/fuzz.ts`, opt-in).** Fuzz qemu-mode acotado en tiempo, ejecutado *dentro* del sandbox
de aislamiento, con corpus semilla + diccionario minado de `rabin2`; un crash reproducido registra un finding
`fuzz-crash` (`confirmed_in_emulation`). Como Ghidra, la capa AFL++ no se hornea en la imagen: sin `afl-fuzz`
presente, `available:false` honesto — nunca finge haber fuzzeado. Validado con AFL++ real dos veces: un NULL-deref
plantado hallado por cobertura (→ SIGSEGV → finding confirmado) y el `busybox` aarch64 real de OpenWrt instrumentado
257k execs (0 crashes honestos). Para binarios de firmware reales (enlazados dinámicamente) se pasa
`QEMU_LD_PREFIX=<rootfs>` y `-m none` (un fork qemu-mode muere bajo cap `--as`).

**El flujo (`agent/session.ts`).** Tras el nodo ②, el orquestador corre node ④ sobre el objetivo top (garantizando
su triage), registra los candidatos como findings + priors de reachability (write-back de Nivel-2), y decide la
emulación por nivel de aislamiento: `full` → auto-run bajo sandbox sin aprobación; si no → `awaiting_approval`.
`/api/agent/config` expone `phase4: { isolation, fuzzing, autoRun }`.

**RTOS/Renode (`providers/renode.ts`, opt-in).** Arranca un firmware MCU real bajo Renode y decide "booted" desde los
bytes UART reales (file-backend por UART), nunca por asunción; descubre el UART correcto siguiendo el grafo de
includes `using` del `.repl` de la plataforma, y degrada honestamente a `blocked_by_platform` sin Renode o sin
plataforma. Validado con muestra real: Contiki OS sobre un STM32F4 Discovery emulado (ELF demo canónico de Renode)
arrancó e imprimió `Contiki 3.x started` en uart4 → `confirmed_in_emulation`. Corre bajo aislamiento `full` (netns +
cpu + wall-clock); los caps `--as`/`--fsize` se omiten porque el GC de .NET y los ficheros mmap de Renode abortan bajo
ellos. **UEFI/chipsec** queda reconocido pero **no integrado** — degradación honesta, sin fingir cobertura.

**Validado de extremo a extremo** en la imagen firmware (mock LLM para ①②④): config Fase-4 con `isolation:full`;
sesión completa `triaje → extracción → preflight → ② → ④ → emulación`; node ④ produce un candidato de
command-injection desde el scaffold real de radare2; **la emulación qemu-user real se auto-ejecuta bajo netns +
prlimit SIN aprobación**; proof-state honesto; el candidato queda como `needs_runtime_reproduction`. Tests unitarios
cubren el scaffold de taint, el parseo de ④, el constructor de invocación aislada y el de fuzzing — sin tocar
`node:sqlite`.

---

## 13. Dirección propuesta — Fase 5: inteligencia externa (OSINT + disclosure)

**Idea (a acordar antes de construir).** Añadir un track donde uno o varios agentes **conectados a internet**
investiguen el firmware en profundidad: procedencia y fabricante, productos que lo usan, vulnerabilidades ya
publicadas, material de claves cuando sea público, y la vía de reporte responsable al fabricante. Es la extensión
natural del análisis, pero **rompe la identidad local-only de FirmLab**, así que su diseño gira alrededor de esa
tensión: el modo local, determinista y sin red sigue siendo el DEFAULT; internet es un opt-in aparte, explícito y
auditable.

### Principios no negociables (heredados y reforzados)

- **Flag separado, no `FIRMLAB_AGENT`.** Un `FIRMLAB_RESEARCH` (o `FIRMLAB_NET`) distinto, porque cambia la
  postura de privacidad de forma fundamental. Con él apagado, cero red externa — comportamiento actual intacto.
- **Egress mínimo y con ledger.** Nunca salen bytes de firmware. Solo salen derivados: hashes, nombres+versiones
  de componentes (SBOM), strings de identidad (vendor/modelo), CN de certificados. Antes de cada sesión de
  research se muestra un **"qué sale de esta máquina"** explícito y se pide consentimiento.
- **Determinista primero, también aquí.** Las consultas (NVD/OSV, security.txt, FCC ID, mirrors GPL, PSIRT) son
  *providers deterministas* con **fuentes allowlisted**; el agente interpreta, prioriza y sintetiza — no navega
  libre. Cada afirmación externa se **cita a su fuente** y lleva su propio estado (`needs_correlation`), nunca se
  auto-confirma contra el binario.
- **La reachability manda.** Un CVE publicado para un componente es una *pista*, no un hallazgo: solo el corpus
  de reachability / la reproducción per-imagen decide si aplica AQUÍ. Priors, no conclusiones (regla del §2/§6).
- **Solo defensivo.** Disclosure responsable, no armamentización: se descubre el contacto de seguridad y se
  **redacta** un reporte; el humano lo envía. Sin exploición de objetivos vivos, sin publicación, sin auto-send.
- **Aislamiento del track.** El agente de red corre en su propio sandbox con egress allowlisted (DNS/HTTP a
  dominios permitidos), reutilizando `providers/isolate.ts` endurecido para *permitir* solo esas salidas.

### Cómo encaja en el esqueleto

Es un track paralelo a los nodos ①–⑤, no un sustituto: consume los datos deterministas (identidad, SBOM, strings,
secretos, findings con proof-state) y produce **inteligencia citada** que enriquece el dossier y la síntesis ⑤.
Cada agente de red es un nodo con entrada estructurada, salida registrada y rationale — misma disciplina.

### Fases (una o varias, incrementales)

- **5.0 · Procedencia e identidad.** De strings/identidad (vendor, modelo, versión, banners de bootloader, CN de
  certs) → fabricante + producto + familia de firmware, vía fuentes allowlisted (FCC ID, páginas de vendor,
  mirrors GPL). Mayormente determinista; el agente desambigua. Salida: ficha de procedencia citada.
- **5.1 · Inteligencia de vulnerabilidades.** Correlaciona el SBOM (componente+versión) con avisos publicados
  (NVD/OSV/GitHub advisories/PSIRT) → CVEs conocidos; cruza con los priors de reachability del corpus para marcar
  cuáles son *plausiblemente* alcanzables aquí (nunca auto-confirmados). El nodo ranquea y explica, citando.
- **5.2 · Procedencia de claves y artefactos.** Cuando aplique, investiga si claves de cifrado/firma o
  decryptors del firmware están **publicados** (releases GPL, documentación de vendor, investigación previa) —
  solo procedencia y cita; jamás un servicio de cracking. Marca si la imagen usa una clave conocida/por defecto.
- **5.3 · Asistencia a disclosure responsable.** Descubre el contacto de seguridad del fabricante (security.txt,
  CNA/PSIRT, coordinación CERT) y **redacta** un reporte desde los hallazgos confirmados (con sus proof-states).
  Lo envía el humano. Sin auto-send, sin publicación.

### Decisiones abiertas (a cerrar al empezar 5.0)

- Motor del agente de red: ¿Claude Agent SDK con herramientas allowlisted, o providers deterministas + un nodo
  LLM de síntesis (más barato, más auditable)? Preferencia inicial: lo segundo, escalando a lo primero si hace
  falta.
- Mecanismo de egress-allowlist (proxy con lista de dominios vs. netns + resolvedor restringido).
- Formato del ledger de datos-que-salen y del consentimiento por sesión.
- Caché local de resultados OSINT en el corpus (para reproducibilidad y para no reconsultar), respetando ToS.

### Estado — 5.0/5.1 implementado

Construido y validado con servicios reales. Todo tras `FIRMLAB_RESEARCH` (separado de `FIRMLAB_AGENT`); con el
flag apagado, cero red externa.

- **Config + choke point** (`research/config.ts`): gate por `FIRMLAB_RESEARCH`, allowlist de hosts, y un
  `allowlistedFetch` que **rechaza cualquier host fuera de la lista** antes de abrir socket.
- **Procedencia** (`providers/provenance.ts`, determinista): extrae vendor/modelo/versión/URLs/dominios/CN/banners
  de los strings del análisis **y de ficheros de banner del rootfs** (`/etc/issue`, `/etc/os-release`…). Puro.
- **Ledger de egress** (`research/egress.ts`): declara qué sale (nombres+versiones → api.osv.dev) y **qué nunca
  sale** (bytes de firmware, secretos, claves). Se muestra antes y con el resultado.
- **OSV** (`providers/osv.ts`): correlaciona el SBOM (mapa syft→ecosistema OSV) con avisos **publicados** en
  api.osv.dev; egress = solo nombre+versión+ecosistema. Un aviso para un componente presente es una *pista*, no un
  bug confirmado — la reachability la decide la imagen. Constructor/parser puros y testeados.
- **Síntesis** (`agent/intel.ts`): brief **citado** vía el LLM (DeepSeek por defecto), con priors de reachability
  del corpus; disciplina de disclosure responsable (localizar contacto, *redactar* — nunca enviar).
- **Ruta + job** (`routes/research.ts`): `/research/status`, `POST/GET /images/:id/research`. Web: panel "External
  intelligence" en el dossier (gated; run + ledger + tabla de avisos citados + brief).

Validado en el contenedor: flag-off inerte (status disabled, POST 400); flag-on → SBOM syft real (194 paquetes)
→ **OSV.dev real** (80 consultados, 70 avisos; p.ej. `apt 2.6.1 → DEBIAN-CVE-2011-3374`) → procedencia
(`acme-networks`/`v1.2.3` de `/etc/issue`) → **brief real de DeepSeek**. Tests puros: OSV, provenance, config-gate,
egress — sin tocar `node:sqlite`.

**5.2/5.3 — procedencia de claves + disclosure (implementado).**
- **5.2** (`providers/keys.ts`): resume material de claves del análisis **y de un escaneo acotado del rootfs
  extraído** (las claves viven comprimidas dentro del FS, invisibles a nivel de imagen). Una clave privada embebida
  es **efectivamente pública** (extraíble de cualquier dispositivo); `sharedInImages` (cross-ref del corpus) lo
  prueba directamente. Valores redactados; nunca es un servicio de cracking.
- **5.3** (`providers/securitytxt.ts`): descubre el contacto de disclosure vía RFC 9116
  (`/.well-known/security.txt`), pero **solo para dominios que el operador metió en el allowlist**; los demás se
  reportan como "no comprobado — añádelo al allowlist" (sin egress sorpresa). El brief de intel redacta el reporte
  con ese contacto; lo envía el humano. Validado con `security.txt` real (cloudflare → contacto hackerone) y la rama
  no-allowlisted honesta.

**Pendiente en este track** (deuda, `docs/ROADMAP.md`): más fuentes que OSV/security.txt (NVD/PSIRT/CNA); un
generador de reporte de disclosure descargable; mecanismo de egress-allowlist reforzado (proxy/netns) y caché OSV en
el corpus.
