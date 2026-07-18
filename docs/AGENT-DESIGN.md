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
