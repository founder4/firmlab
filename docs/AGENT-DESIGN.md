# FirmLab — orquestación autónoma (diseño)

Plan para llevar FirmLab de un banco de herramientas operado por clics a un sistema que ejecute sesiones de
pentest de firmware con criterio autónomo: reporta lo que encuentra estáticamente, pero además reconduce,
reconfigura y ejecuta en función de las conclusiones que va sacando.

Este documento fija la arquitectura, el principio rector y las fases. Es un plan, no código; cada fase se
envía por separado.

---

## Principio rector: el agente orquesta, nunca es la fuente de un hallazgo

La identidad actual de FirmLab —local-only, sin red, determinista, reproducible (ver `ARCHITECTURE.md`,
"Deterministic core, optional tools")— **no se sacrifica**. La capa autónoma se añade *encima* y va detrás de
un flag; con el flag apagado, FirmLab sigue siendo exactamente lo que es hoy.

La regla que hace esto viable:

> El núcleo determinista (`@firmlab/core`) y los providers son la **verdad de base**. El agente lee sus
> resultados, razona sobre ellos, decide la siguiente acción y redacta la narrativa — pero **todo hallazgo
> tiene su evidencia en la salida de una herramienta**. El agente no emite un CVE, un secreto o una
> arquitectura por su cuenta: los cita.

Consecuencia directa: **no hay hallazgos alucinados**. Un informe siempre contiene los hechos deterministas y
reproducibles, más una capa de análisis y priorización escrita por el agente sobre esos hechos. Si el agente
se equivoca, se equivoca *interpretando datos reales que quedan a la vista*, no inventándolos.

Esto también resuelve la tensión de la no-determinismo: los datos son reproducibles; lo que varía entre
ejecuciones es el camino que el agente eligió recorrerlos, y ese camino queda registrado en el transcript de
la sesión.

---

## Por qué el código ya está a un 80%

`apps/api/src/providers/` **ya es un registro de herramientas**. Cada provider es lo que un modelo llama
"tool": una función con parámetros claros y salida estructurada tipada.

| Provider | Herramienta | Salida (en `resultJson`) |
|---|---|---|
| `extract` | binwalk `-Me` | rootfs, árbol, arch modal, binario de red sugerido |
| `sbom` | syft + grype | paquetes + CVEs |
| `gitleaks` | gitleaks | secretos (redactados) |
| `decompile` | radare2 | triaje: hardening, imports, símbolos, strings |
| `ghidra` | analyzeHeadless | pseudocódigo C |
| `emulate` | qemu-*-static | stdout/stderr/exitCode de la ejecución user-mode |
| `diff` | (puro, sin red) | deltas de identidad / paquetes / ficheros |

Hoy quien encadena esto es el usuario haciendo clic: extraer → ver un `dropbear` + un `.cgi` → decompilar el
CGI → buscar inyección → emular. **Un agente ejecuta ese mismo bucle decidiendo él según lo que encuentra.**
El salto no es construir capacidad nueva — está construida y probada— sino añadir la capa que decide.

Lo que hay que añadir:

1. **Esquemas de herramienta** — cada provider expuesto como definición JSON-schema (nombre, descripción,
   params, forma del retorno). Los tipos en `packages/core/src/types.ts` y los `*Result` de cada provider ya
   son casi eso.
2. **Runner del agente** — el bucle que llama al modelo con el set de tools, ejecuta la elegida a través del
   sistema de jobs actual (`startJob`), y le devuelve el resultado estructurado. El **Claude Agent SDK** está
   hecho para exactamente este bucle sobre tools propias; la alternativa es un bucle manual de tool-use sobre
   la Messages API.
3. **Tabla de sesiones** — como `jobs` pero un nivel arriba: objetivo, plan, transcript, hallazgos acumulados,
   presupuesto gastado, estado (`planning` → `running` → `done`/`error`/`stopped`).
4. **Gobernador de límites** — tope de pasos, de tokens, de dinero y de tiempo por sesión; política de qué
   tools se auto-aprueban y cuáles exigen confirmación humana.

---

## Arquitectura objetivo

```
┌─ apps/web ─────────────────────────────────────────────────────────┐
│  + vista de Sesión: plan en vivo, transcript, hallazgos, presupuesto │
└───────────────▲────────────────────────────────────────────────────┘
                │ /api  (polling de sesión, como jobs hoy)
┌─ apps/api ─────┴───────────────────────────────────────────────────┐
│  NUEVO  capa de orquestación (detrás de FIRMLAB_AGENT=1)            │
│    session store      objetivo · plan · transcript · hallazgos      │
│    agent runner       bucle LLM ↔ tools ↔ resultados                │
│    governor           presupuesto · política de aprobación          │
│    tool registry      providers expuestos como JSON-schema          │
│         │ startJob(...)  ← reutiliza el runner y el cap actual       │
│  providers  extract · sbom · gitleaks · decompile · ghidra · emulate │
│  store      images · analysis · jobs · (NUEVO) sessions              │
└───────────────▲────────────────────────────────────────────────────┘
                │ funciones puras (bytes → datos estructurados)
┌─ packages/core┴────────────────────────────────────────────────────┐
│  entropy · signatures · structure · strings · filesystem            │
│  VERDAD DE BASE — el agente cita esto, no lo sustituye              │
└────────────────────────────────────────────────────────────────────┘
```

El agente no reemplaza nada por debajo de `providers`. Se inserta como un cliente más de `startJob`.

---

## Los cuatro problemas reales (dónde está el trabajo)

No están donde la intuición dice. Enchufar un LLM es lo fácil; esto es lo difícil.

### 1. Radio de daño — el crítico

Un agente autónomo que decide "voy a emular todos los binarios" está ejecutando código de firmware
potencialmente malicioso, elegido por un controlador no determinista. Hoy `runUserModeEmulation`
(`providers/emulate.ts`) tiene SIGKILL a 20 s y confinamiento al rootfs (`resolveInsideRootfs`) — suficiente
para un humano que pulsa *un* binario, insuficiente para un bucle que itera "prueba a ejecutar esto otro".

Pasamos de una app que **analiza** a una que **actúa**. Las acciones necesitan una frontera de contención dura:

- Contenedor **aislado por sesión**, efímero, sin montajes del host más allá del rootfs de esa imagen.
- **Sin red de salida** desde el sandbox de ejecución (nota: hoy `grype` sí descarga su BD de CVEs al correr —
  esa descarga se hace en una fase de *análisis* controlada, separada de la fase de *ejecución* del agente).
- seccomp / caps mínimas; la emulación nunca comparte kernel-surface con el orquestador.
- La emulación es la única tool que *ejecuta código del target*; se mantiene en la lista de **aprobación
  humana** hasta que el sandbox de la Fase C esté cerrado.

### 2. La ruptura de las tres promesas, contenida por diseño

Un controlador LLM es nube, no determinista y cuesta dinero por ejecución — lo contrario de local/determinista/
gratis. El principio rector (§1) lo contiene: el agente va detrás de `FIRMLAB_AGENT=1`; apagado, cero red y
cero coste; encendido, los *datos* siguen siendo reproducibles y solo el *recorrido* varía. La postura de red
elegida es **núcleo determinista intacto + agente opcional encima** (no cloud-first, no modelo autoalojado como
default).

### 3. Coste y fuga

Una sesión autónoma puede iterar sin fin y quemar tokens. Presupuesto **duro** por sesión, no consejo:
máximo de pasos, de tokens, de dinero y de tiempo de pared; y condición de parada por rendimientos
decrecientes (K acciones seguidas sin hallazgo nuevo → cerrar). El governor corta la sesión al alcanzar
cualquier límite y deja el estado en `stopped` con lo acumulado hasta ese punto.

### 4. Workers y aislamiento — sin sobre-ingeniería

El runner in-process con cap 2 (`providers/jobs.ts`) no aguanta N sesiones autónomas concurrentes, cada una
abriendo tool-calls en abanico. Pero **no se salta a Kubernetes**. Progresión:

- **Corto plazo:** una sesión *es* un job largo; las herramientas pesadas siguen como sub-jobs del runner
  actual, respetando el cap. Una sola imagen de contenedor.
- **Largo plazo (Fase C):** cada sesión recibe su propio contenedor efímero, orquestado por un dispatcher;
  varias sesiones en paralelo, cada una aislada. Ese es el "desplegar workers" del objetivo — el destino, no
  el paso 1.

---

## Camino incremental: gatear → andar → correr

Cada fase se envía sola, es útil por sí misma y desriesga la siguiente. Empezar por la C es cómo no se termina
ninguna.

### Fase A — Copiloto / analista (riesgo nuevo: cero)

El agente lee resultados **ya calculados** (estático + extracción + los jobs que existan) y escribe: análisis,
priorización de hallazgos por severidad/explotabilidad, y recomendaciones de siguientes pasos. **Solo lectura**
sobre datos existentes — no ejecuta ninguna tool.

- Es esencialmente `providers/report.ts` con cabeza: hoy el informe agrega secciones; aquí el agente las
  interpreta y las ordena por lo que importa.
- Cumple ya "reporta lo que encuentra con inteligencia".
- Barato, seguro, entregable desde el primer día. Endpoint nuevo + una llamada al modelo con los datos ya en
  SQLite. Sin sandbox, sin sesiones, sin governor todavía.

### Fase B — Orquestación supervisada (riesgo: acotado)

El agente ya *llama* a los providers como tools, dentro de una **sesión**, con presupuesto y política de
aprobación. Aquí aparece el "reconduce y reconfigura": el agente extrae, ve el rootfs, decide qué escanear y
qué decompilar según lo que hay, y encadena.

- Introduce: session store, agent runner, governor, tool registry.
- Emulación **con aprobación humana** (aún no hay sandbox de la Fase C).
- Un solo contenedor; concurrencia limitada por el cap actual.
- Entregable: "lanza una sesión sobre esta imagen" → el agente conduce extract → sbom/gitleaks/decompile según
  criterio → informe redactado por él con hallazgos citados.

### Fase C — Workers autónomos (riesgo: el grande, ya con red de seguridad)

Contenedor aislado por sesión, sesiones en paralelo, sandbox de ejecución cerrado, control de egress. Aquí sí
es "desplegar workers ejecutando sesiones autónomas completas", incluida emulación sin aprobación manual
porque el radio de daño ya está contenido.

- Introduce: dispatcher de workers, contenedores efímeros, sandbox seccomp/no-egress, límites de recursos por
  worker.
- Es un proyecto en sí mismo; depende de que A y B hayan estabilizado el contrato de tools y el governor.

---

## Decisiones abiertas (para resolver antes de construir cada fase)

- **Modelo y SDK.** Claude vía Agent SDK (bucle gestionado) vs bucle manual sobre la Messages API. Requiere
  fijar IDs de modelo y coste — pendiente de consultar la referencia de la API cuando se aborde la Fase A.
- **Frontera de aprobación exacta.** Qué tools son auto-aprobables en Fase B. Propuesta inicial: extract /
  sbom / gitleaks / decompile / ghidra / diff auto; **emulate** con confirmación hasta Fase C.
- **Formato del transcript de sesión.** Qué se persiste para que una sesión sea auditable y reanudable.
- **Coordinación retención ↔ sesiones.** `retention.ts` hoy puede borrar una imagen y su rootfs por debajo de
  un job en curso (ver ROADMAP / providers) — con sesiones largas esto se agrava. Una sesión activa debe
  marcar su imagen como no-desalojable.

---

## Qué NO cambia

- `@firmlab/core` permanece con `dependencies: {}`, puro y determinista.
- Con `FIRMLAB_AGENT` sin activar: sin red, sin coste, comportamiento idéntico al actual.
- Los providers no se reescriben; se envuelven como tools.
- El binding loopback y el modo local-only siguen siendo el default.
