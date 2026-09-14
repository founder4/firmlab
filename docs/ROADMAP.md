# FirmLab roadmap

Historial de qué se envió y cuándo, fase a fase. Lo que falta por construir vive en un único sitio,
[`BACKLOG.md`](BACKLOG.md) — este fichero no lo duplica.

---

## Fases 0–2 — consolidación del despliegue y del workbench determinista

- **Fase 0.** Arreglos de build de Docker, estado "auth-gated" de salud, primeros tests de `apps/web`.
- **Fase 1.** Navegación móvil (drawer off-canvas), shell `100dvh`, grids de una columna, objetivos táctiles.
- **Fase 2.** SBOM/CVE (syft+grype) y triaje binario (radare2) como jobs persistidos.

## Fase 3 — profundidad de análisis e identidad fiable

Refinamiento de arquitectura/endianness (decodificador `ih_arch` de uImage + voto modal sobre el rootfs
extraído), gitleaks como scan profundo, diff de firmware con hashes de contenido, exportación de informe HTML.

## Fase 4 — fiabilidad y plataforma

Cola de jobs acotada (`FIRMLAB_MAX_CONCURRENT_JOBS`), retención/cuota de datos, gestión multi-imagen
(búsqueda/tags/borrado masivo), ampliación del paquete de firmas, decompilación Ghidra opcional, y el primer
recipe guiado de emulación full-system por arquitectura.

## Fase 5 — calidad, tests y hardening

Tests de componente/interacción web (jsdom + Testing Library), PWA + pulido móvil, defensa en profundidad de la
API (`FIRMLAB_API_TOKEN`/`FIRMLAB_RATE_LIMIT`/`FIRMLAB_STRICT_CSP`), toasts de error estructurados, diff por
hash de contenido, y el primer fixture de integración end-to-end (`apps/api/scripts/integration.mjs`).

---

## Fase 6+ — motor de firmware con autonomía consciente

Carvado de la plataforma madre (Galert) hacia un dominio único: FirmLab determinista, local, visual y —de
forma distintiva— con estado (un corpus persistente que aprende del dominio entre imágenes). Todo lo de esta
fase está detrás de `FIRMLAB_AGENT`; con el flag apagado, FirmLab sigue siendo local-only y sin red. Fases 0–1
de este bloque no necesitan LLM en absoluto; el agente se apoya encima después.

- **Fase 0** — proof-states + libro de hallazgos, tabla de binarios, preflight determinista, dossier, providers
  de la escalera de emulación.
- **Fase 1** — corpus persistente entre imágenes, referencias cruzadas, watchlist de reglas Nivel-1, vistas web
  del corpus.
- **Fase 2** — copilot de solo lectura: capa LLM multi-proveedor (DeepSeek por defecto), disciplina de
  proof-state, panel de dossier.
- **Fase 3** — nodos de decisión ① triage y ② selección de objetivo sobre un orquestador determinista
  (`agent/session.ts`), un governor con topes duros de pasos/tokens/USD/tiempo, transcripción
  auditable/reanudable, y emulación detrás de aprobación humana con el rango CLAMPEADO al techo del preflight
  (`clampRung`) — la honestidad se aplica en código, no la decide el modelo. Diseño completo en
  [`AGENT-DESIGN.md`](AGENT-DESIGN.md).
- **Fase 4** — nodo ④ zero-day: razona sink→source sobre un scaffold de taint determinista más priors de
  corpus Nivel-2, y construye un disparador — pero el proof-state lo ata a `needs_runtime_reproduction`, solo un
  disparo real decide la subida (esto es la "debt #3" que cita `agent/session.ts`). Aislamiento por sesión con
  primitivas del SO (`prlimit` + `unshare -n` + teardown garantizado, sin contenedor anidado, "debt #2"),
  reportado como contención PARCIAL. Fuzzing AFL++ opt-in ("debt #1") con harness por clase (file/stdin/network,
  con desocketing opcional). RTOS/Renode ("debt #4") arranca firmware real seleccionando plataforma del catálogo
  real que Renode trae instalado (216 en v1.16.1), nunca una familia hardcodeada. UEFI/chipsec añade una vía de
  análisis offline propia para `uefi-bios`. Nodo ⑤ ("debt #5") cierra la sesión con una narrativa citada sobre
  los hallazgos confirmados. (Los comentarios `debt #N` en el código, p. ej. `agent/session.ts`, `routes/fuzz.ts`,
  `routes/renode.ts`, se refieren a esta lista.)
- **Fase 5** — inteligencia externa, detrás de su PROPIO flag `FIRMLAB_RESEARCH` (separado de `FIRMLAB_AGENT`):
  fingerprint de procedencia, OSV.dev + NVD (consulta por CPE, con fallback a keyword) + CISA KEV, huellas de
  clave embebida con reutilización de corpus, descubrimiento de `security.txt` (RFC 9116) solo en dominios
  permitidos. Cada fetch pasa por un allowlist y un libro de egreso que declara qué sale exactamente.
- **Fase 6 — Captura y adquisición (COMPLETA, 6.0–6.6).** Cierra el ciclo ANTES del análisis: adquirir firmware
  de un dispositivo en vivo (interceptar una OTA al vuelo), tallar el blob del tráfico y auto-ingerirlo. Segunda
  lane que toca red (detrás de `FIRMLAB_CAPTURE`, propio y separado de `FIRMLAB_RESEARCH`): descubrimiento LAN
  + detección de backends, proxy de red con auto-ingesta, posicionamiento activo (ARP-spoof) + agente de captura
  LAN token-autenticado, escalera de capturabilidad + preflight + plantilla Frida de unpinning, reensamblado BLE
  (Nordic-DFU) y Zigbee (OTA cluster 0x0019) sin necesitar dongle para la mitad de reensamblado, y una superficie
  de aprendizaje (timeline OTA por familia de dispositivo + priors por vendor). Diseño completo en
  [`CAPTURE-DESIGN.md`](CAPTURE-DESIGN.md).

---

## Línea base actual — 2026-09-14

- Contrato de despliegue reproducible, CI de audit/tipos/tests/build/smoke de Docker, y verificación exacta de
  revisión OCI.
- La web restaura resultados de análisis profundo persistidos, carga rutas de forma perezosa, y se ha probado a
  390×844.
- La semántica del censo de hallazgos es explícita (establecido/pista/bloqueado/descartado/afirmado/otros).
- El corpus de validación se mide con la matriz generada y su manifiesto bloqueado — ver
  [`CORPUS-VALIDATION.md`](CORPUS-VALIDATION.md) en vez de copiar aquí recuentos volátiles.
- Las sondas web usan petición de control + desafíos independientes, y exponen cobertura intentada/completada.
- `netns` y los rlimits se reportan como contención PARCIAL: no aíslan filesystem, PID namespace ni
  credenciales del host, así que nunca eximen la aprobación del operador por sí solos.
- Las versiones de kernel correlacionan por una consulta NVD acotada a la CNA de Linux; la correlación por
  módulo exige anclas de identidad a nivel de bytes y sigue siendo una pista, nunca un veredicto de
  explotabilidad del dispositivo.
- La campaña de cobertura (`pnpm corpus:campaign`) corrió completa el 2026-09-12: de 106 celdas que una lectura
  ingenua contaba como deuda ejecutable, exactamente UNA lo es — el resto son negativos reales, búsquedas
  inconcluyentes por construcción, topes que una re-ejecución no mueve, o artefactos sin rootfs que necesitan
  reacquisición. Ningún cell del corpus declara herramienta ausente. Ver
  [`CORPUS-VALIDATION.md`](CORPUS-VALIDATION.md).
- La auditoría transversal de límites quedó cerrada: selecciones y tablas rankean antes de cortar, conservan el
  denominador previo al cap y distinguen «no preguntado» de una respuesta negativa en corpus, Research, Zero-day,
  ExportReach/MCP, identidad MCU/eCos, narrativa e informe exportado.
- Una reproducción que encuentra un artefacto de `qemu-user` ya no termina como defecto: W9 agenda una única
  escalada full-system por imagen, registra su resultado en el mismo ledger y la campaña reconoce el remedio en
  resultados guardados por builds intermedias.
- El panel web de cobertura traduce las ocho disposiciones estructuradas y muestra el siguiente paso de cada etapa
  degradada; las corridas antiguas sin `remedy` se presentan como indeclaradas, nunca como resueltas.
- La extracción sin rootfs conserva en cada carve SquashFS las señales estructuradas de bytes ausentes y recomienda
  obtener otra muestra cuando su propio superblock prueba el truncado; los blobs ambiguos siguen indeclarados.
- Device Tree registra el tamaño, los bytes leídos y el tope del barrido crudo. Una imagen sobre 512 MiB queda
  explícitamente sin leer y con remedio `raise-bound`, cubierto sin construir un fixture gigante.

Lo siguiente, en el orden acordado, vive en [`BACKLOG.md`](BACKLOG.md).
