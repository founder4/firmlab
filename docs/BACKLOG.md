# FirmLab — backlog

Única lista de trabajo pendiente del proyecto — sustituye a los tres sitios donde antes vivía dispersa
(`BACKLOG.md`, la sección "remaining backlog" de `ROADMAP.md`, y el §4 de `METHODOLOGY-GAPS.md`). Lo ya cerrado
no vive aquí: vive en `git log -- docs/BACKLOG.md`, que conserva la evidencia medida de cada arreglo si hace
falta consultarla. Este fichero es de nuevo corto porque ese es el punto: un backlog que hay que desplazar para
leerlo deja de usarse como backlog.

`ROADMAP.md` es el historial de qué se envió y cuándo; `METHODOLOGY-GAPS.md` mapea la cobertura contra OWASP
FSTM/ISTG. Ninguno de los dos duplica esta lista.

## Superficie agente y MCP

- [x] **Contrato MCP verificable en CI.** `apps/api/src/mcp/server.ts` ya concentra herramientas, recursos y
  prompts, y `mcp/format.test.ts` fija muchas cargas, pero aún no hay una prueba del contrato que un cliente ve.
  Construir el servidor contra el cliente falso existente y guardar/revisar una instantánea versionada de nombres,
  esquemas de entrada, anotaciones, recursos y prompts. Un cambio intencionado actualiza la instantánea; uno
  accidental —en especial ampliar una herramienta, cambiar su semántica de sólo lectura o borrar un prompt— debe
  fallar en CI. Añadir un recorrido record/replay de llamadas inocuas contra el API de prueba. Debe ser local y
  determinista: MCP Observatory puede evaluarse como implementador de ese patrón, pero no se convierte en
  dependencia ni fuente de veredicto. *(Hecho en `64d5b06`: el cliente real del SDK recorre por transporte en
  memoria las 19 herramientas, un recurso, dos plantillas y tres prompts; la instantánea versionada fija nombres,
  esquemas, anotaciones e instrucciones, y una cassette local reproduce las diez herramientas de sólo lectura sin
  abrir sockets ni ejecutar proveedores. Importar el servidor ya no reclama stdio. La auditoría independiente
  encontró además que una variante de capitalización de `x-firmlab-author-kind` podía combinar `human, agent` y
  atribuir una fila del agente a una persona; `0fd7b74` elimina todas las variantes antes de estampar exactamente
  `agent`, con regresión sobre la cabecera que llega a Fetch.)*
- [x] **Conservar la causa de bloqueo en la superficie MCP.** `symreach`/`exportreach` distinguen `platform`,
  `harness` y `request` mediante `blockedBy`, pero `mcp/format.ts` no lo transporta. Un agente que sólo consume MCP
  vuelve a ver tres ausencias distintas como una sola; añadir el campo como opcional para resultados persistidos y
  fijar el significado de cada valor en el payload. *(Hecho en `f982ba8`: ambos payloads conservan el discriminante
  opcional y añaden su significado y remedio; los resultados persistidos anteriores siguen siendo válidos sin él.)*
- [x] **Cubrir la respuesta MCP de jobs todavía activos.** `jobPayload` no es exportable y su rama `stillRunning`
  no tiene prueba directa. Extraer la decisión pura o alcanzarla con el cliente replay, fijando que agotar el timeout
  devuelve job id, estado y log parcial sin convertir una ejecución incompleta en error ni en resultado negativo.
  *(Hecho en `f982ba8`: `jobPayload` es exportable y sus estados `queued` y `running` quedan fijados como inacabados,
  con id, estado, cola final del log y la instrucción de continuar mediante `firmlab_job_status`.)*
- [x] **Rechazar explícitamente `proofState` en `firmlab_record_assertion`.** La descripción dice que el campo se
  rechaza, pero el esquema Zod actual puede eliminar una clave desconocida antes de que llegue a la ruta que sí la
  rehúsa. Hacer estricto el input MCP y probar el error, sin permitir nunca que una afirmación de operador elija su
  propio estado de prueba. *(Hecho en `f982ba8`: el contrato publica `additionalProperties: false`, la llamada
  devuelve error nombrando `proofState` y la regresión demuestra que no se llega a emitir ningún POST al API.)*
- [x] **Auditoría estática de la superficie agentic antes de publicar.** Evaluar un scanner que funcione local y
  emita SARIF sobre `.mcp.json`, `AGENTS.md`/`CLAUDE.md`/`GEMINI.md` y el servidor MCP; SkillSpector,
  `mcp-scanner` y `skilltotal` son candidatos, no requisitos. Adoptar sólo reglas reproducibles y con revisión de
  falsos positivos; prohibido enviar instrucciones, firmware o configuraciones a un servicio externo por defecto.
  El resultado es una señal de revisión de supply chain, permisos, tool poisoning y drift, nunca una prueba de
  aislamiento ni una puerta que degrade la operación local sin explicar por qué. *(Hecho con
  `scripts/agent-surface-audit.mjs`: escáner propio, determinista y sin red, que emite SARIF 2.1.0 con 14 reglas
  revisables —endpoints remotos, paquetes npx sin fijar, shells, secretos literales, Unicode oculto, invariantes de
  AGENTS/CLAUDE/GEMINI, transporte sólo stdio, esquema estricto de aserciones, cabecera de autor y frontera de
  evidencia no confiable—. Los errores bloquean `pnpm biome`; los avisos no. Si no puede leer un fichero propio sale
  con 2, nunca limpio. Primer aviso real: `.mcp.json` lanza `@playwright/mcp@latest` sin versión fijada.)*
- [x] **Corpus adversarial de contenido no confiable para el agente.** Los nodos de juicio reciben strings de
  firmware, findings, metadatos de CVE/NVD, resultados de webprobe e inteligencia externa. Crear fixtures de
  inyección directa e indirecta que intenten alterar objetivo, cobertura, presupuesto o aprobación. Las pruebas
  deben demostrar que el texto queda como evidencia citada/no confiable y no puede: invocar una herramienta no
  planificada, elevar un `ProofState`, ampliar egress, activar `preapproveAll` ni ejecutar emulación sin el flujo
  humano existente. Inspirarse en AgentDojo/ASB para los casos, sin incorporar sus runtimes ni ejecutar ataques
  contra servicios reales. *(Hecho en `473ccc4`: una cassette local versionada cubre inyección directa desde texto
  de firmware e indirecta desde findings/webprobe y advisories; los cinco prompts separan el objetivo del operador
  de un sobre `evidence` explícitamente no confiable y sin fences cerrables. Siete regresiones fijan que los parsers
  no admiten tool calls, cobertura, presupuesto, egress, aprobación ni prueba elegida por el modelo; el preflight
  conserva su techo, fase 4 queda en `awaiting-approval` sin autorización externa y todo candidato nace como
  `needs_runtime_reproduction`. No se llama a modelos, servicios ni proveedores reales.)*

## Kernel, emulación, RTOS, UEFI

- [ ] Profundizar la correlación kernel-CVE. Ya hay paginación NVD acotada con denominadores/estados parciales y
  el selector solo descarta un advisory cuando un subsistema mapeado está probado `off`; config ausente,
  subsistema no mapeado y páginas no examinadas siguen explícitamente provisionales. El VEX de proveedor ya está
  hecho (`9688463`, `96e496a`, `b8f8c63`: veredicto sobre filas kernel-cve y grype, nunca cambia el estado de
  prueba). Falta usar diff de parches para resolver backports sin inferirlos, que exige fuentes del kernel del
  proveedor y no es acotable sin red.
- [x] Hacer que la reparación del guest alcance una ruta ejecutada. *(Hecho en `294c841` y endurecido en
  `619f618`.)* El boot real del WR940N en contenedor desechable y sin red probó primero que la entrada anterior no
  se ejecutaba: `busybox init` anteponía `exec` y el `msh` 1.01 tampoco aceptaba la aritmética del contador. La
  entrada corregida, de 244 bytes y compatible con ese shell, dejó HTTP/80 y HTTPS/443 alcanzables en la segunda
  pasada (la variante sin reparación observó 156 SYN y ninguna respuesta). El hallazgo mantiene separados el
  efecto de red y el readback: los marcadores propios se perdieron por el cierre de sesión de BusyBox, de modo que
  `reportedRunning` sigue en falso y no se afirma que el teardown se ejecutara sólo porque respondieron puertos.
  El tap de consola está acotado para toda entrada y sólo acepta marcadores como líneas completas. Evidencia y
  límites (`n=1` por variante) en `docs/OPERABILITY-VALIDATION.md`.
- [ ] Decidir si `isKernelLogLine` (`guest-repair.ts`) debe filtrar también trazas `firmadyne: …` sin marca de
  tiempo dentro del bloque del ruleset. Diferido, no probado: `WR940N_CONSOLE` (job 486be04e, en
  `emulate-system.test.ts`) se declara literal y trae `firmadyne: do_execve[…]` al principio de línea, pero la
  consola literal del 2026-10-04 del mismo equipo las trae con `[ t.ttt]`. Si existe, iptables-save se ejecuta
  entre los marcadores, así que un ruleset vacío se leería como no vacío ("0 rule(s)" en vez de "NO iptables
  rules") — degrada la frase, no inventa reglas. Confirmar con la consola cruda guardada antes de tocarlo.
- [ ] Ampliar RTOS más allá del boot. Ya existe un parser byte-only acotado para listas de tareas FreeRTOS cuando
  se suministran símbolos/layout (`pxCurrentTCB` y lista circular), con ciclo, truncado y punteros fuera de rango
  explícitos, y ya está cableado a la API: `POST /images/:id/rtos/tasks` acepta un snapshot de RAM que declara
  base, endian y anchura de puntero (validado antes del parser; nada se infiere ni se toma por defecto) más las
  direcciones de símbolos que aporta el operador, y persiste por carril cobertura, nodos y bytes
  intentados/completados y los límites aplicados, como máximo `needs_runtime_reproduction` y sin sincronizar
  findings. *(Actualizado en Ola 5: completado el recorrido tipado de listas con nombre —delayed, suspended,
  pending ready, terminated— con orden de ticks de despertar y verificación de punteros de contenedor en `4c637be`,
  corregida la alineación natural estándar de punteros ABI C de 64 bits en `ba17ca4`, e integrada la vista web
  responsiva con entradas de dirección e inspección de ticks en `RtosTaskSnapshotPanel`).* *(2026-10-02: fuente real de
  SÍMBOLOS hecha — `packages/core/src/elf-symbols.ts` lee cada `SHT_SYMTAB` con locales (las listas de `tasks.c` son
  `static`), marca duplicados como ambiguos y la variante SMP `pxCurrentTCBs` aparte; `POST/GET
  /images/:id/rtos/elf-symbols` y el panel rellenan sólo símbolos resueltos a una única dirección absoluta. Validado
  en sólo lectura contra el corpus: Zephyr-STM32L072 y Contiki-STM32F4 dan tabla leída con 0/11 nombres FreeRTOS, y
  `dragon_reto_stripped.elf` da `no-static-symbol-table`, declarado como no-negativo; el corpus no tiene ningún ELF
  FreeRTOS, así que el caso resuelto sólo está probado con ELF sintéticos.)* *(2026-10-02: fuente real de MEMORIA
  hecha — `apps/api/src/providers/renode-ram.ts` emula el firmware bajo Renode de forma acotada (1-30 s, por defecto 2 s),
  pausa la emulación y vuelca la SRAM del SoC (`DumpBinary`) haciendo coincidir los segmentos `PT_LOAD` no ejecutables y
  símbolos resueltos con los periféricos `Memory.MappedMemory` del `.repl`; `POST/GET /images/:id/rtos/ram-capture` y
  `RtosTaskSnapshotPanel` permiten lanzar la captura o cargar el volcado directamente en el formulario de inspección.
  Contención offline estricta con proxy loopback que rechaza accesos SVD remotos. Validado en ejecución real en contenedor
  `--network none` con `Zephyr-STM32L072-Button.elf` volcando 20.480 bytes de `sram` en [0x20000000, +0x5000]; la captura
  no afirma que el planificador haya arrancado ni que existan tareas, manteniéndose en `needs_runtime_reproduction`). QA de navegador 2026-10-02 contra API sintética local (Chromium 1440 y 390, sin errores de consola ni peticiones fallidas): la sección renderiza, y sin Renode en el host el clic devuelve `blocked_by_platform` con el motivo; resuelta y validada la deduplicación de avisos (se suprime el aviso genérico cuando hay motivo explícito de rechazo, preservando avisos independientes de reintento/recursos remotos; 30/30 tests unitarios y QA real en Chromium 390 y 1440 en EN/ES sin desbordamiento). Auditoría offline 2026-10-02 (`task_3f5ee9aac7a9` / `ctx_9a3185922094`): especificado diseño puro core+API para listas ready por prioridad con `configMAX_PRIORITIES` (1..64) y `sizeof(List_t)` declarado confrontado con `listRecordSize(layout)`, detectado y corregible defecto S1 de direcciones de listas repetidas en API manual; panel web y prefill ELF quedan como tareas secuenciadas posteriores). Implementado 2026-10-02 core+API: `deriveFreeRtosReadyLists` deriva `pxReadyTasksLists[0..N-1]` desde base, `configMAX_PRIORITIES` y `sizeof(List_t)` declarados por el operador, rechazando un tamaño distinto de `listRecordSize(layout)`, un `st_size` que no cuadra con N×tamaño, N fuera de 1..64 y el desbordamiento de direcciones; `POST /rtos/tasks` acepta `symbols.readyListArray` (excluyente con `readyLists`), recorre los carriles derivados con `parseFreeRtosNamedList` (anota `pxContainer`/`uxNumberOfItems`) y corrige S1 (dirección repetida entre `readyLists` manuales → 400). Campos persistidos nuevos opcionales; `proofState` sigue `needs_runtime_reproduction`. Residuo explícito: igualdad de tamaño es necesaria, no suficiente (TickType_t de 64 bits en puerto de 64 bits da el mismo `List_t` de 40 bytes). Panel web (F1) 2026-10-02: el formulario declara el array (dirección, `configMAX_PRIORITIES`, `sizeof(List_t)`, `st_size` opcional), excluyente con las filas manuales, valida en cliente el tamaño contra 20/40 bytes y la coincidencia con `st_size`, reclama las direcciones derivadas frente a las listas de estado y rechaza direcciones ready manuales repetidas; el resultado indica cómo se derivaron las listas. QA Chromium contra API local con datos sintéticos desechables (1440 EN y 390 ES, sin errores de consola, peticiones fallidas ni desbordamiento horizontal). Prefill ELF (F2) 2026-10-02: `freeRtosSnapshotSymbols` lleva `readyListArray {base, symbolSize}` (opcional en el prefill persistido) sólo si `pxReadyTasksLists` se resuelve; el formulario rellena dirección y `st_size`, nunca `configMAX_PRIORITIES` ni `sizeof(List_t)`. Sin QA de navegador propia: no añade maquetación y la ruta de relleno está cubierta por tests unitarios.*
  *(2026-10-03: hay un ELF FreeRTOS real compilado — V11.1.0, procedencia en
  `apps/api/src/providers/__fixtures__/freertos-stm32f4/PROVENANCE.md` — y `apps/api/scripts/rtos-freertos-e2e.mjs`
  encadena símbolos → captura RAM Renode (`stm32f4.repl`, offline) → recorrido sin direcciones a mano: las listas
  ready/delayed/suspended contienen exactamente las tareas creadas, a 1/3/7 s, y un `sizeof(List_t)` mal declarado
  se rechaza. Es emulación de un build sintético; no prueba un dispositivo, otras configuraciones ni el corpus.)*
  Faltan: un ELF FreeRTOS de fabricante (el corpus sólo tiene Zephyr y Contiki), variantes de layout declaradas `configUSE_MINI_LIST_ITEM = 0`/bytes de integridad (F3) y anotación por `uxTopReadyPriority` (F4) — ambas exigen verificar la semántica contra el fuente de FreeRTOS, no de memoria, y no hay fuente local ni red en la campaña —, colas de eventos/bloqueo y fuzzing de periféricos/MMIO (µEmu/P2IM/Fuzzware); Renode sigue demostrando vida, no cobertura del HAL.
- [ ] UEFI restante. La imagen ya tiene un parser acotado del descriptor Intel SPI que registra regiones,
  solapes, huecos y bytes examinados sin confundir defaults estáticos con registros vivos. Desde 2026-10-02 lee
  además `FLMSTR1` (maestro CPU/BIOS) y emite `spi-descriptor-host-write` (`static_confirmed`, medium) sólo cuando
  las dos disposiciones de chipsec (`common.xml` 8 bits en 16/24; `pch_1xx`+ 12 bits en 8/20) coinciden en conceder
  escritura a la región del descriptor; si discrepan queda `layout-dependent`, nunca se elige una. Contrastado sin
  red con `get_SPI_master()` y los campos de `pch_1xx.xml` de chipsec sobre bytes sintéticos; el corpus no tiene
  ningún descriptor Intel real (OVMF es virtual) y el FRAP vivo sigue sin leerse. Desde 2026-10-02 también
  `spi-descriptor-host-me-write` (región Intel ME, índice 2 según `hal/spi.py` de chipsec) con la misma regla de
  acuerdo y sólo si el mapa habilita la región ME; y la vista de chipsec muestra el descriptor (estado o motivo,
  mapa de regiones, veredictos del maestro CPU/BIOS incluido `layout-dependent`) y dice «sin decodificar» cuando
  chipsec no corrió, en vez de «sin volumen UEFI». QA Chromium 1440 EN y 390 ES contra API local con imagen
  sintética desechable, sin errores ni desbordamiento. Revisión independiente (2026-10-02, `review-spi.md`): en las
  definiciones de chipsec de la generación de 12 bits `FLMAP0` no tiene campo NR, así que NR+1 no es un recuento de
  regiones allí; ya no se afirma «el mapa no declara región ME», se lee FLREG2 y la declaración ME queda
  `layout-dependent`. `NM=0` (chipsec lo lee como «sin maestros») deja el acceso del maestro en `unknown`; el hallazgo
  ME exige además la región habilitada con ambas anchuras de FLREG (13 y 15 bits); la cobertura incluye FLMSTR1. Si
  NM es base cero o no sigue sin poder establecerse sin la hoja de datos. Siguen pendientes
  LogoFAIL, callouts SMM (`CommBuffer`) y una captura PRx/BIOS-lock que pruebe la postura en ejecución.
- [ ] Fuzzing avanzado. El planificador ya elige cmplog/compcov/plain según arquitectura, fija canal de entrada
  archivo/stdin/socket, comprueba la arquitectura de `FIRMLAB_DESOCK` y declara cero ejecuciones/crashes con sus
  límites. Faltan un libdesock preconstruido por arquitectura y evidencia de runs reales; fuzzing
  stateful/full-system (Fuzzware/µEmu) sigue siendo la frontera RTOS.
- [x] Cross-binary dataflow: el primer scaffold acotado enlaza escrituras y lecturas de la misma clave literal
  UCI/NVRAM entre artefactos distintos y un sink del consumidor, separa namespaces y excluye autoenlaces. Es una
  correlación `needs_runtime_reproduction`: no inventa orden temporal, control-flow ni ausencia de sanitización.
- [x] Librerías nunca preguntadas: filtrar `.so` de la cola de alcanzabilidad es correcto para la pregunta
  actual, pero deja una librería vulnerable como candidato que nada resuelve nunca. Cargar el `.so` y arrancar
  simbólicamente desde una función exportada es un peldaño distinto, no una variante del actual.
- [x] uClibc ya no distorsiona el sweep de reachability. Medido sobre los bytes del WDR3600: ambos ficheros son
  ELF32 MIPS big-endian ET_DYN con entry point no nulo; `libutil-0.9.30.so` tiene PT_INTERP y DT_SONAME, mientras
  `libmsglog.so` no tiene PT_INTERP. El predicado actual exige PT_INTERP y ausencia de DT_SONAME para ET_DYN, así
  que ambos dan `runnable=false` y ya no abren los 45 candidatos. La regresión fija las dos formas sin confundir
  esta cola de programas con la pregunta separada de analizar funciones exportadas de una biblioteca. Esa
  pregunta separada ya tiene un escalón simbólico acotado desde exports (máximo 16), con intentados/completados y
  resultados inconclusos explícitos; se validó con `libmagic.so.1` sin cambiar el modo de ejecutables.
- [x] Presentar el modo simbólico de librerías en los resúmenes UI/MCP: hoy el resultado persistido conserva la
  cobertura en `library`, pero los consumidores antiguos miran `sinks` y pueden mostrar 0/0. Añadir además tests
  directos de la clasificación `reachTargetKind` y de la rama library de opacidad. *(Hecho: `SymReachPanel` lee `library`
  cuando `mode` es `library` —exports considerados/totales, «alcanzable desde un export», la función de origen y
  una nota que lo declara más débil que la alcanzabilidad desde la entrada—; `reachabilityPayload` en MCP añade
  `mode` y un bloque `library` con significado por sink; la rama de opacidad sale a `opacidad-symreach.ts` (pura)
  con sus tests, y `reachTargetKind` tiene regresión sobre disco, incluido el caso ilegible.)*

## moria/mithril (nmatt0) — evaluado contra el corpus real, no adoptado

- [ ] Evaluar moria (C++20 MIT) como extractor junto a binwalk+sasquatch+jefferson+ubireader: añade formatos que
  hoy faltan (btrfs, XFS, NTFS, HFS+, EROFS, exFAT, F2FS) y no requiere sudo. Complementa, no sustituye — sobre
  el SquashFS LZMA no estándar del TP-Link WR940N diagnostica mal la causa ("vendor obfuscation" cuando es LZMA
  parcheado). Reconciliar su diagnóstico con `extract-diagnose.ts` antes de adoptar.
- [x] Llevar el rúbrico de confianza de 4 niveles de moria (magic 25 / structural 60 / consistent 85 / verified
  99, con camino de RECHAZO estructural) a `signatures.ts`: nuestras reglas eran magic + decode sin rechazo
  (sobre el mismo fichero, 203 hits de core frente a 4 de moria, casi todo ruido). *(Hecho en `e609854`: el
  `tier` del hit es lo que los bytes sostuvieron en ESE offset y `confidence` sigue siendo el prior de la regla
  —dos ejes, no uno reescribiendo al otro—; el tier base se deriva de lo que la regla ya declara, de modo que no
  hay campo nuevo que se desincronice, y `atOffset` sube un escalón porque un offset absoluto es una restricción
  que una coincidencia no alcanza. `verify` corre siempre y antes del cap, porque un rechazo saca la regla del
  set de ids que `inferIdentity` lee. El denominador viaja con el resultado —`matched` / `rejected` /
  `rejectedByRule`— para que «aquí no hay ELFs» no se lea igual que «todos los `\x7fELF` fallaron su e_ident».
  Los seis chequeos sobre reglas existentes son elf, gzip, lzma, pem-cert, trx y `uefi-fv`, este último el que
  más pesa: `_FVH` son cuatro bytes ASCII y enrutaba una imagen entera a `uefi-bios` sin leer nada más.
  `classEvidence` separa además CÓMO se decidió la clase —`exact-signature` / `heuristic` / `unknown`— para que
  leer la cabecera del formato y contar strings dejen de renderizarse igual.)*
- [x] Portar los `soft_constraints` de moria: restricciones que PENALIZAN sin rechazar, para el caso en que un
  campo es sospechoso pero no imposible. Nuestro `verify` es binario hoy —acepta a un nivel o rechaza— y por eso
  ningún chequeo llega a `verified` (99), que queda reservado a recomputar un checksum sobre el payload y hoy no
  lo alcanza ninguna regla. La pieza que falta es el peldaño de arriba, no el de abajo. *(Hecho para uImage y TRX
  (HDR0): CRC-32 propio en core —sin dependencias y apto para navegador—, contrastado en test con `node:zlib`.
  uImage llega a `verified` si cuadran el CRC de cabecera y el del payload; cabecera sí y payload no queda en
  `consistent` («modificada o re-empaquetada»); cabecera que no cuadra baja a `magic`, sin rechazar. TRX guarda el
  registro sin inversión final: cuadra → `verified`, no cuadra → `structural`. Medido el 2026-09-26 sobre las 15
  muestras locales: 18 cabeceras uImage en 9 imágenes, las 18 con CRC de cabecera correcto, 12 `verified` y 6
  `consistent` (AliExpress, IMOU); el TRX de DVRF_v03 `verified`; tiempo de escaneo igual a la línea base y buffer
  intacto. HDR1 sigue sólo con el chequeo estructural: no había ninguna imagen HDR1 real para medir su checksum.)*
- [ ] Completar los magics de contenedor de vendor: `e609854` añade 21 (SEAMA, WRGG, Netgear CHK y DNI, las tres
  variantes de Ubiquiti, TRX v2/HDR1, CFE, la tabla safeloader `fwup-ptn` de TP-Link, IMAGEWTY de Allwinner,
  RKFW/RKAF de Rockchip, IVT de i.MX, bFLT, vendor_boot y vbmeta y la tabla DTBO de Android, FMAP, CBFS, el
  descriptor de flash de Intel y `$FPT`), no las ~130 del plan original. **El límite no es el esfuerzo: es que
  cada magic va emparejado con un chequeo de campos que el propio formato declara y con capacidad de rechazar, y
  un magic que no se puede comprobar estructuralmente es una regla que dispara sobre coincidencias que después
  hay que explicar.** Quedan fuera por eso, no por olvido: Realtek (`csys`/`cr6c`/`cs6c`), Sercomm, el header
  MTK y el header legacy de TP-Link —reconstruirlos de memoria es justo la clase de afirmación que la tabla CVE
  curada tiene prohibida—. Reautorarlos clean-room contra la fuente del formato (OpenWrt `mkfwimage`-style) es
  lo que falta. *(Header legacy de TP-Link hecho: `tplink-v1`, magic de 24 bytes versión + «TP-LINK
  Technologies», rechazo si kernel/rootfs exceden la longitud declarada, y `verified` cuando el MD5 con sal
  recomputa. Formato y las dos sales —`normal` y `boot`— medidos el 2026-09-26 sobre las muestras locales, no
  recordados: 6 de 7 cabeceras reales verifican (exterior con bootloader → `boot`, interior → `normal`) y la de la
  imagen MR3220 dentro del volcado Asus queda en `structural`, sin rechazo. Realtek, Sercomm y MTK siguen
  pendientes: ninguna muestra local los contiene —los «MTK» del corpus son cadenas sueltas, no cabeceras—.)*
  Xiaomi ya está cubierto por HDR1 y no necesita regla propia: un magic identifica un FORMATO de
  contenedor, no una marca, y las descripciones no atribuyen de más.
- [x] Corroboración JFFS2 por tipo de nodo compartida entre escáner y clasificador. El predicado puro exportado
  `isJffs2Node` vive en core: el escáner rechaza el magic de dos bytes si el word siguiente no es un tipo de nodo
  válido y eleva uno válido a `consistent` (85), mientras el clasificador vuelve a aplicar el mismo predicado a
  sus hits —también a hits persistidos por builds anteriores— antes de contar el umbral de cuatro. El chequeo se
  ejecuta antes del cap, conserva `matched`/`rejected`/`rejectedByRule` y el cap no puede cambiar el conjunto de
  ids ni la identidad. Medido el 2026-09-16 sobre 16 MiB nuevos de `crypto.randomBytes`: 809 magics casados, 527
  rechazados, de ellos 522 JFFS2 (`jffs2-be` 254 + `jffs2-le` 268), y 282 supervivientes; la aleatoriedad es solo
  medida, no oráculo de test. Fixtures deterministas cubren nodos LE/BE válidos, magic incidental, acuerdo entre
  clasificador/escáner, hits legacy, rechazo antes del cap y los denominadores explícitos.
- [ ] Portar la tabla CPE de banners binarios de moria (17 componentes: openssl, busybox, dropbear, dnsmasq,
  curl, zlib, lighttpd, wget, wpa_supplicant, hostapd, mosquitto, glibc, musl, mbedtls, gnutls, openvpn, lua,
  u-boot) a `compmap`/`component-cve.ts`, frente a los 5 actuales. Habilitaría un mirror NVD dirigido (solo esos
  productos, ~700 KB) para CVE offline con `FIRMLAB_RESEARCH=0`. *(Parcial, 2026-09-26: añadidos los seis que aparecen con
  versión legible en binarios REALES de las muestras locales —hostapd, wpa_supplicant, uClibc-ng, GnuTLS, Lua y
  avahi—, cada patrón leído del binario. CVE sólo donde NVD, consultado contra esa versión exacta, da un rango
  defendible: OpenSSL gana CVE-2020-1967, -2022-0778, -2023-0286 y -2024-6119 (un rango por serie, sufijos de dos
  letras `1.0.2zd` ya comparables) y uClibc-ng CVE-2021-43523 y -2022-30295 con suelo en su primera versión.
  Rechazados con motivo: CVE-2022-23303/23304 en hostapd y wpa_supplicant (abiertos por abajo, sin versión
  verificada en la que entró ese código) y CVE-2021-26720 en avahi (script del paquete Debian, no upstream).
  Medido sobre los rootfs: Tenda pasa de 0 a 5 CVE. Sin muestra real con versión legible quedan zlib, lighttpd,
  wget, mosquitto, glibc, musl, mbedtls, openvpn y u-boot; uClibc 0.9.30 (TP-Link) no lleva cadena de versión y
  no se lee del nombre de fichero. Pendiente: KRACK, que NVD enumera incluyendo 0.5.9 pero exige representar
  una lista enumerada y precondiciones por rol AP/cliente.)*
- [ ] **NO adoptar** el pase de secretos de mithril: sobre la Tenda-Camera, 12 de 18 hallazgos son falsos
  positivos (tablas de etiquetas TLS de hostapd/wpa_supplicant leídas como claves PEM). `pem-scan.ts` ya exige
  que el cuerpo decodifique. Lo único aprovechable es su tier `validated` (recomputar un checksum embebido).
- [ ] **NO adoptar** la procedencia de componentes de mithril sin re-gating: no restringe su pase de banner de
  kernel a ELF y sobreatribuye (kernel 4.4.0 desde `tailscaled` en una imagen 5.4.213 real; openssl 1.0.1 desde
  una cadena de compatibilidad de `tor`, no la librería enlazada). Su `origin_path` es reutilizable SI la
  atribución la decide nuestra propia regla.

## Corpus y presentación de resultados

- [x] Desambiguar el nombre "corpus" en CLI/UI (tres cosas sin relación: `apps/api/src/corpus.ts`,
  `ops/corpus/validation-samples.lock.json`, `ops/yara/corpus.lock.json`) — ya documentado en
  `ARCHITECTURE.md` § "The three corpora", falta homogeneizar el naming visible. *(Hecho en `c23d4a3`: el
  vocabulario lo fija `ARCHITECTURE.md` y el corpus persistente es el *cross-image corpus* en toda cadena visible.
  Los nombres `corpus:*` NO se renombran —están en `docs/` y en automatización— sino que ganan alias cualificados
  que corren el comando idéntico (`validation-corpus:matrix`/`:campaign`, `cross-image-corpus:reindex`/
  `:refresh-credentials`), más el `yara-corpus:sync` que nunca tuvo; cada `--help` abre nombrando su propio corpus
  y descartando los otros dos, y `sync-yara-corpus.sh` ganó el `--help` con el que antes erraba. La página Corpus
  tiene el `page-head` que le faltaba; sidebar, tarjeta de Overview y panel de referencias cruzadas quedan
  cualificados en los dos catálogos. `scripts/corpus-naming.test.mjs` (3 casos, en `pnpm test`) comprueba que
  ningún alias derive del nombre que aliasa y lanza los comandos REALES para leer su `--help`, porque lo que un
  módulo exporta y lo que `--help` imprime son dos afirmaciones distintas. Corregido donde se lee, no donde se
  almacena: los comentarios de módulo de `corpus.ts`/`secret-hash.ts`/`pem-scan.ts` siguen diciendo "persistent
  corpus" y ninguno es una cadena visible.)*
- [x] Puntuar vectores CVSS v4.0 en `osv.ts` (`cvssV3BaseScore` solo hace v3.0/v3.1; v4.0 necesita la tabla
  MacroVector). 4 de 121 avisos del corpus cacheado quedan sin graduar — se conservan sin recortar, pero no se
  ordenan bien. *(Hecho: `providers/cvss-v4.ts` implementa el procedimiento MacroVector con las tres tablas de
  FIRST vendorizadas verbatim (`cvss_lookup.js`/`max_composed.js`/`max_severity.js`, BSD-2-Clause), no
  reconstruidas. `osvSeverityScore` encadena `cvssV3BaseScore(s) ?? cvssV4Score(s)` — los prefijos de versión son
  disjuntos, ninguno tapa al otro — y `extractSeverity` de `nvd.ts` antepone `cvssMetricV40` dejando intactos los
  peldaños de abajo. Un vector truncado sigue sin graduar en vez de completarse a ojo. `cvss-v4.test.ts` lleva 15
  casos cuyos valores esperados los produjo la implementación de referencia de FIRST, no este código.)*
- [ ] Re-ejecutar SBOM en las imágenes ya desplegadas: sus resultados guardados son anteriores a
  `packageTotal`/`vulnerabilityTotal`, así que las fichas siguen mostrando el denominador de la lista recortada
  (500 = `PKG_CAP`) como si fuera el total. Verificable sin correr nada: en el `resultJson` del último job `sbom`
  de cada imagen, `packageTotal` ausente ⇒ la ficha miente. Solo depende del carril SBOM, que es local.
  Medido el 2026-09-19 sobre el contenedor desplegado: 8 de 9 jobs `sbom` sin `packageTotal`, y la única refrescada
  (`81154df7`) declara `packageTotal=2019` frente al cap de 500 que las otras muestran como total — el denominador
  engaña por 4×. **Esta re-ejecución tiene una dependencia de orden que no es obvia y que se paga una sola vez:**
  los 8 resultados viejos corrieron CON grype disponible, y `syncFindings` borra y reinserta las filas de su
  `source`, así que re-ejecutar sin base de grype en el despliegue sustituye correlación existente por una
  negativa. Aprovisionar la base va primero, siempre; comprobar `grype db status` dentro del contenedor antes de
  lanzar la campaña, no después.
- [ ] Re-ejecutar el carril **research** en las imágenes ya desplegadas: sus resultados OSV/NVD son anteriores a
  `totalMatching`/`cveIds`/`upstream`, y esos tres campos los escribe `providers/osv.ts` / `providers/nvd.ts`, no
  `providers/sbom.ts`. Re-ejecutar SBOM no los rellena: es otro carril, con otro job y detrás de
  `FIRMLAB_RESEARCH`. Iba junto al punto anterior en una sola entrada y eso los hacía parecer un solo arreglo.
- [x] El cruce contra KEV vacío **no** es «ningún CVE explotado en la naturaleza»: `research/run.ts` alimenta
  `fetchAndMatchKev` con `collectCveIds(osv, nvd)`, de modo que sin una ejecución de research posterior a
  `cveIds` la entrada del cruce es el conjunto vacío y la salida también. *(Hecho en `8b6e4e1`: el retorno vacío
  lleva `notCheckedCode: 'no-input'` e `inputCveCount: 0`, ambos opcionales para siempre, no descarga el catálogo
  y el log dice «not asked» en vez de imprimir un cero. Un fallo real de descarga queda separado como
  `fetch-failed`; la web muestra los tres desenlaces —sin entrada, fallo y cero medido— con textos propios en
  inglés y español, y conserva el fallback honesto para resultados persistidos por builds anteriores.)*
- [x] Decidir si el cruce KEV debe incorporar también los CVE del carril SBOM. La base de grype ya trae un
  proveedor `kev` embebido, por lo que podría ser un cruce local sin red, pero sigue siendo una decisión de
  política distinta de presentar honestamente una entrada vacía del carril research. *(Decidido: **no** se mezclan.
  El cruce research sigue alimentándose sólo de OSV + NVD; el carril SBOM lleva su propia respuesta, offline, en
  `SbomResult.grypeKev` (opcional para siempre) vía `grypeKevAnnotation` en `sbom.ts`. Evidencia medida sólo en
  lectura en el contenedor desplegado el 2026-09-26: grype 0.119.0, esquema v6.1.9, tabla
  `known_exploited_vulnerability_handles` con 1 726 filas y proveedor `kev` capturado 2026-09-26T00:33:03Z; la salida
  JSON pone `vulnerability.knownExploited[].cve` en cada match —también en filas `GHSA-…`, así que se indexa por ese
  `cve` y no por el id— y **omite** el campo cuando está vacío, de modo que la ausencia sólo es un cero medido si
  `descriptor.db.providers.kev.captured` existe. Tres estados: sin campo (grype no emparejó: no se preguntó),
  `no-kev-provider` (desconocido, nunca cero) y `annotated` con la fecha del snapshot. Mezclar los ids en el cruce
  research haría depender su resultado de si y cuándo corrió otro carril, contra un catálogo de otra fecha. Después,
  `normalizeSbom` pone `evidence.knownExploited` (fuente `grype-db`, fecha del snapshot) **sobre** la fila CVE que ya
  existe —también sobre la fila `GHSA-…` cuyo `knownExploited.cve` la nombra— vía `grypeKevByVulnerabilityId`, sin
  filas nuevas ni cambio de proof state o severidad: KEV es explotación en otro lugar, no alcanzabilidad aquí. La
  vista SBOM muestra el insignia KEV por fila y los tres estados —no registrado, desconocido, cero medido sobre las
  coincidencias de grype— y nombra los CVE KEV cuyas filas quedaron fuera del listado. Corregido en revisión: el
  índice por id era de un solo valor, así que un `GHSA-…` que alias dos CVE KEV conservaba sólo el último indexado;
  ahora cada id guarda la lista y `evidence.knownExploited.cves` los nombra todos, en una sola fila. La vista declara
  también su propio corte de 300 filas por tabla (numerador = filas en pantalla, denominador = total real) aunque el
  proveedor no haya recortado, y cada insignia KEV es un `<details>` nativo —teclado y táctil, nombre accesible con
  CVE y fecha— en lugar de un `title` sólo al pasar el ratón.)*
- [x] Distinguir en W9 un grype que falló al correr de un grype que no puede correr. `sbomRun` (`opacidad.ts`)
  mandaba los tres casos de `grypeAvailable:false` al mismo `remedy: 'install-tool'`, y el tercero —grype corrió y
  lanzó— es un `retry`: una campaña de cobertura no lo reintentaba y lo reportaba como despliegue a arreglar. El
  `note` sí llevaba la frase exacta, pero `opacidad-remedy.ts` prohíbe expresamente derivar el remedy parseando la
  nota en inglés, así que el arreglo es un campo discriminante en `SbomResult` (opcional para siempre, como
  `grypeReason`), no una heurística sobre el texto. *(Hecho en `68ea988`: `SbomResult.grypeOutcome` con cuatro
  valores —`matched` · `tool_absent` · `db_absent` · `run_failed`— y `remedyForGrypeOutcome` mapeándolos en el
  módulo puro. `sbom-grype-outcome.test.ts` no afirma sobre un resultado escrito a mano sino que corre el `runSbom`
  real con `node:child_process` mockeado, porque el caso que importa es aquel en que TODO está presente: binario en
  PATH, base válida en disco —el test comprueba que se llamó a `grype db status` y que devolvió `valid:true`— y la
  ejecución fallando igual. Revertir sólo la rama `run_failed` con los tests puestos falla una afirmación exacta:
  `expected 'install-tool' to be 'retry'`. Las otras dos conservan `install-tool`, y la de base ausente sigue
  lanzando únicamente `grype db status`: la negativa no se convierte en descarga.)*
- [x] El mismo defecto un escalón más arriba, encontrado al arreglar el anterior y no implementado por no ampliar
  el alcance: un **syft que corre y lanza** llega a `sbomRun` como `available:false` igual que un syft ausente, y el
  paso emite `remedy: 'install-tool'` con la nota literal `'syft/grype not installed'` — falsa cuando syft está
  instalado y la invocación falló. `runSbom` ya distingue los dos casos en el `reason` que compone
  (`'syft not installed'` frente a `` `syft failed: ${message}` ``), así que el arreglo es el mismo de `68ea988`
  aplicado a la otra mitad del carril y la nota debería salir de `r.reason` en vez de estar escrita a mano.
  Verificable: un job `sbom` con syft presente cuya ejecución falle debe dejar `remedy: 'retry'` en el paso.
  *(Hecho: `SbomResult.syftOutcome` con tres valores —`ran` · `tool_absent` · `run_failed`— fijado en `unavailable()`
  en cada rama de `runSbom` y `ran` en el retorno `available:true`; `remedyForSyftOutcome` (`opacidad-remedy.ts`, el
  gemelo puro de `remedyForGrypeOutcome`) mapea `run_failed → retry`, `tool_absent → install-tool` y un resultado
  anterior sin discriminante a `undefined`: desconocido, nunca convertido en diagnóstico de despliegue. La rama
  `!r.available` de `sbomRun` saca ya la nota de `r.reason` y el remedy del campo, no de la prosa —la regla de
  `opacidad-remedy.ts` intacta—. `sbom-syft-outcome.test.ts` (4 casos) conduce el `runSbom` real con
  `node:child_process` mockeado: el que importa es syft EN PATH cuya invocación lanza, que deja `run_failed` /
  `retry` y no vuelve a gastar en grype; más syft ausente (`tool_absent` / `install-tool`, sin spawn), syft que corre
  (`ran`) y el mapeo puro incluido el `undefined`.)*
- [x] Completar la cobertura del lead de clave derivada del loader sin ensanchar sus afirmaciones. *(Hecho en
  `532f873` y corregido tras revisión en `f3b414f`: la auditoría corre antes de la precondición de entorno U-Boot,
  persiste `loaderKeyAudit` opcional incluso con cobertura completa vacía y declara el prefijo máximo de 4 MiB.
  Core comparte el parser estructural ENC1 con `encrypted.ts`; el contenedor exige longitud, cuerpo completo y
  entropía. La receta sigue siendo una señal independiente —ancla real de derivación/decrypt + primitiva—, por lo
  que `sha256` junto a un ENC1 válido fuera de un loader ya no fabrica un lead. Los candidatos seed/salt se ordenan
  primero por cercanía y luego por forma, conservando la constante próxima bajo el cap de 12. Minúsculas/base64
  siguen cerradas hasta disponer de corpus.)*
- [x] Llevar `loaderKeyAudit` a la cobertura/opacidad y a la web: el resultado ya persiste intento, finalización,
  límites y leads, pero todavía no participa en esos resúmenes y por tanto el usuario no ve esa cobertura vacía.
  *(Hecho: `providers/uboot-outcome.ts` es el único mapeo, compartido por el paso W9 y por la ruta de cobertura, que
  sustituye la celda U-Boot por el job dedicado más reciente con el campo. La lectura es estricta —booleanos
  exactos, contadores enteros no negativos, `bytesRead <= totalBytes` y `complete` sólo si son iguales—; cualquier
  otra forma, incluido un «completada» sin cota de bytes, es `unknown`/degradada y nunca «corrió vacía». La web
  aplica el mismo predicado. `listJobs` desempata `createdAt` por `rowid`, así que dos jobs en el mismo
  milisegundo ya no eligen el «más reciente» por el orden en que SQLite devuelva las filas.)*
- [x] Evitar la segunda lectura/escaneo del prefijo de 4 MiB cuando el análisis U-Boot también encuentra entorno;
  medir primero y conservar separados el resultado de entorno y la evidencia de la auditoría del loader.
  *(Hecho: `scanLoaderKeyPrefix` recorre el prefijo una sola vez y `composeLoaderKeyAudit` lo combina con las
  variables del entorno o sin ellas. Medición fijada por test: el código anterior invocaba dos veces la detección
  y el recorrido ENC1 en el camino con entorno; el nuevo los invoca una vez. La lectura física ya era una y sigue
  siéndolo.)*
- [x] Añadir casos directos de `loaderKeyAudit` para fichero mayor de 32 MiB y fallo de lectura. *(Hecho: una
  imagen dispersa de 32 MiB + 1 byte fija la lectura global en 32 MiB, la auditoría en 4 MiB y conserva el lead
  acotado; una ruta inexistente fija `attempted: false`, `completed: false`, cero leads y ausencia de `scan`.)*
- [x] Aprovisionar la base de vulnerabilidades de grype en el despliegue. Desde que el carril SBOM dejó de
  descargarla sola (ver `providers/sbom-db.ts`), un contenedor recreado no tiene base y el resultado declara la
  negativa en vez de correlacionar. *(Hecho: **horneada** en `Dockerfile.tools` — `ENV GRYPE_DB_CACHE_DIR=/opt/grype-db`
  y un `grype db update` en la capa base, de modo que un contenedor recreado nunca se queda sin base y ningún paso
  de operador se interpone entre un deploy y un carril que funciona. La otra opción sigue soportada y sin código
  nuevo: `grypeDbDir()` lee `GRYPE_DB_CACHE_DIR` y cae a `FIRMLAB_DATA_DIR/grype-db`. El coste se declara donde se
  paga —la base es exactamente tan vieja como la imagen— y lo que lo hace sostenible es que la fecha viaja hasta
  el lector: regla 4 de `sbom-db.ts`, `GrypeDatasetFact.stale` y la frase de la fila de Capacidades.
  **El primer borrador del bloque PASABA sin hornear nada**: sin `GRYPE_DB_CACHE_DIR` en el entorno, `grype db
  update` escribe en `~/.cache/grype`, `grype db status` responde `Status: valid` sobre ESA copia y la receta sale
  con 0 habiendo dejado `/opt/grype-db` vacío — medido el 2026-09-19 contra `firmlab-tools:latest`, con
  `du -sh` imprimiendo `0` al lado de un parte de salud limpio. De ahí el `find … -size +100M` que afirma que la
  base está en el directorio al que la imagen va a apuntar de verdad; los dos caminos del guard están ejercitados,
  el de rechazo y el de aceptación.)*
- [x] Que Capacidades distinga «grype presente» de «grype con base»: sondeaba el binario y decía sólo lo primero,
  así que la página prometía una pregunta que el carril iba a rechazar. Medido en vivo el 2026-09-19 sobre el
  contenedor desplegado: `/api/tools` devolvía 28 de 28 herramientas disponibles, grype entre ellas, mientras
  `grype db status` decía `database does not exist`. *(Hecho: `ToolDataset` en `tools.ts` es un SEGUNDO eje, no un
  valor peor de `available` — plegarlo en `available:false` habría afirmado que el despliegue no tiene grype, que
  es justo lo que `CLAUDE.md` prohíbe, y habría mandado a `blocked_by_platform` a todo proveedor que consulta
  `isToolAvailable`. El hecho es puro y neutro de idioma (`grypeDatasetFact` en `sbom-db.ts`, espejo del split
  `ProbeResult`→`ToolStatus`), la frase se compone por petición en el idioma del lector, y **no entra en la caché
  de sondeo**: un binario no aparece en el PATH mientras el servidor corre, pero una base sí, y un `ready:false`
  cacheado seguiría negándola hasta reiniciar la API. La página gana un cuarto estado con su propio recuento,
  contado aparte de `available` y nunca restado de él. `dataset` ausente significa que esa herramienta no necesita
  base, NUNCA que la suya esté bien. 8 casos nuevos; los 2 que importan de `Capabilities.test.tsx` fallan al
  revertir el componente, y el tercero es control negativo y pasa en ambos sentidos.)*
- [x] Añadir un test de propiedad o regla de lint que detecte `.slice(N)` sobre la misma expresión de la que
  luego se deriva un recuento — el patrón que ya pagaron `extractStrings`, `scanSignatures` y `sbom.ts`.
  *(Hecho en `a6e95d2`: `scripts/check-slice-denominator.mjs`, en `pnpm biome` y suelto como
  `pnpm check:slice-denominator`. La propiedad que exige: si una colección se trunca por un cap y el valor
  truncado se cuenta, alguna colección de la que deriva tiene que contarse también en el mismo ámbito. Lleva un
  checker del compilador de TypeScript y no un grep porque 142 de los 296 slices acotados del workspace no son
  colecciones —sobre todo strings, donde `.length` es un desplazamiento y no una población— y `text.slice(at, at +
  320)` y `rows.slice(0, cap)` son la misma sintaxis con distinta pregunta; dos filtros más se calibraron contra
  sitios reales que un borrador anterior marcaba (un único argumento no negativo es el RESTO, no un cap, como en
  `nvd.ts`/`boot-cmdline.ts`, y los identificadores se siguen hasta su declaración, de modo que
  `candidates.length` cubre `rank(candidates).slice(…)`). Sobre este árbol: 337 fuentes, 296 slices acotados, 154
  sobre colecciones, 62 de ellos contados, 0 infracciones. `check-slice-denominator.test.mjs` lleva 14 casos e
  incluye el camino de éxito —el corte que nadie cuenta, el corte inline sin nombre— y el fichero que el
  compilador no puede abrir, que se reporta en vez de contarse como limpio.)*
- [x] Exponer `credmatch` en la web: único route sin ninguna referencia en `apps/web/src` pese a 1.337 líneas y
  ✓ en cuatro muestras de la matriz. *(Hecho en `79caece`: `components/CredMatchPanel.tsx` (295 líneas) con
  `CredMatchPanel.test.tsx` (214), la sección registrada en `image-sections.ts`/`section-index.ts`/
  `ImageDetail.tsx` y las cadenas es/en en `locales/*/credmatch.ts`. `1b10314` la hizo tolerante a resultados
  dispersos.)*
- [x] Exponer `funcdiff` y lanzar `ghidra` desde la web. *(`FuncDiffPanel` en la sección Diff, contra la base del
  selector; la fila de Ghidra en «Capacidades sin lector» lanza el job y se desactiva si `analyzeHeadless` falta.)*
- [x] Ghidra: lector del pseudocódigo guardado y selector de binarios alimentado por `api.binaries`.
  *(Hecho el 2026-10-01: `GhidraFunctions` en Specialised scans, texto escapado y límites visibles;
  probado con 40 funciones guardadas de WR940N en desktop y 390×844, sin mutar el corpus.)*
- [x] funcdiff: `textDiffs` muestra extractos antes/después y diff unificado con sus límites y decompilador.
  *(Hecho el 2026-10-01; resultados antiguos sin campo siguen desconocidos. La revisión encontró y corrigió
  resultados tardíos de otra base/imagen, con tests de promesas diferidas. QA desktop/móvil de funcdiff usa
  fixture; no se repitió el proveedor ni se escribió en el corpus desplegado.)*

- [x] **Cancelar un job desde la UI.** `POST /jobs/:jobId/cancel`, controles globales por imagen e historial,
  estados persistidos `cancelling`/`cancelled`, retirada de la cola y terminación de grupos de procesos propios
  sin `pkill`. La capacidad se libera tras comprobar procesos y sockets; una limpieza no verificada conserva
  el slot y un error visible. Agente/MCP terminan sin interpretar resultados parciales; los hallazgos anteriores
  se conservan. *(Hecho el 2026-10-01: pruebas de procesos hijos/nietos, 25 iteraciones Linux de sockets,
  Chromium con API temporal y QEMU real pausado; evidencia en `OPERABILITY-VALIDATION.md`.)*
- [ ] Ampliar la propiedad de ejecución más allá de grupos Unix locales si se necesita cancelar procesos que
  cambien de sesión o recuperar árboles tras reiniciar la API. Hoy se declara la limpieza interrumpida como
  no verificada; Windows rechaza la cancelación de árboles en ejecución y las esperas de red son cooperativas.
- [x] **Rutas de la API sin cliente web, de valor medio/bajo** (auditoría del 2026-09-27; las de valor alto —snapshot
  RTOS, funcdiff, lanzar Ghidra, reensamblado BLE/Zigbee— ya tienen UI): `POST /images/:id/analysis` y
  `/analysis/reanalyze-all` (re-clasificar tras cambiar el clasificador sin borrar y resubir), y leer el estado actual de
  aprobación del agente en Ajustes. Decidir cuáles son sólo para scripts/MCP antes de construir UI. *(Re-clasificación
  expuesta en la Ola 4: `api.reanalyzeCorpus` con confirmación e informe localizado en el corpus —recuentos de la ruta,
  sólo filas cambiadas o fallidas, clase conservada en un fallo— y `api.reanalyzeImage` como «Reclasificar imagen» junto a
  la clase del dossier, que actualiza la identidad en sitio y relee el análisis. La aprobación del agente ya se lee y edita en Ajustes —`api.agentApproval`, conmutador manual/todo con su alcance y aviso, en `7544f9d`/`e7f8f5e`—; comprobado el 2026-10-02, la entrada seguía abierta sólo por no actualizarse.
  Lanzar `component-cve` y
  `auxsecrets` sueltos implementado en `7544f9d` con botones dedicados, sondeo de job y refresco acotado del libro mayor de hallazgos;
  resultados persistidos de `chipsec` y `renode` expuestos en `dbb39d4` en SimulationMenu con vistas compartidas y precedencia de ejecución
  en vivo; borrador de modelo y baseUrl en Ajustes corregido en `7544f9d` para no blanquear valores guardados; acción de reindexación y
  reporte localizado de corpus implementado en `4e04ddb`; edición de notas y retirada de fuentes calculadas con previsualización
  implementado en `7a06bc5` y `b2738d1`; verificación sintética Playwright de ambas oleadas en Chromium añadida en `a84bc71` vía
  `scripts/qa-wave2.mjs` y `scripts/qa-wave3.mjs` pasando al 100% en EN y ES en 390px y 1440px).*
- [x] **Cap de edición de notas vs MAX_NOTE del API.** La cota de edición de notas en cliente (`MAX_NOTE_EDIT = 4000`) era
  más estricta que la cota de creación en el API (`MAX_NOTE = 20000`), así que una nota de auditoría de retirada larga no
  podía editarse. *(Resuelto: el cliente usa una única cota `MAX_NOTE = 20000` para crear y editar, y valida también en la
  creación el cuerpo y el autor (`MAX_NOTE_AUTHOR = 80`) antes de enviar. Las notas de auditoría siguen siendo editables
  —una nota es razonamiento, no una afirmación—, pero `retirementNote` se escribe sin pasar por la ruta que aplica
  `MAX_NOTE`, y los títulos y la fuente no tenían cota; ahora la nota recorta cada línea enumerada a `MAX_LISTED_LINE = 300`
  diciendo cuántas y por qué regla, y la fuente se acota a `MAX_RETIRE_SOURCE = 1024` (reflejado en el cliente), de modo
  que un test fija que la nota cabe en `MAX_NOTE` en todas las cotas de entrada. Una nota ya almacenada por encima de la
  cota abre el editor con el motivo, no con un botón muerto.)*

- [x] Cancelación de esperas HTTP dentro de un job: abortar peticiones y lecturas de cuerpo en curso cuando
  el job se cancela, sin esperar los timeouts de 15s/6s ni emitir peticiones posteriores. `linkJobCancellation`
  en `job-cancellation.ts` combina la señal del llamador/timeout con la del job mediante `AbortSignal.any`
  (fuera de un job devuelve la base intacta para no alterar el descubrimiento compartido); cableado en
  `allowlistedFetch` y en `runWebProbe`/`fetchFirmwareLoopback`. *(Hecho en `5c664fb`: 9 tests nuevos, cancelación
  comprobada con socket real y lecturas parciales, suite API 2.805 passed, Biome limpio y sin envenenar caché.)*
- [x] `FuzzPanel.test.tsx › refuses to run without a target binary` anclado a estado cargado. *(Hecho en
  `e7f8f5e`: el test espera a `screen.findByText(en.panels.fuzz.runnable)` antes de hacer clic, asegurando
  que la resolución de capacidades asíncronas no deje el botón deshabilitado por carrera.)*
- [x] **Mostrar las restricciones de ejecución disponibles para el agente.** `/agent/config` conserva
  `partial` y añade `netns: '-n' | '-rn' | null` y `resourceLimits`; Ajustes y el panel de sesión separan red
  aislada, red del host y campo antiguo desconocido. *(Hecho el 2026-10-01; se limita explícitamente a
  capacidades del runner, sin atribuirlas a resultados guardados ni a todos los proveedores.)*
- [ ] Cargar un perfil AppArmor propio (derivado de `docker-default` permitiendo el uid map) para no correr
  `unconfined`. Sigue siendo trabajo de despliegue, no parte de la presentación de capacidades.
- [x] Ajustes → AI & Agent tiene desbordamiento horizontal a 390 px en las filas existentes del editor/configuración.
  *(Hecho en `e7f8f5e`: extracción de estilos de `Row` a clases CSS `settings-row` y `settings-row-label`,
  `overflow-wrap: anywhere` para identificadores largos, botones segmentados con wrap y apilado en columna
  a `<= 600px`. Validado con `apps/web/src/pages/Settings.qa.mjs` en Chromium sintético a 390px y 1440px en EN/ES
  sin desbordamiento ni errores.)*

## Deuda de política (decisiones a escribir, no bugs)

- [x] Dos estándares de CVE conviven sin decisión escrita: grype (vía manifiesto syft) acepta CVE-2016-2148 para
  busybox 1.18.4; la tabla curada de `component-cve.ts` la rechaza porque NVD la respalda con un rango abierto
  sin CPE enumerado. Cada fila nombra su fuente, pero qué estándar aplica es hoy un accidente de qué proveedor
  corrió. *(Hecho en `ca7ac2c`: la decisión está escrita en `CLAUDE.md` § «Which standard applies when both lanes
  run» — los dos carriles corren siempre y ninguno suprime al otro, y solo el curado alcanza `static_confirmed`.
  `curatedCveVerdict` (`component-cve.ts`) pone el veredicto SOBRE la propia fila de grype vía
  `findings-normalize.ts` (`claimed`/`rejected`/`outside_curated_range`), y el silencio — componente sin mapear, o
  una versión de manifiesto como `1.18.4-1` que la tabla no puede comparar — se registra como ausencia de
  veredicto, no como desacuerdo.)*
- [x] Una enmienda a una afirmación de operador no registra autor, mientras que una retirada sí — se puede
  reescribir la afirmación de otra persona y el libro mayor atribuye la redacción nueva al autor original. En la
  única superficie cuyo propósito es la procedencia. *(Hecho: `amendedBy`/`amendedByKind` en `OperatorAssertion` y
  en cada revisión superada, el nombre desde el cuerpo como en `withdrawnBy` y el tipo desde el transporte como en
  el alta. `assertedBy` no se reasigna nunca, las filas antiguas dicen «autor sin registrar» en vez de acreditar al
  autor original, y la atribución se renderiza igual en API, MCP, informe, divulgación y panel.)*

- [x] Una retirada registra `withdrawnBy` pero no el TIPO de autor, mientras que el alta y la enmienda sí lo
  estampan desde el transporte: hoy no se distingue «un agente retiró la afirmación de una persona» de «la retiró
  una persona». Es el último de los tres actos del libro mayor al que le falta la mitad de la atribución.
  *(Hecho: `withdrawnByKind` en `OperatorAssertion`, el nombre desde el cuerpo y el tipo desde el transporte como en
  el alta y la enmienda. `withdrawalAuthor` devuelve un tercer estado — `kind: null` — porque `withdrawnBy` es
  anterior al campo y toda retirada vieja lleva nombre sin tipo: colapsarlo a `human`, como hace `amendmentAuthor`
  sin riesgo por haber nacido con su par, afirmaría justo lo que nadie registró. Se renderiza igual en API, MCP,
  informe, divulgación y panel, y la procedencia del alta y de la enmienda no se toca.)*

- [x] Research por omisión (`080ef0d`) dejó dos lanes leyendo «sin declarar» de forma distinta. *(Hecho en el
  `fix(research)` siguiente a `080ef0d`.)* (1) `dbUpdateAllowed` (`providers/sbom-db.ts`) exigía un `'1'` literal:
  Ajustes y la ejecución de research decían ON mientras grype rehusaba pidiendo encender un carril ya encendido.
  Ahora decide con el mismo `decideFlag` que `loadResearchConfig` (override › entorno › catálogo), y la nota del job
  distingue «ON por omisión» de «ON declarado». Consecuencia aceptada y escrita: sin base aprovisionada y sin nada
  declarado, el primer job de SBOM **descarga** la base; la evitan una base aprovisionada o `FIRMLAB_RESEARCH=0`.
  (2) Un `FIRMLAB_HASH_LOOKUP=1` junto a research sin declarar estaba inerte antes del cambio y se habría vuelto
  egress de hashes en el siguiente despliegue sin que nadie decidiera nada. Decisión: un doble opt-in son dos
  consentimientos **declarados**; el valor por omisión no es ninguno. `decideDependent` (`flags.ts`) lo arma sólo
  con el padre declarado `1` y, si no, lo reporta `inertReason: 'parent_default'`; Ajustes lo muestra «en espera» con
  un botón que guarda ese `1`, y el job de research escribe en el log qué consentimiento falta. El homelab tiene
  research declarado en el compose, así que su hash lookup sigue armado.
- [ ] Seguimientos del punto anterior:
  - [x] (a) Exponer `hashLookupHeld` en `GET /research/status` y mostrar antes de lanzar si el hash lookup está *en
    espera*. *(Hecho: el status proyecta la postura de autorización sin afirmar ejecución, y el panel pre-run
    distingue los estados en espera y armado.)*
  - [ ] (b) Validar en contenedor la rama «research por omisión + sin base de grype» (descarga real y nota del log)
    — sigue abierto porque el cambio no incluía despliegue.
  - [ ] (c) Aclarar que el botón «Encenderlo explícitamente» guarda un override `1`, que desde entonces gana a un
    `FIRMLAB_RESEARCH=0` posterior en el compose; es la precedencia de siempre, pero sigue abierto que la fila de
    research diga que su `1` guardado es el consentimiento del que depende el hash lookup.

## Ideas evaluadas, no programadas (de la revisión de wairz)

- [ ] Puente UART host↔dispositivo físico: el único ítem ISTG-INT que no es trabajo de laboratorio puro, porque
  es software en el lado host.
- [ ] Inventario de capacidades al estilo capa (qué PUEDE hacer un binario, distinto de qué tiene de malo);
  FirmLab hoy solo hace la segunda pregunta.
- [ ] Fuentes de vendor-PSIRT/CNA para el track de inteligencia externa: no hay una API única gratuita que las
  cubra todas (referenciado desde `docs/AGENT-DESIGN.md`).
- [x] Formalizar visibilidad de capacidades por clase de dispositivo en la UI — el gating ya existe en
  `specsForClass`/`coverage.ts`, falta el acabado visual. *(Hecho: `/tools` expone el plan previo a ejecución de
  cada clase directamente desde `specsForClass`, y Capacidades lo presenta como matriz separando «planificada»,
  «worker construido» y «herramienta disponible». El plan no afirma ejecución ni disponibilidad, conserva los
  motivos es/en y un cliente contra una API anterior simplemente omite la matriz.)*

## Deuda estructural y de proceso

- [x] Orca `worktree new-child` toma como base `origin/main`, no el HEAD del coordinador (2026-10-03: `679f267`,
  81 commits detrás; los hijos de la ola VEX se avanzaron a mano). Resuelto el 2026-10-04 subiendo `main` (87
  commits, fast-forward). Regla que queda: antes de lanzar workers en hijos, `main` publicado o base del hijo
  verificada con `git log -1` en cuanto se crea.

- [ ] Reconciliar la documentación de despliegue con esta estación antes de la próxima entrega. Observado
  2026-10-03: `deploy.sh --check` y `/health` sitúan el contenedor en `679f267`, 81 commits detrás de
  `2eb659a`; Docker declara `proxy_net`, sin puertos publicados, y bind interno `0.0.0.0`. Coincide con el modo
  homelab descrito al principio de `DEPLOYMENT.md`, pero su sección del 28 de septiembre afirma red de host y
  loopback. Precisar el ámbito de esa evidencia histórica y verificar el contrato efectivo, sin cambiar red,
  permisos ni despliegue para hacer coincidir el texto. Plan en `COORDINATION-PLAN-2026-10-03.md`.

- [x] Estabilizar la espera inicial de `AnalysisActionsPanel.test.tsx`: durante la validación completa del contrato
  MCP, el caso de estado vacío agotó una vez la espera mientras seguía mostrando «Leyendo ejecuciones anteriores…».
  El fichero pasó después aislado (8/8) y la suite completa volvió a pasar (629/629), así que primero hay que
  reproducir y medir la carrera antes de cambiar producción o ampliar timeouts a ciegas.
- [x] `ReportBuilder.test.tsx` («translates the assertion partition…») falló una vez en `pnpm test` completo el
  2026-09-26 sin encontrar «no cuenta ni para ese total…»; aislado pasó 3/3 y la suite web 629/629. Misma familia
  que la espera de `AnalysisActionsPanel`: probablemente carga, no lógica. Reproducir antes de tocar nada.
  *(Ambos resueltos el 2026-09-26, misma causa: el test esperaba algo que existe ANTES de que se resuelva la carga
  —el marco estático del informe, o que `jobs` hubiera sido llamado— y después consultaba síncronamente el estado
  cargado. Ahora ambos esperan texto que sólo existe tras la carga; producción no cambia. 4/4 en paralelo con la
  suite de API como carga.)*
- [x] Revisar el reparto core/api: `packages/core` son ~2.500 líneas frente a ~91.000 de `apps/api`, con
  dominio puro viviendo en la capa de aplicación. *(Auditado el 2026-09-26: siguen siendo 65 importadores de
  `store.js`, pero el reparto correcto es 43 rutas + 22 módulos fuera de `routes/`, no 24. La decisión es que core
  recupere por fases sólo el dominio byte-only y portable: primero el contrato compartido `FindingDraft`; después
  `boot-cmdline.ts` completo y las porciones puras de `extract-diagnose.ts`/`component-cve.ts`; en API queda un
  `nvd-domain` puro separado de su I/O/cache. `opacidad-plan.ts` y `opacidad-leads.ts` permanecen en API por sus
  ejecutores, localización, filesystem y providers; los normalizadores específicos de proveedor también. La
  justificación histórica de carga en tests ya no es absoluta porque `store.ts` usa `createRequire` y los tests lo
  importan. P0 completado: `FindingDraft`, el contrato puro compartido por normalizadores, providers, rutas y
  ledger, ya pertenece a `@firmlab/core`; la API sólo lo consume y conserva todos sus campos opcionales.
  `boot-cmdline` también pertenece ya a core, con el parser, auditoría, tipos, cotas y pruebas en su superficie
  pública y sólo bindings/imports en API. La porción byte-only de `extract-diagnose` está en core —parsers y
  diagnóstico SquashFS/LZMA—, mientras API conserva sólo el adaptador de filesystem y recovery. Las porciones
  puras de `component-cve` también están en core
  (`packages/core/src/component-cve.ts`: tabla curada, versiones, extracción, `matchCves`, `curatedCveVerdict`,
  drafts y sus pruebas); en API queda sólo el recorrido acotado del rootfs. La integración final de exports está
  completada. `nvd-domain` también está en core (`packages/core/src/nvd-domain.ts`: tabla CPE curada, versiones,
  tiers y ranking antes del cap, cotas y decisión de paginación, query/cache key, parser de respuesta, merge de
  candidatos y descripción de lo descartado, con sus pruebas); en API (`providers/nvd.ts`) quedan sólo el fetch
  allowlisted, la caché en disco, el bucle de batch y los tipos de resultado persistidos. Paridad verificada
  objeto a objeto contra el build previo: 4.317 comparaciones, 0 diferencias.)*
- [x] Cubrir con test los cuatro componentes web sin cobertura: `DeepAnalysisDetails.tsx` (569 líneas),
  `KernelPosture.tsx`, `BinVulnPanel.tsx`, `PresetsPanel.tsx`. *(Hecho en `4f8ab72`: 10 casos para
  `DeepAnalysisDetails` —tenía 4 de sus 10 proveedores—, 7 para `KernelPosture`, 8 para `BinVulnPanel` y 8 para
  `PresetsPanel`, que no tenían fichero de test ninguno. Sus decisiones ya estaban cubiertas —`kernel-posture.ts`
  se prueba sin DOM— pero nada mostraba que los paneles las CABLEEN: que cuatro estados vacíos lleguen a cuatro
  frases distintas y no a una tabla vacía, que un fetch fallido se lea como «no ha corrido» y no como un kernel
  limpio, que `dispatchPreset` mande cada modo a su endpoint con sus argumentos, y que un resultado persistido por
  un build anterior renderice una raya y no un cero. Cuatro defectos de producción salieron de ahí, cada uno
  conservado sólo porque un test falla sin él: `FileBrowser` dejaba montados los bytes del fichero anterior
  mientras la siguiente lectura estaba en vuelo, y un rechazo sobrevivía al fichero que rechazaba; `DiffPanel` no
  tenía guarda de obsolescencia y con dos selecciones en vuelo ganaba la que resolviera última; `FilesystemTree`
  expandía desde un `<div>`, así que el control que revela el resto del rootfs era inalcanzable por teclado (ahora
  `<button>` con `aria-expanded`, puesto sólo donde hay algo que expandir); y el botón de borrar preset se
  anunciaba como "✕" en todas las filas. La suite web queda en 49 ficheros y 596 casos.)*
- [x] Cubrir los visuales dibujados a mano, que seguían sin test: `SignalCanvas.tsx` (280 líneas),
  `SbomGraph.tsx` (230), `EntropyChart.tsx` (174), `StructureMap.tsx` (125). `FilesystemTree` ya no estaba en esta
  lista: `4f8ab72` le dio 4 casos al convertir su fila en un control accesible. *(Hecho en `697b197`: 21 casos en
  `visuals.states.test.tsx` sobre los estados que un fixture no alcanza, y tres de los cuatro mentían por omisión
  —cada uno un recuento impreso sin aquello de lo que se contó—. `SignalCanvas` tenía su recuento de marcas DENTRO
  de la guarda de la leyenda de categorías, así que la imagen con menos que leer era justo la que no lo veía, y ese
  recuento contaba sólo lo dibujado: la mayoría de hallazgos de un rootfs real no llevan offset, de modo que
  `signal.offTape` dice cuántos tiró la regla. `SbomGraph` indexaba los CVE por nombre de paquete contra un listado
  que el proveedor recorta a 500, así que un Critical podía caer fuera del grafo sin llegar a nodo, tooltip ni
  recuento — `sbom.offGraph` lo nombra en la leyenda—, y el «0 de 412 afectados» sin motor era una medición que no
  ocurrió. Verificado revirtiendo ambos componentes con los tests puestos: 8 de los 21 fallan, uno por afirmación.
  `31981dc` corrigió después la redacción de esa última: `c2b0c9f` hizo que `grypeAvailable:false` dejara de
  significar «grype no está instalado», y la leyenda declara ya el resultado y no la causa, que es del banner.)*

## De la revisión de galert — análisis y adquisición (2026-09-14)

_Tres técnicas que galert cubre y FirmLab no, extraídas contrastando `apps/worker/prompts/firmware/*` de
galert contra los providers actuales. El resto del pipeline de firmware de galert ya está igualado o superado
aquí (funcdiff, webprobe, FwHunt, opacidad), así que la lista es corta a propósito._

- [ ] **(a) Adquisición de imagen hermana + pivote de descifrado.** Cuando la imagen primaria está cifrada (o
  falta un baseline de diff), bajar UNA release más antigua/no-cifrada o adyacente del MISMO producto, recuperar
  la clave AES del binario `*upgrade*`/U-Boot/updater PC-side, y re-extraer el rootfs en claro para los providers
  downstream. Hoy `encrypted.ts` se detiene en el diagnóstico ("AES-128, unrecoverable without key") y
  `METHODOLOGY-GAPS.md` §1 stage-2 lo reconoce como gap ("No pull-from-vendor"). Es outbound y scope-sensible →
  detrás de `FIRMLAB_RESEARCH`/egress-ledger, adquiriendo SOLO el producto ya identificado y registrando
  procedencia (SHA-256, URL, versión confirmada por strings, no por nombre de fichero). Firmware bajado = dato
  no confiable, nunca se ejecuta. Ref: galert `firmware-acquire.txt`.
- [x] **(b) Triage de CVE por contexto de dispositivo.** Un score CVSS es una afirmación sobre una clase de
  despliegue, y el firmware embebido no es la clase para la que se puntuó. *(Hecho: `providers/cve-device-triage.ts`,
  puro y sin store, con dos reglas que apuntan en direcciones opuestas: una **LPE baja** un escalón donde la imagen
  no envía privilegio del que escalar —`/etc/passwd` con root y cuentas de servicio `nologin`, que es el router
  SOHO típico—, y un **DoS sube** un escalón donde no hay nada que reinicie —`rtos`/`baremetal` no tienen modelo de
  procesos, así que un fallo se lleva el dispositivo y no un demonio—. `impactFromVector` clasifica la forma del
  fallo desde el vector CVSS v3.x/v4.0 (v4 renombra C/I/A a VC/VI/VA y se leen los dos juegos), y el orden de las
  pruebas es deliberado: un fallo que da ejecución de código Y tumba la caja es RCE, no DoS — leer disponibilidad
  primero habría archivado cada RCE como DoS y lo habría ESCALADO en RTOS.*

  *Las cuatro negativas son el diseño, no un recorte: **(1)** nunca suprime una fila ni cambia un recuento —el
  veredicto cabalga SOBRE el hallazgo igual que `curatedCveVerdict`, y hay un test que fija el recuento con y sin
  contexto—; **(2)** la severidad publicada se conserva siempre, en `publishedSeverity` sobre la evidencia y en la
  frase, de modo que un lector que rechace la regla puede deshacerla; **(3)** **solo evidencia POSITIVA puede
  despriorizar** — un `/etc/passwd` ilegible es `unknown`, no un límite de privilegio ausente, y todo `unknown`
  devuelve `null`: no existe camino de «no pudimos mirar» a «esto importa menos», que es la única inversión que
  todo el banco existe para impedir. El escalado es la dirección segura y sí puede correr sobre una propiedad
  estructural de la clase; **(4)** se mueve un escalón y nunca llega a `info`, porque una fila `info` se lee como
  inventario y despriorizar hasta ahí habría sido suprimir por la puerta de atrás.*

  *Cableado en los dos carriles bajo un único binder —`deviceContextFor` en `findings.ts`, para que el scan
  autónomo y la ejecución manual no puedan darle respuestas distintas a la misma imagen—: filas de grype vía
  `normalizeSbom` (con `SbomVuln.cvssVector` nuevo, **opcional para siempre**, y `preferredCvssVector` eligiendo
  3.1 → 3.0 → 4.0 porque grype adjunta una entrada por fuente y quedarse con la primera haría que la elección
  fuera un artefacto del orden del feed) y filas curadas de kernel vía `kernelCveFindings`, donde `impactSeverity`
  mapeaba LPE→high en toda imagen por igual. En el kernel se limita a las filas `applicable`: una fila `unknown`
  ya es `blocked_by_platform` y ponerle una severidad confiada argumentaría lo contrario de lo que esa fila dice.
  34 casos nuevos; revertir cada regla con los tests puestos falla 4 y 1 respectivamente, en el módulo puro y en
  los dos puntos de cableado.)*

  ***Un defecto de la primera versión, encontrado solo al correrla contra bytes reales** (`bc81da2` → arreglado
  después): `impactFromVector` leía `AV:L` a secas como escalada. Un fallo local que NO requiere privilegio
  (`PR:N` — la forma de todo bug de parser multimedia o de formato de fichero) no es una escalada: no hay
  privilegio del que parta, así que «esta imagen no envía privilegio del que escalar» no dice nada sobre él.
  Medido sobre la GL.iNet desplegada el 2026-09-19: de 29 filas SBOM despriorizadas, **12 lo estaban por ese
  razonamiento inválido**, `CVE-2023-49501` (ffmpeg, `AV:L/PR:N/I:H`) entre ellas, bajada high→medium. Ahora
  `LPE` exige `PR:L`/`PR:H` y esas filas son un impacto `local` propio sobre el que ninguna regla actúa. El
  carril kernel nunca estuvo afectado: su `impact` es curado a mano y esas sí son escaladas reales. La suite
  unitaria estaba verde con el defecto dentro, porque sus fixtures venían de la misma suposición que el código —
  la trampa que `CLAUDE.md` ya nombra.)*

- [x] El **checklist de CVE embebidos de alto valor** de galert contra la tabla curada. *(Hecho el 2026-09-19,
  cada rango consultado de uno en uno contra la API de NVD, ninguno de memoria. **BusyBox awk**: las nueve
  entradas de 2021 parecen un aviso con un rango y no lo son — sus suelos son 1.16.0, 1.18.0, 1.21.0, 1.26.0 y
  1.28.0, y `CVE-2021-42383` no tiene rango sino un CPE enumerado en 1.33.1. Copiar el primero habría reclamado
  cuatro CVE contra la BusyBox 1.18.4 del corpus que NVD no pone ahí. Más `CVE-2022-30065` (CPE 1.35.0) y las
  tres de 2023 con CPE enumerado en **1.36.1**, que es justo lo que envía la GL.iNet. **dnsmasq DNSpooq**: los
  siete, suelo 2.0 como la regla de al lado y `highExclusive` llevando el `< 2.83` de NVD en vez de adivinar
  cuál fue la última release; los cuatro que exigen DNSSEC llevan `precondition` y por eso quedan en
  `needs_runtime_reproduction` y no en `static_confirmed` — la versión está confirmada, la vulnerabilidad no.
  **curl SOCKS5** (`CVE-2023-38545`): componente nuevo, con los dos `versionRes` leídos de los binarios reales
  del rootfs de la BE3600 (`curl 8.6.0 (aarch64-openwrt-linux-gnu) %s` en `/usr/bin/curl` y `libcurl/8.6.0` en
  `libcurl.so.4.8.0` — cadenas distintas en ficheros distintos); el rango 7.69.0–<8.4.0 **no** cubre la 8.6.0 que
  el corpus envía, y hay un test que lo fija contra esa versión exacta. **Dropbear empty-auth** no es un CVE:
  `fsaudit.ts` ya lo audita como configuración (`auditServiceConfigs`, root+contraseña vacía). **DirtyPipe** ya
  estaba en `KERNEL_CVE_RULES` desde antes.)*

- [x] Poda por **subsistema de kernel** de la lista de candidatos NVD. *(Hecho: `subsystemGate` en
  `kernel-cve.ts`. El valor no estaba en la tabla curada sino donde el ruido vive de verdad — la consulta por
  prefijo que devuelve miles de filas, buena parte en drivers de GPU, sonido y USB-gadget que un router no
  compila. La CNA de Linux cita el asunto del commit que arregla el fallo, y los asuntos del kernel llevan
  prefijo `subsistema: resumen` por convención (`drm/amdgpu:`, `usb: gadget: f_fs:`, `ALSA:`), así que el gate
  **ancla en el prefijo y no hace grep**: un fallo del scheduler cuya descripción mencione `drm/amdgpu` no se
  descarta por no haber GPU. Seis `CONFIG_*` nuevos en `KERNEL_OPTION_KNOWLEDGE` (DRM, FB, SOUND, USB_GADGET,
  INFINIBAND, KVM) resueltos por el `inferKernelOption` de tres estados que ya existía, de modo que **solo un
  `off` con evidencia autoritativa descarta nada** y una imagen sin config ni kallsyms no poda ni una fila. Un
  `off` deja la fila en `false_positive` —comprobado y descartado— sin cambiar el recuento; un `on` retira de la
  frase la escapatoria «puede que el subsistema no esté»; un `unknown` la deja intacta diciendo que indeterminado
  no es ausente. `selection.configOptions` transporta el veredicto que la corrida de postura ya calculó, para que
  el carril de research no vuelva a responder una pregunta ya hecha y puedan discrepar.)*

- [x] **La tabla curada de componentes no tiene ruta propia.** `runComponentCve` solo lo invoca `opacidad.ts`, de
  modo que refrescar sus filas exige un scan autónomo completo: al validar las entradas nuevas el 2026-09-19,
  re-ejecutar `compmap` no tocó ni una fila `component-cve` —es otro proveedor— y hubo que lanzar `opacidad`
  sobre la Asus y esperar a que terminase. Medido: esa imagen pasó de **1 fila** (solo pppd) a **14** (7 DNSpooq
  + 6 awk + pppd), así que el refresco importa. Todos los demás proveedores tienen `POST /images/:id/<kind>`;
  éste no, y es el único cuyo contenido cambia cuando se edita una TABLA en vez de un binario del despliegue.
  Añadir la ruta y registrarla en `index.ts` es el patrón ya establecido en `docs/ARCHITECTURE.md`. *(Hecho en
  `ca76f1a`: `POST /api/images/:id/component-cve` crea un job tipado propio, usa el último rootfs extraído, deja
  que el provider declare honestamente la ausencia de rootfs y sincroniza únicamente el source estable
  `component-cve`. Cuatro pruebas de ruta fijan el 404, la creación, el resultado y el reemplazo acotado de
  findings.)*

- [x] **Decidido: `CVE-2017-14491` se mantiene, y el criterio pasa a ser dato exigible.** La prosa decía que la
  tabla reclama un CVE «solo donde NVD enumera CPEs para las versiones en mano», lo que hacía parecer esa
  entrada una violación: se reclama sobre la misma forma —rango abierto, cero CPEs enumerados— por la que
  `CVE-2016-2148` se rechaza. *(Resuelto contando, no discutiendo: de las 26 reglas, 11 son `bounded`, 6
  `enumerated` y **nueve** abiertas por abajo, así que la lectura estricta descalifica las nueve —`CVE-2016-7406`
  incluida—. Ésa casa con el Dropbear 2012.55 del corpus y produce hoy un hallazgo correcto en dos imágenes: la
  lectura estricta **cuesta un verdadero positivo** por cumplir una frase, luego la frase era lo que estaba mal
  (y nunca fue la regla — cuatro de las cinco entradas originales tienen cero CPEs enumerados). Lo que de verdad
  separa un rango abierto reclamable de `CVE-2016-2148` es si el suelo se puede DEFENDER desde lo que el aviso
  trata, y eso se afirmaba en comentarios en vez de registrarse. Ahora es `nvdBacking` + `floorRationale` en la
  propia regla, con un test que **rechaza** una entrada abierta por abajo que no justifique su suelo —verificado
  quitándole la justificación a `CVE-2017-14491`: falla nombrándola— y la justificación viaja hasta el hallazgo,
  de modo que el lector ve que el límite inferior es de esta tabla y por qué sin abrir el código. `CLAUDE.md`
  § «Claiming a CVE» reescrito para decir lo que la tabla hace. `CVE-2016-2148` sigue rechazada porque para ella
  no se puede escribir ningún suelo: «before 1.25.0» abarca una línea 1.x continua sin frontera de serie dentro.)*

## Scheduler de leads sobre el ledger (opacidad)

- [x] Programar la siguiente pregunta a partir de findings YA en el ledger, no solo de los drafts frescos de un
  provider. `AUTONOMOUS-WORKERS.md` §11.3 lo fija como el cuello de botella medido: 136 candidatas pwnable
  elegibles para `symreach` y cada scan solo pregunta 3; 127 filas `binary-cmdexec-sink` sin lead-kind ninguno.
  Hoy los lead-builders leen los drafts que un provider acaba de devolver, así que nada en el código puede
  agendar una pregunta contra una fila ya persistida. Es la mejora de autonomía que más mueve el censo de
  proof-states (más que cualquier provider nuevo) y encaja en `opacidad`/`agent` sin motor nuevo — el
  agente-MCP existente puede conducirlo. Es la contrapartida DETERMINISTA del mercenario (abajo): mismo objetivo
  —alcanzar los leads sin resolver— desde el lado honesto y reproducible.
  **Hecho (slice determinista):** `runOpacidad` toma una instantánea del ledger ANTES de que cualquier executor
  re-sincronice su source (`ledgerLeads` en `opacidad-leads.ts`, excluyendo asserciones de operador vía
  `partitionByProvenance`), y `binvulnRun`/`symreachRun` rankean la unión de drafts frescos + filas persistidas de
  `binary-pwnable-candidate`, `binary-cmdexec-sink` y `sink-reachable`. Un conjunto de supresión derivado del
  `source` de las filas (`symreach:<t>`, `symreach:<t>#cmdexec`, `dynprobe:<t>#<sink>`) salta la pregunta que un
  scan anterior ya hizo — que es lo que avanza el censo entre scans en vez de re-preguntar las tres más pequeñas —
  sin gastar presupuesto fresco, porque los caps siguen contando `c.planned`. Presupuestos por-fuente
  (reachability/cmdexec/reproduction) y `OPACIDAD_DYNAMIC_STEP_CAP` intactos; el conductor MCP/agente queda para su propio
  apartado.

## Mercenario — agente 100% autónomo, opt-in (rompe determinismo/reproducibilidad)

- [ ] Nuevo apartado (arm C productizado y en cuarentena) para los casos más difíciles, donde el pipeline
  determinista devuelve poco: agente 100% autónomo, modelo/proveedor configurable por API, toolchain cruda, con
  modo de objetivo (assess / resolver-CTF / libre) y clasificación del artefacto ("esto es un reto CTF", "target
  de investigación", "dispositivo de producción"). Invariante NO negociable: su salida NUNCA escribe
  proof-states disciplinados en el ledger honesto — vive en un almacén en cuarentena, y las afirmaciones
  interesantes se devuelven a los providers deterministas para verificación (reconciliación arm C → arm A).
  Diseño completo y tests de aceptación: `docs/MERCENARY-DESIGN.md`.

## Sidequest — Jev (System One Model) como provider de los nodos de juicio

- [ ] Evaluado 2026-09-22, no programado: Jev (TypeSafe AI, acceso anticipado desde 2026-09-15) es un modelo que
  no emite texto sino **valores tipados con probabilidad calibrada**, entrenado solo con datos sintéticos vía RLCD
  (se optimiza la probabilidad contra el resultado, no contra la preferencia de un anotador), 40-200× más
  barato/rápido que un LLM frontera. Su forma de salida es exactamente la de los dos nodos de decisión de
  `agent/nodes.ts` (① Triage, ② Target selection), que hoy devuelven JSON estricto con enums
  (`classConfidence`/`priority`/`rung`) arrancado de la prosa de un LLM. Encaje acotado, **sin arquitectura
  nueva**: un provider más en `llm.ts` detrás del mismo `FIRMLAB_AGENT`, en el slot que ocupa DeepSeek. El premio
  es doble — borra el peaje de parseo de prosa (`extractJsonObject`, tolerancia a fences, `completeJson` con su
  «recovery attempt»/`fallbackUsed` y el fallo `No JSON object found`), y convierte `classConfidence: 'medium'`
  (una palabra que el modelo elige) en una probabilidad **calibrada y umbralizable**, que es lo más alineado con
  el ethos de honestidad del proyecto (proof states, banner de cobertura, «a bound is not an answer»). No toca el
  invariante: el `ProofState` lo sigue decidiendo el código, y `resolvedClass` sigue ganando al clasificador
  medido (`suggestedClass`/`classAgreement` ya guardan el desacuerdo). NUNCA en proof state, en `component-cve.ts`
  (rangos de NVD, jamás de recall — y Jev es sintético puro) ni en el routing de `specsForClass`, ni en
  `packages/core` (zero-dep). Bloqueadores para pasar de aquí: (1) es cerrado y en acceso anticipado — no se
  auto-hospeda ni se pinnea, choca con «flags off = sin red, determinista», así que sería otro flag como DeepSeek,
  no un default; (2) su calibración es contra SU distribución (sintética), no contra ground truth de firmware —
  hay que **medirla sobre el corpus** (`docs/CORPUS-*`) antes de que esa confianza pueda gatear nada, o es otro
  número que suena seguro sin comprobar contra los bytes; (3) ironía Jevons (de la que toma nombre): abaratar el
  juicio 40-200× invita a correr el lane autónomo mucho más ampliamente, lo contrario de la contención deliberada
  del proyecto. Acción hoy: ninguna en código; reabrir cuando haya acceso estable y se pueda validar calibración.

## Sidequest — RAG de referencia: separar por tipo de material, no un RAG general

- [ ] Evaluado 2026-09-22, no programado: la pregunta era si introducir un RAG (manuales, ISAs, especificaciones,
  técnicas, vulnerabilidades, walkthroughs). Veredicto: **no un RAG general cableado al pipeline** —pelearía con
  el invariante y duplicaría `research/`—; la respuesta es distinta por tipo de material.
  - **Vulnerabilidades/advisories → NO.** Ya existe la forma correcta: `research/` (OSV/NVD/KEV/security.txt tras
    `FIRMLAB_RESEARCH`, con `egress.ts`/`cache.ts`) + `agent/intel.ts`, que produce un brief CITADO donde un
    advisory es un LEAD, nunca un confirmado de la imagen. Un RAG generativo reintroduce el «from recall» que
    `component-cve.ts` (`nvdBacking`/`floorRationale`) existe para prohibir — y la recuperación semántica mezcla
    justo lo que no debe (las 9 entradas awk de BusyBox: un aviso aparente, cinco lower bounds distintos). Los
    rangos quieren consulta versionada exacta, no top-k de chunks parecidos.
  - **ISA / convenciones de llamada / syscalls / MMIO-periféricos / datasheets → útil, pero es TABLA
    estructurada, no RAG.** Aquí hay hueco real: llena carencias ya nombradas en este backlog (fuente de
    símbolos/memoria FreeRTOS, fuzzing MMIO µEmu/P2IM, callouts SMM UEFI). Pero «base MMIO de la UART / número de
    syscall / offset de struct» quiere lookup EXACTO, determinista y testeable, no vecinos semánticos. El RAG solo
    se justifica para la prosa larga (un manual describiendo un protocolo de arranque) y únicamente como CONTEXTO
    de los nodos de juicio (`agent/nodes.ts`), ya acotados por el preflight.
  - **Técnicas/walkthroughs → único RAG generativo que merece la pena, y SOLO en el lane mercenario.** La
    metodología aquí es código (`specsForClass`, planes de `opacidad`, FSTM/ISTG). El sitio donde un RAG de
    técnicas no contamina nada es el arm mercenario en cuarentena (`docs/MERCENARY-DESIGN.md`): su salida no
    escribe proof-states en el ledger honesto y se reconcilia por los providers deterministas, así que una
    alucinación no envenena el ledger.
  - Innegociables si se hace: el RAG jamás decide `ProofState` ni rango de CVE (vive como lead
    `needs_runtime_reproduction` en el canal `external_advisory`, como `intel.ts`); tras flag, off por defecto,
    reusando el ledger de egreso de `research/`; y citar o callar. Acción de alto valor / bajo riesgo: (a) tabla
    de referencia ISA/MMIO determinista para las carencias RTOS/UEFI, (b) opcional RAG de técnicas confinado al
    mercenario. Ninguna es «un RAG» en el sentido que motivó la pregunta.

## Ajustes — observaciones de la campaña de operabilidad

- [x] Observado 2026-10-02: después de guardar modelo o base URL, el editor limpia el draft a `''` y
  muestra el campo vacío hasta remontar, aunque el servidor conserva el valor. Revisar la distinción
  entre draft ausente y vacío en `LLMSettings`, conservando el comportamiento write-only de API keys.
  *(Hecho en `7544f9d`: `delete next[key]` en `LlmProviderEditor` en lugar de asignar cadena vacía; las API keys
  conservan su enmascaramiento y borrador write-only mientras model y baseUrl mantienen su valor visible; probado
  en `Settings.test.tsx`.)*

## Emulación dinámica — superar la frontera FSTM-7 / GAP-01 (trabajo a futuro)

- [ ] Diseño y hoja de ruta en `docs/EMULATION-FUTURE.md`: síntesis de hardware para arrancar firmware SOHO con
  red operativa en emulación pura, atacando las tres causas raíz medidas (bucles de sondeo MMIO, ausencia de
  switch DSA, fragilidad de `LD_PRELOAD`/libnvram). Priorizable por fases: **Fase 1 — Universal Virtual DSA
  Switch** (Capa II; depende de una detección de familia de switch RTL83xx/BCM53xx/QCA8337: ya existe un
  detector puro y acotado en `packages/core/src/switch-family.ts` que sólo da leads estáticos —`QCA8337` como literal
  exacto, RTL83xx/BCM53xx sólo a nivel de plantilla porque el repositorio no verifica qué miembros son switches;
  compatible strings, nombres de driver/módulo y formato de etiquetado siguen diferidos sin fuente—; expuesto como job
  bajo demanda `POST/GET /images/:id/switch-family` con carril de bytes crudos y carril de rootfs extraído
  acotado —orden por ruta relativa, symlinks no seguidos, sin findings—. Validado 2026-10-02 contra el corpus en un
  contenedor `--network none` con el volumen en sólo lectura: WDR3600, WR940N y MR3220 dan `vendor-only` (Atheros,
  y Qualcomm en los dos últimos), DVRF da `template-only` (`BCM5397` en `usr/lib/libshared.so`, carril parcial por un
  fichero >4 MiB truncado) y el carril crudo no ve nada en ninguno, como se esperaba con kernel y squashfs
  comprimidos. Ningún resultado nombra una familia por sí solo: el siguiente paso real es una fuente primaria para
  fijar miembros exactos RTL83xx/BCM53xx y compatibles de device-tree, no ampliar heurísticas); **Fase 2 — integrar Fuzzware/µEmu como provider** para modelado MMIO (no motor TCG propio;
  frontera ya nombrada en este backlog); **Fase 3 — snapshot/fork** (`savevm`/`loadvm`) enlazado a `webprobe.ts`
  + AFL++. Techo de prueba honesto: `confirmed_in_emulation` de daemons de red (hoy `br-lan` nunca sube), NUNCA
  `confirmed_full_system` ni «idéntico al físico» — el entorno sintético es permisivo por diseño (`types.ts`). La
  Capa IV (Avatar2/JTAG) queda FUERA DE ALCANCE: rompe la premisa sin-hardware.

- [ ] Pre-aprovisionar localmente los 13 SVD que las plataformas de Renode piden por HTTPS (p. ej. bajo
  `FIRMLAB_DATA_DIR`, reescribiendo `ApplySVD` en una copia de la plataforma). Desde 2026-10-02 Renode corre con
  `OFFLINE_RENODE_ENV` (proxy a un puerto loopback que rechaza) porque el contenedor desplegado no puede crear netns y
  cada arranque descargaba el SVD; validado en contenedor `--network none` con un listener en el puerto 9 que recibe
  los `CONNECT dl.antmicro.com:443`, y el Zephyr STM32L072 del corpus sigue arrancando (`confirmed_in_emulation`, UART
  en usart2) con el SVD rechazado y nombrado en el resultado. Qué cambia el SVD en el comportamiento de periféricos
  no se ha medido. El sondeo de capacidades `renode --version` no carga plataforma y sigue sin el entorno offline.

## Revisiones independientes de la campaña (2026-10-02)

- [x] switch-family (revisión `review-switchfamily.md`, hallazgo 5): se omiten los detalles de ficheros
  completamente examinados sin candidatos, menciones, near misses, registros descartados ni fronteras pendientes;
  la cobertura y los agregados siguen contando todos los ficheros. `deferred` se persiste sólo en `overall`.
  Campos opcionales de conservación/omisión y UI compatible con resultados antiguos. Caso real de filesystem
  sintético con 1.024 ficheros: JSON de 8.300 bytes, un resultado detallado, 1.023 omitidos; QA Chromium EN 1440/ES
  390 sin errores ni desbordamiento. Ver `docs/PROJECT-WORK-2026-10-03.md`.
- [x] VEX riesgo 5: CSAF `first_affected`/`last_affected`/`first_fixed` ya cuentan como grupos con semántica
  no soportada, con ejemplos acotados y omisiones visibles en cobertura/veredictos. No se infieren intervalos
  ni se elevan a afirmaciones exactas. Se conservan conflictos, límites e identidades versionadas.
- [x] VEX riesgo 9: los documentos nombrados `.openvex.json`, `.vex.json` o con `csaf` en el nombre
  preceden a JSON admitidos sólo por el directorio, antes de los caps de ficheros y bytes; desempate por ruta en
  orden code-unit. Regla de selección registrada en cobertura, con campo opcional para resultados antiguos.
  Denominadores y rechazos por symlink permanecen explícitos. No recupera entradas fuera del cap del inventario.
- [x] VEX riesgo 8: SBOM manual (resultado y GET), el paso SBOM de W9 y research persisten
  `vendorVex` (`providers/vendor-vex-coverage.ts`) con una única lectura reutilizada para normalizar, también sin
  hallazgos ni CVE. Tres estados: búsqueda intentada (cobertura, documentos con sus contadores de omisión,
  rechazos), no intentada con motivo (research sin respuesta NVD de kernel, o sin rootfs) y campo ausente en
  resultados antiguos («no registrado», nunca cero). UI compartida `VendorVexCoverage` en SBOM, research, W9 y
  kernel posture. Validación 2026-10-03 en `7c8c8ea`: gates completos verdes (4660 tests); QA Chromium EN/ES a
  1440/390 con datos sintéticos de componente, sin overflow ni errores. No ejercitado contra el corpus desplegado.
- [x] VEX riesgo 6, variante acotada (2026-10-03): sin especificación CSAF/OpenVEX primaria fijada en local, las
  estructuras no leídas se cuentan por CVE (`unreadStructureCount`/ejemplos/regla, opcionales) en vez de
  interpretarse: product_id definido sólo en `branches`/`relationships` (nunca casa por su ID bruto, que perdía la
  restricción de versión del helper), árbol truncado (profundidad 32 / 10 000 nodos), `identifiers` y
  `subcomponents` anidados de OpenVEX. Los veredictos por fila lo nombran como omisión `unread_structure`; la
  cobertura persistida y la UI lo muestran. Gates completos verdes (4675 tests). Pendiente: interpretar esas
  estructuras cuando haya fuentes primarias y fixtures verificados.
- [ ] VEX de proveedor restante (revisión `review-vex.md`): interpretación semántica del riesgo 6 (hoy contado como omisión, arriba) y nits 11–15 (el riesgo 8 se cerró arriba). Fallo conservador asumido: una fila grype de ecosistema de lenguaje (pypi/npm) no casa con un purl tipado
  hasta que la fila lleve su ecosistema. Interpretar intervalos CSAF queda pendiente de un contrato verificado.
  Revisión de código 2026-10-03: W9 persiste una selección propia de campos, por lo que ampliar solo `SbomResult`
  no resuelve el riesgo 8. En el riesgo 6, una referencia CSAF de branches no indexada cae al ID bruto y puede
  perder la restricción de versión del helper omitido; exigir regresión del fallback antes de habilitar nuevas
  coincidencias. Los subcomponents de statement ya se leen; faltan los anidados dentro del producto.

## Orca — continuidad desatendida (2026-10-02)

- [x] El supervisor no reanudaba a un coordinador cuyo estado nativo `working` quedaba congelado (Claude,
  17:12–17:37Z del 2026-10-02, recuperación manual): con `working` no se leía pantalla ni se esperaba `tui-idle`, y
  la frescura daba `unknown` para siempre. Ahora un `working` caducado (>180 s o sin marca) exige lectura renderizada
  y espera nativa, y sólo es `idle` si ambas coinciden (compositor vacío, sin borrador, selector, cuota ni turno
  visible en curso). Claude muestra el compositor vacío mientras trabaja, así que el indicador de turno activo es
  obligatorio. Ver `docs/ORCA-CAMPAIGN-RELIABILITY.md`.
- [x] Política de capacidad de campaña y lanzador de workers guardado (`policy.mjs`, `launch-worker.mjs`,
  `orca-campaign-launch-worker`): bloqueos de proveedor/modelo, recuperación sólo con canario viable, motivo de relevo
  obligatorio; el guardián registra la parada dura que ve en pantalla. Ver `docs/ORCA-CAMPAIGN-RELIABILITY.md`.
- [ ] `worker-start --agent antigravity` no supera `agent_readiness` con Antigravity CLI 1.2.14 (`tui-idle` nunca se
  satisface aunque el compositor renderizado esté vacío); se recurrió a `dispatch --inject`, que deja el carril sin
  supervisión. Reportar a Orca o reconocer el compositor renderizado como preparado.
- [ ] Capturar en bytes un fotograma real de Claude inactivo con `working` nativo congelado para sustituir el
  fixture reconstruido del test. *(2026-10-02 18:27Z: capturado en bytes un fotograma real de Claude inactivo —«✻ Churned for … · done»,
  compositor vacío, pie— y añadido como fixture; su fila nativa estaba en `done`, así que sigue faltando un fotograma
  capturado con la fila congelada en `working`.)* *(La reanudación real de punta a punta con el guardián corregido ya está probada:
  2026-10-02, 18:12–18:14Z, petición `520a0e0a…` confirmada; ver `docs/ORCA-CAMPAIGN-RELIABILITY.md`.)*

- [x] Recuperar al coordinador que termina su turno sin espera: supervisor externo con plazo fijo,
  verificación de identidad/estado, journal, exclusión por Run y reactivación comprobada con Claude y
  Antigravity reales. Diagnóstico y receta en `docs/ORCA-CAMPAIGN-RELIABILITY.md`.
- [ ] Ensayo de resistencia de ocho horas, con candidatos disponibles y presupuesto observados. La
  transferencia por salida real del coordinador ya se comprobó (adopción del mismo Run, generación 1→2);
  las pruebas breves actuales no demuestran esa duración ni el agotamiento de todos los servicios. Orca conserva wake/nudge best-effort y Antigravity no expone
  `turn_started`; requerir evidencia nativa o reconocer incertidumbre.
- [x] Estabilizar `apps/api/src/research/config-cancellation.test.ts`: el test de petición bloqueada cancela
  tras 20 ms y exige que el servidor haya recibido una petición; bajo carga puede cancelar antes del socket
  (observado 2026-10-02 en `pnpm test`, requests=0). Sincronizar con la llegada real antes de cancelar, con
  espera acotada y manteniendo la comprobación de aborto rápido. No atribuir esta carrera al supervisor.
  *(Hecho: el test espera la recepción real en el servidor de loopback con plazo de 3 s, rechaza que la petición
  se resuelva antes de cancelar y mide por separado que la cancelación aborte con `AbortError` en menos de 2 s;
  49 ejecuciones del fichero, 48 de ellas a concurrencia 8, sin fallo.)*

- [ ] Observado en la campaña de cuatro horas (2026-10-02): el coordinador Claude agotó la cuota y su
  reserva Claude compartía el mismo límite. El segundo traspaso no llegó a adoptar el Run; el supervisor
  quedó en `unknown / input_prompt_unrecognized` durante el bloqueo, aunque su PID seguía vivo y `gaps`
  estaba vacío. Recuperación manual del mismo Run a generación 3. Exigir una prueba de ejecución real del
  sucesor y un dominio de capacidad distinto al agotar cuota; reconocer y registrar bloqueos de capacidad
  sin equipararlos a salida del proceso ni enviar entrada a un selector. La resistencia de cuatro horas
  sigue sin estar demostrada. Registro en `docs/FOUR-HOUR-CAMPAIGN.md`.


- [ ] Recuperación automática tras recibo ambiguo de retiro por cuota o de un receptor que llega al límite
  antes de adoptar el Run: el guardián conserva `quotaRetirement`/`pending` y bloquea sin duplicar cierres ni
  prompts. Hace falta un protocolo de reconciliación con prueba nativa antes de automatizar esos casos.
  El retiro por cuota con recibo positivo y sucesor preparado sí está implementado; no equivale a agotamiento
  comprobado de todos los servicios ni al ensayo de resistencia de cuatro/ocho horas.
