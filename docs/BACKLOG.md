# FirmLab — backlog

Única lista de trabajo pendiente del proyecto — sustituye a los tres sitios donde antes vivía dispersa
(`BACKLOG.md`, la sección "remaining backlog" de `ROADMAP.md`, y el §4 de `METHODOLOGY-GAPS.md`). Lo ya cerrado
no vive aquí: vive en `git log -- docs/BACKLOG.md`, que conserva la evidencia medida de cada arreglo si hace
falta consultarla. Este fichero es de nuevo corto porque ese es el punto: un backlog que hay que desplazar para
leerlo deja de usarse como backlog.

`ROADMAP.md` es el historial de qué se envió y cuándo; `METHODOLOGY-GAPS.md` mapea la cobertura contra OWASP
FSTM/ISTG. Ninguno de los dos duplica esta lista.

## Kernel, emulación, RTOS, UEFI

- [ ] Profundizar la correlación kernel-CVE. Ya hay paginación NVD acotada con denominadores/estados parciales y
  el selector solo descarta un advisory cuando un subsistema mapeado está probado `off`; config ausente,
  subsistema no mapeado y páginas no examinadas siguen explícitamente provisionales. Falta usar diff de parches o
  VEX de proveedor para resolver backports sin inferirlos.
- [ ] Hacer que la reparación del guest alcance una ruta ejecutada. El código ya inserta una primera entrada
  `::sysinit:` estructuralmente segura en `/etc/inittab` y, si no puede, degrada al principio ejecutable de `rcS`,
  con restauración byte-exacta y pruebas del orden. Falta el boot real del WR940N con evidencia de consola/red:
  las pruebas de composición no autorizan a afirmar que el servicio quedó alcanzable en el dispositivo.
- [ ] Ampliar RTOS más allá del boot. Ya existe un parser byte-only acotado para listas de tareas FreeRTOS cuando
  se suministran símbolos/layout (`pxCurrentTCB` y lista circular), con ciclo, truncado y punteros fuera de rango
  explícitos. Faltan el cableado API, una fuente real de símbolos/memoria y fuzzing de periféricos/MMIO
  (µEmu/P2IM/Fuzzware); Renode sigue demostrando vida, no cobertura del HAL.
- [ ] UEFI restante. La imagen ya tiene un parser acotado del descriptor Intel SPI que registra regiones,
  solapes, huecos y bytes examinados sin confundir defaults estáticos con registros vivos. Siguen pendientes
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
- [ ] Presentar el modo simbólico de librerías en los resúmenes UI/MCP: hoy el resultado persistido conserva la
  cobertura en `library`, pero los consumidores antiguos miran `sinks` y pueden mostrar 0/0. Añadir además tests
  directos de la clasificación `reachTargetKind` y de la rama library de opacidad.

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
- [ ] Portar los `soft_constraints` de moria: restricciones que PENALIZAN sin rechazar, para el caso en que un
  campo es sospechoso pero no imposible. Nuestro `verify` es binario hoy —acepta a un nivel o rechaza— y por eso
  ningún chequeo llega a `verified` (99), que queda reservado a recomputar un checksum sobre el payload y hoy no
  lo alcanza ninguna regla. La pieza que falta es el peldaño de arriba, no el de abajo.
- [ ] Completar los magics de contenedor de vendor: `e609854` añade 21 (SEAMA, WRGG, Netgear CHK y DNI, las tres
  variantes de Ubiquiti, TRX v2/HDR1, CFE, la tabla safeloader `fwup-ptn` de TP-Link, IMAGEWTY de Allwinner,
  RKFW/RKAF de Rockchip, IVT de i.MX, bFLT, vendor_boot y vbmeta y la tabla DTBO de Android, FMAP, CBFS, el
  descriptor de flash de Intel y `$FPT`), no las ~130 del plan original. **El límite no es el esfuerzo: es que
  cada magic va emparejado con un chequeo de campos que el propio formato declara y con capacidad de rechazar, y
  un magic que no se puede comprobar estructuralmente es una regla que dispara sobre coincidencias que después
  hay que explicar.** Quedan fuera por eso, no por olvido: Realtek (`csys`/`cr6c`/`cs6c`), Sercomm, el header
  MTK y el header legacy de TP-Link —reconstruirlos de memoria es justo la clase de afirmación que la tabla CVE
  curada tiene prohibida—. Reautorarlos clean-room contra la fuente del formato (OpenWrt `mkfwimage`-style) es
  lo que falta. Xiaomi ya está cubierto por HDR1 y no necesita regla propia: un magic identifica un FORMATO de
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
  productos, ~700 KB) para CVE offline con `FIRMLAB_RESEARCH=0`.
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
- [ ] Decidir si el cruce KEV debe incorporar también los CVE del carril SBOM. La base de grype ya trae un
  proveedor `kev` embebido, por lo que podría ser un cruce local sin red, pero sigue siendo una decisión de
  política distinta de presentar honestamente una entrada vacía del carril research.
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
- [ ] Completar la cobertura del lead de clave derivada del loader sin ensanchar sus afirmaciones: hoy
  `auditLoaderDerivedKey` corre sólo después de localizar y parsear un entorno U-Boot, examina un prefijo de 4 MiB
  que declara en la evidencia y reconoce ENC1 con longitud, cuerpo completo y entropía; mover la auditoría antes de
  esa precondición para que un loader sin entorno legible pueda producir el lead y persistir la cobertura también
  cuando el resultado sea vacío. Centralizar además el predicado ENC1 que hoy comparten conceptualmente
  `encrypted.ts` y `uboot.ts`, y puntuar candidatos seed/salt más allá de la forma deliberadamente estrecha
  guion+mayúsculas (minúsculas/base64 necesitan corpus antes de abrir la heurística). Verificable: loader con receta
  + ENC1 real y sin bloque de entorno produce un lead acotado; el mismo magic en rodata no lo hace.
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

## Ideas evaluadas, no programadas (de la revisión de wairz)

- [ ] Puente UART host↔dispositivo físico: el único ítem ISTG-INT que no es trabajo de laboratorio puro, porque
  es software en el lado host.
- [ ] Inventario de capacidades al estilo capa (qué PUEDE hacer un binario, distinto de qué tiene de malo);
  FirmLab hoy solo hace la segunda pregunta.
- [ ] Fuentes de vendor-PSIRT/CNA para el track de inteligencia externa: no hay una API única gratuita que las
  cubra todas (referenciado desde `docs/AGENT-DESIGN.md`).
- [ ] Formalizar visibilidad de capacidades por clase de dispositivo en la UI — el gating ya existe en
  `specsForClass`/`coverage.ts`, falta el acabado visual.

## Deuda estructural y de proceso

- [ ] Revisar el reparto core/api: `packages/core` son ~2.500 líneas frente a ~91.000 de `apps/api`, con
  dominio puro (`opacidad-plan.ts`, `boot-cmdline.ts`, `nvd.ts`, `opacidad-leads.ts`, `findings-normalize.ts`…)
  viviendo en la capa de aplicación solo porque no puede importar `store.js` (65 módulos acoplados, 24 fuera de
  `routes/`). Decidir si core recupera ese dominio o si se documenta como workaround deliberado.
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

## Emulación dinámica — superar la frontera FSTM-7 / GAP-01 (trabajo a futuro)

- [ ] Diseño y hoja de ruta en `docs/EMULATION-FUTURE.md`: síntesis de hardware para arrancar firmware SOHO con
  red operativa en emulación pura, atacando las tres causas raíz medidas (bucles de sondeo MMIO, ausencia de
  switch DSA, fragilidad de `LD_PRELOAD`/libnvram). Priorizable por fases: **Fase 1 — Universal Virtual DSA
  Switch** (Capa II; depende de una detección de familia de switch RTL83xx/BCM53xx/QCA8337 que aún NO existe en
  `signatures.ts`); **Fase 2 — integrar Fuzzware/µEmu como provider** para modelado MMIO (no motor TCG propio;
  frontera ya nombrada en este backlog); **Fase 3 — snapshot/fork** (`savevm`/`loadvm`) enlazado a `webprobe.ts`
  + AFL++. Techo de prueba honesto: `confirmed_in_emulation` de daemons de red (hoy `br-lan` nunca sube), NUNCA
  `confirmed_full_system` ni «idéntico al físico» — el entorno sintético es permisivo por diseño (`types.ts`). La
  Capa IV (Avatar2/JTAG) queda FUERA DE ALCANCE: rompe la premisa sin-hardware.
