# FirmLab — backlog

Única lista de trabajo pendiente del proyecto — sustituye a los tres sitios donde antes vivía dispersa
(`BACKLOG.md`, la sección "remaining backlog" de `ROADMAP.md`, y el §4 de `METHODOLOGY-GAPS.md`). Lo ya cerrado
no vive aquí: vive en `git log -- docs/BACKLOG.md`, que conserva la evidencia medida de cada arreglo si hace
falta consultarla. Este fichero es de nuevo corto porque ese es el punto: un backlog que hay que desplazar para
leerlo deja de usarse como backlog.

`ROADMAP.md` es el historial de qué se envió y cuándo; `METHODOLOGY-GAPS.md` mapea la cobertura contra OWASP
FSTM/ISTG. Ninguno de los dos duplica esta lista.

## Kernel, emulación, RTOS, UEFI

- [ ] Profundizar la correlación kernel-CVE: el prefijo NVD puede tener miles de candidatos (2.037 para Linux
  2.6.31); usar config/subsistema, diff de parches o VEX de proveedor para descartar, y paginar más allá de los
  primeros 50 sin presentarlos como el conjunto completo.
- [ ] Hacer que la reparación del guest alcance una ruta ejecutada: la intervención al final de `rcS` sigue
  siendo inerte en el WR940N (`rcS` para en la línea 45 de 46, antes de llegar). Candidatos a investigar:
  `/etc/inittab`, un `preInit` antes de `rcS`, o la línea de comandos del kernel. Desbloquea además emulación
  interactiva/introspectable en vivo (`run_command_in_emulation`, enumeración de servicios).
- [ ] Ampliar RTOS más allá del boot: fuzzing de periféricos/MMIO (µEmu/P2IM/Fuzzware) y enumeración de tareas
  (`pxCurrentTCB`/listas de hilos). Renode hoy demuestra vida, no cobertura del HAL.
- [ ] UEFI restante: LogoFAIL (bugs de parser de imagen), callouts SMM (`CommBuffer` sin validar, clase
  efiXplorer), y postura de rango protegido SPI/BIOS-lock. Ya hay una BIOS real en el corpus y los 409 módulos
  rankeados tienen disposición terminal — falta la técnica, no el dato.
- [ ] Fuzzing avanzado: cmplog/compcov para resolver magic bytes, un libdesock preconstruido por arquitectura de
  guest (para que el harness de red funcione sin `FIRMLAB_DESOCK`), y un lado de entrada para el fuzzer.
  Fuzzing stateful/full-system (Fuzzware/µEmu) sigue siendo la frontera de investigación para RTOS.
- [ ] Cross-binary dataflow: extender el scaffold de taint (hoy limitado a un binario) a través de binarios; W4
  ya prueba la forma dentro de uno.
- [ ] Librerías nunca preguntadas: filtrar `.so` de la cola de alcanzabilidad es correcto para la pregunta
  actual, pero deja una librería vulnerable como candidato que nada resuelve nunca. Cargar el `.so` y arrancar
  simbólicamente desde una función exportada es un peldaño distinto, no una variante del actual.
- [x] uClibc ya no distorsiona el sweep de reachability. Medido sobre los bytes del WDR3600: ambos ficheros son
  ELF32 MIPS big-endian ET_DYN con entry point no nulo; `libutil-0.9.30.so` tiene PT_INTERP y DT_SONAME, mientras
  `libmsglog.so` no tiene PT_INTERP. El predicado actual exige PT_INTERP y ausencia de DT_SONAME para ET_DYN, así
  que ambos dan `runnable=false` y ya no abren los 45 candidatos. La regresión fija las dos formas sin confundir
  esta cola de programas con la pregunta separada de analizar funciones exportadas de una biblioteca.

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
- [ ] Re-ejecutar el carril **research** en las imágenes ya desplegadas: sus resultados OSV/NVD son anteriores a
  `totalMatching`/`cveIds`/`upstream`, y esos tres campos los escribe `providers/osv.ts` / `providers/nvd.ts`, no
  `providers/sbom.ts`. Re-ejecutar SBOM no los rellena: es otro carril, con otro job y detrás de
  `FIRMLAB_RESEARCH`. Iba junto al punto anterior en una sola entrada y eso los hacía parecer un solo arreglo.
- [ ] El cruce contra KEV vacío **no** es «ningún CVE explotado en la naturaleza»: `research/run.ts` alimenta
  `fetchAndMatchKev` con `collectCveIds(osv, nvd)`, de modo que sin una ejecución de research posterior a
  `cveIds` la entrada del cruce es el conjunto vacío y la salida también. Queda pendiente decidir si además se
  cruza contra los CVE que aporta el carril SBOM — la base de grype ya trae un proveedor `kev` embebido y sería
  un cruce local, sin red — y, mientras no se haga, que la superficie diga que la pregunta no se hizo.
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
- [ ] El mismo defecto un escalón más arriba, encontrado al arreglar el anterior y no implementado por no ampliar
  el alcance: un **syft que corre y lanza** llega a `sbomRun` como `available:false` igual que un syft ausente, y el
  paso emite `remedy: 'install-tool'` con la nota literal `'syft/grype not installed'` — falsa cuando syft está
  instalado y la invocación falló. `runSbom` ya distingue los dos casos en el `reason` que compone
  (`'syft not installed'` frente a `` `syft failed: ${message}` ``), así que el arreglo es el mismo de `68ea988`
  aplicado a la otra mitad del carril y la nota debería salir de `r.reason` en vez de estar escrita a mano.
  Verificable: un job `sbom` con syft presente cuya ejecución falle debe dejar `remedy: 'retry'` en el paso.
- [ ] Aprovisionar la base de vulnerabilidades de grype en el despliegue. Desde que el carril SBOM dejó de
  descargarla sola (ver `providers/sbom-db.ts`), un contenedor recreado no tiene base y el resultado declara la
  negativa en vez de correlacionar. Decidir entre las dos opciones, ninguna gratis: hornearla en
  `Dockerfile.tools` (capa de ~2,2 GB en la imagen base, reproducible, caduca con la imagen) o un paso de
  provisión documentado contra el volumen de datos (`GRYPE_DB_CACHE_DIR=$FIRMLAB_DATA_DIR/grype-db grype db
  update`, una vez, sobrevive al redespliegue). Verificable: `grype db status` dentro del contenedor. Falta
  además que Capacidades distinga «grype presente» de «grype con base»: hoy sondea el binario y dice sólo lo
  primero, así que la página promete una pregunta que el carril va a rechazar.
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
- [ ] **(b) Triage de CVE por contexto de dispositivo.** Complementa el item de "profundizar correlación
  kernel-CVE" de arriba con reglas de poda de falsos positivos: CVE de GUI/X11 = FP en un headless; subsistema
  del kernel no compilado (Bluetooth/USB-gadget/FS exóticos) = FP; LPE local = severidad menor cuando todo ya
  corre como root (común en embebido); DoS = mayor en RTOS (sin init que reinicie una tarea caída) que en Linux
  (watchdog reinicia). Preservar SIEMPRE el score NVD base y anotar el ajuste con su rationale. Encaja en
  `component-cve.ts`/`kernel-cve.ts`. Ref: galert `firmware-sbom.txt` (device-context triage + checklist de CVE
  embebidos de alto valor: BusyBox awk, Dropbear empty-auth, dnsmasq DNSpooq, curl SOCKS5, DirtyPipe).
- [ ] **(b') Fuentes de taint específicas de firmware.** Enriquecer el scaffold de taint (ver "cross-binary
  dataflow" arriba) con las SOURCES canónicas de vendor, que rara vez son un `recv` crudo: getters HTTP/CGI
  (`websGetVar`/`webGetVar`/`GetValue`/`get_cgi`/`httpGetEnv`) y NVRAM/env (`nvram_get`/`nvram_safe_get`/
  `acosNvramConfig_get`/`getenv` — valores que el operador puede fijar por la UI y un daemon consume sin
  sanear), + el atajo de command-template `%s` (`rabin2 -z | grep '%s'` → `axt` al builder). Alimenta
  `taint.ts`/`webtaint.ts`. Ref: galert `firmware-binary.txt` / `firmware-zeroday.txt`.

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
  (reachability/cmdexec/reproduction) y `MAX_DYNAMIC_STEPS` intactos; el conductor MCP/agente queda para su propio
  apartado.

## Mercenario — agente 100% autónomo, opt-in (rompe determinismo/reproducibilidad)

- [ ] Nuevo apartado (arm C productizado y en cuarentena) para los casos más difíciles, donde el pipeline
  determinista devuelve poco: agente 100% autónomo, modelo/proveedor configurable por API, toolchain cruda, con
  modo de objetivo (assess / resolver-CTF / libre) y clasificación del artefacto ("esto es un reto CTF", "target
  de investigación", "dispositivo de producción"). Invariante NO negociable: su salida NUNCA escribe
  proof-states disciplinados en el ledger honesto — vive en un almacén en cuarentena, y las afirmaciones
  interesantes se devuelven a los providers deterministas para verificación (reconciliación arm C → arm A).
  Diseño completo y tests de aceptación: `docs/MERCENARY-DESIGN.md`.
