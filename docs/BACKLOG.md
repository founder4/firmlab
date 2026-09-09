# FirmLab — backlog

## Cerrado en esta iteración

- [x] Eliminar las vulnerabilidades de producción y hacer reproducibles las imágenes Docker.
- [x] Unificar el arranque full-system para que QEMU reciba una imagen de disco, no el directorio rootfs.
- [x] Reconciliar como interrumpidos los jobs `queued`/`running` después de reiniciar la API.
- [x] Entregar `exportreach`: API, panel web, i18n, tests, validación sobre firmware real y hallazgos accesibles al agente.
- [x] Dejar `pnpm audit` completamente limpio actualizando Vitest, Vite y la cadena jsdom/undici.
- [x] Confirmar Biome limpio en `exportreach` y en el workspace completo.
- [x] Añadir CI para instalación congelada, auditoría, Biome, tipos, tests, build y smoke test de Docker.
- [x] Mostrar resultados dinámicos y de agentes como conclusiones con evidencia y clasificar bien el historial full-system.
- [x] Reconciliar el triaje del agente con la identidad medida y enriquecer sus nodos con contexto determinista acotado.
- [x] Integrar `exportreach`, `credmatch` y `yarascan` en `opacidad`, cobertura y MCP.
- [x] Persistir y mostrar telemetría operativa de DeepSeek (tokens de razonamiento y recuperación JSON), sin guardar pensamiento interno.
- [x] Configurar un corpus YARA reproducible: YARA Forge Core fijado por hash, heurísticas de firmware, fixtures y despliegue read-only.
- [x] Corregir la severidad YARA externa: una regla sin `meta.severity` queda `info` y pendiente de triaje, no se inventa `high`.
- [x] Vigilar releases YARA sin autodespliegue, comparar candidata/producción sobre los mismos rootfs y exigir positivos inertes.
- [x] Integrar `webprobe` en la ventana viva de QEMU y automatizar una campaña de cinco arranques full-system reproducibles.
- [x] Sondear activamente también el HTTPS autofirmado/heredado del invitado, con la relajación TLS confinada a loopback.
- [x] Poner el resultado por delante en Dashboard, corpus y ficha: recuento de hallazgos, cobertura con barra, censo en tarjetas, filtros y búsqueda, e informe replegado a un `<details>`.
- [x] Persistir e hidratar el análisis profundo al recargar, manteniendo el resultado y su trazabilidad fuera del estado efímero del componente.
- [x] Exigir despliegues reproducibles: build exacta, revisión OCI, comprobación de `latest` y verificación posterior contra el commit solicitado.
- [x] Reducir deuda del frontend: rutas lazy, bundle principal de 739,58 kB a 427,07 kB, tests de páginas y runtimes vigentes en GitHub Actions.
- [x] Verificar el libro mayor a 390×844 con navegador real y corregir el desbordamiento de cadenas largas en Update Path.
- [x] Desglosar el censo por semántica: establecido, pista, bloqueo, descartado, testimonio y otros; `unproven` queda sólo como agregado de compatibilidad.
- [x] Fijar una matriz ejecutable del corpus (SHA/tamaño/clase/arquitectura, stages y gates) y ampliarlo de 19 a 23 muestras con BIOS Framework oficial, Contiki, Zephyr y QMK.
- [x] Correlacionar kernel y módulos con CVE sin sobreactuar la evidencia: CPE del kernel restringido a la CNA de Linux, prefijo/truncación explícitos y NetUSB ligado a CVE-2015-3036 sólo por identidad byte-level.
- [x] Cerrar el hueco QMK con evidencia binaria: `boot2` y vector XIP de RP2040, más marcadores QMK corroborados; la muestra oficial queda clasificada como `rtos`/`arm` sin depender del nombre del fichero.
- [x] Convertir el límite FwHunt en una campaña reanudable por lotes disjuntos, con cobertura acumulada y denominador visible; la campaña real del BIOS Framework dejó los 35/35 lotes resueltos, 404/409 módulos escaneados, 5 no convergentes explícitamente desconocidos y 0 sin intentar.
- [x] Evitar que `opacidad` pise una campaña FwHunt dedicada: exclusión mutua por imagen, reutilización del resultado durable, reinicio explícito y reintento automático de lotes con módulos fallidos.
- [x] Compactar FwHunt: un único snapshot durable, veredictos agregados reconstruibles desde sus lotes y borrado de snapshots acumulativos sustituidos; la respuesta final del Framework conserva 51.308 veredictos por lote sin duplicarlos en el agregado.
- [x] Aislar módulos EFI no convergentes: timeout de 180 s por módulo, terminación de todo el grupo de procesos, `tini` como reaper y estado terminal `finalizedWithFailures` que permite continuar sin llamar limpio a un fallo.
- [x] Hacer que la cobertura y la matriz lean la campaña FwHunt durable más reciente en vez del snapshot histórico incrustado en el último `opacidad`.
- [x] Ejecutar las dos muestras nuevas `dragon_reto*`: las 14 celdas `not-run` bajaron a 0 y la matriz viva quedó regenerada con 25 muestras / 390 etapas.
- [x] Revalidar las 33 celdas `no-input`: dependen exclusivamente de BeanView, Asus y AliExpress; una extracción fresca confirmó, respectivamente, volúmenes de datos sin rootfs, SquashFS truncado y LZMA corrupto. Reintentarlas no recupera bytes ausentes.
- [x] Evaluar YARA Forge Core 20260830 contra los mismos 8 rootfs: compila, conserva los 3 positivos inertes, añade 134 reglas, elimina 4 y no introduce ni pierde matches en el corpus actual. La promoción sigue siendo una decisión separada.
- [x] Completar la campaña FwHunt de OVMF: 12/12 lotes terminales, 131/136 módulos con veredicto, 5 no convergentes explícitamente desconocidos y 0 módulos sin intentar (antes quedaban 124).

- [x] Plegar el libro mayor por forma de hallazgo: una corrida de filas que dicen lo mismo sobre sujetos distintos se dibuja como una línea con su recuento y se despliega en el sitio. Medido sobre DVRF, 129 filas pasan a 59 líneas y los cuatro `static_confirmed` de la clave privada encabezan la tabla. La clave de plegado incluye severidad y estado de prueba, así que un grupo es homogéneo en los dos ejes que ordenan la tabla y el orden de `compareFindings` se conserva exacto — se redibuja, no se reordena. Filas impugnadas, testimonios y hallazgos obtenidos sobre un sujeto alterado nunca se pliegan. La etiqueta del grupo se deriva de los tokens en que coinciden todos sus miembros, no de la máscara, y donde difieren de verdad conserva la elisión.
- [x] Extraer de `providers/jobs.ts` el planificador de concurrencia a `job-scheduler.ts`, sin un solo import: la admisión, la cola FIFO y la contabilidad de huecos pasan de intesteables a 15 tests. El hueco es ahora un token con `release()` idempotente, y soltarlo es lo que arranca al siguiente, sin ventana en la que el contador baje. De paso cierra dos defectos latentes: `Math.max(1, Number(...))` propagaba `NaN` para un `FIRMLAB_MAX_CONCURRENT_JOBS` no numérico y dejaba la cola parada para siempre, y un `insertJob` que lance ya no deja el hueco colgado bajando el techo de concurrencia de forma permanente.
- [x] Dejar de leer un cero de secretos como un parte limpio. La búsqueda de cadenas recorre la imagen desde el offset 0 y para al llegar a su límite de 20.000, así que trunca por desplazamiento — por orden de llegada, lo único que un límite aquí no puede hacer en silencio: medido, la GL.iNet de 106 MB paraba en el 11,0 % del fichero y la cápsula BIOS Framework de 34,5 MB en el 92,5 %, y ambas se renderizaban como «No secret-like strings detected in the raw image» (la GL.iNet, con 12 secretos que gitleaks sí encontraba en el mismo firmware). `scanStrings`/`scanSecrets` reportan ahora hasta dónde llegó el recorrido y cuántas coincidencias hubo antes del corte de listado, `StaticAnalysis.secretScan` lo persiste como campo opcional para siempre, y el panel separa los dos límites: el del recorrido descartó bytes que nunca miró, el del listado descartó coincidencias ya examinadas y ordenadas. El estado vacío dice además que la heurística lee ASCII en bruto y que un secreto dentro de un sistema de ficheros comprimido no puede encontrarse en esa etapa. Los análisis guardados por builds anteriores no llevan el campo, y ausente no significa completo: se migran con `POST /analysis/reanalyze-all`.
- [x] Reparar el corte silencioso de `scanSignatures`, que a diferencia del de cadenas cambiaba un resultado persistido. El escaneo recorre ahora siempre el buffer entero y el cap deja de pararlo: pasado el límite sólo se admite la PRIMERA aparición de un id no visto, así que la lista sigue acotada —Obsbot 5.004, Tenda 5.002, GL.iNet 5.000— y el conjunto de ids queda completo. Verificado contra las 25 imágenes del corpus: identidad y conjunto de ids idénticos al escaneo sin límite en 25 de 25, con el Obsbot recuperando el `cramfs` que antes no aparecía. `scanSignaturesDetailed` reporta además `matched`, y `StaticAnalysis.signatureScan` lo persiste como campo opcional para siempre.
- [x] Decir en el mapa de estructura que es una muestra acotada, ahora que existe el recuento — y decir a la vez que la clase y los sistemas de ficheros NO lo son, porque leen el conjunto de tipos y ése ya no se trunca. La confusión corre en la dirección mala: desconfiar de la clase porque el mapa está capado descarta justo la parte sólida.
- [x] Rankear antes de recortar en `sbom.ts`. `matches.slice(0, VULN_CAP)` corría ANTES de `rankVulnerabilities`, así que el corte era por el orden de emisión de grype —orden de llegada— y `counts` era un recuento de los supervivientes presentado como total. Los paquetes era peor en la práctica: medido en el despliegue, syft catalogó 2.019 en la GL.iNet y el resultado persistido decía `packageCount: 500`, que es `PKG_CAP` exacto — un límite con el nombre de un recuento. Ahora se rankea y se cuenta sobre TODAS las coincidencias y sólo después se corta; los paquetes se ordenan por nombre antes del corte; `packageTotal` y `vulnerabilityTotal` se persisten como campos opcionales para siempre y la UI muestra los totales reales más la regla del listado.
- [x] Reportar el total real de funciones en Ghidra, y no la longitud de su propia lista. `Decompile.java` hacía `break` al llegar al cap, así que nada llegaba a saber cuántas funciones tenía el binario; el proveedor fijaba `functionCount: functions.length` y `capabilities.ts` leía ese par como denominador sobre numerador, de modo que el widget de cobertura sólo podía imprimir «40 de 40». El walk recorre ahora hasta el final y el cap sólo detiene la descompilación —mismo patrón que `scanSignatures`—, el script emite `functionTotal`/`eligible` y el denominador pasa a ser `eligibleCount`, con `null` honesto cuando no se registró. Validado en contenedor sobre `usr/bin/httpd` de TP-Link WR940Nv6: **40 de 4.037 elegibles, 4.600 totales — 1,0 % real frente al 100 % que mostraba**. El fixture `{ functionCount: 900, functions: [{}, {}] }` del test se sustituyó: describía datos que el proveedor no puede producir.
- [x] Dejar de reportar como éxito una descompilación que no descompiló nada (encontrado al validar el punto anterior, no por un test). `analyzeHeadless` es un lanzador Java y el decompilador que dirige es un binario NATIVO que Ghidra no trae precompilado para arm64: en el contenedor desplegado falta (`os/linux_arm_64/decompile does not exist`), así que la ejecución termina bien, se listan las 40 funciones con nombre y firma —que vienen del analizador, no del decompilador— y las 40 traen `pseudocode: ""`. `isToolAvailable` pasaba, nada lanzaba, y se devolvía `available: true`. Ahora `allPseudocodeEmpty` lo reconduce al caso bloqueado que `buildGhidraFindings` ya compone; exige que TODAS estén vacías, porque una función que falla es normal y no debe condenar la ejecución.
- [x] Compilar los componentes nativos de Ghidra para arm64. La release oficial trae `decompile` y `sleigh` para linux_x86_64, mac_arm_64, mac_x86_64 y win_x86_64, y nada para linux_arm_64, que es la arquitectura del despliegue. Receta en `Dockerfile.tools`, con tres cosas que rompieron el primer intento: el Makefile no tiene caso para `aarch64` y cae al de 32 bits pasando `-m32`; `OSDIR` queda vacío por lo mismo, así que `install_ghidraopt` copiaría a `os//decompile`; y los directorios de objetos no los crea ninguna regla, vienen en la distribución, de modo que tras un `make clean` cada compilación muere con «can't create ghi_opt/xml.o». Validado en contenedor sobre `usr/bin/httpd` de TP-Link WR940Nv6: 0 de 40 funciones vacías, pseudocódigo MIPS legible, y ya no aparece `os/linux_arm_64/decompile does not exist`.
- [x] Ejercitar las 22 herramientas declaradas en `tools.ts` contra entradas REALES en vez de `--version`, para buscar el mismo defecto de «presente pero inútil». Ghidra era el único caso. Cinco veredictos de «vacío» de la primera pasada eran fallos de la sonda, no de las herramientas: `mkfs.ext2 -V` escribe en stderr; la sonda de cadenas de r2 usaba sintaxis de paginador interactivo; `angr` y `fwhunt_scan` viven en venvs dedicados (`FIRMLAB_ANGR_PYTHON`, `FIRMLAB_FWHUNT_PYTHON`) y se probaron con `python3` pelado — la sonda real da `angr 9.2.213` y `fwhunt-scan ok`; y gitleaks daba 0 sobre la clave AWS canónica porque está en SU PROPIA allowlist de ejemplos, mientras que contra una clave RSA generada al vuelo y un token con formato GitHub detecta las dos.
- [x] Portar a `osv.ts` el patrón de `nvd.ts` — y encontrar, al validarlo contra respuestas reales, que el truncamiento no era el defecto que más costaba. El corte de 50 corría antes de cualquier orden, sin total y sin ranking; ahora `parseOsvAnswer` lee el array entero, publica `totalMatching`, ordena por el CVSS que el aviso declara y sólo entonces recorta. Medido sobre las 34 respuestas cacheadas del despliegue: la lista de curl 8.6.0 (63 avisos) dejaba fuera un **9,8**, y ahora lo peor que descarta es un 5,3. La puntuación hubo que calcularla de verdad: **117 de 121 avisos graduados declaran su gravedad ÚNICAMENTE como vector CVSS v3** y ninguno como nivel con nombre, así que una primera versión que sólo entendía `HIGH`/`9.8` dejaba el 100 % del corpus real en «sin graduar» y no reordenaba nada — el fixture del test se había escrito desde la misma suposición que el código. `cvssV3BaseScore` implementa las ecuaciones de la especificación; un vector v4.0 (4 de 121) no se puntúa, y **no se recorta por ello**: recortar un aviso por no poder leerlo es que el límite responda la pregunta que no supo leer.
- [x] Reparar, encontrado en esa misma validación, que la referencia cruzada contra KEV nunca había visto un solo CVE de OSV. Los registros Debian se llaman `DEBIAN-CVE-2016-2781` y ponen el CVE en `upstream`; **ninguno de los 133 avisos reales trae `aliases` y ninguno tiene un CVE como id**, así que `collectCveIds`, que leía id y aliases, devolvía cero. Sobre el corpus cacheado: **0 → 124 CVE** cruzados contra las 1.674 entradas de KEV (0 known-exploited, ya un negativo real y no un conjunto vacío). Además el conjunto de CVE deja de ser la lista recortada — 19 de esos 124 sobreviven sólo por eso — y la etiqueta de la web muestra el CVE en vez del id de la base de datos.
- [x] Sacar del presupuesto de consultas de OSV los componentes que OSV no puede responder. El tope de 80 se tomaba sobre la lista entera y el orden de llegada es el de syft —alfabético—, de modo que en un rootfs OpenWRT de ~2.000 paquetes los 80 huecos se iban en módulos de kernel sin ecosistema y no se preguntaba nada respondible: el mismo defecto que `rankNvdCandidates`. Un componente no mapeable no cuesta petición, luego ya no cuesta presupuesto; `skipped` cuenta ahora todos y no sólo los que el tope alcanzaba, y `notQueried`/`notQueriedRule` dicen qué dejó fuera el tope y con qué regla.

## Siguiente

### Cobertura y análisis

- [ ] Convertir la matriz del corpus en una campaña programada: hoy quedan 0 celdas `not-run`, 85 `degraded` y 33 `no-input` entre 390 etapas aplicables; priorizar las degradadas desbloqueables por clase y coste, y no contar como deuda ejecutable los tres artefactos que requieren reacquisición.
- [ ] Profundizar la correlación de kernel: el prefijo NVD puede tener miles de CVE (2.037 para Linux 2.6.31); usar config/subsistema, diff de parches o VEX de proveedor para descartar candidatos y paginar más allá de las primeras 50 sin presentarlas como el conjunto.
- [ ] Hacer que la reparación del invitado alcance una ruta ejecutada y recuperar red/console interactiva en full-system; la intervención al final de `rcS` sigue siendo inerte.
- [ ] Ampliar RTOS a fuzzing de periféricos/MMIO y enumeración de tareas; Renode demuestra vida, no cobertura del HAL.

### Corpus persistente — construido, cableado y vacío

Medido contra el despliegue vivo del 5 de septiembre de 2026 (25 imágenes): `artifact_occurrence` 2.003 filas de sólo 8 imágenes, `component_occurrence` 356 de 3, `credential_occurrence` 8 de 4, `reachability_prior` 3 de 3, `corpus_rule` ninguna. La página `/corpus` muestra `REUSED CREDENTIALS: 0` y `WATCHLIST RULES: 0`. La ventaja estructural que declara el comentario de módulo de `corpus.ts` no ha producido todavía un solo prior cruzado.

- [x] Alimentar el corpus desde todas las fuentes de secretos que SON secretos, sin exponer ninguno. Un camino uniforme y redaction-safe: cada proveedor estampa en su hallazgo una identidad hasheada —`evidence.secretHash` para un valor (nvram) o `evidence.secretHashes[]` para el material de clave de un fichero (`fsaudit`/`auxsecrets`)—, el `keyFingerprint` puro de `pem-scan.ts` la calcula (SHA-1 de la mitad PÚBLICA cuando la clave decodifica, del cuerpo base64 cuando no), y `credentialHashesFromFindings` (puro, en `findings-normalize.ts`) las recoge para que la ruta/opacidad llame a `recordCredentialHashes`. El valor NUNCA sale del proveedor; el corpus sigue guardando sólo un SHA-1, igual que ya hacía `hashSecret`. **`certs` queda deliberadamente FUERA**: un certificado es material público y meterlo en `credential_occurrence` es exactamente la sobreactuación que el comentario de la ruta gitleaks ya pagó con las claves dnscrypt. Validado contra bytes reales: la clave RSA device-wide de la Tenda-Camera —en dos particiones jffs2 y una reextracción— colapsa a UNA huella (`63949fb7…`), la de otro dispositivo (IMOU) difiere, y el cuerpo de la clave no se filtra en la huella. `hashSecret` se extrajo a `secret-hash.ts` para que los proveedores puros lo compartan sin arrastrar el store.
- [x] Ampliar el alcance de `flagKnownCredentials`: ya no filtra por `source === 'secrets'` ni lee sólo un `evidence.value` en claro, sino que casa contra la MISMA identidad que grabó el recorder —`evidence.secretHash`/`secretHashes` cuando el proveedor la estampó, o `hashSecret(evidence.value)` para el clasificador de cadenas que guarda el valor literal—. Con esto el Nivel 1 alcanza los hallazgos redactados (nvram, material de clave), no sólo los 3 de `secrets`. Su valor sigue supeditado a que exista una regla en la watchlist (`ruleCount` sigue en 0 hasta promover una).
- [x] Añadir `pnpm corpus:reindex` (`POST /corpus/reindex`): la ruta de reconciliación que faltaba. Reconcilia el corpus contra todo lo que ya está en el banco **desde estado ya persistido** — el bundle de análisis de la fila de la imagen, el libro mayor, el resultado guardado del último job y la tabla `binaries` —; no ejecuta una herramienta, no abre un socket y no relee un solo byte de firmware, así que es barato y seguro apuntarlo a un despliegue vivo. La decisión vive pura en `corpus-reindex.ts` (18 tests) y `corpus.ts` la ata al store; los cinco `recordX` devuelven ahora **filas insertadas**, que bajo `INSERT OR IGNORE` es cuántas faltaban y no cuántas veces se llamó a insert.

  Validado contra una copia de la base desplegada (25 imágenes, nunca un segundo escritor sobre la viva). El camino de escritura no se ejercita con el corpus intacto —todo lo que se ofrece ya estaba—, así que se borró una imagen de la copia: la reconciliación devolvió **358 componentes y 1.163 artefactos**, y una segunda pasada insertó **0**. Idempotencia demostrada, no supuesta.

  Tres cosas que la corrida real corrigió y que no habría encontrado ningún fixture:
  - **`rowsOffered` contaba llamadas, no filas.** El SBOM de la GL.iNet ofrece 500 paquetes que son 358 pares `(name, version)` distintos; presentar «0 de 502» invitaba a leer que el corpus guarda 502. Se colapsa ahora por la clave primaria de cada tabla, que es exactamente lo que `INSERT OR IGNORE` conserva.
  - **Un reindexado hereda la cota del resultado que reconcilia.** El SBOM guardado de la GL.iNet trae 500 de los 2.019 paquetes que syft catalogó, porque se escribió antes de arreglar ese cap, y su pase de cadenas paró en el 11 % del fichero. `boundedInputs` lo dice por imagen y por tipo; y un tercer estado importa tanto como los dos: un resultado anterior al campo de cobertura no declara cota ninguna, y eso es **NO CONSTA**, nunca «lo leyó entero» (7 de los 8 SBOM guardados).
  - **Reconcilia hacia el ÚLTIMO resultado guardado, no hacia la unión de todos.** La GL.iNet tenía 361 filas de componentes acumuladas en dos corridas de SBOM y volvieron 358: las tres de la corrida superada son irrecuperables por definición. Es un límite de lo que un reindexado puede RESTAURAR, no de producción, donde no se borra nada.

  Y el resultado que corrige la premisa de este propio punto: **el reindexado NO puede poblar `credential_occurrence` desde el material de clave**. 72 filas del libro mayor en 12 imágenes vienen de `fsaudit`/`nvram`/`auxsecrets` y **ninguna lleva identidad estampada**, porque se escribieron antes de `c8a1516`. Esa identidad nunca se calculó y no está en disco para leerla. El informe lo nombra en vez de dejar que «0 ofrecidas / 25 imágenes con entrada» se lea como «revisadas las 25, no hay material de clave».

- [ ] Re-ejecutar `fsaudit`/`nvram`/`auxsecrets` sobre las 25 imágenes tras desplegar `c8a1516`, y sólo entonces `pnpm corpus:reindex`. Ése —y no el reindexado— es el paso que produce las 72 identidades que hoy faltan; medido, es la única brecha que una reconciliación no puede cerrar. Después, un `credentialReuse` en 0 sería por fin un negativo real.
- [x] Filtrar `componentPrevalence` con `HAVING imageCount > 1`, como ya hace `credentialReuse`: la tabla titulada «qué versiones abarcan más imágenes» devolvía 200 filas donde ninguna superaba 1, rellenas de módulos de kernel con versión `UNKNOWN` y 0 CVE. Y su estado vacío dice ahora por qué lo está —`sbomImageCount` de `imageCount` imágenes tienen SBOM— con un mensaje interpolado en ambos idiomas, igual que la sección de credenciales.
- [ ] Decidir qué papel juega `vendor` en `deviceFamilyKey`: está sin poblar en 25 de 25 imágenes, de modo que las 13 familias son `unknown:clase:arquitectura` y cuatro routers sin relación comparten los priors de alcanzabilidad del Nivel 2. O se puebla desde la evidencia ya disponible (cadenas del rootfs, banners de servicio, FCC-ID, rutas NVRAM) o se retira de la clave; lo que no puede seguir es una clave que promete vendor y siempre responde `unknown`.
- [ ] Desambiguar el nombre «corpus», que designa tres cosas sin relación entre sí: el corpus persistente entre imágenes (`apps/api/src/corpus.ts`), el corpus de validación de 25 muestras (`ops/corpus/validation-samples.lock.json`) y el corpus de reglas YARA (`ops/yara/corpus.lock.json`).

### Presentación de los resultados

- [ ] Puntuar los vectores CVSS v4.0 en `osv.ts`. Hoy `cvssV3BaseScore` implementa v3.0/v3.1 y devuelve `null` para v4.0, cuya puntuación base necesita la tabla MacroVector; esos avisos quedan sin graduar y se conservan sin recortar, que es el comportamiento seguro, pero no se ordenan. Son 4 de 121 en el corpus cacheado y crecerán.
- [ ] Re-ejecutar la investigación sobre las imágenes con SBOM tras desplegar esto: los resultados guardados no llevan `totalMatching`, `cveIds` ni `upstream`, así que sus tablas siguen mostrando el denominador de la lista y su cruce contra KEV sigue siendo el vacío que era. La caché de avisos en disco sirve las respuestas sin volver a salir a la red.
- [x] Terminar la auditoría de límites. Barridos los 558 sitios candidatos del repo en tres frentes —los 83 proveedores; las 44 rutas más `store.ts`/`findings.ts`/`retention.ts`/`corpus.ts`/`opacidad*`; y `agent/`, `research/`, `capture/`, `mcp/`, `packages/core` y `apps/web`—, cada candidato leído y trazado hasta un campo persistido, una respuesta de API/MCP o un píxel. Los cuatro que este punto dejó marcados sin verificar quedan resueltos: `funcdiff-run.ts:90` y `:210` confirmados (ahora `:94` y `:221`), `chipsec.ts:490` confirmado (ahora `:533`), `diff.ts:100` confirmado (en `:122`). **37 defectos verificados**, listados abajo por lo que le hacen al lector; lo revisado y sano queda anotado para que el barrido no se repita.
  - [x] `fcc.ts`: el pase de cadenas leía sólo los primeros 16 MB y un cero se renderizaba como «No FCC ID found in the firmware» — una cota presentada como negativo absoluto. `rawImageStrings` reporta ahora `bytesScanned`/`totalBytes`, `FccResult.scan` lo persiste (opcional para siempre) y, cuando la imagen supera el prefijo, el `reason` dice qué no miró en vez de afirmar que no hay; el negativo limpio se reserva para las imágenes que caben enteras. También anota el corte de listado cuando se alcanzan los 20 IDs.
  - [x] `gitleaks.ts`: `findingCount` era `findings.length` tras el `slice(0, FINDING_CAP)`, así que un rootfs con más de 500 leaks persistía 500 como si fueran todos (el total real sólo iba al log). Nuevo campo `total` (opcional para siempre) con el recuento pre-cap; `findingCount` queda como el listado, y la web muestra «Showing 500 of N» cuando el listado se truncó.
  - [x] `disclosure.ts`: el borrador de divulgación listaba `kevMatches.slice(0, 20)` sin decir que había más, presentando los primeros 20 KEV como el conjunto entero —justo las entradas que un analista más necesita saber que existen—. Ahora, cuando hay más de 20, añade una línea «showing 20 of N KEV matches» (`kevMore`, en ambos idiomas).

- [ ] Anotar como patrón, no como incidencias: los tres defectos de esta clase encontrados hasta ahora (`extractStrings`, `scanSignatures`, `sbom.ts`) comparten forma —cap aplicado antes de ordenar, o recuento leído de la lista ya recortada— y los tres cambiaban lo que la pantalla afirmaba. Merece un test de propiedad o una regla de lint que detecte `.slice(` sobre la misma expresión de la que luego se deriva un recuento.
- [x] Re-analizar el corpus desplegado tras desplegar `secretScan`. Ya estaba hecho, y lo dice una medición y no una suposición: el reindexado del corpus comprueba, por imagen, si el análisis guardado declara su cobertura, y sobre las 25 imágenes del despliegue devolvió **cero** entradas `static-scan` en «cota NO CONSTA» — es decir, las 25 llevan el campo, y las cinco acotadas (GL.iNet 11,0 %, Obsbot 16,3 %, GE800 21,6 %, Tenda 71,5 %, Framework BIOS 92,5 %) muestran su aviso. Lo que sigue sin migrar es el SBOM: 7 de los 8 resultados guardados son anteriores a `packageTotal`.
- [ ] Exponer `credmatch` en la web: es el único route sin ninguna referencia en `apps/web/src`, pese a sus 1.337 líneas, un source estable en el libro mayor y ✓ en cuatro muestras de la matriz como «W3 · Credential cross-reference».

### La auditoría de límites — 37 defectos verificados, pendientes de arreglo

Cuatro subpatrones, los mismos que pagaron `ghidra`, `sbom`, `scanSignatures`, `secrets`, `fcc`, `gitleaks`, `osv`
y `disclosure`: **(A)** cap antes de ordenar, así que el conjunto superviviente es un artefacto del orden de
llegada · **(B)** un recuento leído de la lista ya recortada y presentado como total · **(C)** una cota
renderizada como negativo limpio · **(D)** un presupuesto gastado en candidatos que no pueden responder. La regla
de la casa para el arreglo: un campo añadido a un resultado persistido es **opcional para siempre**.

#### Cambian un veredicto, o convierten una cota en un negativo

- [ ] `copilot.ts:78` **(A)** — `findings.slice(0, 120)` sobre el `ORDER BY createdAt DESC` de `listFindings`, así
  que la «evaluación priorizada» del copiloto la escriben los proveedores que corrieron *los últimos*. Medido
  contra la base desplegada: en la imagen `81154df7` (799 hallazgos, 41 críticos / 230 altos) **las 120 filas que
  llegan al modelo son todas de `sbom`**, y `symreach`, `binvuln`, `webtaint`, `gitleaks`, `credmatch`, `fsaudit`,
  `emulate-system`, `zeroday` y `fwhunt` caen enteros. Ordenar por `findingRank` (ya exportado de `@firmlab/core`,
  ya usado por la narrativa) antes del corte, y declarar la regla y el descarte en `buildCopilotUserPrompt`.
- [ ] `providers/component-cve.ts:367` **(A)+(C)** — la caminata del rootfs es una pila LIFO con `WALK_CAP = 8000`
  dirents y sin flag de truncamiento, mientras el `reason` dice «N componente(s) versionados, M CVE emparejados de
  la tabla curada». Es el peor del grupo porque es **el camino de la afirmación CVE curada**: un veredicto que
  suena completo sobre una caminata parcial.
- [ ] `providers/funcdiff-run.ts:94` **(B)+(C)** — `listElves` recorre ambos rootfs con una pila LIFO que para a los
  20.000 dirents y devuelve un `Map` pelado; `paired: shared.length` presenta una intersección capada como el
  emparejamiento entero. Peor: como las dos caminatas pueden truncar en subárboles distintos, un par grande puede
  llegar a `empty('the two rootfs share no binary at the same path — they are probably not two builds of one
  device')`, **un veredicto seguro y falso fabricado enteramente por la cota**. Nunca emitir esa frase si alguna
  caminata truncó.
- [ ] `providers/uboot.ts:562` / `:607` **(C)** — `readBounded(imagePath, READ_CAP)` lee 32 MB y luego devuelve
  `notFound('No U-Boot environment found in the image.')`. El defecto de `fcc.ts` literal, en una clase donde los
  volcados de 64–128 MB son rutina. El comentario de módulo dice «reads a bounded prefix»; la frase que ve el
  operador, no.
- [ ] `llm.ts:152` y `:182` **(C)** — ni `parseChatCompletionsResponse` ni `parseAnthropicResponse` leen
  `finish_reason`/`stop_reason`, así que una respuesta cortada en `maxTokens` (4096 por defecto, y los tokens de
  razonamiento de DeepSeek cuentan) vuelve como un `LlmResult` normal — y `opacidad.ts:1094` deja que **ese texto
  truncado sustituya a la narrativa determinista completa** y lo guarda en la fila del job como el informe.
- [ ] `capture/proxy.ts:233` (y la misma forma en `capture/agent.ts:78`) **(C)** — un cuerpo por encima de
  `MAX_BODY_BYTES` (64 MB) no se lee nunca, así que `scoreFirmwareFlow` corre sobre un buffer vacío y `carved`
  queda en 0; el flujo se dibuja en `Capture.tsx:503` idéntico a uno cuyos bytes SÍ se examinaron y no eran
  firmware, y `realizedCeiling` (`capture/preflight.ts:154`) reporta `metadata_only` — un negativo limpio para una
  captura que sí aterrizó.
- [ ] `tools.ts:236-255` **(C)** — el único `catch {}` de `probe()` colapsa «binario ausente» (ENOENT), «la sonda
  salió distinto de cero» y «la sonda excedió `timeoutMs`» en un mismo `available: false`, que `/tools` agrega en
  `groups[…].available/total` y cada proveedor convierte en `blocked_by_platform`: **un timeout se renderiza como
  «este despliegue no puede»**, la trampa que CLAUDE.md ya nombra para las sondas de la JVM y de angr.
- [ ] `agent/session.ts:337` **(C)** — `if (target && gov.check().ok)` salta el nodo ④ entero cuando el gobernador
  está agotado **sin registrar paso alguno** (todos los demás caminos de salto registran uno con su motivo) y sin
  motivo de parada; la corrida llega a `persist(session, 'done', …)` y, si una emulación aislada confirmó algo,
  `readAgentSession` la lee como `proven` — un análisis terminado cuyo nodo de razonamiento nunca corrió.
- [ ] `agent/session.ts:279` **(C)** — `runClosingSynthesis` vuelve en silencio con el gobernador agotado
  (`if (!governor.check().ok) return;`), dejando la sesión en `done` con `haltReason: null` y sin paso `synthesis`,
  mientras el camino de *error* cuatro líneas más abajo sí registra un `skipped` con su motivo.
- [ ] `providers/webprobe.ts:253` + `:262` **(C)+(D)** — 40 puntos de inyección × (6 payloads de comando + 4 de
  traversal) = 400 peticiones contra `maxRequests = 200`, así que con los valores por defecto el `break outer`
  salta **siempre** hacia el punto 20; el negativo dice entonces «No command injection or traversal reproduced over
  200 requests against 40 injection point(s)», reclamando cobertura de 40 puntos de los que la mitad no se tocó.
  Aparte, `[...discovered, ...BUILTIN_POINTS].slice(0, 40)` concatena descubiertos primero, así que una página con
  40+ formularios descarta en silencio todos los endpoints de router integrados.
- [ ] `providers/chipsec.ts:533` **(C)** — `copyBounded(firmwarePath, imgCopy, FIRMWARE_READ_CAP)` trunca la imagen
  a 64 MB antes de que `chipsec_util uefi decode` la vea; si el decode no produce listado, el resultado es
  `blocked('… the image has no parseable UEFI firmware volume … Not a UEFI/BIOS image, or an unsupported layout.')`
  — un veredicto de identidad sobre una copia recortada, sin mencionar el corte. (Sus otros dos caps,
  `MODULE_SAMPLE_CAP` y `VARIABLE_SAMPLE_CAP`, están resueltos de forma ejemplar.)
- [ ] `capture/scan.ts:66` (con `providers/discover.ts:264`) **(A)+(C)** — `tryExec` devuelve a propósito el stdout
  parcial de una herramienta abortada, así que un `arp-scan` matado en `discoverTimeoutMs` da un prefijo del rango
  de direcciones; `runDiscovery` reporta entonces `Swept <subnet> with arp-scan: N device(s)` y el transcript
  escribe `[done] inventory updated with N device(s)`. Un barrido cortado se presenta como la LAN, y lo que
  sobrevive son las direcciones bajas.
- [ ] `providers/rtos.ts:78` / `:160` / `:289` **(C)** — `SCAN_CAP`/`FIRMWARE_READ_CAP` de 16 MB, y el negativo «No
  eCos/flag markers either — static analysis found nothing to assert.» se afirma sobre ese prefijo sin nombrarlo.
  Magnitud baja (un blob bare-metal rara vez pasa de 16 MB), pero la frase es una cota vestida de negativo.
- [ ] `providers/encrypted.ts:232` **(C)** — `READ_CAP` de 1 MB; `plaintextTags` y `verdict.bodyEntropy` se calculan
  sobre ese prefijo, y sin embargo el `reason` imprime «body entropy X bits/byte» y el fundamento del hallazgo
  afirma «The body is a high-entropy plateau» — una afirmación sobre el cuerpo entero desde una muestra de 1 MB.

#### Presentan una cota como total

- [ ] `providers/diff.ts:122` **(B)** — `addedIds: addedIds.slice(0, CVE_CAP)` (500) e igual `removedIds`, sin
  ningún total en `FirmwareDiffResult['cves']`; `apps/web/src/pages/ImageDetail.tsx:1261` dibuja
  `+${result.cves.addedIds.length} added`, así que un diff que introduce 1.400 CVE muestra «+500 added» — y lo
  muestra **junto a** `addedBySeverity`, que `diffCves` cuenta sobre el conjunto sin truncar, de modo que los dos
  badges se contradicen en pantalla. El bloque `files` del mismo resultado lo hace bien (`counts` en `:175`), que
  es lo que convierte esto en un olvido y no en un diseño. Mismo patrón en `packages`, `:100`.
- [ ] `retention.ts:26`, `:95`, `:141` **(B)+(C)** — el `budget = 500_000` de `dirSize` para la caminata a medio
  árbol y devuelve una suma parcial que `storageUsage()` reporta como `totalBytes` sin flag —mientras la caché de
  research medida dos líneas más abajo **sí** devuelve `truncated` más una nota—, y `sweepRetention` compara ese
  suelo contra `FIRMLAB_MAX_DATA_BYTES`, así que un volumen por encima de cuota **infra-evicta en silencio**: el
  camino de éxito del guard otra vez. Hoy `/data/extract` tiene 19.811 entradas para 25 imágenes (~2,8k por imagen
  extraída), luego el presupuesto muerde hacia las ~175 imágenes o con un solo carve recursivo profundo de binwalk.
- [ ] `providers/decompile.ts:120`, `:126`, `:133` **(B)** — `imports`, `symbols` y `strings` son cada uno
  `slice(0, 300)` sin total, mientras `functionCount: rawFuncs.length` en el mismo resultado es exacto: el fichero
  ya conoce la regla y la aplica a uno de cuatro campos. Las longitudes recortadas se imprimen luego como totales
  en el log del job (`:139`) y, de cara al usuario, en el resumen de triaje del informe HTML (`report.ts:184-186`).
  Aguas abajo, `taint.ts:88` deriva sumideros y fuentes de esa lista capada de imports, así que el
  `hasTaintSurface: false` que llega a `opacidad.ts:894` y `agent/zeroday.ts:139` puede ser un artefacto del cap.
- [ ] `providers/webtaint.ts:262` (+ `:372`) **(B)+(C)** — `listHandlers` para en `MAX_FILES = 400` en el orden de
  `HANDLER_DIRS`, y `runWebTaint` además hace `continue` sobre cualquier handler de más de 512 KB sin registrarlo;
  el `reason` dice entonces «Scanned N web handlers, M tainted», donde N es el recuento post-cap y post-salto
  presentado como la superficie web.
- [ ] `providers/kernelposture.ts:1449` / `:1468` **(B)** — `moduleCount: kos.length` se calcula desde
  `walkFiles(..., WALK_FILE_CAP)` (4.000 ficheros, LIFO, sin flag), así que el denominador de la frase de `:1542`
  —«X de Y módulos no se abrieron (cap N, ordenado por ruta)»— está él mismo capado. La mitad `MODULE_SAMPLE_CAP`
  está bien resuelta (`inspectedCount` frente a `moduleCount`); lo silencioso es la caminata de debajo.
- [ ] `providers/extract.ts:453` / `:468` **(B)** — `registerRootfsBinaries` para en `MAX_BINARIES = 2000` con un
  `break` sobre `entries` en orden de árbol y devuelve sólo `count`; nada registra cuántos ELF se saltaron. El
  recuento del panel Binaries (`ImageDetail.tsx:473` y `:524`) y **todo proveedor que llame a `listBinaries`**
  tratan por tanto un prefijo del orden de caminata como el inventario completo.
- [ ] `providers/devicetree.ts:605` **(B)** — `collectFromDir` deja de *recolectar* al llegar a `BLOB_CAP` (8), así
  que un noveno o vigésimo `.dtb` en disco nunca llega a ser candidato y es por tanto invisible para `droppedBlobs`
  (`:725`) — justo el contador cuya nota en `:764` («N device tree(s) más allá del cap de 8 no se analizaron»)
  existe para declarar ese cap. Un directorio con 20 dtb reporta 8 árboles y ninguna nota.
- [ ] `corpus.ts:253` y `:264` **(B)** — `credentialReuse` y `componentPrevalence` son `LIMIT 200` (correctamente
  tras `ORDER BY imageCount DESC`) sin un `COUNT(*)` hermano, y `/corpus/overview` entrega los arrays a la página
  como «el corpus»; con 200 filas la página no puede decir que hay más. Hoy no muerde (0 grupos de reuso, 0 de
  prevalencia), pero el reindexado existe para que deje de ser cero. *(Números de línea previos a `f61945b`.)*
- [ ] `corpus.ts:107` **(C)** — `listReachabilityPriors` capa en 200 ordenando por `createdAt DESC`, y **ambos**
  consumidores (`research/run.ts:347`, `agent/zeroday.ts:173`) filtran por priors *confirmados* **después** del cap,
  así que en cuanto una familia pasa de 200 filas un prior probado se cae por el final y se lee como «no hay prior
  para esta familia». Filtrar o rankear dentro de la consulta.
- [ ] `copilot.ts:97` **(B)** — `operatorAssertions: asserted.slice(0, 40)` mientras `counts` (`:96`) sólo lleva
  `findings` y `binaries`, y el prompt de `:111` le dice al modelo «Counts may exceed the arrays shown; use
  `counts` for totals»: para el único array cuya sobreafirmación justifica todo el corte operador/medido, ese total
  no existe. Añadir `counts.operatorAssertions`.
- [ ] `agent/nodes.ts:218` **(B)+(A)** — `signatures: analysis.signatures.slice(0, 40)` entrega al modelo de triaje
  40 aciertos **en orden de offset** y sin recuento de lo descartado, aunque `analysis.signatureScan.matched` está
  en el mismo bundle (5.004 listadas de 32.372 en la Obsbot de 61,7 MB). El modelo lee el array como el conjunto de
  firmas de la imagen y decide `resolvedClass` / `shouldExtract` con él.
- [ ] `agent/nodes.ts:420` **(B)** — `binaries.slice(0, 60)` está al menos rankeado (`listBinaries` ordena por
  `networkFacing DESC, path ASC`), pero el contexto de selección de objetivos no declara total, así que un modelo
  eligiendo objetivos de emulación sobre un rootfs de 400 ELF lee el array como el inventario.
- [ ] `research/run.ts:118` **(B)+(C)** — `scanRootfsKeys` recorre con `visited < 4000 && out.length < 20` y salta
  todo fichero ≥ 32 KiB, sacando directorios en orden DFS; `:326` registra luego `Keys: ${keyMaterial.length}
  embedded` y ese mismo array pasa a ser `IntelContext.keyMaterial`, que el prompt de inteligencia trata como *el*
  material de clave embebido del borrador de divulgación. En un rootfs de más de 4.000 entradas el recuento es un
  suelo producido por la disposición de directorios, y nada lo dice.
- [ ] `apps/web/src/pages/ImageDetail.tsx:619` **(A)+(B)** — `analysis.entropy.highEntropyRegions.slice(0, 20)`
  dibuja las veinte primeras regiones *por offset* sin total en ningún sitio del panel. La API devuelve la lista
  entera; una imagen con más regiones pierde las posteriores —a menudo las mayores— y el lector no tiene forma de
  saber que la tabla es un prefijo. Ordenar por tamaño antes del corte y añadir el «mostrando N de M» que ya
  llevan las tablas de OSV y del mapa de componentes.
- [ ] `apps/web/src/pages/Corpus.tsx:124` **(B)** — `overview.componentPrevalence.slice(0, 100)` recorta la lista
  que la API ya limitó a 200, sin total y sin nota al pie: las filas 101–200 desaparecen sin nada en pantalla que
  indique el corte.

#### Gastan un presupuesto en un orden sin significado

- [ ] `opacidad.ts:730` / `:759` **(A)** — `selectExportReachTargets(listBinaries(id), 4)` elige 4 objetos y la
  línea de paso de W9 dice `export reachability: 4 selected object(s), 0 reachable sink path(s)` sin denominador y
  sin regla de selección, cuando el pozo real de candidatos son 896 `.so`/`.ko` en `81154df7` (160/135/131/130 en
  los cuatro TP-Link/Tenda) — y ese pozo es a su vez el `MAX_BINARIES = 2000` en orden de caminata de
  `providers/extract.ts:453`. Contar los candidatos filtrados y declarar la regla como ya hace `binvulnRun`.
- [ ] `providers/funcdiff-run.ts:221` **(A)** — `changedPaths.slice(0, maxPairs)` se queda con los 20 binarios
  cambiados **alfabéticamente** primeros, porque `shared` se ordena en `:200`. El truncamiento en sí se reporta
  bien (`notAnalyzed`, más un hallazgo `function-diff-truncated` en `:313`), pero *cuáles* 20 sobreviven lo decide
  el alfabeto, así que en un parche de seguridad `/bin/ash` gana a `/usr/sbin/httpd`.
- [ ] `research/run.ts:321` **(D)+(B)** — el presupuesto de security.txt se gasta en `provenance.domains.slice(0,
  5)`, es decir los cinco primeros en *orden de escaneo de cadenas* de una lista ya capada en 20 por `uniqCap`
  (`providers/provenance.ts:54`); `:326` reporta luego `Disclosure: ${checked}/${securityContacts.length} domains
  checked`, cuyo denominador es la lista ya truncada, y la web (`ImageDetail.tsx:1710`) sólo dibuja esas filas. Un
  operador lee «no security.txt» de un fabricante cuyo dominio real nunca se preguntó.
- [ ] `agent/zeroday.ts:159` **(A)** — `relatedFindings` filtra por binario y luego hace `.slice(0, 12)` sobre el
  orden de recencia de `listFindings`, sin orden por severidad y sin total, así que un hallazgo estático crítico
  del mismo binario registrado por una etapa anterior cae en favor de doce filas `info` más nuevas — en el
  contexto que decide qué sumideros pasan a ser candidatos de zero-day.
- [ ] `agent/zeroday.ts:171` **(A)** — `priors.vulnerableComponents` es `refs.components.filter(cveCount > 0)
  .slice(0, 10)`, y `corpusRefs` (`corpus.ts:294`) lee `component_occurrence` **sin `ORDER BY`**, o sea en orden de
  inserción de SQLite: los diez componentes que se presentan al modelo como los vulnerables de la familia son los
  diez insertados primero, no los de más CVE. Igual `confirmedBefore` en `:175`.

#### Recortan sin decirlo, con menos consecuencia

- [ ] `opacidad-narrative.ts:87` **(A)+(C)** — `buildAttackPath` rankea bien y luego hace `.slice(0, 6)`, pero la
  sección se titula «Attack path (chain of evidence)» y no declara ni cuántas filas cualificaron ni la regla: en
  `81154df7` son **6 de 527** filas no descartadas de severidad media o superior (120 en `398d50ef`, 90 en
  `57c12e70`).
- [ ] `providers/exportreach.ts:192` (que llega al agente por `mcp/server.ts:472` → `jobPayload`, sin glosa)
  **(C)** — `summarise` cuenta sólo `reachable`, `not_reached` y `absent`, así que la frase que lee el agente omite
  en silencio todo sumidero cuyo desenlace fue `budget_exhausted` o `no_call_site`
  (`scripts/angr-cfgreach.py:197,205`). Implica que cada sumidero preguntado obtuvo respuesta; uno con presupuesto
  agotado no obtuvo ninguna, y `buildExportReachFindings` tampoco emite nada por él. Es además la única herramienta
  de alcanzabilidad que **no** pasa por el mapa `meaning` de `reachabilityPayload`.
- [ ] `routes/chipsec.ts:45-46` (y `routes/renode.ts:28,33`) **(C)** — los `seconds` del operador se acotan en
  silencio (5–180 y 3–120) y luego **no se registran en los params del job** (`startJob(id, 'chipsec', {}, …)`), así
  que `/images/:id/runs` —el registro construido precisamente para volver de una línea a la corrida que la
  produjo— no puede decir con qué presupuesto de tiempo salió un veredicto, al contrario que `symreach`, `fuzz` y
  `webprobe`, que sí persisten el suyo.

#### Adyacentes y limítrofes, valorados y no incluidos arriba

- [ ] `providers/extract.ts:360` — `walkRootfs` capa en 100.000 entradas en orden DFS y el resultado alimenta
  `summarizeFs` → `summary.totalFiles`, las listas de setuid/world-writable/notables y el inventario de ELF
  registrados. `Walked N filesystem entries` y `files: summary.totalFiles` se presentan como totales sin flag.
- [ ] `packages/core/src/structure.ts:229` (`looksLikeEcos`) y `mcu.ts:194` (`decodeAscii`) — dos prefijos de 4 MB
  que convierten «el marcador no está en los primeros 4 MB» en un veredicto de clase sin decirlo. El comentario
  argumenta que ninguna imagen que llega ahí alcanza el cap; la aritmética es la misma **(C)** si alguna lo hace.
- [ ] `apps/web/src/components/ReportBuilder.tsx:216` — el informe exportado recorta la tabla de estructura a 24
  segmentos sin total al lado.

#### Auditado y sano — para que el barrido no se repita

Cumplen la regla, verificados en el sitio del cap *y* en su camino de reporte: `binvuln.selectFindings` y
`fsbrowse.ts` (`totalEntries` + `truncated` + `truncationRule`) son las dos referencias · `compmap.selectElfScan`
(rankea antes del cap, `dropped`/`total`/`rule`) · `nvram.ts` · `fsaudit.ts` · `nvd.ts` · `hashlookup.ts`
(`skipped_cap` separa «nunca preguntado» de «preguntado sin acierto») · `fdt.ts` · `auxsecrets.ts` · `fssearch.ts` ·
`egress.ts` · `pem-scan.ts` · `boot-cmdline.ts` · `certs.ts` · `symreach.ts` · `updatepath.ts` · `credmatch.ts` ·
`kmod.ts` (regla explícita «por PUNTUACIÓN y luego RUTA, nunca por orden de caminata») · `yarascan.ts` ·
`fwhunt.ts` + `fwhunt-outcome.ts` · `funcdiff.ts` · `exportreach.ts` (`namedTruncated`) · `extract-diagnose.ts` ·
`extract-neutered.ts` · `report-assertions.ts` · `coverage.ts` · `emulate-system.ts` · los caps de módulo y
variable de `chipsec.ts` · `VAR_CAP`/`MAX_VARIANTS` de `uboot.ts` · los caps de periférico de `devicetree.ts` ·
`esp.ts`. En el store y el libro mayor: `store.ts` (sus dos `LIMIT` son `LIMIT 1` legítimos; `listFindings`,
`listJobs`, `listBinaries`, `listImages`, `listCaptureFlows`, `listSteps` no están capados), `findings.ts`,
`findings-retire.ts` (`retirementNote` es el ejemplo trabajado), `findings-normalize.ts`, `operator-findings.ts`,
`opacidad-leads.ts` y `opacidad-plan.ts` (`capped` *y* `cappedByKind`, más el paso «W9 · Re-plan (cap reached)»),
`opacidad-exportreach.ts`. En las lanes: `agent/governor.ts`, `agent/approval.ts`, `agent/intel.ts`;
`research/cache.ts` (el modelo del género: `scanCacheEntries` devuelve `truncated` y `measureResearchCache` dice
que es un suelo), `research/egress.ts`; los 15 de `capture/` salvo `proxy.ts`/`agent.ts`/`scan.ts`; `mcp/format.ts`
entero salvo `firmlab_export_reachability`. En core: `strings.ts`, `analyze.ts`, `signatures.ts` (los ya
arreglados), `entropy.ts`, `filesystem.ts`, `findings-rank.ts`, `binwalk.ts`. En web: `ComponentMap.tsx`,
`FindingsLedger.tsx` (`selectLedgerRows`), `SimulationMenu.tsx`, `HardwareInterfaces.tsx`,
`DeepAnalysisDetails.tsx`, las tablas de OSV/NVD, gitleaks y SBOM de `ReportBuilder.tsx`.

Caps que existen y no pueden morder, deliberadamente fuera: `servicemap.ts:416`, `fsaudit.ts:586`,
`portmap-run.ts:71`. Fuera de alcance por definición: truncamiento de líneas de log.

**Cobertura del barrido, dicha y no implicada.** Siete ficheros no se leyeron de punta a punta —`emulate-system.ts`
(2.449 líneas), `updatepath.ts` (2.290), `fwhunt.ts` (1.725), `kernelposture.ts` (1.653), `kmod.ts` (1.490),
`yarascan.ts` (1.423), `credmatch.ts` (1.337)—: de cada uno se leyó **todo sitio de cap y su camino de reporte**.
Veinte ficheros pequeños de `providers/` se cribaron por grep de constantes de cap, `.slice(0, N)`, bucles de
caminata acotados y campos `Count`/`Total` asignados desde `.length`, salieron vacíos y no se leyeron línea a
línea: `boot-diagnose`, `boot-reproducibility`, `carve`, `decoy`, `discover`, `extract-recover`, `flowscore`,
`full-system-run`, `guest-console`, `guest-repair`, `isolate`, `kernel-cve`, `kev`, `portmap`, `preflight`,
`rootfs-gate`, `securitytxt`, `trigger`, `fuzz`. De `store.ts`, las líneas 1–500 (esquema y tipos de fila) sólo por
grep. `firmlab_run_worker` devuelve resultados de proveedor en crudo, así que **cualquier cap dentro de esos once
proveedores llega al agente sin glosa**; no se auditó esa superficie como tal.


### Deuda estructural

- [ ] Revisar el reparto entre core y api: `packages/core` son 2.353 líneas frente a 84.223 de `apps/api`, y el dominio puro (`opacidad-plan.ts` 674, `boot-cmdline.ts` 868, `nvd.ts` 547, `opacidad-leads.ts` 511, `findings-normalize.ts` 312…) vive en la capa de aplicación porque no puede importar `store.js`. Son 65 módulos acoplados al store, 24 de ellos fuera de `routes/`. Decidir si core recupera ese dominio o si la regla se documenta como lo que es: un workaround, no una arquitectura.
- [ ] Cubrir con test los 11 componentes web que no lo tienen, empezando por los que no son visuales: `DeepAnalysisDetails.tsx` (569 líneas), `KernelPosture.tsx` (218), `BinVulnPanel.tsx` (200), `PresetsPanel.tsx` (182) y `WebProbePanel.tsx` (123); los visuales dibujados a mano (`SignalCanvas` 280, `SbomGraph` 230, `EntropyChart` 174, `StructureMap` 125, `FilesystemTree` 61) van después.

### Proceso y documentación

- [x] Resuelta la colisión entre `scripts/ui-expose.sh` y el servicio permanente `firmlab-view` del compose. `ui:up` reutiliza el endpoint si `/health` responde, el fallback usa el nombre separado `firmlab-ui-expose` y una etiqueta de propiedad, y `ui:down` sólo retira un contenedor que tenga esa etiqueta y no pertenezca a Compose. Cubierto por pruebas de no mutación, rechazo y retirada segura.
- [ ] Hacer que `scripts/corpus-matrix.mjs` compare contra la tirada anterior y señale las regresiones de celda antes de convertir la matriz en campaña programada. Hoy no tiene noción alguna de run previo: entre la matriz del 23 de agosto y la del 5 de septiembre, `W5 · Reachability (diag_tracertbutton)` pasó de `✓1` a `△` mientras el agregado subía de 110 a 130 `found`, y nada lo dijo. Automatizar la generación sin detectar regresiones sólo automatiza el ruido; un número que sube no distingue cobertura nueva de otra tirada de dados.
- [ ] Dejar de transcribir a mano en `ROADMAP.md` los recuentos que genera la matriz: el documento generado se quedó fijado el 23 de agosto con 376 celdas mientras la prosa ya citaba 390, dos semanas con dos fuentes de verdad para el mismo número. Que el ROADMAP enlace la matriz en vez de copiarla.
- [ ] Decidir el destino de `yara-candidate-report.md`, hoy sin trackear en la raíz del repo: o se archiva fechado bajo `docs/` o entra en `.gitignore`. La promoción del corpus 20260830 es, en sí, una decisión ya evaluada y de bajo riesgo (0 matches nuevos, 0 perdidos, 3 positivos inertes conservados).
