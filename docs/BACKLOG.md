# FirmLab — backlog

Única lista de trabajo pendiente del proyecto — sustituye a los tres sitios donde antes vivía dispersa
(`BACKLOG.md`, la sección "remaining backlog" de `ROADMAP.md`, y el §4 de `METHODOLOGY-GAPS.md`). Lo ya cerrado
no vive aquí: vive en `git log -- docs/BACKLOG.md`, que conserva la evidencia medida de cada arreglo si hace
falta consultarla. Este fichero es de nuevo corto porque ese es el punto: un backlog que hay que desplazar para
leerlo deja de usarse como backlog.

`ROADMAP.md` es el historial de qué se envió y cuándo; `METHODOLOGY-GAPS.md` mapea la cobertura contra OWASP
FSTM/ISTG. Ninguno de los dos duplica esta lista.

## Cobertura y análisis (opacidad / W9)

- [ ] Distinguir un kernel monolítico (sin `lib/modules`) de un tallado que se dejó `lib/modules` (`kmod.ts`):
  decidible con `CONFIG_MODULES` del `.config` embebido, una tabla `kallsyms` con símbolos de módulo, o rastro
  en `carveTrace`. Hoy la celda queda explícitamente indeclarada.
- [ ] Estructurar `extract-diagnose` para el caso sin rootfs: distingue en PROSA volúmenes-sin-rootfs / filesystem
  tallado que no abre / nada salió, pero `remedyForNoRootfs` solo declara remedio para el primero. Falta subir
  `SquashfsDiagnosis.short`/`idTableInZeroFill` a `NoRootfsDiagnosis.blobs` (opcionales para siempre).
- [ ] Reportar el `READ_CAP` de 512 MB del barrido en crudo de `devicetree.ts`: una imagen mayor se lee
  parcialmente sin decirlo. Latente — ninguna muestra del corpus actual lo alcanza.
- [ ] Mostrar el `remedy` de cada etapa degradada en la web (hoy solo lo lee `scripts/corpus-campaign.mjs`); el
  panel de cobertura dice "degradada" sin decir si se arregla con una corrida, una herramienta u otra muestra.
  Necesita i18n ES/EN para las ocho disposiciones.

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
- [ ] uClibc distorsiona el sweep de reachability: `lib/libutil-0.9.30.so` y `lib/libmsglog.so` abren los 45
  candidatos del WDR3600 porque `runnable` deja pasar un `.so` con entry point. El predicado real es si el
  entry point es un PROGRAMA, no solo si tiene uno.

## moria/mithril (nmatt0) — evaluado contra el corpus real, no adoptado

- [ ] Evaluar moria (C++20 MIT) como extractor junto a binwalk+sasquatch+jefferson+ubireader: añade formatos que
  hoy faltan (btrfs, XFS, NTFS, HFS+, EROFS, exFAT, F2FS) y no requiere sudo. Complementa, no sustituye — sobre
  el SquashFS LZMA no estándar del TP-Link WR940N diagnostica mal la causa ("vendor obfuscation" cuando es LZMA
  parcheado). Reconciliar su diagnóstico con `extract-diagnose.ts` antes de adoptar.
- [ ] Llevar el rúbrico de confianza de 4 niveles de moria (magic 25 / structural 60 / consistent 85 / verified
  99, con camino de RECHAZO estructural) y sus `soft_constraints` a `signatures.ts`: hoy nuestras reglas son
  magic + decode sin rechazo (sobre el mismo fichero, 203 hits de core frente a 4 de moria, casi todo ruido).
  Añade también ~130 magics de contenedor de vendor (TP-Link, D-Link, Netgear CHK, Xiaomi, Ubiquiti, Realtek,
  Sercomm, MediaTek) reautorados clean-room.
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

- [ ] Desambiguar el nombre "corpus" en CLI/UI (tres cosas sin relación: `apps/api/src/corpus.ts`,
  `ops/corpus/validation-samples.lock.json`, `ops/yara/corpus.lock.json`) — ya documentado en
  `ARCHITECTURE.md` § "The three corpora", falta homogeneizar el naming visible.
- [ ] Puntuar vectores CVSS v4.0 en `osv.ts` (`cvssV3BaseScore` solo hace v3.0/v3.1; v4.0 necesita la tabla
  MacroVector). 4 de 121 avisos del corpus cacheado quedan sin graduar — se conservan sin recortar, pero no se
  ordenan bien.
- [ ] Re-ejecutar SBOM en las imágenes ya desplegadas: los resultados guardados son anteriores a
  `totalMatching`/`cveIds`/`upstream`, así que sus tablas siguen mostrando el denominador de la lista vieja y el
  cruce contra KEV sigue vacío.
- [ ] Añadir un test de propiedad o regla de lint que detecte `.slice(N)` sobre la misma expresión de la que
  luego se deriva un recuento — el patrón que ya pagaron `extractStrings`, `scanSignatures` y `sbom.ts`.
- [ ] Exponer `credmatch` en la web: único route sin ninguna referencia en `apps/web/src` pese a 1.337 líneas y
  ✓ en cuatro muestras de la matriz.

## Deuda de política (decisiones a escribir, no bugs)

- [ ] Dos estándares de CVE conviven sin decisión escrita: grype (vía manifiesto syft) acepta CVE-2016-2148 para
  busybox 1.18.4; la tabla curada de `component-cve.ts` la rechaza porque NVD la respalda con un rango abierto
  sin CPE enumerado. Cada fila nombra su fuente, pero qué estándar aplica es hoy un accidente de qué proveedor
  corrió.
- [ ] Una enmienda a una afirmación de operador no registra autor, mientras que una retirada sí — se puede
  reescribir la afirmación de otra persona y el libro mayor atribuye la redacción nueva al autor original. En la
  única superficie cuyo propósito es la procedencia.

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
- [ ] Cubrir con test los componentes web sin cobertura: `DeepAnalysisDetails.tsx` (569 líneas),
  `KernelPosture.tsx` (218), `BinVulnPanel.tsx` (200), `PresetsPanel.tsx` (182); después los visuales dibujados
  a mano (`SignalCanvas`, `SbomGraph`, `EntropyChart`, `StructureMap`, `FilesystemTree`).
