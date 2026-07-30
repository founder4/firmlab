# Estado del loop

Backlog en uso: `docs/BACKLOG.md` (el del proyecto; no se crea otro en la raíz).

## Cómo se usa este fichero

El loop dispara **el mismo prompt** en cada iteración, así que este fichero es la única memoria entre
iteraciones: la agenda de abajo dice qué toca, y el historial dice qué ya se hizo y qué destapó. Al empezar
una iteración se lee la agenda y se coge **el primer punto sin marcar**; al terminar se marca, se anota en el
historial y se apunta en `docs/BACKLOG.md` cualquier cosa nueva que haya salido.

## Agenda en curso (orden acordado 2026-07-30)

Tres bloques, en este orden y por esta razón: el egreso contradice una promesa que el producto publica; la
inferencia de red desbloquea tres capacidades que hoy no tienen a qué hablarle; el bloque 2 de visibilidad son
cinco proveedores que corren y no se pueden leer.

### Bloque A — los defectos activos (⚠ en `docs/BACKLOG.md`)

- [x] **A1. El invitado emulado tiene internet de salida.** Cerrado en iter 10 (`f969750`). No era implementar
      `restrict=on` —ya existía— sino que el flag era opt-in: el defecto estaba en el valor por omisión. La
      condición que el backlog puso para invertirlo ya estaba contestada en la base de datos y nadie la había
      leído.
- [x] **A2. El cap de listado esconde el binario que el rank existe para promover.** Cerrado en iter 11
      (`a234b9a`). Ninguna de las dos formas de arreglo que proponía el backlog: ambas reparaban los leads y
      dejaban el ledger mal. La exposición pasa a ser clave de orden entre severidad y tamaño.
- [ ] **A3. El extractor neutraliza a `/dev/null` los symlinks que escapan, en silencio**, y cada proveedor
      lee después un fichero vacío y lo reporta como ausencia. Es la regla 3 del proyecto incumplida en el
      extractor.
- [ ] **A4. La rama de reglas de yara nunca ha visto un yara real** — validada contra un stub que hablaba el
      CLI de YARA 4.x. `yara` no está en ninguna receta (es deliberado: el corpus de reglas lo trae el
      operador), así que esto es decidir si se instala o si la rama se declara no validable aquí.

### Bloque B — inferencia de red (§4 #1 de `METHODOLOGY-GAPS.md`)

- [ ] **B1. Inferencia de red al estilo firmadyne/FirmAE.** Los kernels firmadyne ya trazan cada `execve`, así
      que la consola lleva las interfaces y direcciones que el firmware *intenta* configurar: observar lo que
      quiere y re-arrancar con una NIC/VLAN que encaje. Desbloquea `webprobe`, la enumeración de servicios y
      cualquier test protocol-aware, que hoy a menudo no tienen demonio alcanzable. Mientras no exista,
      `confirmed_full_system` significa honestamente «el sistema arrancó».

### Bloque C — bloque 2 de la auditoría de visibilidad

- [ ] **C1. Cinco capacidades con ruta y cero lectores en `apps/web`**: `yarascan`, `funcdiff`, `fwhunt`,
      `nvram`, `ghidra`. Cada una trae su propia historia de cobertura. `DynProbeResult` ni está tipado en el
      cliente, así que `controlOffset` — el punto entero de la sonda — no tiene dónde leerse.
- [ ] **C2. Trece métodos de API sin llamante.** El más agudo es `amendAssertion`: `OperatorPanel` pinta el
      historial de enmiendas y no hay UI capaz de producir una.
- [ ] **C3. Cuatro secciones sin enlace en ninguna parte**: `structure`, `files`, `hardware`, `compmap`. La
      más cara es `files`, «la superficie que permite comprobar la evidencia de un hallazgo en vez de
      confiarla». `overview` es un id muerto que `resolveSection` remapea a `dossier`.
- [ ] **C4. El endurecimiento por binario se recoge y nunca se muestra** (`nx`, `canary`, `pic`, `bits`,
      `sha1`, `importsSummary`) mientras la matriz anuncia `hardening: done`.

### Deuda de documentación, para cerrar en cualquier iteración con hueco

- [ ] **D1. `METHODOLOGY-GAPS.md` §4 item #2 está desfasado.** Describe tres cotas mal asignadas y las
      etiqueta «cheapest value in the ledger»; las tres están arregladas (`e8b23c0`, `22a7961`, y el probe
      rank habilitado el 29-07). Re-derivar el item con lo que sigue abierto.

## Definición de hecho (la de la casa, por iteración)

- [ ] 1. Un punto de la agenda cerrado — no varios a medias.
- [ ] 2. La lógica de decisión, pura y exportada, en un módulo que no importe `store.js`, con tests que
      afirmen que «no se preguntó» ≠ «se preguntó y no había».
- [ ] 3. `pnpm test` · `pnpm check` · `pnpm biome` en verde, con los recuentos anotados.
- [ ] 4. **Validación in-container sobre bytes reales**, no solo la suite: `pnpm ui:shot` o `docker exec` con
      la salida citada. Los 9 iters anteriores encontraron así defectos que ningún test alcanzaba.
- [ ] 5. Lo surgido y no implementado, en `docs/BACKLOG.md`, con su evidencia y su impacto.
- [ ] 6. Commits convencionales, minúscula, **sin trailers de atribución**. Commit local; no se hace `push`.

## Tarea cerrada: Campos que hacen invisible una limitación (bloque 1 de la auditoría de visibilidad)

De `docs/BACKLOG.md` → «Workbench UI — the visibility audit», item ◐. Cuatro cerrados en `1a2fa17`
(`Finding.rationale`, `elfBudgetExhausted`, cobertura de búsqueda, `kev.reason`). **Los seis puntos del DoD
quedaron cerrados en 9 iteraciones** (`121320c`); los dos puntos flojos que siguen abiertos pasan a la agenda
de arriba o se quedan aquí anotados por falta de muestra en el corpus.

- [x] 1. `ResearchResult.hashLookup` se renderiza, y sus **seis** desenlaces son distinguibles entre sí —
      en particular `skipped_salted` (nunca se envió) no puede leerse como `miss` (se consultó y no había).
- [x] 2. `BootDiagnosis.daemonsStarted` / `daemonsExited` se renderizan: «nunca arrancó» ≠ «arrancó y murió con SIGSEGV».
- [x] 3. `SecureBootPosture.note` y `DeviceTreeResult.rejected` se renderizan.
- [x] 4. `OperatorAssertion.withdrawnReason` y `FuzzResult.reason` se renderizan.
- [x] 5. Denominadores de investigación: `osv.skipped`, `nvd.notQueried`, `nvd.truncated[]`, `egress.neverSent`.
- [x] 6. Cada uno lleva un test que afirma que el caso «no se preguntó» se distingue del caso «se preguntó y no había».

## Puntos flojos detectados

- [x] `hashLookup` entero sin lector — impacto: **alto** — evidencia: `grep -rn hashLookup apps/web/src` sólo
      encontraba `api.ts:676` (el tipo) y un fixture de test. Seis desenlaces producidos por
      `providers/hashlookup.ts:272-366` y ninguno llegaba a pantalla.
- [x] `daemonsStarted`/`daemonsExited` sin lector — impacto: medio — evidencia: `SimulationMenu.tsx` pintaba
      `cause`/`summary`/`evidence` y no la lista de demonios; `api.ts:183-184`.
- [x] `SecureBootPosture.note` sin lector — impacto: medio — evidencia: `api.ts:126`; `SimulationMenu.tsx:363-386`
      pintaba `secureBoot`/`setupMode`/`testKey`/`variableCount` y no `note`, que es la frase del proveedor para
      cuando el almacén de variables no era extraíble.
- [x] `DeviceTreeResult.rejected` sin lector — impacto: medio — evidencia: `api.ts:948`.
- [x] `OperatorAssertion.withdrawnReason` — **evidencia original CORREGIDA al auditar**: sí se lee en
      `OperatorPanel`, que pinta `attribution` (`OperatorPanel.tsx:212`), y esa frase la compone la API a la hora
      de leer (`routes/operator.ts:80-81` → `operator-findings.ts:494`, `WITHDRAWN by X: <razón>`). Lo que sigue
      abierto es el LEDGER: `FindingsLedger.tsx:358` pinta sólo `t.findings.withdrawnSuffix` junto al autor y la
      razón no aparece — impacto: bajo. Pendiente para la próxima iteración con este alcance corregido.
- [x] `FuzzResult.reason` sin lector — impacto: bajo (resultó **alto**) — evidencia: `api.ts:231`.
- [~] `BootDiagnosis.cause` se muestra como identificador crudo — **descartado: es la convención de la casa, no
      un descuido.** Este proyecto imprime los códigos verbatim y los glosa en la frase de al lado — es
      literalmente lo que hace `ProofStateBadge` con `proofState` (test: «prints the proof-state CODE verbatim
      and glosses it in Spanish»). Aquí la glosa es `summary`, que va inmediatamente debajo y la compone el
      proveedor midiendo. Traducir el código lo alejaría del valor que viaja en el JSON y en el MCP, y añadir
      una segunda redacción de la misma frase es ruido. Evidencia: `SimulationMenu.tsx:466` + `FindingsLedger.tsx`
      `PROOF_STATE_META`.
- [x] `egress.attempts` contaba como «a dónde quiso ir» las RESPUESTAS a nuestras propias sondas — impacto:
      **alto** — evidencia: captura de `/image/c8e1ffa0/simulate` sobre el contenedor desplegado: ~150 filas
      `10.0.2.2:<puerto efímero> tcp · the emulator itself · 1 frame`. 10.0.2.2 es el host visto desde slirp y
      esos puertos altos son el lado NATeado de los reenvíos que ABRIMOS nosotros, así que el panel presenta como
      intención del firmware el eco de la intervención del banco de pruebas. Además la lista no lleva cota: la
      página mide 8582 px de alto y las dos filas que importan quedan sepultadas.
- [x] La nota de aislamiento se imprime aunque la lista esté vacía — impacto: bajo — evidencia: captura
      `/image/c8e1ffa0/simulate` tras el arranque `f5301511-1d6`: «This boot was isolated, so nothing below was
      reached … this is what the firmware asked for» encima de «The guest addressed nothing beyond the emulator»,
      y el firmware no pidió nada. `SimulationMenu.tsx` la pinta incondicionalmente.
- [ ] El carril UEFI/chipsec no tiene ninguna muestra en el corpus — impacto: medio — evidencia: las 16 imágenes
      de `/api/images` son rtos/embedded-linux/baremetal/esp-soc/encrypted/openwrt; `chipsec_util` está instalado
      (`/api/tools`) pero ninguna imagen llega a decodificar un volumen. Todo lo de `chipsec.ts` está probado
      contra fixtures sintéticas y nunca contra un BIOS real.
- [ ] El mismo árbol leído dos veces no se dice que es el mismo — impacto: bajo — evidencia: en `447719f7` el
      rechazado de `raw image offset 10186216` mide 60082 bytes, exactamente los del blob que sí se lee vía
      `FIT /images/ubi → UBI volume kernel /images/fdt-1`. Son la misma vista cruda y reensamblada del mismo
      árbol y el panel las presenta como dos cosas sin relación.
- [x] Denominadores OSV/NVD sin lector — impacto: medio — evidencia: `api.ts:639-647`, `:671`.
      `nvd.truncated[]` no necesita lector propio: la insignia por fila `totalMatching` («8 of 35 shown»)
      ya lo dice, y duplicarlo sería una segunda redacción del mismo hecho.

## Historial

- iter 1: renderizado `hashLookup` completo en el panel de investigación (`ImageDetail.tsx:1523` + componente en
  `:1581`), seis desenlaces con etiqueta y significado propios, `skipped_salted` separado de `miss`, y el carril
  apagado dicho como «la pregunta no llegó a hacerse» en vez de una lista vacía. 3 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1731 / web 297, todo verde ·
  `pnpm check` → Done · `pnpm biome` → 413 ficheros, sin errores.
  Punto flojo nuevo detectado, NO implementado (fuera de alcance de esta iteración): `egress.destinations` y
  `egress.neverSent` siguen sin lector aunque `neverSent` es literalmente «estos destinos no se contactaron» —
  ya estaba en la lista del DoD #5, se confirma su ubicación en `api.ts:636`.
- iter 2: lista de demonios renderizada (`SimulationMenu.tsx:501` `DaemonList`), y dos defectos encontrados al
  auditarla: (a) `diagnoseUnreachable` elegía `exited[0]` — truncado por orden de llegada, justo lo que prohíbe la
  regla 4 del proyecto — ahora `rankExits` antepone la muerte por señal, dice cuántos otros salieron y los lista;
  (b) el panel guardaba el resultado del ledger sólo si traía `egress`, así que descartaba el diagnóstico
  precisamente en los arranques que no contactaron nada — que son la mayoría del corpus. 7 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1735 / web 300, todo verde · `pnpm check` → Done ·
  `pnpm biome` → 431 ficheros sin NUL, 413 comprobados, sin errores.
  Punto flojo nuevo detectado, NO implementado (fuera de alcance): el `cause` se pinta como código crudo
  (`badge` con `no-service-started`) sin frase traducida; `unreachableTitle` es sólo cabecera. Anotado abajo.
  Verificado además contra el despliegue real: `/image/c8e1ffa0/simulate` en `firmlab` (build 6324c3e) pinta
  «NETWORK DAEMONS ON THIS BOOT · httpd · SIGSEGV (exit 139) · last open: /proc/simple_config/system_mode»,
  0 errores de consola y 0 peticiones fallidas. Esa captura destapó el punto flojo nuevo de arriba.
- iter 3: cerrado el punto de `egress.attempts`. La dirección de un flujo TCP se decide ahora por banderas
  (SYN sin ACK = lo abrió el invitado; SYN+ACK = lo aceptó; cualquier cosa en un flujo que no abrió = respuesta),
  por FLUJO y no por destino; UDP no reclama dirección; una trama con banderas cortadas se queda en la lista y se
  cuenta aparte. Las tres cotas que truncaban en silencio (200 destinos, 100 nombres, y una nueva de 40 filas en
  pantalla) dicen qué dejaron fuera y por qué regla. Además las fixtures TCP llevaban cabecera de 8 bytes: al
  empezar a leer banderas TODAS caían en la rama «demasiado corta para decidir» y la suite habría seguido verde
  sin probar nada — ahora llevan cabecera real de 20.
  Verificación: `pnpm test` → core 75 / api 1747 / web 303 verde · `pnpm check` → Done · `pnpm biome` → limpio ·
  y contra bytes reales, que es lo que lo destapó: arranque full-system nuevo del MR3220 en el contenedor
  desplegado (`cef8b8c`, job `f5301511-1d6`) → `attempts 0 · answered 116 · undecided 0 · dropped 0 ·
  guestFrames 116`. Las 116 tramas que el invitado puso en el cable eran las 116 respuestas a nuestras 116 SYN.
  La página pasó de 8582 px a 3384 px y ahora dice «116 frames were this guest ANSWERING connections opened from
  outside it». `undecided 0` confirma que con `maxlen=256` las banderas siempre se capturan.
- iter 4: cerrado `SecureBootPosture.note`. Auditando salió el defecto de debajo, que es el que le daba sentido:
  `readNvramPosture` devolvía `null` en dos situaciones opuestas (chipsec no sacó ningún listado NVRAM / sacó
  listados que no parsearon ni una variable) y el panel pintaba ambas como la misma ausencia — que se lee como
  «esta imagen no tiene almacén de variables», la única conclusión que ninguna de las dos sostiene. Nuevo
  `describeNvramStore` (puro) las separa y viaja como `nvramStoreNote` (opcional para siempre). El `note` propio
  ahora va al lado de la insignia en vez de enterrado en `reason`, dice de cuántas variables se leyó, y declara la
  cota de 40 nombres que truncaba en silencio. 8 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1752 / web 306 verde · `pnpm check` → Done · `pnpm biome` → limpio ·
  contra el build desplegado (`2ce3aa2`): `docker exec firmlab node -e 'import(...dist/providers/chipsec.js)'`
  devuelve las tres frases distintas y `""` cuando sí hubo postura; y `POST /images/c8e1ffa0/chipsec` real →
  `status done`, rama bloqueada temprana intacta y `nvramStoreNote: undefined` (correcto: el decode no llegó al
  almacén, y la razón ya dice por qué).
  **Limitación de la verificación, dicha explícitamente:** no hay ninguna imagen UEFI en el corpus (las 16 son
  rtos/embedded-linux/baremetal/esp-soc/encrypted/openwrt), así que la rama que compone `nvramStoreNote` desde un
  decode UEFI real no se ha ejecutado nunca sobre bytes reales — sólo sobre el build desplegado con entradas
  sintéticas. Anotado abajo como punto flojo del corpus, no del código.
- iter 5: cerrado `DeviceTreeResult.rejected`. Era la forma más nítida del defecto: la frase del proveedor termina
  en «(see rejected)», apuntando a un campo que nadie pintaba — y en `447719f7`, la única imagen del corpus que
  los produce, `found` es TRUE, así que ni esa frase salía en pantalla (el banner que la lleva sólo se dibuja
  cuando no se encontró nada). Nuevo bloque `RejectedHeaders` FUERA de ese banner, con la frase de que una
  cabecera que no se pudo recorrer es un límite del lector y no un hallazgo de que ahí no haya árbol, y con cota
  de 6 filas que dice lo que corta (el proveedor no acota nada). 3 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1752 / web 309 verde · `pnpm check` → Done ·
  `pnpm biome` → limpio (tras `biome:fix`, un formato en el locale es) ·
  y sobre bytes reales: `pnpm ui:shot /image/447719f7/hardware` contra el build desplegado (`e0ff8a2`) →
  «2 FDT HEADERS VALIDATED BUT WOULD NOT READ» con las dos entradas, sus tamaños y las razones completas del
  proveedor; 0 errores de consola, 0 peticiones fallidas.
- iter 6: cerrado `FuzzResult.reason`, que era el de mayor impacto de los dos del DoD #4 y no el de menor:
  `unavailable()` rellena el MISMO `FuzzResult` que una campaña completa, con `crashes: 0`, y el panel pintaba ese
  cero en color OK con `reason` en ninguna parte — una ejecución que no pudo ocurrir se leía exactamente igual que
  una limpia. Sus dos motivos tampoco son intercambiables: «AFL++ not installed» es del despliegue y «binary not
  found in rootfs» es una ruta mal escrita, y en ese segundo caso la insignia de arriba sigue diciendo `runnable`.
  Ahora se suprimen las estadísticas (su `harness: 'file'` / `isolation: 'none'` son valores por defecto, no
  decisiones de nadie) y se imprime el binario, el motivo del proveedor y la frase «no hay recuento de fallos —
  no es un recuento de cero». 3 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1752 / web 312 verde · `pnpm check` → Done · `pnpm biome` → limpio ·
  bytes reales sobre el build desplegado (`4449391`): `POST /images/c8e1ffa0/fuzz {"binary":"bin/does-not-exist"}`
  → `{available:false, reason:"binary not found in rootfs", crashes:0}` y la captura de `/simulate` muestra el
  aviso con esa frase exacta, con la insignia `runnable` al lado — el caso que hacía peligroso el render anterior.
  0 errores de consola, 0 peticiones fallidas.
- iter 7: cerrado `withdrawnReason` con el alcance corregido de la iteración anterior. El ledger pintaba
  «— WITHDRAWN» junto al autor y dejaba tras el chevron la razón ORIGINAL de la afirmación: la única prosa
  alcanzable en una fila retirada era el argumento A FAVOR de una afirmación que ya no se sostiene. Ahora el
  motivo va en la fila, no tras un clic (para leer que algo se retiró no hay que descubrir que hay algo que
  desplegar), con el autor de la retirada nombrado, y la celda desplegada se reetiqueta «for the claim that was
  retracted». Una retirada sin motivo registrado lo dice en vez de parecer que no hubo retirada. 5 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1752 / web 317 verde · `pnpm check` → Done ·
  `pnpm biome` → limpio (tras `biome:fix`) · y sobre el despliegue real (`89ec6cc`): afirmación creada y
  retirada por la API real en `c8e1ffa0`, y la fila leída de la página con playwright:
  `▸ ● The telnet daemon is compiled out of this build | asserted by aaron — WITHDRAWN | withdrawn by aaron: I
  was reading the wrong build — the retail image does ship it. | operator:aaron | asserted · not measured |
  operator_report`, y al desplegarla: `WHY THIS STATE — FOR THE CLAIM THAT WAS RETRACTED`.
  **Residuo retirado**: esa afirmación iba atribuida a `aaron` y él nunca la hizo, así que se borró de
  `findings` en el contenedor (no hay ruta DELETE — el ledger no borra retiradas — se hizo por SQLite).
  Corpus de vuelta a 81 hallazgos, 0 afirmaciones.
- iter 8: cerrado el DoD #5. `osv.skipped` y `nvd.notQueried` se pintan bajo las insignias que matizan — «0 avisos»
  junto a «3 consultados» se leía como «no hay» cuando significaba «ninguno entre los tres que preguntamos». Y el
  registro de egreso de `research/egress.ts`, que es la razón por la que se puede encender la única bandera del
  producto que toca internet, no lo pintaba nadie: una promesa de privacidad que no se puede leer no es una
  promesa. Un destino con cuenta 0 dice «nada sobre tu firmware» y no «como mucho 0» — es una dirección, no una
  cota. Además dos cotas mudas: las dos tablas cortaban a 12 filas sin decirlo, y la celda de avisos de OSV
  cortaba a 8 mientras la de NVD a su lado lleva desde siempre «N of M shown». 5 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1752 / web 322 verde · `pnpm check` → Done · `pnpm biome` → limpio ·
  y sobre datos reales del despliegue (`47462de`), leído de la página con playwright en `447719f7`:
  «46 SBOM components could not be mapped to an OSV ecosystem and were never asked about», «66 candidates went
  unasked at NVD», `api.osv.dev · at most 500`, `services.nvd.nist.gov · at most 72`,
  `www.cisa.gov · nothing about your firmware`, y las 6 líneas de «Never sent, on any run». 0 errores de consola.
  La línea «Showing N of M components» no aparece en esa imagen porque tiene 7 y 5 componentes, por debajo de la
  cota — la rama se comporta bien, no es un fallo; su caso está cubierto por test.
- iter 9: cerrada la nota de aislamiento. Las dos frases de política están escritas sobre una lista («nothing
  below was reached», «could reach these from this machine») y se imprimían siempre, así que un arranque que no
  se dirigió a nada pintaba una promesa de destinos encima de un hueco, y la aislada afirmaba «esto es lo que el
  firmware pidió» de un firmware que no pidió nada. Que es justo el caso del MR3220 y estaba en pantalla ahora
  mismo. Las variantes vacías dicen lo que sí vale la pena: con bloqueo, que no tuvo nada que detener y que son
  dos hechos independientes; sin bloqueo, que la puerta estaba abierta y el invitado no la cruzó — medición de
  ESE arranque, no propiedad del firmware. Conmuta por el recuento EXTERNO, no por la lista entera. 4 tests.
  Descartado en la misma auditoría: `BootDiagnosis.cause` crudo (razón escrita arriba).
  Verificación: `pnpm test` → core 75 / api 1752 / web 326 verde · `pnpm check` → Done · `pnpm biome` → limpio
  (tras `biome:fix`) · y sobre el despliegue real (`098779a`), leyendo `/image/c8e1ffa0/simulate` con playwright:
  PRESENTE «the block had nothing to stop», AUSENTES «nothing below was reached» y «this is what the firmware
  asked for». 0 errores de consola.
- iter 10 (2026-07-30): cerrado **A1**, el egreso del invitado emulado. La hipótesis de la agenda era falsa en su
  premisa: `restrict=on` ya estaba implementado y cableado desde antes, así que no había nada que construir — el
  defecto era que `FIRMLAB_EMU_ISOLATE` es opt-in, de modo que «con todas las banderas apagadas: sin red, sin
  coste, comportamiento determinista» era **falso por omisión**. Y la condición que el propio backlog había puesto
  para invertirlo («whether any rung DEPENDS on outbound») **ya estaba medida en la base de datos y nadie la había
  leído**: dos arranques full-system de la misma imagen WDR3600 a 16 minutos, uno abierto y otro aislado,
  registraron los MISMOS 15 destinos externos y el MISMO `confirmed_full_system`; y de todos los arranques
  guardados, sólo esa imagen ha direccionado jamás algo externo. Reproducido dos veces más hoy hasta cuatro
  arranques, todos `ext=15` / `confirmed_full_system`. Aislar no cuesta ni un destino ni un veredicto, y confirma
  sobre bytes reales lo que `egress.ts` sólo afirmaba: bloquear no esconde el intento, porque `filter-dump`
  captura la trama antes de que slirp decida su suerte.
  El default pasa a ser propiedad declarada del catálogo (`defaultOn`) y no un accidente de `=== '1'`.
  **Tres defectos que el cambio destapó, los tres arreglados:** (a) `resolveFlags` leía `=== '1'` directamente, lo
  que habría deshecho el default en silencio y pintado el interruptor APAGADO en Settings mientras el emulador sí
  aislaba; (b) `enabled` funde «nadie lo pidió» con «el operador lo pidió» en cuanto un flag puede venir
  encendido, y la dirección peligrosa es la otra — un invitado abierto sólo puede ocurrir porque alguien lo abrió,
  así que `decideFlag` los separa y `describeEgressPolicy` compone tres frases donde había dos; (c) **la suite
  fijaba el default viejo con una aserción que pasaba** (`expect(f.enabled).toBe(false)`, comentada como «which is
  the permissive direction»), fixture y código escritos desde la misma suposición — la trampa que este repo ya
  tiene pagada.
  **Descartado con su razón:** renombrar a un `FIRMLAB_EMU_EGRESS` opt-in, que habría dejado la tabla sin
  excepciones. Hay un override guardado de `FIRMLAB_EMU_ISOLATE=1` en el despliegue real, y renombrar habría
  cambiado en silencio lo que esa fila significa. Es la trampa del «campo persistido escrito por una build más
  vieja», aplicada a los ajustes.
  Verificación: `pnpm test` → core 75 / api 1763 / web 326 verde · `pnpm check` → Done · `pnpm biome` → limpio
  (tras arreglar a mano un template literal que biome marca como *unsafe fix* y no toca solo) ·
  y sobre el despliegue real (`f969750`): el camino del éxito, que es el que nadie ejecuta — override borrado,
  `decideFlag({})` → `{enabled:true, stated:false, byDefault:true}`, `source=default`, ningún otro carril
  encendido; arranque real `c0df50a3-e89` con la orden `-netdev user,id=n0,restrict=on,hostfwd=tcp::43593-:80,
  hostfwd=tcp::43594-:443` — el `restrict=on` de serie **y los dos forwards intactos a su lado**, que es la
  propiedad de qemu comprobada sobre la orden real y no leída en su documentación; y las tres frases de política
  leídas del build desplegado, distintas entre sí las tres. La rama ABIERTA se validó llamando al módulo, no
  arrancando: arrancarla habría abierto de verdad la red del WDR3600, que es lo que esta iteración cierra.
  **Puntos flojos nuevos, anotados en `docs/BACKLOG.md` y NO implementados:** `environmentValue` responde ahora a
  otra pregunta y su único lector no se actualizó (impacto bajo); y las tres frases de política llegan al LOG y
  no al panel, que sigue conmutando por el booleano `isolated` a secas (impacto medio).
- iter 11 (2026-07-30): cerrado **A2**, la cota que escondía el demonio. **Reproducido primero sobre el rootfs real
  del WDR3600 en el build desplegado, antes de tocar nada:** 124 ELFs → 58 candidatos → 45 listados, y
  `usr/bin/httpd` NO estaba; a la cabeza `lib/libutil-0.9.30.so` (3964 B), `lib/libmsglog.so` (4644 B) y
  `sbin/pktlogconf` (7548 B). Es decir, la cota gastaba el ledger exactamente en los stubs de uClibc que el propio
  backlog denuncia, y borraba de la lista al demonio que el rank de sondas existe para promover — porque ese rank
  lee `findings`, la lista POST-cota.
  **No tomé ninguna de las dos formas de arreglo que el backlog proponía** (devolver los candidatos descartados, o
  que el rank lea `candidates`): las dos reparan los leads y dejan el ledger mal, y la segunda produce leads que
  nombran binarios ausentes del ledger — el efecto secundario que la propia entrada señalaba. Si un binario merece
  una sonda, merece una fila. Así que la exposición es ahora **clave de orden**, entre severidad y tamaño, y entra
  como `ReadonlySet<string>` opcional para que `selectFindings` siga siendo pura (la misma forma que el corpus
  opcional del ranking de módulos UEFI). Después: `usr/bin/httpd` en **posición 0**, 1.717.140 B, con
  `strcpy/strcat/sprintf/vsprintf/sscanf`.
  La exposición NO gana a la severidad: un `critical` en un binario no referenciado sigue siendo peor que un
  `medium` en un demonio, e invertirlo dejaría que un socket blanquease un hallazgo débil hasta la cabeza.
  **`undefined` ≠ `new Set()`**, que es la parte que sostiene todo: sin señal significa que W3/W4 no corrieron, y
  señal vacía que corrieron y no nombraron nada — real, porque `runServiceMap` devuelve cero servicios en DVRF.
  Ordenan igual y son hechos opuestos, así que la `reason` los separa en prosa. La exposición se calcula ahora
  ANTES de la barrida; se construía sólo para el rank de sondas, y por eso la cota nunca la tuvo.
  **Comprobado que el arreglo no queda inerte**, que era el riesgo real: el `runServiceMap` real sobre el WDR3600
  da `httpd | /usr/bin/httpd | autostart: true`, `interestingBinaries` lo convierte en
  `{usr/bin/httpd → "it is an autostart network daemon (httpd)"}`, y en **todas** las clases que barren binarios el
  plan pone `servicemap`@6 y `webtaint`@14 delante de `binvuln`@15. Además `runBinVuln` tiene un único llamante, el
  de W9, así que no hay ruta manual que se salte la señal.
  **Un defecto que los tests destaparon:** la exposición es un ESCALÓN, no un override. Entre dos demonios
  expuestos el tamaño sigue desempatando, así que con cota 1 se queda dropbear (900 KB) y cae httpd (1,7 MB). Mi
  primera aserción decía lo contrario, escrita leyendo la exposición como orden total — el código tenía razón.
  Un expuesto puede seguir sin caber, así que los que caen se NOMBRAN en `exposedDropped` en vez de contarse;
  opcional para siempre, porque `[]` sería una afirmación sobre un ranking que nunca tuvo señal.
  Verificación: `pnpm test` → core 75 / api 1773 / web 326 verde · `pnpm check` → Done · `pnpm biome` → limpio ·
  y las tres ramas de exposición leídas del build desplegado (`a234b9a`) sobre el rootfs real: sin señal
  («No exposure signal reached this sweep … silence about what is exposed, not a finding that nothing is»),
  vacía («The exposure signal DID reach this sweep and named no binary … having asked»), y nombrando
  («1 binary(ies) were flagged as exposed and ranked ahead of smaller candidates»).
  **Puntos flojos nuevos en `docs/BACKLOG.md`, NO implementados:** (a) los stubs de uClibc no toman «algunas
  sondas» sino el LEDGER — posiciones 1–2 de los 45 listados del WDR3600; la clave de exposición repara la cabeza
  de la lista y no hace nada con la cola, impacto medio, es ya la mayor distorsión que queda en la barrida;
  (b) la señal de exposición se apoya en `network && autostart` sin ninguna evidencia de puerto detrás — el
  WDR3600 da `ports: []` para su httpd — defendible para ORDENAR, más discutible en `daemonLeads`, cuyos hallazgos
  sí se leen como afirmaciones sobre un servicio expuesto.
