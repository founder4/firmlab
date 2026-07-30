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
- [x] **A3. El extractor neutraliza a `/dev/null` los symlinks que escapan, en silencio.** Cerrado en iter 12
      (`92553de`). La mitad de ficheros de cuentas ya estaba resuelta y la entrada del backlog no lo sabía; el
      hecho se registra ahora donde se descubre, una vez, no en cada lector.
- [x] **A4. La rama de reglas de yara nunca ha visto un yara real.** Cerrado en iter 13 (`12fbd79`). Se instaló
      un yara 4.2.3 real y la rama falló: no era un defecto de formato, era la ruta de recuperación entera
      desactivada. `Dockerfile.tools` gana `yara`; falta un rebuild `--tools` para que el desplegado lo tenga.

### Bloque B — inferencia de red (§4 #1 de `METHODOLOGY-GAPS.md`)

- [x] **B1. Inferencia de red al estilo firmadyne/FirmAE.** Cerrado en iter 14 (`6ad7423` + `c0eb9b2`), con el
      alcance corregido: la inferencia de red YA estaba construida (`inferGuestNetwork`, dos pasadas
      observe→reach). El bloqueo real, que el propio backlog tenía registrado, era la intervención en el arranque
      del invitado — y con ella el WR940N abre dos puertos donde el control abre cero.

### Bloque C — bloque 2 de la auditoría de visibilidad

- [x] **C1. Cinco capacidades con ruta y cero lectores en `apps/web`.** Cerrado en iter 15 (`04af0f4` +
      `98fc9cd`). Y eran DOS estados en el enunciado y son TRES: `unavailable` es su propio hecho.

- [◐] **C2. Trece métodos de API sin llamante.** Iter 16 (`666047a`): cerrado el que el propio punto llamaba el
      más agudo, `amendAssertion` — el ledger ya tenía lector del historial y ningún escritor. Los doce restantes
      NO son doce defectos: los paneles leen el resultado del job que ELLOS lanzaron, así que un resultado que sí
      está en la base de datos desaparece al recargar. Es un patrón de hidratación en ~5 sitios, anotado con esa
      diagnosis en `docs/BACKLOG.md`.

- [x] **C3. Secciones sin enlace.** Cerrado en iter 17 (`8457011`). Y eran DIEZ, no cuatro: `secrets` y
      `testbench` no estaban ni en la cuenta. La pista de la cascara era la otra mitad del defecto.

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
- iter 12 (2026-07-30): cerrado **A3**, lo que el extractor corta. **La hipótesis estaba a medias equivocada y
  comprobarlo primero fue lo que lo destapó:** la mitad de ficheros de cuentas YA estaba resuelta —
  `inspectAccountFile` detecta `symlink-escapes` y `auditAccountSources` emite `account-db-redirected`, verificado
  sobre el DVRF real, que devuelve `{"state":"symlink-escapes","target":"/dev/null"}` para los cuatro ficheros y
  produce el hallazgo. La entrada del backlog llevaba escrito que nada lo hacía. Lo abierto era todo lo demás.
  Medido primero: **126 entradas neutralizadas en seis imágenes**; DVRF con `passwd/shadow/group/hosts/resolv.conf`
  y la IMOU Ranger con 93, **45 de ellas bajo `/sbin`** (`netinit`, `syshelper`, `gethwid`, `armbenv`,
  `sb_util_r/w`) — binarios que la cámara sí trae y que la barrida de ELFs nunca abre, porque un recorrido que
  salta symlinks también los salta sin decir nada.
  **El arreglo no es un parche en cada lector.** `providers/extract-neutered.ts` (puro `classifyExtractedPath` /
  `stageImpact` / `neuteredFindings`, con `scanNeutered` fino, 15 tests) registra el hecho donde se DESCUBRE, una
  vez, en el resultado de extracción y como hallazgo `extract-integrity`; así el silencio posterior de cualquier
  proveedor sobre esas rutas queda ya explicado. El clasificador juzga un symlink por su DESTINO antes de mirar
  ningún tamaño, porque `statSync` sobre `etc/passwd -> /dev/null` devuelve 0 bytes y quien se para ahí ha
  convertido la negativa del extractor en una afirmación sobre el sistema de ficheros del fabricante.
  `stageImpact` dice qué PREGUNTA se quedó sin hacer, no qué ruta se cortó.
  **Lo que se niega a afirmar:** el destino original, que la sustitución descartó. Una entrada cortada prueba que
  el firmware tenía algo ahí y nada sobre qué. Los symlinks que escapan van en un hallazgo aparte precisamente
  porque su destino sobrevivió y sigue siendo legible.
  Verificación: `pnpm test` → core 75 / api **1790** / web 326 verde · `pnpm check` → Done · `pnpm biome` → limpio
  (tras ordenar un import que biome marca como *unsafe fix*) · y sobre bytes reales en el build desplegado
  (`92553de`): DVRF → 446 entradas recorridas, 12 cortadas, «7 en the credential and service-config audit reads
  this directory»; IMOU → 329 recorridas, 31 cortadas, «15 en the ELF sweep and the emulation rungs run binaries
  from here». Y el número que resume todo, de la barrida real sobre la IMOU: **24 ELFs examinados contra 31
  entradas cortadas** — el extractor destruyó más rutas de las que la barrida abrió, y ese número no existía.
  **Puntos flojos nuevos en `docs/BACKLOG.md`, NO implementados:** (a) `scanNeutered` sólo inspecciona el rootfs en
  uso, no los árboles de carve hermanos — la IMOU tiene DOS y las 93 se reparten entre ellos, 31 en el que apunta
  el extract guardado, y `auxsecrets` sí lee particiones hermanas; impacto medio, debería recibir el directorio de
  salida como hace `diagnoseNoRootfs`; (b) todo extract almacenado antes de hoy no trae `neuteredPaths` y nada
  marca cuáles están así — se lee correctamente como «nunca se inspeccionó», pero hace que un recuento del corpus
  dé cero; (c) `fsaudit.readInside` sigue fundiendo ausente/ilegible/escapa en `''` para lo que no es un fichero
  de cuentas, y es la última instancia del patrón.
- iter 13 (2026-07-30): cerrado **A4**, la rama de yara. La decisión era instalar o declarar no validable: instalé
  un **yara 4.2.3-4/arm64 real** en el contenedor y lo conduje contra el rootfs del DVRF con un corpus de 3
  ficheros, uno roto a propósito. Primero lo bueno: **el parser de líneas de match, escrito contra un stub,
  acierta** — 6 líneas reales, 3 grupos, 0 ilegibles, incluida la regla sin tags que yara imprime como `[]`. La
  hipótesis del backlog era falsa ahí.
  El fallo estaba en los diagnósticos del compilador, y era grande. **yara imprime en DOS formas y el módulo
  conocía una**, porque se escribió desde el orden de impresión de `cli/yara.c`:
  `mod.yar(1): error: unknown module "string"` (ámbito de fichero, funcionaba) frente a
  `error: rule "Broken" in bad.yar(1): undefined string "$nope"` y
  `warning: rule "Slow" in w1.yar(1): string "$a" may slow down scanning` (ámbito de regla, descartadas del todo —
  y es la forma COMÚN, la que produce cualquier regla rota o lenta de un corpus real).
  **Y no era un defecto de formato: desactivaba la recuperación.** `compileEachRuleFile` está condicionado a que
  el parser encuentre un error, así que nunca se disparaba. A/B sobre los mismos bytes reales:
  ANTES `state=scan_failed`, `reason="Command failed: yara -e -g -a 60 …"`, declaradas 5 / **aplicadas 5** /
  rechazadas 0, **0 matches y ningún fichero escaneado**; DESPUÉS `state=scanned`, 5 / 4 / 1, 4 grupos de match,
  5 hallazgos, **235 ficheros escaneados**. Un solo fichero malformado en un ruleset público devolvía cero matches
  mientras el denominador afirmaba haber aplicado las cinco reglas — una cota leyéndose como respuesta. Tercera
  instancia de «un guardián sólo vale lo que su camino de éxito, que es el que nadie ejecuta».
  **Predicción del backlog corregida:** decía que Debian carece del módulo `cuckoo`. No es cierto — importan
  cuckoo, magic, hash, dotnet, math, pe, elf, time, console, macho y dex; sólo falla un nombre inventado. Así que
  `missing-module` no tiene disparador en esta plataforma, que es un hecho sobre su cobertura y no razón para
  quitarla. Verificado además que `-a` es `--timeout=SECONDS` (el uso del proveedor es correcto) y que **el orden
  de salida de `--scan-list` no es el de la lista** — yara escanea en hilos, así que nada puede depender de él.
  Los fixtures de los tests son ahora cadenas CAPTURADAS del binario, no redactadas desde el fuente.
  Verificación: `pnpm test` → core 75 / api **1793** / web 326 verde · `pnpm check` → Done · `pnpm biome` → limpio.
  Un fallo propio en el camino: escribí la expectativa del test en un orden distinto al de las líneas de stderr, y
  el parser conserva el orden de yara — el código tenía razón, la aserción no.
  **Puntos flojos nuevos en `docs/BACKLOG.md`, NO implementados:** (a) el desplegado no tendrá yara hasta un
  rebuild `--tools`, así que `/api/tools` seguirá reportándolo ausente y el proveedor seguirá degradando con
  honestidad — correcto, pero hay que decirlo para que no se dé el arreglo por vivo; (b) un warning con ámbito de
  regla ya se parsea y sigue sin cambiar nada, porque `compileEachRuleFile` filtra a `level === 'error'` — una
  regla lenta es riesgo de cobertura bajo `-a`, y la prosa del módulo promete más de lo que hace.
  **Cerrado también el punto (a) en la misma iteración**, ya que era el que dejaba el arreglo sin llegar al
  despliegue: `deploy.sh --tools` reconstruyó la base y `/api/tools` pasa de 24 a **25 de 25 disponibles**, con
  yara 4.2.3. Validación final sobre el build desplegado (`8011ea2`), sin módulos copiados a mano: corpus de 2
  ficheros con uno roto sobre el rootfs real del DVRF → `state: scanned`, 235/235 escaneados, 0 demasiado grandes
  / 0 sobre cota / 0 fallidos, el rechazado nombrado (`broken.yar · undefined-identifier · undefined string
  "$nope"`), y `Telnetd_Binary [network,backdoor]` acertando en `bin/busybox` a `medium` / `static_confirmed`,
  junto a la frase de cobertura «1 rule matched — 1/2 rule(s) applied over 235/235 file(s)».
- iter 14 (2026-07-30): cerrado **B1**, y el alcance de la agenda estaba mal por tercera vez seguida. La
  inferencia de red **ya existía**: `inferGuestNetwork` es puro, exportado, lee consola y cable, y produce tres
  desenlaces; el dos-pasadas observe→reach lleva tiempo funcionando. Lo que el backlog SÍ tenía registrado —y la
  agenda no recogió— es que el bloqueo del peldaño dinámico no es `planForwards` ni la inferencia, sino una
  **intervención en el arranque del invitado**. Y `guest-repair.ts` la tenía compuesta, pura, con 13 tests y
  **cero llamantes**: componía la línea y nadie la escribía.
  Verificadas primero las premisas del diseño sobre bytes reales: los tres routers traen `etc/rc.d/iptables-stop`
  de **284 bytes idénticos**, ninguno lo llama desde `rcS`, los tres tienen applet `ping`, y el WR940N y el MR3220
  **no tienen `sleep`** — por eso el temporizador es un ping.
  **El resultado, con control:** misma imagen del WR940N, ambas pasadas reconstruidas de cero para que el rebuild
  no sea la variable → con reparación `open: [{80},{443}]`, sin ella `open: []`. **Primer servicio alcanzable que
  este peldaño produce en el corpus**, y desbloquea `webprobe`, la enumeración de servicios y cualquier test
  protocol-aware.
  **Y el mecanismo NO está confirmado, y el resultado lo dice:** `ruleset.ran` volvió FALSE — la línea añadida no
  imprimió sus marcadores — así que la imagen llevaba la reparación demostrablemente y su autoinforme falta. El
  efecto está medido, el camino causal por `iptables-stop` no. Es exactamente lo que la cabecera del módulo exigía
  poder reportar, y `interventions` lleva los dos hechos a cada hallazgo de ese arranque.
  La pieza pura que faltaba no era la línea sino la DISPOSICIÓN: `interventions: []` ya significaba «la imagen tal
  como se envía», y eso sólo es cierto si el firmware se examinó. `describeRepairDisposition` añade `attempted` y
  los cuatro desenlaces dan cuatro frases. `rcS` restaurado byte a byte (mismo sha256, 795 bytes) tras los dos
  arranques.
  **Dos defectos propios en el camino, y los dos son trampas que este repo tiene documentadas:**
  (a) **escribí el byte NUL literal** en el regex de applets en vez del escape. `tsc` pasó, el test falló por una
  razón aparente distinta, y **grep dejó de ver el fichero entero**, así que toda la edición parecía no existir;
  `scripts/check-nul.sh` lo nombró con su línea. La medición posterior sobre los tres busybox confirma que el
  delimitador NUL es el predicado correcto: `ping` va NUL-delimitado en los tres y `sleep` sólo en el WDR3600,
  mientras una búsqueda por espacios acierta `ping` en los tres por casualidad y pierde el `sleep` del WDR3600.
  (b) **una imagen en caché se reutilizaba con la disposición equivocada** — tercera instancia esta sesión de «un
  guardián sólo vale lo que su camino de éxito». La reutilización comparaba sólo mtimes, así que el primer arranque
  reparado recibió una imagen construida SIN reparación y devolvió `repair: undefined`: el operador pidió una
  intervención y no la tuvo. `imageReusable` exige ahora que coincida la disposición, en las DOS direcciones — y la
  segunda dirección se ganó el sueldo al instante, porque sin ella el control habría reutilizado la imagen reparada
  y habría invertido el experimento.
  Verificación: `pnpm test` → core 75 / api **1810** / web 326 verde · `pnpm check` → Done · `pnpm biome` → limpio
  (tras cambiar el regex por `includes`, que biome rechaza con razón por carácter de control) · override de
  validación retirado, los dos flags de emulación vuelven a `source: default`.
  **Puntos flojos nuevos en `docs/BACKLOG.md`, NO implementados:** (a) los marcadores de la reparación no reportan
  y nada explica por qué — impacto **alto**, es la diferencia entre un efecto medido y uno entendido, y deja sin
  explicar el POR QUÉ de los dos puertos abiertos; (b) `agent/session.ts:627` pasa el DIRECTORIO del rootfs donde
  `runFullSystem` espera la imagen de disco, así que el peldaño full-system del agente no ha podido arrancar nunca
  — impacto medio.
- iter 15 (2026-07-30): cerrado **C1**. Verificada primero la afirmación, que estaba parcialmente desfasada:
  `funcdiff`, `fwhunt` y `nvram` sí se MENCIONAN en la web (matriz de técnicas, locales), pero mención no es lector
  de resultado — `ghidraResult` tenía cero llamantes fuera de `api.ts`, `nvram` no tenía ni tipo ni método, y
  `yarascan` no aparecía en ninguna parte. La afirmación se sostiene.
  **Y el enunciado decía dos estados: son tres.** `available: false` es su propio hecho — la pregunta SÍ se hizo y
  este despliegue no pudo responderla — y fundirlo con «nadie preguntó» o con «corrió y no había» pierde justo la
  distinción sobre la que está construido el banco. Ése era el defecto escondido dentro del arreglo.
  `capabilities.ts` (puro, 13 tests) decide el estado y saca el denominador de cada proveedor; un denominador
  ausente se imprime como desconocido y nunca como 0, porque un cero inventado es una medición que nadie hizo.
  **Los tres estados validados vivos en una sola pantalla** (`/image/a2c03536/deepscans`, deploy `98fc9cd`, 0 errores
  de consola): `yarascan` → *could not answer*, «no rule corpus is configured: FIRMLAB_YARA_RULES is unset» —con
  yara YA instalado desde la iter 13, que es exactamente el «yara está instalado» ≠ «este despliegue puede
  responder» que su `ToolSpec` afirmaba; `nvram` → *ran*, 0 hallazgos, «0 stores examined · this provider reports no
  denominator», junto a la negativa del propio proveedor a leerse como «este dispositivo no tiene nvram»;
  `dynprobe` → *could not answer* con el timeout del gdbstub literal; `fwhunt`/`ghidra` → *has not run*;
  `funcdiff` → su BASE ausente nombrada como entrada que falta y no como etapa sin correr.
  Añadí `DynProbeResultView` al cliente y, al darme cuenta de que nadie lo leía, añadí `dynprobe` como sexta fila —
  un tipo sin lector habría sido el mismo defecto que esta iteración arregla.
  La sección se llama `deepscans` y no `capabilities` porque la navegación global ya tiene una página *Capabilities*
  (la matriz de herramientas).
  **Un defecto que sólo se vio mirando la página**: las filas eran un grid de spans inline, así que la descripción y
  la frase de estado salían pegadas en una palabra («…corpus you supplyNothing has asked…»). Arreglado en `c2714c3`.
  Verificación: `pnpm test` → core 75 / api 1810 / web **350** verde · `pnpm check` → Done · `pnpm biome` → limpio.
  **Puntos flojos nuevos en `docs/BACKLOG.md`, NO implementados:** (a) `deepscans` pinta el ESTADO y el denominador,
  no la carga de cada proveedor — matches, stores, pseudocódigo y detalle por binario siguen sin superficie, impacto
  medio para yarascan y fwhunt, cuyos matches son el hallazgo; (b) `deepscans` es alcanzable sólo por URL, así que
  suma una quinta a las cuatro secciones sin enlace de C3 y hay que cerrarlas juntas — impacto alto, un panel al que
  nadie puede navegar es un panel sin lector, el mismo defecto un nivel más arriba; (c) **`scripts/ui-drive.mjs`
  trunca el texto visible que reporta, a mitad de frase y sin marcarlo** — la página pintó seis filas y el volcado
  cortó dentro de la tercera, así que buscar `dynprobe` en él no devolvía nada y la fila parecía ausente. Es el
  instrumento de validación del propio loop subestimando lo que vio: una cota leyéndose como respuesta, dentro de la
  herramienta que existe para cazarlas.
- iter 16 (2026-07-30): **C2 a medias, y a propósito.** Medidos de nuevo: siguen siendo 13, y uno es mío
  (`funcdiffResult`, de la iter 15). Cerrado el que el punto llamaba el más agudo, `amendAssertion`: `OperatorPanel`
  pintaba el historial completo de enmiendas —`amendedAt`, `supersedes`, cada revisión sustituida, leído a la
  defensiva— y ninguna UI podía producir una. Un lector para un escritor que nunca se construyó, el inverso exacto
  del defecto de la iteración anterior.
  **La decisión pura es el DIFF, no el formulario.** Una enmienda que no cambia nada no puede registrarse: empujaría
  la original a `supersedes` y la reemplazaría por una idéntica, fabricando historial a partir de un submit, en la
  única superficie cuyo propósito entero es la procedencia. Y los dos «nada» vuelven a diferir: formulario sin tocar
  frente a campo reteclado al mismo valor — valores idénticos, sucesos distintos, frases distintas, ambos rechazados.
  Verificado sobre el despliegue real: afirmación creada y enmendada por la API real, `amendedAt` puesto con 1
  revisión sustituida, la fila dice «Amended 2026-07-30; 1 earlier claim is kept in the record», el formulario abre
  pre-rellenado con lo almacenado y sin editar nada imprime «Nothing was edited… which manufactures a revision out
  of a form submit» con **Save amendment deshabilitado**. La tabla de RETIRADAS no ofrece enmendar.
  **Dos defectos míos:** condicioné el botón a un autor —mal por dos motivos, la ruta deliberadamente no acepta
  autor para que una edición no reasigne la autoría, y exigirlo desactivaba el botón sin que la API lo pida—; y el
  test del reteclado no probaba nada, porque `fireEvent.change` con el valor que ya está en el DOM no dispara
  ningún `onChange` de React y pasaba como «untouched».
  **La diagnosis de los doce restantes queda CORREGIDA, y es UN defecto y no doce:** cada panel lee el resultado del
  job que él lanzó (`SimulationMenu`→`runChipsec`, `WebProbePanel`→`runWebProbe`, `TestBench`→`decompile`), así que
  un resultado de chipsec/renode/webprobe/decompile/kernel que SÍ está en la base de datos desaparece de la pantalla
  al recargar, y el getter que lo traería es el método sin llamante. Es un patrón de hidratación en ~5 sitios.
  Por eso el punto queda a medias y no cerrado: la mitad nombrada está hecha y la otra tiene ahora una diagnosis
  precisa en vez de una lista de trece nombres.
  Verificación: `pnpm test` → core 75 / api 1810 / web **363** verde · `pnpm check` → Done · `pnpm biome` → limpio.
  **Puntos flojos nuevos en `docs/BACKLOG.md`:** (a) **una enmienda no registra autor y una retirada sí** —
  `withdrawnBy` es obligatorio, y una afirmación puede reescribirla alguien que no es su autor quedando atribuida al
  original sin rastro del editor, en la superficie cuyo propósito es la procedencia; impacto medio-alto, y es cambio
  de API; (b) **`--click` del driver pulsaba el elemento equivocado en silencio** — `getByText(x,{exact:false})
  .first()` aterrizaba en la prosa «Amended 2026-07-30» en vez del botón, y pulsar un div no falla, así que la
  captura mostraba un formulario sin abrir. Arreglado (`40205bc`): interactivos primero, exacto antes que subcadena,
  y dice qué pulsó. **Dos falsos negativos del instrumento del propio loop en dos iteraciones es en sí el hallazgo:
  todo lo que este loop afirma haber visto lo ha visto a través de él.**
- iter 17 (2026-07-30): cerrado **C3**, y el enunciado volvía a quedarse corto. Medido: la aplicación tiene
  exactamente TRES sitios que navegan a una sección —el timeline con 8 pasos, un enlace a `operator`, otro a
  `dossier`— contra 20 secciones. **Diez sólo se alcanzaban por URL**, y `secrets` y `testbench` no estaban ni
  contadas. `SectionIndex` en el dossier las enlaza todas.
  **Y la pista de la propia cascara era la otra mitad del defecto:** «Navigate the analysis from the step timeline»
  apuntaba a un control que llega a 8 de 19. Una pista que contesta mal es peor que ninguna — no era sólo que
  faltara el enlace, es que la cascara decía dónde buscarlo y no estaba ahí. Corregida en los dos idiomas.
  **Lo que el índice se niega a hacer**: decidir a qué secciones enruta una CLASE de dispositivo. Ese mapa existe
  una vez en `specsForClass`, y una segunda copia en la web serían dos listas de lo mismo a un commit de
  contradecirse. Así que se listan y enlazan todas, siempre. Lo que sí dicen las filas es por qué una sección puede
  estar vacía al llegar, con los dos hechos que la página ya tiene — y `extraction-not-run` se mantiene aparte de
  `extraction-found-no-rootfs`, porque fundirlos manda al operador a lanzar una extracción que ya corrió. Una
  sección sin rootfs SIGUE enlazada: el defecto era la inalcanzabilidad.
  Validado sobre el despliegue (0 errores de consola): DVRF pinta **19 secciones enlazadas** y `files` en `ready`;
  la Pico RP2040 —extracción corrida, sin rootfs— pinta `files`/`secrets`/`testbench` como
  `extraction-found-no-rootfs` con «That is a measured property of this image, not a stage nobody started», y
  `entropy` sigue en `ready` porque no lee el rootfs.
  **Un defecto mío que sólo se vio mirando:** lo añadí al FINAL del dossier, o sea debajo de un ledger de 110
  hallazgos, a 16.500 px. Un índice al que nadie baja es un índice que no existe — el defecto que el componente
  existe para arreglar, reintroducido por dónde lo puse. Ahora está a 312 px de una página de 8.480.
  Verificación: `pnpm test` → core 75 / api 1810 / web **380** verde · `pnpm check` → Done · `pnpm biome` → limpio
  (tras un `biome:fix` que no corrí antes de commitear, y que dejó la puerta en rojo un commit).
  **Punto flojo nuevo en `docs/BACKLOG.md`:** el timeline sigue cubriendo 8 de 19 y es la navegación principal —
  `deepscans`, `testbench`, `opacidad`, `operator` y `diff` son etapas de trabajo real que no aparecen en la
  secuencia. Si deben estar es una pregunta de diseño (el timeline modela el PIPELINE, no la lista de secciones),
  y por eso hay que decidirla en vez de dejarla como efecto secundario de cuándo se añadió cada sección.
