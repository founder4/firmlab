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

## Siguiente

### Cobertura y análisis

- [ ] Convertir la matriz del corpus en una campaña programada: hoy quedan 0 celdas `not-run`, 85 `degraded` y 33 `no-input` entre 390 etapas aplicables; priorizar las degradadas desbloqueables por clase y coste, y no contar como deuda ejecutable los tres artefactos que requieren reacquisición.
- [ ] Profundizar la correlación de kernel: el prefijo NVD puede tener miles de CVE (2.037 para Linux 2.6.31); usar config/subsistema, diff de parches o VEX de proveedor para descartar candidatos y paginar más allá de las primeras 50 sin presentarlas como el conjunto.
- [ ] Hacer que la reparación del invitado alcance una ruta ejecutada y recuperar red/console interactiva en full-system; la intervención al final de `rcS` sigue siendo inerte.
- [ ] Ampliar RTOS a fuzzing de periféricos/MMIO y enumeración de tareas; Renode demuestra vida, no cobertura del HAL.

### Corpus persistente — construido, cableado y vacío

Medido contra el despliegue vivo del 5 de septiembre de 2026 (25 imágenes): `artifact_occurrence` 2.003 filas de sólo 8 imágenes, `component_occurrence` 356 de 3, `credential_occurrence` 8 de 4, `reachability_prior` 3 de 3, `corpus_rule` ninguna. La página `/corpus` muestra `REUSED CREDENTIALS: 0` y `WATCHLIST RULES: 0`. La ventaja estructural que declara el comentario de módulo de `corpus.ts` no ha producido todavía un solo prior cruzado.

- [ ] Alimentar el corpus desde todas las fuentes de secretos: `auxsecrets` (22 hallazgos en 4 imágenes), `nvram` y `certs` no llaman a `recordCredentials`; sólo lo hacen `secrets` (3 hallazgos) y `gitleaks` (13). El corpus nunca vio el 58 % de los secretos del libro mayor, y ésa es la causa directa del `credentialReuse: 0`.
- [ ] Ampliar el filtro de `flagKnownCredentials` (`corpus.ts:169`, `f.source !== 'secrets'`) a esas mismas fuentes: hoy el Nivel 1 entero —watchlist, elevación a crítico y el «auto-flag it on future uploads» que promete la propia UI— sólo puede alcanzar 3 de los 38 hallazgos de secretos, aunque se promuevan reglas. Son dos defectos apilados: el corpus no graba `auxsecrets` y, aunque lo grabara, tampoco lo elevaría.
- [ ] Añadir `pnpm corpus:reindex`: hoy sólo se registra en el instante del upload (`routes/images.ts:121`) o del SBOM (`routes/sbom.ts:39`), sin ninguna ruta de reconciliación, así que una base de conocimiento persistente acumula el sesgo de *cuándo* se subió cada imagen en vez de qué contiene. Las tablas son `INSERT OR IGNORE` sobre datos inmutables, luego el reindexado es idempotente por construcción.
- [ ] Filtrar `componentPrevalence` con `HAVING imageCount > 1`, como ya hace `credentialReuse` (`corpus.ts:212`, el único `HAVING` del fichero): la tabla titulada «qué versiones abarcan más imágenes» devuelve 200 filas en las que ninguna supera 1, rellenas de módulos de kernel con versión `UNKNOWN` y 0 CVE. Y que su estado vacío diga por qué lo está —3 de 25 imágenes tienen SBOM—, igual que sí hace la sección de credenciales: un resultado vacío debe decir por qué, también aquí.
- [ ] Decidir qué papel juega `vendor` en `deviceFamilyKey`: está sin poblar en 25 de 25 imágenes, de modo que las 13 familias son `unknown:clase:arquitectura` y cuatro routers sin relación comparten los priors de alcanzabilidad del Nivel 2. O se puebla desde la evidencia ya disponible (cadenas del rootfs, banners de servicio, FCC-ID, rutas NVRAM) o se retira de la clave; lo que no puede seguir es una clave que promete vendor y siempre responde `unknown`.
- [ ] Desambiguar el nombre «corpus», que designa tres cosas sin relación entre sí: el corpus persistente entre imágenes (`apps/api/src/corpus.ts`), el corpus de validación de 25 muestras (`ops/corpus/validation-samples.lock.json`) y el corpus de reglas YARA (`ops/yara/corpus.lock.json`).

### Presentación de los resultados

- [ ] Agrupar y priorizar el libro mayor por proof state. Medido sobre DVRF (`57c12e70`): 129 hallazgos en una lista plana de unos 16.000 px, de los que 91 (71 %) son `needs_runtime_reproduction` y sólo 33 `static_confirmed`; 45 filas comparten una única forma de título y `binvuln` aporta 60 de 129. `FindingsLedger.tsx` no agrupa ni colapsa en ninguna de sus 585 líneas, así que una CVE confirmada pesa lo mismo que la fila 47 de «este binario importa strcpy». Contradice el cuidado de `selectFindings` en `binvuln.ts`, que evita truncar por orden de llegada y luego se pinta en plano: un límite no es una respuesta, pero una lista tampoco.
- [ ] Exponer `credmatch` en la web: es el único route sin ninguna referencia en `apps/web/src`, pese a sus 1.337 líneas, un source estable en el libro mayor y ✓ en cuatro muestras de la matriz como «W3 · Credential cross-reference».

### Deuda estructural

- [ ] Extraer de `providers/jobs.ts` un planificador puro (admitir, liberar, encolar) que no importe `store.js`, y dejar que `jobs.ts` lo enlace. Hoy el primitivo de concurrencia no tiene fichero de test y es intesteable por la propia regla del repo — y es justo el componente cuyo comportamiento causó el bug del puerto gdb fijo cuando W9 programó dos sondas concurrentes. El patrón ya está resuelto en `opacidad-plan.ts` y `findings-normalize.ts`; falta aplicarlo donde más duele.
- [ ] Revisar el reparto entre core y api: `packages/core` son 2.353 líneas frente a 84.223 de `apps/api`, y el dominio puro (`opacidad-plan.ts` 674, `boot-cmdline.ts` 868, `nvd.ts` 547, `opacidad-leads.ts` 511, `findings-normalize.ts` 312…) vive en la capa de aplicación porque no puede importar `store.js`. Son 65 módulos acoplados al store, 24 de ellos fuera de `routes/`. Decidir si core recupera ese dominio o si la regla se documenta como lo que es: un workaround, no una arquitectura.
- [ ] Cubrir con test los 11 componentes web que no lo tienen, empezando por los que no son visuales: `DeepAnalysisDetails.tsx` (569 líneas), `KernelPosture.tsx` (218), `BinVulnPanel.tsx` (200), `PresetsPanel.tsx` (182) y `WebProbePanel.tsx` (123); los visuales dibujados a mano (`SignalCanvas` 280, `SbomGraph` 230, `EntropyChart` 174, `StructureMap` 125, `FilesystemTree` 61) van después.

### Proceso y documentación

- [ ] Hacer que `scripts/corpus-matrix.mjs` compare contra la tirada anterior y señale las regresiones de celda antes de convertir la matriz en campaña programada. Hoy no tiene noción alguna de run previo: entre la matriz del 23 de agosto y la del 5 de septiembre, `W5 · Reachability (diag_tracertbutton)` pasó de `✓1` a `△` mientras el agregado subía de 110 a 130 `found`, y nada lo dijo. Automatizar la generación sin detectar regresiones sólo automatiza el ruido; un número que sube no distingue cobertura nueva de otra tirada de dados.
- [ ] Dejar de transcribir a mano en `ROADMAP.md` los recuentos que genera la matriz: el documento generado se quedó fijado el 23 de agosto con 376 celdas mientras la prosa ya citaba 390, dos semanas con dos fuentes de verdad para el mismo número. Que el ROADMAP enlace la matriz en vez de copiarla.
- [ ] Decidir el destino de `yara-candidate-report.md`, hoy sin trackear en la raíz del repo: o se archiva fechado bajo `docs/` o entra en `.gitignore`. La promoción del corpus 20260830 es, en sí, una decisión ya evaluada y de bajo riesgo (0 matches nuevos, 0 perdidos, 3 positivos inertes conservados).
