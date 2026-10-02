# Campaña transversal de cuatro horas — 2026-10-02

Mandato: avanzar en el proyecto y probar continuidad, priorizando el trabajo de FirmLab. Ventana fija
11:07:39–15:07:39 UTC (13:07:39–17:07:39 Madrid); no se extiende para ocultar interrupciones.
Run `run_fa2f177609e4`. Contexto y estado operativo fuera del repo en
`~/.local/state/orca-campaign/campaigns/firmlab-2026-10-02-four-hours/`.

## Evidencia hasta la recuperación

El primer traspaso a Claude fue probado a las 11:12:36 UTC (generación 1→2). Ejecutó varias olas con Codex,
Claude y Antigravity: regresión de cancelación HTTP, detector de familias de switch con carriles y panel,
resolución de símbolos ELF y prefill RTOS, veredictos VEX sin alterar proof states y Renode con entorno
que rechaza sus descargas implícitas. Las limitaciones y evidencia real están en el backlog.

Claude y la reserva Claude alcanzaron la misma cuota. El envío al sucesor fue aceptado, pero **no adoptó**
el Run. Desde aproximadamente 11:53 UTC hasta la recuperación manual a las 12:07:26 UTC no hubo
coordinación comprobada. El supervisor seguía vivo, pero no reconocía el compositor bloqueado por cuota;
`unknown` y `gaps: []` no prueban continuidad. Root recuperó el mismo Run, generación 3, conservando el
plazo. La tarea de captura RAM nunca comenzó con Claude: la transcripción muestra cuota antes de editar;
se cerró el Dispatch detenido y se reintentó con Antigravity, cuya ejecución de herramientas está observada.

## Integración y validación de recuperación

`b8f8c63` integra la UI VEX pendiente: declaraciones del fabricante junto a las filas y cobertura de
búsqueda en postura kernel, sin sustituir ni cambiar el proof state. Incluye dos correcciones de formato.

Gates completos ejecutados tras la recuperación: `pnpm check`, `pnpm test`, `pnpm build`, `pnpm biome`
pasaron. 4.329 tests: core 467, API 2.916, web 835, scripts 111. Chromium real contra API local sintética,
con respuestas VEX interceptadas en el navegador: 16 casos (hallazgos/postura kernel, EN/ES, 390/1440 px,
claro/oscuro), sin excepciones ni desbordamiento del documento. Capturas e informe en `qa-recovery/` del
estado operativo. No se mutaron el corpus ni la base desplegada.

## Avance en generación 4 (Antigravity)

Tras el relevo formal y adopción de `run_fa2f177609e4` en generación 4 por Antigravity
(`term_8496d58e-619b-40ca-a8f2-6903eac02384`):

1. **Captura de RAM Renode**: Integrado el proveedor `apps/api/src/providers/renode-ram.ts`, rutas
   Fastify `POST/GET /images/:id/rtos/ram-capture` y cableado web completo en `RtosTaskSnapshotPanel.tsx`
   con soporte i18n (EN/ES) y carga directa del volcado en el formulario. Validado en ejecución real
   en contenedor `--network none` sobre `/data/images/22c69f6e/Zephyr-STM32L072-Button.elf` volcando
   20.480 bytes de `sram` [0x20000000, +0x5000] con peticiones remotas SVD rechazadas. Pruebas de contrato
   de rutas añadidas en `rtos.test.ts` (18 tests pasando).
2. **Corrección de observabilidad de cuota en el supervisor**: Reparado `skills/orca-campaign/scripts/watch.mjs`
   para reconocer bloqueos de cuota/sesión como fase `blocked` (motivo `capacity_blocked`) y registrar
   intervalos durables en `gaps`, sin intentos de auto-toma de control ni entradas ciegas. 44 tests unitarios
   verificados. Habilidad canónica reinstalada y nuevo supervisor iniciado (PID 94159) en fase `working`.
3. **Validación completa de repositorios**: `pnpm check`, `pnpm test` (4.365 tests: core 467, API 2.945, web 838 y scripts 115), `pnpm build`
   (core, api, web) y `pnpm biome` (0 errores, 0 advertencias) verificados y limpios.

## Pendiente

- Mantener supervisión activa del buzón de orquestación y del plazo fijo `2026-10-02T15:07:39Z` (17:07:39 Madrid).
- En el plazo de cierre, terminar la API sintética temporal (PID 92345), generar el informe final
  en `status.md` (en español) y consolidar el balance de la campaña.

## Segunda interrupción y verificación independiente

Antigravity terminó su turno a las 12:46:57 UTC (14:46:57 Madrid). Hasta la recuperación manual de root
a las 14:43:03 UTC (generación 5), el supervisor vivo siguió devolviendo
`unknown / input_prompt_unrecognized`, con `gaps: []`. No hubo coordinación continua comprobada en
esas aproximadamente 1 h 56 min. La corrección de cuota no había resuelto la reactivación de Antigravity.

Causa capturada: el supervisor usaba `terminal read` sin `--screen`. Ese modo devuelve salida acumulada,
no el compositor renderizado. La misma terminal con `--screen` muestra el prompt vacío `>` y el footer
Gemini, mientras la lectura anterior sólo contenía el resumen final. El arreglo está en curso con
propiedad exclusiva de los archivos del supervisor y pruebas de fuente de pantalla/borrador/bloqueo.
No se debe inferir un compositor vacío a partir de `done` o de líneas en blanco.

Root repitió `pnpm check`, `pnpm test`, `pnpm build` y `pnpm biome` tras recuperar el Run: todos pasan,
con 4.365 tests. La prueba de cuatro horas **ha fallado** por las interrupciones, aunque el proyecto
haya avanzado y las correcciones posteriores pasen pruebas. Se conserva el cierre original a las
15:07:39 UTC. El reloj transcurrido no equivale a trabajo continuo.

### Corrección de la segunda interrupción

El supervisor ahora pide `--screen` y exige una fuente renderizada; rechaza borradores no vacíos,
incluso espacios y tipos inesperados, y no toma textos históricos de cuota como un bloqueo actual.
Los intervalos de observación desconocida se registran con motivo y límites, sin simular inactividad
ni permitir toma de control. 52 pruebas focalizadas pasan y la suite completa da 4.373 tests
(core 467, API 2.945, web 838, scripts 123). Biome pasa. Instalación global y plugin Antigravity
actualizados; supervisor anterior detenido sin forzar y nuevo PID 38720, mismo plazo. La lectura
real del Antigravity que falló ya devuelve `idle` con prompt vacío comprobado. La reactivación
real controlada queda pendiente de su recibo y ejecución; no basta con instalar el arreglo.

## Cierre: generación 6 y prueba controlada de reactivación (Claude)

Claude `term_c960cc64` ejecutó un canario real (lectura, herramienta, escritura) a las 14:47 UTC y adoptó el
mismo Run desde su propia terminal a las 14:55:20 UTC (`run-show`: generación 6). Con autorización explícita
terminó una vez su turno a propósito con el compositor vacío: el supervisor PID 38720 observó `idle` a las
14:55:53 y 14:56:23, envió una reactivación (`d0287bfa…`, 14:56:55) aceptada e iniciada, y el journal la
liquidó como `confirmed` a partir de ejecución nueva, con `uncertainty: null` y `gaps: []`. Nadie más envió
continuación. Esto prueba **un** ciclo idle → reactivación → confirmado en Claude. No prueba la
reactivación automática de Antigravity (sólo su reconocimiento de pantalla renderizada), ni resistencia ante
cuota real, ni continuidad de cuatro horas: la campaña sigue **fallida** por las dos interrupciones
(~14 min y ~1 h 56 min).

QA de la captura de RAM en navegador real contra la API sintética local (127.0.0.1:8911, datos sintéticos,
reiniciada sobre el build actual porque la instancia anterior era previa a la ruta): la sección renderiza sin
errores de consola ni peticiones fallidas; sin Renode en el host, el clic devuelve `blocked_by_platform` con el
motivo. Límites que siguen en pie: no hay ELF FreeRTOS real en el corpus; la RAM capturada de Zephyr no prueba
tareas; las etiquetas de familia de switch y el fabricante son sólo indicios; falta validar la red real del WR940N.
