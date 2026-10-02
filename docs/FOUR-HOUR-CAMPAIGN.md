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

## Pendiente

Captura RAM Renode: validar proveedor y ruta con memoria real en contenedor sin red. Corregir la
observabilidad del bloqueo de cuota y verificar reserva de otro servicio con ejecución real antes de
ceder autoridad. La prueba de duración **no está superada** y los gates anteriores no cubren cambios
posteriores. El próximo coordinador actualizará contexto/estado y evidencia final al cerrar la ventana.
