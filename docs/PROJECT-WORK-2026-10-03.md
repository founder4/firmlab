# Trabajo de backlog retomado — 3 de octubre de 2026

Tras la petición del usuario se retomó el proyecto desde `1461c43`, con el checkout limpio. El journal anterior
seguía en `deadline` (20:35:13Z del día 2), sin nuevas observaciones ni avances posteriores en Git. Eso no prueba
un nuevo fallo técnico de cuota; tampoco prueba trabajo durante la noche. Esta sesión es trabajo solicitado
ahora, con Run `run_5432c0122c21`, no una extensión del ensayo de cuatro horas ni un ensayo de resistencia.

## Cambios entregados

- VEX/CSAF: grupos `first_affected`, `last_affected` y `first_fixed` pasan a contarse como semántica no soportada,
  con ejemplos acotados en orden documental. Llegan a cobertura y omisiones de veredictos sin convertirse en
  rangos ni afirmaciones exactas. Conservan los conflictos reales y la compatibilidad con documentos antiguos.
  Commit `d815773`.
- switch-family: el resultado se agrega sobre todos los ficheros leídos antes de compactarlo. Se conservan
  detalles de señales, near misses, truncado, registros descartados y fronteras pendientes; se omiten los de
  lecturas completas sin señales. Los recuentos de examinados/bytes/inputs permanecen completos, los campos
  nuevos son opcionales y la UI distingue detalles omitidos de ficheros no escaneados. `deferred` aparece una
  sola vez en `overall`. La compactación es idempotente. Commit `204e82d`.
- Selección VEX: nombres que identifican documentos VEX/CSAF preceden a JSON aceptados sólo por el nombre
  de un directorio, antes de caps de ficheros y bytes. Desempate por ruta original en orden code-unit, conteos
  y rechazos sin cambios, regla registrada en cobertura y tipada como opcional en el cliente. Commit `b4450aa`. Tests de filesystem
  conservan el documento real aunque haya más candidatos genéricos que plazas. El inventario sigue acotado.

## Evidencia

Filesystem sintético desechable con 1.024 ficheros: 1.024 examinados, cero saltados, un resultado detallado,
1.023 detalles omitidos y un JSON de 8.300 bytes. El test exige menos de 20 KB y una reducción superior a 50×
respecto a los detalles por fichero completos, manteniendo el candidato, su procedencia y los denominadores.

QA Chromium sobre los componentes actuales, mediante Vite local en loopback y respuestas API sintéticas:
1440 px EN y 390 px ES; sin excepciones, errores de consola, peticiones fallidas ni desbordamiento horizontal.
Se inspeccionó la captura móvil. No es QA del despliegue ni del corpus vivo. Harness, JSON, resumen y capturas
quedan en `~/.local/state/orca-campaign/project-work-20261003/`.

Primera validación integrada: `pnpm check`, `pnpm test`, `pnpm build`, `pnpm biome` verdes;
498 tests core, 3017 API, 864 web y 202 Node: 4581 tests.

## Coordinación y límites

La tarea VEX de Antigravity falló antes de inyectar instrucciones en `agent_readiness`, sin recursos residuales.
No se contó como trabajo ejecutado. La misma Task se reintentó con Codex después de canario real y `tui-idle`
positivo: `task_4b1ee66adca4`, `ctx_17a01cc9560f`; terminó con `worker_done` explícito y se procesó antes de ack.
Su `worker-release` dejó la terminal preexistente como externa, sin acción de proceso. Se reutilizó para
`task_6e2f1c4b5819` / `ctx_a9a2d284390f` (selección VEX), también con inicio real y `worker_done` succeeded,
91 tests enfocados y Delivery procesada antes de ack. Ambos intentos definitivos se revisaron e integraron. El proveedor Anthropic
sigue bloqueado en la política anterior; no se lanzó Claude para esquivar el límite ni se cambiaron modelos,
cuentas o créditos. Root revisó e integró los cambios y ejecutó las validaciones completas.

No despliegue, descargas de firmware, investigación externa ni mutaciones del corpus/base de datos vivos.
Los pendientes de resistencia/relevo real, preparación de Antigravity y las otras limitaciones VEX continúan
registrados en `docs/BACKLOG.md`.


## Validación final y siguiente prioridad

Tras integrar la selección VEX se repitieron y pasaron `pnpm check`, `pnpm test`, `pnpm build` y `pnpm biome`:
498 tests core, 3031 API, 864 web y 202 Node, 4595 en total. No hay workers reclamables en este Run.
Después de liberar ambos Dispatches y comprobar `tui-idle`, se cerró únicamente la terminal Codex creada para
esta sesión (`ptyKilled: true`); los procesos de la campaña anterior no se tocaron.

Próximos pendientes de producto: conservar cobertura VEX en SBOM/research incluso sin filas; lectura acotada de
identidades CSAF/OpenVEX aún no soportadas. Los intervalos CSAF necesitan un contrato verificado antes de
interpretarlos. RTOS y emulación mantienen los requisitos de fixtures reales y validación de semántica local del
backlog. La prueba de relevo ante cuota real y el ensayo largo continúan pendientes; esta sesión no los acredita.
