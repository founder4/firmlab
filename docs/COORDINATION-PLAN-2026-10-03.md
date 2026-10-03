# Diagnóstico y plan de coordinación — 3 de octubre de 2026

Mandato de esta sesión: revisar el estado, los últimos avances y los recursos de Orca para determinar cómo
seguir. Es una revisión y planificación acotada, no una nueva campaña desatendida ni una autorización de
despliegue, descarga de firmware, investigación externa o escritura sobre el corpus vivo.

## Estado contrastado

| Superficie | Evidencia de esta revisión | Consecuencia |
|---|---|---|
| Checkout | `main`, HEAD `2eb659a`, limpio al iniciar | Base concreta para las próximas tareas |
| Referencia remota local | `origin/main` está 81 commits por detrás; no se hizo fetch | Es un dato de la referencia local, no una verificación del servidor remoto |
| Despliegue | `deploy.sh --check` y `/health` coinciden en `679f267`; salud `ok` | El contenedor está 81 commits por detrás de HEAD; la salud no demuestra que incorpore los cambios |
| Red efectiva | Docker: `NetworkMode=proxy_net`, sin puertos publicados; API interna `0.0.0.0` | Coincide con el modo homelab del inicio de DEPLOYMENT, no con su sección de red de host del 28 de septiembre |
| Orca | 1.4.219, runtime conectado; un único worktree del proyecto | Crear hijos separados antes de editar en paralelo |
| Última entrega | Run `run_5432c0122c21`, dos tareas terminadas | No reabrir sus Dispatches ni atribuirles trabajo nuevo |
| Validación completa previa | Registro `PROJECT-WORK-2026-10-03.md`: check/test/build/biome verdes, 4.595 tests | Evidencia histórica de HEAD, no una ejecución completa realizada por esta revisión |
| Validación actual | Build core y tests focalizados de VEX/switch-family: 61 core + 123 API, todos pasan | Confirma esas regresiones; no sustituye gates completos ni herramientas reales |

`pnpm biome` también pasó en esta revisión, sin modificaciones automáticas.

La inspección de red no auditó Traefik, autenticación ni accesibilidad desde otro equipo. No se infiere una
exposición accidental de un bind interno. Se inspeccionó el despliegue; no se modificó.

## Qué se ha avanzado

1. **Operabilidad:** cancelación con propiedad de grupos de procesos, limpieza verificada antes de liberar
   capacidad, exposición de aislamiento parcial y lectores de Ghidra/funcdiff.
2. **RTOS:** símbolos ELF, captura RAM de Renode, listas FreeRTOS por prioridad y formulario/prellenado.
   El volcado real de Zephyr demuestra captura, no enumeración real de tareas FreeRTOS.
3. **UEFI/SPI:** lectura estática de permisos de escritura del descriptor y región ME; desacuerdos entre
   generaciones se declaran. No existe aún evidencia de registros de protección vivos.
4. **VEX/CSAF:** afirmaciones del proveedor sin modificar proof states, defensas de identidad/parseo,
   omisiones de límites CSAF y prioridad de documentos nombrados antes de caps.
5. **Switch-family:** detector acotado, cobertura explícita y compactación de detalles sin perder denominadores.
   Los indicios de fabricante/plantilla no equivalen a identificar un switch exacto.
6. **Orca:** detección de inactividad/cuota, política de capacidad y relevo con retiro/adopción verificados.
   El transporte se probó con disparador sintético; las campañas de cuatro/ocho horas no están acreditadas.

## Orden de avance

### Primera ola: cerrar la cobertura VEX y preparar una entrega verificable

**A. Cobertura VEX de extremo a extremo — prioridad de producto.** SBOM y research deben conservar el
resumen de búsqueda incluso si no hay CVE, no casa ninguna afirmación o todos los documentos son rechazados.
Persistir campos opcionales y distinguir búsqueda vacía, parcial, no ejecutada y resultado antiguo sin datos.
Reutilizar una única lectura cuando proceda; no eliminar findings ni cambiar su severidad o proof state.
La UI y los consumidores deben leer esa cobertura independientemente de las filas de hallazgos.

La revisión independiente confirmó la pérdida en `routes/sbom.ts:33–46`, `opacidad.ts:415–459` y
`research/run.ts:290–297,405–416`. W9 selecciona explícitamente los campos que persiste en
`opacidad.ts:1412–1421`: ampliar solo `SbomResult` es insuficiente. Research debe conservar su condición
actual de ejecutar la correlación VEX cuando hay respuesta kernel; una ejecución nueva sin esa respuesta
dirá «no intentado», mientras la ausencia del campo en resultados antiguos seguirá siendo «no registrado».

Aceptación: fixtures de cero filas, sin rootfs, rechazo de documento, caps de inventario/ficheros/bytes,
ejecución manual y W9, research con red simulada localmente, y resultados guardados antes del campo. Pruebas
focalizadas, QA Chromium EN/ES a 1440/390, con errores y overflow medidos. Las respuestas sintéticas se
identifican como tales; no se presentan como validación del corpus desplegado.

**B. Preparación operativa en paralelo, de solo lectura.** Reconciliar el compose efectivo y la sección
histórica de DEPLOYMENT; precisar las comprobaciones del artefacto candidato y el plan de retorno. Revisar
la lista de 81 commits y separar código integrado, pruebas reales históricas y funciones aún no ejercidas
en despliegue. No cambiar modo de red, permisos, flags ni publicar para resolver una diferencia documental.

La entrega posterior tiene un gate independiente: validación completa del candidato, QA y autorización de
despliegue. Refrescar SBOM/research son operaciones distintas de desplegar. Antes de refrescar SBOM debe
verificarse la base local de grype, porque la sincronización sustituye las filas existentes de ese source.
Research además necesita alcance de red explícito. No se programa una campaña ciega sobre todas las imágenes.

### Segunda ola: ampliar identidades VEX con un contrato comprobado

Abordar `product_tree.branches`/`relationships` y `products[].identifiers`/`subcomponents` de OpenVEX.
Separar identidad del producto y del subcomponente; conservar límites de profundidad/nodos y denominadores
de lo omitido. No interpretar intervalos CSAF ni convertir un identificador ambiguo en coincidencia exacta.

Primero fijar fuentes primarias/versiones y fixtures esperados. Si no hay material local verificable, queda
pendiente el acceso documental necesario; no se rellena la semántica de memoria. Hasta implementar soporte,
una alternativa acotada es hacer visibles esas formas no leídas como omisiones.

Matiz de la revisión: `vendor-vex.ts:260–298` solo indexa `full_product_names`; en `:639–641`, una referencia
no resuelta cae al ID bruto. Si ese ID parece un componente conocido puede perderse la restricción de versión
del helper omitido. Es un riesgo confirmado por lectura de código, no una medición de firmware afectado;
la aceptación debe probar que ese fallback no elude una identidad versionada. Los subcomponentes a nivel
de statement sí se leen; el hueco OpenVEX corresponde a los anidados dentro del producto y a sus identifiers.

Esta ola sigue al contrato de cobertura de A. Para evitar solapamiento, A puede usar un nuevo helper puro
`apps/api/src/providers/vendor-vex-coverage.ts` sin editar el adaptador de descubrimiento. La segunda ola posee
solo `packages/core/src/vendor-vex.ts`, su test y `apps/api/src/providers/vendor-vex-discover.ts` con su test.
Si ya existen fuentes verificadas, esa parte puede adelantarse en paralelo con propiedad disjunta; la
integración final debe probar que las nuevas omisiones sobreviven la proyección del resumen.

### Tercera ola: demostrar capacidad dinámica concreta

Elegir una prueba pequeña con un resultado observable antes de ampliar la arquitectura:

- **RTOS:** fixture FreeRTOS con ELF, versión/configuración y layout conocidos; enlazar símbolos → captura RAM
  → listas de tareas y contrastar el resultado esperado. El corpus actual no lo aporta; adquisición/compilación
  y procedencia requieren un contrato propio.
- **Guest WR940N:** comprobar que la reparación de arranque alcanza realmente la ruta de inicio y recoger
  consola/red en un entorno desechable. No basta con que la edición de `inittab` sea correcta.
- **Renode offline:** medir qué cambia al aportar SVD locales frente al rechazo actual; registrar procedencia
  y mantener el comportamiento sin red.

El switch virtual DSA, Fuzzware/µEmu, Mercenario y RAG quedan detrás de estos prerrequisitos. Son trabajos de
mayor incertidumbre, no sustitutos de las comprobaciones pendientes. La lista única de pendientes sigue
siendo BACKLOG; este documento fija secuencia y criterios, no otro inventario.

## Asignación de recursos

| Rol | Asignación | Condición |
|---|---|---|
| Coordinador | Este agente: contratos, propiedad, revisión de diffs, integración y gates | Único dueño de integración y documentación de estado |
| Implementador API | Codex, hijo de HEAD validado, tarea A | Inicio real observado; propiedad de SBOM/research/adaptador definida antes de lanzar |
| Implementador UI | Codex o proveedor con capacidad verificada, segundo hijo | Empieza tras fijar contrato API; propiedad exclusiva de cliente/componentes/locales |
| Revisor | Claude si se demuestra recuperación; en su defecto otro Codex | Solo lectura, revisión de código y pruebas independiente del resumen del autor |
| Antigravity | Revisión acotada o evidencia visual cuando supere preparación | Un intento supervisado con recibo ready y ejecución real; no usar dispatch sin supervisión para esquivar readiness |

Para A, separar propiedad API (`providers/sbom.ts`, `routes/sbom.ts`, `opacidad.ts`, `opacidad-narrative.ts`,
`research/run.ts`, helper `providers/vendor-vex-coverage.ts` y tests correspondientes) de propiedad web
(`api.ts`, `pages/ImageDetail.tsx`, `components/OpacidadPanel.tsx`, nuevo `VendorVexCoverage.tsx`, sus tests
y locales `en/es/imageDetail.ts`). El coordinador asignará los nombres de nuevos tests en el Dispatch; ningún
worker recibe por defecto toda la carpeta ni los normalizadores de findings. Una ampliación de consumidor
requiere ajustar esa propiedad antes de editar.

Máximo habitual: dos implementadores y un revisor, además del coordinador. No lanzar los tres proveedores
por disponibilidad nominal. El registro de capacidad conserva Anthropic bloqueado desde el 2 de octubre,
sin reset conocido; esto no demuestra su cuota actual, pero tampoco autoriza a considerarlo recuperado.
Codex tiene ejecución nueva comprobada en este Run; no hay una medida fiable de capacidad restante.
Dos agentes del mismo proveedor no constituyen una reserva frente a una cuota compartida.

Herramientas: Git/pnpm para diffs y validación; Docker para pruebas desechables offline y lecturas del
despliegue; Orca CLI para el ciclo de vida; Chromium/Playwright para QA de UI. `.mcp.json` declara `firmlab`
(Docker) y `playwright` (npx), pero su configuración no prueba conectividad actual: no se invocaron durante
esta revisión. Usar MCP de FirmLab solo con operaciones explícitas del contrato de cada tarea, pues también
expone acciones que pueden ejecutar análisis. No hace falta instalar otro conector para la primera ola.

Cada Task llevará target, cambio, restricciones, archivos propios y aceptación; cada intento usará sus IDs
reales. Integrar ramas asentadas una a una, procesar cada Delivery antes de ack y liberar los workers al
aceptar su `worker_done`. No dejar procesos abiertos como sustituto de un plan de continuidad.

Una campaña desatendida futura necesita mandato/plazo propios, supervisor independiente, reservas de
dominios de capacidad distintos con ejecución comprobada y relevo del mismo Run observado. Empezar por
un ensayo corto con criterios de éxito antes de repetir cuatro u ocho horas. Esta sesión no lo inicia.

## Gate para declarar una implementación lista

Construir core antes de consumidores; durante desarrollo, ejecutar solo pruebas relevantes. Tras integrar:
`pnpm check`, `pnpm test`, `pnpm build`, `pnpm biome`. Añadir evidencia en contenedor para herramientas y
navegador real para UI según CLAUDE. Registrar qué se probó con fixtures, qué con herramientas y qué se
leyó de resultados históricos. No equiparar más tests, más hallazgos o más terminales a mayor cobertura.

## Registro de esta revisión

Run de diagnóstico `run_d0b58e4d1702`. Revisión VEX de solo lectura asignada a
`task_f913f9d06fa1` / `ctx_f306183eab90`, mediante el lanzador con política de capacidad.
Recibo `ready`, `turn_started` observado. Terminó con `worker_done: succeeded`; se contrastó su informe
de código y se incorporaron el límite de persistencia de W9 y el fallback de identidad CSAF a este plan.
`worker-release` confirmó `released` y cierre de su terminal con transcripción archivada; Delivery reconocida
después de procesar el resultado, cero workers reclamables. El revisor no ejecutó tests: los 184 casos y
Biome mencionados arriba fueron ejecutados por el coordinador. Informe detallado local:
`/tmp/firmlab-vex-planning-review.md`.

No se cambiaron archivos de producción, ni se desplegó, descargó firmware, habilitó research o mutó el
corpus/base viva. Las únicas escrituras previstas en el repositorio son este plan y el pendiente descubierto
en BACKLOG; la compilación de core actualizó su salida local ignorada por Git.
