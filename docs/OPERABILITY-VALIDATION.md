# Validación de operabilidad — 2026-10-01

Esta sesión implementa cancelación de jobs, presentación de las restricciones disponibles del runner y
lectores de Ghidra/funcdiff. No despliega cambios ni ejecuta análisis sobre el corpus persistido.

## Aislamiento

`GET /agent/config` añade `phase4.netns` y `phase4.resourceLimits`, incluso con el agente deshabilitado.
Los clientes antiguos conservan `phase4.isolation`; la web trata los campos nuevos ausentes como desconocidos.
La información describe capacidades de `runIsolated`, no restricciones aplicadas a un resultado histórico
ni a todos los proveedores. Los límites de recursos y el namespace de red no contienen el filesystem,
las credenciales ni los procesos del host, y no sustituyen la aprobación de ejecución.

Se probaron detección concurrente, ausencia de herramientas, namespace directo/rootless, límites sin
namespace, plataforma no Linux y compatibilidad de resultados antiguos. En un contenedor desechable de la
imagen de herramientas existente, con `--network none` y sin volúmenes de datos, el runner detectó
`partial`, `netns: null`, `resourceLimits: true`. Una petición Fastify real con `FIRMLAB_AGENT=0` devolvió
HTTP 200 y esos mismos campos. La restricción de red impuesta al contenedor de prueba no se atribuye al runner.

## Lectores

Ghidra ofrece selector de binarios, funciones guardadas y pseudocódigo escapado. Funcdiff presenta extractos
antes/después, diff unificado, decompilador y límites. Los campos nuevos siguen siendo opcionales en
resultados persistidos. Los tests incluyen resultados antiguos, texto parecido a HTML, límites y promesas
que terminan después de cambiar imagen o base de comparación.

Se abrió el build web integrado con Chromium, a 1440×1000 y 390×844. Un proxy temporal en loopback sirvió
el frontend y permitió únicamente GET/HEAD hacia el banco existente; rechazó mutaciones. El lector de
Ghidra mostró las 40 funciones guardadas de WR940N (`c42ab6f2`) y pseudocódigo real. No hubo errores de
JavaScript, peticiones fallidas ni desbordamiento horizontal en el lector. Funcdiff pasó la misma revisión
visual con una respuesta interceptada de fixture, porque no había un resultado guardado disponible para
esa comparación; esto no demuestra una nueva ejecución de radare2.

Los nuevos indicadores de aislamiento también se revisaron contra la API desplegada anterior: mostraron
restricciones desconocidas, sin inferirlas de `partial`. Se registró por separado en BACKLOG el
desbordamiento móvil preexistente del editor/configuración de Ajustes.

## Cancelación

La extracción cancelada se distingue de una extracción sin archivos. Una solicitud todavía en limpieza
se presenta como `cancelling`; una cancelación completada no aporta una conclusión sobre el firmware.
Los archivos parciales sólo pueden explorarse si existe un directorio conocido con entradas y sin error
de limpieza. Los tests cubren ausencia de salida, salida parcial y limpieza fallida.

La revisión de cancelación verifica procesos descendientes que mantienen sockets incluso después de
salir el proceso principal. En Linux se capturan los inodes de los sockets propios antes de señalizar y
se verifica su desaparición, además de la salida del grupo: el kernel puede retirar un proceso antes de
liberar sus sockets. La capacidad de la cola sólo se devuelve tras comprobar la limpieza. Un fallo conserva
el slot y un error visible, también después de recargar la vista. La recuperación de `cancelling` tras un
reinicio elimina resultados parciales y declara la limpieza no verificada.

La entrega pasó 25 iteraciones de salida del proceso principal con un descendiente de stdio ignorado y
reutilización inmediata del puerto, en un contenedor desechable sin red ni volúmenes de datos. También
verificó hijos/nietos, cancelación repetida, trabajo en cola que nunca empieza, conservación de resultados
terminados y capacidad retenida mientras el proveedor completa su limpieza.

La propiedad cubre descendientes que permanecen en el grupo Unix creado por el runner. No se buscan
sesiones escapadas ni árboles de un proceso anterior tras un reinicio. Windows rechaza explícitamente la
cancelación de árboles en ejecución. Las esperas de red y el trabajo sin subprocesos se cancelan de forma
cooperativa; no se publica un resultado completado ni se libera capacidad mientras sigan pendientes.

El coordinador repitió la integración de cola/procesos/sockets sobre el build final y las 25 iteraciones
pasaron. Una prueba adicional arrancó QEMU real con `qemu-system-mips -M malta -S -nodefaults`, sin cargar
firmware, con gdbstub en un puerto efímero de loopback: cancelación repetida, salida por `SIGKILL`, limpieza
y reutilización inmediata del puerto pasaron en un contenedor desechable con `--network none`.
Chromium contra una API local y SQLite temporales confirmó cancelación de un job en cola y uno en ejecución,
limpieza pendiente y confirmación terminal, sin excepciones de página. Se inspeccionaron las capturas.

## Validación integrada

`pnpm check`, `pnpm test`, `pnpm build` y `pnpm biome` pasaron con los tres cambios integrados.
La suite completa ejecutó 3.996 tests: core 380, API 2.796, web 751 y scripts 69. La comprobación real de
`GET /agent/config` en el contenedor desechable también se repitió tras integrar cancelación y pasó.
Los resultados de Ghidra guardados se leyeron mediante GET; funcdiff se revisó con fixture. Estas pruebas
no atribuyen a una nueva ejecución de proveedores la evidencia histórica del corpus.

La revisión independiente del commit de cancelación no dejó hallazgos P1/P2 pendientes. Repitió 103 tests
API, 61 web y regresiones adicionales para sockets, límites de limpieza, cachés de capacidades, consumidores
terminales y respuestas tardías al cambiar de imagen. Los dos implementadores finalizaron sus tareas de
Orca y sus terminales fueron liberadas.
