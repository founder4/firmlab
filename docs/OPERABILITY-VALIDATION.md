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

## Reparación del invitado WR940N (inittab primero) — 2026-10-04

Pregunta: ¿la reparación `FIRMLAB_EMU_REPAIR` (entrada `sysinit` antes de `rcS` que ejecuta el
`/etc/rc.d/iptables-stop` del propio firmware) llega a ejecutarse en la imagen WR940N real (`c42ab6f2`,
sha256 `42f5c291e2f8…`)? Entorno desechable: contenedor `firmlab-firmware:latest` (`7b6113e`) con `--network none`,
volumen de datos montado `:ro`, copia del rootfs en `tmpfs`, `restrict=on` en QEMU. Sin despliegue, sin escritura
en la base ni en el corpus, sin descarga y sin salida de red del invitado (0 destinos externos en ambas pasadas).

```bash
docker run --rm --network none -e FIRMLAB_EMU_REPAIR=1 -v firmlab_firmlab-data:/live:ro \
  -v $S:/s:ro -v $S/out:/out [-v $PWD/apps/api/dist:/app/apps/api/dist:ro] \
  --tmpfs /work:rw,exec,size=1g --entrypoint bash firmlab-firmware:latest /s/run.sh <tag>
```

`run.sh` copia el rootfs, llama a `runFullSystemFromRootfs('mips', …)` (el mismo punto de entrada del route) y
lee con `debugfs` el `/etc/inittab` del ext2 arrancado.

**Antes (código desplegado).** La línea llegó a la CPU y murió: firmadyne registró
`/bin/sh -c exec (n=0; until …` y la consola imprimió `syntax error`. busybox init antepone `exec ` a toda entrada
con metacaracteres y `exec (` es un error de sintaxis; además el shell del invitado es BusyBox 1.01 **msh**, sin
`$((…))`, y su `exec` vuelve a partir argumentos entrecomillados (verificado con `qemu-mips-static` sobre el
propio busybox). Peor: el resultado dijo `ruleset.ran: true`, «0 reglas, flush ejecutado», porque el lector
buscaba subcadenas y firmadyne imprime el argv completo de cada execve, que contiene los marcadores. Medición
fabricada. Pasada 2: 156 SYN, 0 respuestas.

**Después (este cambio).** Entrada de 244 bytes `::sysinit:2>&1;(set 0 1 … 9;for a do for b do ping … &&break 2;
done;done||exit;…)&`: sin error de sintaxis, el `ping` del propio busybox reintentó hasta que `rcS` levantó `lo`
(~0,1 s de núcleo) y en la pasada 2 respondieron 80/http y 443/https (173 SYN, 82 aceptados, sondas web vivas con
40 peticiones cada una). Veredicto `confirmed_full_system`, con la intervención en el hallazgo.

**Limitación medida y no corregida.** Ningún marcador llegó a la consola: el resultado informa `ran: false` y el
hallazgo dice que nada demuestra que la reparación se ejecutara, aunque los puertos respondieran. Un arranque de
diagnóstico (imagen desechable) mostró la causa: init da a cada entrada su propia sesión, el `sh -c` sale enseguida
y la salida del líder de sesión cuelga la consola para toda la sesión; lo escrito por el stdout heredado se pierde
y lo escrito en un `/dev/console` reabierto llega. La reapertura no se validó de extremo a extremo y no se incluye.
Además, la consola de un arranque firmadyne supera los 256 KB del límite (262 212 bytes), así que el informe se
lee ahora de un *tap* sobre el flujo sin recortar y sólo como líneas completas.

Una sola ejecución de cada variante (`n=1`): no es una afirmación de reproducibilidad. El script
`scripts/verify-full-system-reliability.sh` registra ahora `repair.{staged,reportedRunning,rulesetRead,flushed,
rulesBeforeFlush}` y el criterio `stagedRepairReportedEveryRun`, que hoy fallaría en la WR940N por esa limitación.
