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

## Siguiente

- [ ] Convertir la matriz del corpus en una campaña programada: hoy quedan 14 celdas `not-run`, 82 `degraded` y 33 `no-input` entre 390 etapas aplicables; priorizar por clase y coste.
- [ ] Profundizar la correlación de kernel: el prefijo NVD puede tener miles de CVE (2.037 para Linux 2.6.31); usar config/subsistema, diff de parches o VEX de proveedor para descartar candidatos y paginar más allá de las primeras 50 sin presentarlas como el conjunto.
- [ ] Hacer que la reparación del invitado alcance una ruta ejecutada y recuperar red/console interactiva en full-system; la intervención al final de `rcS` sigue siendo inerte.
- [ ] Ampliar RTOS a fuzzing de periféricos/MMIO y enumeración de tareas; Renode demuestra vida, no cobertura del HAL.
