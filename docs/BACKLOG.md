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

## Siguiente

- [ ] Ampliar el corpus de validación: firmware UEFI de proveedor, variables y módulos completos, y más muestras RTOS/hardware.
- [ ] Reducir deuda del frontend: navegación coherente, tests de páginas sin cobertura, división del bundle y traducción del texto generado por la API.
- [ ] Verificar la capa responsive del libro mayor en un viewport estrecho real: la regla de ≤720px que convierte `findings-table` en tarjetas se escribió y se probó por CSS, pero `ui-drive.mjs` no redimensiona, así que nadie la ha visto renderizada. Añadir un `--viewport` al driver y mirarla.
- [ ] Desglosar el cubo "sin establecer" del censo. Hoy `severityCensus` mete en `unproven` todo lo que `isEstablished` rechaza: pistas, los dos bloqueos, un descarte y el testimonio de un operador. El filtro del libro mayor ya excluye `operator_assertion`, así que la tarjeta puede contar una fila que el filtro no enseña. Son cuatro cosas distintas bajo un número, y la que más importa — pista (accionable) frente a bloqueo (pregunta sin respuesta en este despliegue) — es justo la que el número esconde.
