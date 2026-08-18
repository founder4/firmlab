# FirmLab — backlog

## Cerrado en esta iteración

- [x] Eliminar las vulnerabilidades de producción y hacer reproducibles las imágenes Docker.
- [x] Unificar el arranque full-system para que QEMU reciba una imagen de disco, no el directorio rootfs.
- [x] Reconciliar como interrumpidos los jobs `queued`/`running` después de reiniciar la API.

## Siguiente

- [ ] Actualizar Vitest, Vite y jsdom hasta dejar `pnpm audit` completamente limpio. (Los errores Biome de `exportreach` ya están corregidos — `8b96182`.)
- [ ] Añadir CI: instalación congelada, tipos, Biome, tests, build, auditoría de producción y smoke test de Docker.
- [ ] Terminar la fiabilidad full-system: cinco arranques con reparación, consola legible, puertos derivados del invitado y `webprobe` durante el boot vivo.
- [ ] Mostrar resultados dinámicos y de agentes como conclusiones con evidencia, corrigiendo además la clasificación full-system del historial.
- [ ] Dar a los nodos de juicio del agente el contexto determinista ya disponible y reconciliar `resolvedClass` con la identidad medida.
- [ ] Integrar `exportreach`, `credmatch` y `yarascan` en el escaneo autónomo, la cobertura y las superficies web/MCP apropiadas. (`exportreach` ya tiene superficie web y capacidad manual —`ExportReachPanel` junto a `SymReachPanel`, i18n en/es, tests; validado en contenedor sobre el corpus real: NetUSB.ko → `__kmalloc` alcanzable desde 37 de 228 entradas, biblioteca WR940N sin cabeceras de sección → `no_functions_recovered`—, y sus hallazgos ya llegan a un agente por `firmlab_findings`. Le queda el peldaño AUTÓNOMO: un `exportReachLeads` en `opacidad-leads.ts` que convierta en sondas los objetos `.so`/`.ko` que la cola de `symreach` descarta, con su propio contador de presupuesto angr, más el ejecutor y el `ProviderId` en `opacidad.ts`; medir la interacción del presupuesto con `symreach` en un escaneo completo en contenedor es la parte que hay que medir, no suponer. `credmatch` y `yarascan` siguen sin integrar por ninguna de las tres vías.)
- [ ] Ampliar el corpus de validación: firmware UEFI, variables y módulos completos, reglas YARA y muestras RTOS/hardware.
- [ ] Reducir deuda del frontend: navegación coherente, tests de páginas sin cobertura, división del bundle y traducción del texto generado por la API.
