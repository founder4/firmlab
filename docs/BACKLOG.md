# FirmLab — backlog

## Cerrado en esta iteración

- [x] Eliminar las vulnerabilidades de producción y hacer reproducibles las imágenes Docker.
- [x] Unificar el arranque full-system para que QEMU reciba una imagen de disco, no el directorio rootfs.
- [x] Reconciliar como interrumpidos los jobs `queued`/`running` después de reiniciar la API.
- [x] Entregar `exportreach`: API, panel web, i18n, tests, validación sobre firmware real y hallazgos accesibles al agente.
- [x] Dejar `pnpm audit` completamente limpio actualizando Vitest, Vite y la cadena jsdom/undici.
- [x] Confirmar Biome limpio en `exportreach` y en el workspace completo.
- [x] Añadir CI para instalación congelada, auditoría, Biome, tipos, tests, build y smoke test de Docker.

## Siguiente

- [ ] Terminar la fiabilidad full-system: cinco arranques con reparación, consola legible, puertos derivados del invitado y `webprobe` durante el boot vivo.
- [ ] Mostrar resultados dinámicos y de agentes como conclusiones con evidencia, corrigiendo además la clasificación full-system del historial.
- [ ] Dar a los nodos de juicio del agente el contexto determinista ya disponible y reconciliar `resolvedClass` con la identidad medida.
- [ ] Añadir el peldaño autónomo de `exportreach` a `opacidad` y medir su presupuesto junto a `symreach`.
- [ ] Integrar `credmatch` y `yarascan` en el escaneo autónomo, la cobertura y las superficies web/MCP apropiadas.
- [ ] Ampliar el corpus de validación: firmware UEFI, variables y módulos completos, reglas YARA y muestras RTOS/hardware.
- [ ] Reducir deuda del frontend: navegación coherente, tests de páginas sin cobertura, división del bundle y traducción del texto generado por la API.
