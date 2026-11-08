# Candidata Debian 13 ARM64 de `firmlab-tools` — 2026-11-08

Construida y validada en el host ARM64 del homelab (OrbStack, Docker 29.8.2, builder `orbstack` con driver
`docker`) durante la campaña `run_4723fc97d2d6`, desde la rama `founder4/campaign-tools-20261108`. **No se ha
promovido ni desplegado nada.** `firmlab-tools:latest`, `firmlab-firmware:latest` y el contenedor `firmlab`
conservan los mismos ID antes y después (abajo). Toda la validación funcional se ejecutó con `--network none`,
sin montar datos y montando en sólo lectura únicamente el fixture FreeRTOS y el smoke de seguridad del commit
limpio.

## Lo que había en el host

| Ref | ID | Qué es |
|---|---|---|
| `firmlab-tools:latest` | `sha256:2d0aba372d9d…` | **Ya es Debian 13 arm64.** Creada el 2026-11-04 a partir de `Dockerfile.trixie` (`GRYPE_DB_REFRESH=2026-11-04T21:43:17Z`) |
| `firmlab-firmware:latest` | `sha256:76f8e015d2f0…` | La app de `ac4bdbe` sobre esa base; es la que ejecuta el contenedor `firmlab` |
| `homelab-rollback/firmlab-tools:20261022-pre-trixie` | — | **ausente** (`RETAINED_IMAGE` por defecto de la receta) |
| `homelab-candidate/renode:trixie-20261022` | — | **ausente** (`RENODE_IMAGE` por defecto) |

El backlog dice que «no se ha construido ninguna candidata Debian 13». En este host eso no es exacto: la base
desplegada ya salió de `Dockerfile.trixie` el 2026-11-04. Lo que no existía era una reconstrucción reproducible
desde el árbol actual, porque las dos bases privadas de la receta no están aquí. Restaurar la copia cifrada
`/Users/agfil/homelab/backups/firmlab-pre-trixie-images-20261022.tgz.enc` no se intentó: requiere la clave del
operador y escribir en almacenes compartidos.

## Entradas sustituidas, sólo con refs desechables

Ninguna etiqueta compartida se movió. Se crearon:

- `firmlab-campaign-20261108/retained-src:2d0aba372d9d`: un alias del ID de `firmlab-tools:latest`. Es una etiqueta
  nueva sobre la misma imagen; no la modifica.
- `firmlab-campaign-20261108/renode-src:2d0aba372d9d` (`sha256:5e73a0e69f7e…`): imagen `scratch` con
  `COPY --from=<alias> /opt/renode /renode`, la misma forma que la etapa `artifact` de `Dockerfile.renode-security`.

**Por qué esta sustitución es defendible.** BuildKit indexa la caché de `COPY --from` por el contenido copiado.
Las capas `COPY --from=retained` de syft/grype/gitleaks, `afl-qemu-trace`, rizin, `librz*`, `share/rizin`,
libnvram, los kernels FirmAE y las reglas FwHunt **salieron todas de la caché** de la construcción del
2026-11-04, que copió desde la imagen retenida original. Por tanto esos ficheros son byte a byte los que entregaba
`20261022-pre-trixie`. Sólo `/opt/ghidra` no coincidió, como era de esperar: la base actual ya contiene el
decompilador ARM64 recompilado, y la receta vuelve a compilarlo encima (`make … ghidra_opt sleigh_opt`, 26 s).

**Qué no prueba.** Renode **no** se recompiló desde la fuente: es el binario 1.17.0 parcheado que ya llevaba la
base (`renode --version`: ReleaseHeadless, .NET 8.0.32). Las capas apt/pip/AFL++ también son las cacheadas del
2026-11-04, de modo que la candidata no incorpora actualizaciones Debian publicadas después de esa fecha.

## Candidatas

| Ref | ID | Origen |
|---|---|---|
| `firmlab-campaign-20261108/tools:trixie-304e663` | `sha256:bc60ba22a951…` | `docker build` manual con las dos sustituciones, `GRYPE_DB_REFRESH=campaign-20261108-2026-11-08T03:02:29Z` |
| `firmlab-campaign-20261108/tools:trixie-caf2355` | `sha256:210f116594f2…` | `scripts/tools-candidate.sh` (primera versión, `caf2355`), mismas entradas, `GRYPE_DB_REFRESH=campaign-20261108-script-run` |
| `firmlab-campaign-20261108/firmware:trixie-304e663` | `sha256:758b44ca5e14…` | `Dockerfile.firmware` desde `git archive 304e663` con `TOOLS_IMAGE=…/tools:trixie-304e663` |

Reproducibilidad: las dos candidatas tienen 27 capas y **sólo difieren en la última** (la base Grype). Las 21
primeras coinciden con `firmlab-tools:latest`; de la 22 (`/opt/ghidra`) en adelante difieren, por el motivo
explicado arriba. Las dos son Debian 13 (`VERSION_ID="13"`), `dpkg --print-architecture` = `arm64`.

Grype (offline: `GRYPE_DB_AUTO_UPDATE=false`, `--network none`): esquema v6.1.10, construida el
2026-11-07T06:18:48Z, `Status: valid`, `vulnerability.db` de 3,2 GB en `/opt/grype-db/6/`. La capa final es
distinta de la de la base (`871427ef…` → `13855c81…` / `f46c0621…`). FwHunt: 108 reglas.

## Inventario offline de 28 sondeos

Ejecutado con la misma biblioteca que `deploy.sh` (`scripts/tools-candidate-lib.sh`), cada sondeo acotado por
`timeout` y con `--network none`. Base y candidata dan la **misma** respuesta: 27 `ok` más `analyzeHeadless
present` (sólo presencia, como en `tools.ts`), sin regresiones.

`binwalk unsquashfs sasquatch jefferson lzop ubireader_extract_files cpio radare2 syft grype gitleaks
qemu-{mipsel,mips,arm,aarch64}-static qemu-system-{mips,mipsel,arm,aarch64} mkfs.ext2 renode chipsec angr yara
openssl gdb-multiarch fwhunt` → `ok`; `analyzeHeadless` → `present`.

## Smoke real sobre la candidata (contenedores desechables `--rm --network none`)

| Prueba | Resultado |
|---|---|
| `node apps/api/scripts/integration.mjs` | `PASSED: full provider chain works end-to-end.` 12 ✓, 0 ✗ (extract → sbom con syft/grype → gitleaks → decompile con radare2) |
| `node apps/api/scripts/rtos-freertos-e2e.mjs` (fixture montado `:ro`) | `RESULT: PASS`, 50 PASS, 0 FAIL. Renode capturó 256 KiB de SRAM y rechazó offline 1 recurso remoto (`STM32F40x.svd.gz`), como exige `OFFLINE_RENODE_ENV`. El estado de prueba sigue en `needs_runtime_reproduction` |
| `python3 scripts/security-runtime-smoke.py` (del commit limpio, montado `:ro`) | 4/4 PASS: Ghidra decompiló 40 funciones ARM64 con pseudocódigo no vacío, angr ejecutó un paso simbólico, AFL++ en modo QEMU produjo cobertura, y mitmproxy completó HTTP, HTTPS con su CA y la relectura del flujo guardado |

Esto valida la sandbox del contenedor con fixtures sintéticos. No dice nada de imágenes del corpus ni de un
dispositivo.

## Herramienta nueva: `scripts/tools-candidate.sh`

`deploy.sh --tools` es el camino de promoción: incluso con `--build-only` vuelve a etiquetar
`firmlab-tools:latest` en cuanto pasan sus guards, y sólo acepta las bases privadas por su nombre por defecto. El
script nuevo es la mitad que no promociona:

```bash
scripts/tools-candidate.sh --tag firmlab-campaign-<fecha>/tools:<etiqueta> \
  --retained <ref local> --renode <ref local> [--baseline firmlab-tools:latest] [--report <dir>]
```

- Antes de consultar a Docker rechaza estas etiquetas: compartidas (`firmlab-tools`, `firmlab-firmware`, `firmlab`,
  `homelab-rollback/*`, `homelab-candidate/*`, `firmlab-candidate-input/*`), implícitas o `:latest`, un digest,
  o la etiqueta de una entrada.
  Tampoco sobrescribe una etiqueta que ya exista.
- Rechaza una sustitución de un ARG que la receta no toma, una entrada ausente en el almacén local y un builder
  que no sea `docker`, para que BuildKit no resuelva esos nombres en un registro.
- Aplica las mismas comprobaciones que `deploy.sh` y deja en el informe `inputs.tsv` (cada ref con su ID),
  `inventory-baseline.txt`, `inventory-candidate.txt`, `grype-db-status.txt` y `verdict.txt`.
- Sale con 0 si acepta, con 1 si se niega antes de construir o durante la construcción, y con 4 si rechaza una
  imagen ya construida. La etiqueta queda para inspeccionarla; es única por construcción.
- La primera versión no ejecutaba `docker tag`; sus 11 tests nuevos más los 26 de `deploy.sh` daban 37/37.
  Ese recuento y ese comportamiento son históricos. Desde el endurecimiento posterior crea aliases privados
  nuevos `firmlab-candidate-input/*` para las bases locales, registra sus identidades y no promociona ninguna
  ref compartida. No ejecuta compose, `exec`, `stop` ni montajes. La validación actual y las restricciones de
  receta/informe están en [el informe de procedencia](TOOLS-CANDIDATE-PROVENANCE-20261108.md); el
  [informe de endurecimiento](TOOLS-CANDIDATE-HARDENING-20261108.md) conserva la evidencia real anterior.

En el host real también se comprobaron tres negativas: `--tag firmlab-tools:latest` se rechaza antes de llamar a
Docker; la etiqueta `trixie-caf2355` ya existente se rechaza; y sin sustituciones se detiene nombrando
`homelab-rollback/firmlab-tools:20261022-pre-trixie` como ausente. Esa última es exactamente la causa por la que
este host no podía reconstruir la receta tal cual.

## Estado de las refs compartidas tras la campaña

| Ref | ID antes | ID después |
|---|---|---|
| `firmlab-tools:latest` | `sha256:2d0aba372d9d…` | `sha256:2d0aba372d9d…` |
| `firmlab-firmware:latest` | `sha256:76f8e015d2f0…` | `sha256:76f8e015d2f0…` |
| contenedor `firmlab` | imagen `76f8e015…`, arrancado 2026-11-07T16:06:08Z, healthy | igual |

## Pendiente (no forma parte de esta tarea)

- Recompilar Renode desde la fuente con `Dockerfile.renode-security`. Su SDK está fijado a
  `8.0.426-bookworm-slim@sha256:738f72af…`. Ese digest no está en este host (sólo hay una 8.0.427) y habría que
  descargarlo; en esta campaña no se intentó.
- Si se quieren las actualizaciones Debian posteriores al 2026-11-04, hacer una candidata sin caché de la capa
  apt (`--no-cache-filter` o una clave explícita) y volver a pasar este mismo smoke.
- La promoción es una decisión del operador y va por `deploy.sh --tools`. Con la base actual, ese camino sigue
  exigiendo las dos refs privadas por su nombre por defecto.
- Limpiar las refs desechables cuando ya no hagan falta:
  `docker rmi firmlab-campaign-20261108/{tools:trixie-304e663,tools:trixie-caf2355,firmware:trixie-304e663,renode-src:2d0aba372d9d,retained-src:2d0aba372d9d}`.
  El alias `retained-src` comparte ID con `firmlab-tools:latest`, así que `rmi` sólo quita esa etiqueta.
