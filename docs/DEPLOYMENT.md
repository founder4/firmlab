# Despliegue

FirmLab se despliega de dos formas distintas, y conviene no confundirlas.

## Los dos composes

| | Fichero | Exposición |
|---|---|---|
| **Repo** | `docker-compose.yml` (en este repo) | `127.0.0.1:8799` — solo loopback, el diseño original |
| **Homelab** | `~/homelab/firmlab/docker-compose.yml` | `firmlab.lab.founder4.com` vía Traefik |

El del repo es el modo local-only descrito en el README. El del homelab expone el workbench **a propósito**,
detrás de dos middlewares de Traefik: `tinyauth` (SSO Google, solo la cuenta whitelisteada) y
`crowdsec-bouncer`. Sin puertos abiertos a internet: solo LAN/Tailscale.

> El contenedor sostiene el firmware que subas. **No quites los middlewares de auth** del router de Traefik.
> Que el bind interno sea `0.0.0.0` es necesario para que Traefik lo alcance por `proxy_net`; la exposición
> real la controla el router, no el bind.

## La cadena de imágenes (capas invertidas)

```
Dockerfile.tools      → firmlab-tools:latest       (base pesada: toolchain RE/emulación, ~varios GB)
Dockerfile.firmware   → firmlab-firmware:latest    (FROM firmlab-tools + la app copiada encima)  ← el que se despliega
Dockerfile            → firmlab:latest             (variante lean sin tools, para dev local)
```

**Los tools van en la BASE, la app ENCIMA.** Así un cambio de código de la app reconstruye solo la capa fina de la
app (recompila rápido) — las capas de tools (multi-GB, incl. el compile de ~20 min de AFL++) quedan cacheadas. La
base `firmlab-tools` se reconstruye solo cuando cambia una receta de tool (`deploy.sh --tools`). El compose del
homelab consume `firmlab-firmware:latest`.

## Cómo desplegar

```bash
scripts/deploy.sh              # construye la app sobre la base de tools existente, despliega y verifica
scripts/deploy.sh --tools      # ADEMÁS reconstruye la base de tools (cuando cambió una receta de tool; pesado)
scripts/deploy.sh --check      # solo informa de desfase, no cambia nada
scripts/deploy.sh --build-only # construye y etiqueta sin tocar el contenedor
```

El script construye ambas imágenes **etiquetando `:latest` en el mismo paso**, despliega, y verifica tres
cosas: que el healthcheck pase, que el contenedor corra exactamente la imagen recién construida, y que el
sello de commit coincida con el repo. Si algo no cuadra, sale con error en vez de dejarte creer que fue bien.

## Qué versión está corriendo

Cada imagen se sella con el commit del que salió:

```bash
docker inspect firmlab --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

Compáralo con `git rev-parse HEAD`, o directamente `scripts/deploy.sh --check`. Un sufijo `-dirty` significa
que se construyó con cambios sin commitear.

## El incidente del 2026-07-18

Merece quedar escrito porque la causa raíz es estructural, no un despiste puntual.

**Qué pasó.** El contenedor llevaba días sirviendo una versión sin el frontend responsive ni las cuatro
"waves" de features posteriores. Todo ese trabajo (9 commits, desde `af0dc9d feat: mobile-ready frontend`)
vivía en un worktree de git sin mergear, mientras `main` seguía en el commit inicial.

**Por qué no se detectó.** Confluyeron dos fallos que se tapaban entre sí:

1. **El tag nunca se promovió.** La imagen correcta *sí existía*, construida desde el HEAD del worktree y
   etiquetada `firmlab-firmware:roadmap`. Pero el compose consume `:latest`, y `:latest` apuntaba a una build
   anterior. La imagen buena estaba en disco, sin que nada la usara.
2. **La verificación era circular.** Comprobar que el contenedor corre la imagen recién construida, y que los
   assets servidos son los de esa build, da todo verde — y sigue dando verde si el *fuente* era el viejo.
   Coherencia interna no es actualidad. Faltaba comparar contra el commit más reciente del repo.

**Qué lo arregla.** El sello de commit en la imagen (`--label ...revision`) rompe la circularidad: la
pregunta "¿qué versión corre?" pasa a tener respuesta directa desde el contenedor, sin inferirla de hashes de
assets. Y como `deploy.sh` construye y etiqueta en un solo paso, `:latest` no puede quedarse atrás. El script
además avisa si existe alguna rama por delante de `HEAD`, que es la señal que se pasó por alto.

**Lección general.** Al verificar un despliegue, la cadena imagen→contenedor solo prueba consistencia interna.
La pregunta que importa es si el *fuente* desplegado es el más reciente, y esa hay que hacerla explícitamente.

## Lo que el contenedor NO tiene (y cuesta horas descubrir)

La imagen de herramientas es enorme y eso engaña: lo que falta suele ser lo pequeño y omnipresente.

| Ausente | Qué rompió, y cómo se manifestó |
|---|---|
| `pkill`, `pgrep`, `ps`, `killall` | `teardown()` en `emulate-system.ts` hace `pkill -f`, capturaba el ENOENT en la misma rama que "no encontró nada" y registraba **"Teardown complete (emulators killed)"** sin barrer nada. Los qemu supervivientes se acumulaban entre ejecuciones reteniendo sus puertos reenviados. Para inspeccionar procesos aquí: recorrer `/proc/[0-9]*/cmdline`. |
| ROMs de opción de qemu (`vgabios-cirrus.bin`, `efi-e1000.rom`) | `qemu-system-*` **no arranca en absoluto** sin `-nodefaults` (VGA por defecto) y sin `romfile=` vacío en la NIC. Muere antes de ejecutar una instrucción del invitado, con un mensaje que no menciona ninguna de las dos causas. |
| `genext2fs`, `qemu-img` | La imagen de disco se ensambla con `mkfs.ext2 -d` (e2fsprogs 1.47), que puebla desde un directorio **sin root** — la única vía en un contenedor sin privilegios. |

Los kernels firmadyne **no se llaman como nuestras arquitecturas**: `vmlinux.mipseb.4` para MIPS big-endian,
`vmlinux.armel` sin sufijo `.4`. Solo `mipsel` coincide, que es exactamente por qué el desajuste sobrevivió tanto.

## Variables de entorno poco documentadas

| Variable | Efecto |
|---|---|
| `FIRMLAB_FWHUNT_MODULE_CAP` | Cuántos módulos EFI escanea el pase por módulo de FwHunt (por defecto 12). Lo que recorta se declara en el resultado. |
| `FIRMLAB_RESEARCH_CACHE_TTL_HOURS` | Frescura de la caché de advisories (por defecto 24). Una entrada caduca se vuelve a consultar, nunca se sirve. |
| `FIRMLAB_ANGR_PYTHON` · `FIRMLAB_FWHUNT_PYTHON` | Intérpretes de sus venv propios. angr y fwhunt-scan **no** pueden compartir cierre de dependencias con chipsec. |
| `FIRMLAB_UEFI_IOC` · `FIRMLAB_DESOCK` | Feeds/preloads opcionales. Vacíos por defecto a propósito: nada fabricado. |
| `FIRMLAB_CAPTURE_AGENT_TOKEN` | Sin él, el canal del agente LAN está cerrado (401). |
| `NVD_API_KEY` | Sube el tope de consultas NVD de 6 a 40 y elimina la espera de cortesía de 6,5 s. |

Nota: desde 2026-07-28 los flags de las lanes de red (`FIRMLAB_AGENT`, `FIRMLAB_RESEARCH`, `FIRMLAB_CAPTURE`…)
se **persisten en la base de datos** desde Ajustes › Privacidad. Que la variable no esté en el entorno ya no
significa que la lane esté apagada — consulta `/api/settings/flags` o `/api/research/status`.

## Limpieza

Las builds sucesivas dejan imágenes dangling (cada rebuild desreferencia la anterior; en un día de iteración
se acumularon ~6 GB). Para revisar y limpiar solo lo de FirmLab:

```bash
docker images -f dangling=true          # inspecciona antes de borrar
docker system df                        # cuánto se puede recuperar
```

`docker image prune` borra las dangling de **todos** los proyectos, no solo las de FirmLab. En esta máquina
conviven otros stacks (finanzas, adguard, traefik, crowdsec…), así que si quieres acotarte a FirmLab,
identifícalas primero — las suyas llevan variables `FIRMLAB_*` en `.Config.Env`.

Ojo también con los volúmenes anónimos: un `docker run` suelto sin el volumen nombrado crea uno huérfano con
su propia BD, que luego parece contener datos. El volumen bueno es el nombrado, `firmlab_firmlab-data`.
Inspecciona el contenido antes de borrar ninguno — eso sí es irreversible.
