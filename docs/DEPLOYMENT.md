# Despliegue

FirmLab se despliega de dos formas distintas, y conviene no confundirlas.

## Los dos composes

| | Fichero | Exposición |
|---|---|---|
| **Repo** | `docker-compose.yml` (en este repo) | `127.0.0.1:8799` — solo loopback, el diseño original |
| **Homelab** | `~/homelab/firmlab/docker-compose.yml` | `firmlab.lab.founder4.com` vía Traefik; atajo `127.0.0.1:8899` (`firmlab-view`) |

El del repo es el modo local-only descrito en el README. El del homelab expone el workbench **a propósito**,
detrás de dos middlewares de Traefik: `tinyauth` (SSO Google, solo la cuenta whitelisteada) y
`crowdsec-bouncer`. Sin puertos abiertos a internet: solo LAN/Tailscale. El contenedor `firmlab` no publica
ningún puerto en el host; el servicio `firmlab-view` (socat) publica `127.0.0.1:8899` y reenvía a `firmlab:8799`
por `proxy_net` **saltándose el SSO** — sólo lo alcanza quien ya está en la máquina, y está declarado en ese
compose para que el bypass quede escrito.

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

## Reconciliar resultados WebProbe anteriores a v2

WebProbe v2 añadió controles independientes y cobertura verificable. Los hallazgos calculados por versiones
anteriores no deben seguir apareciendo como confirmados hasta reproducirlos con ese contrato. Tras desplegar una
versión que incluya `reconcile-webprobe.mjs`, ejecuta primero el modo sólo lectura:

```bash
docker exec firmlab node apps/api/scripts/reconcile-webprobe.mjs --db /data/firmlab.db
```

Revisa el resumen y aplica después la misma selección:

```bash
docker exec firmlab node apps/api/scripts/reconcile-webprobe.mjs --db /data/firmlab.db --apply
```

La aplicación es transaccional e idempotente. No borra filas: conserva los datos originales del finding dentro de
su evidencia de revalidación, archiva el JSON completo de cada job modificado en
`evidence_revalidation_archive`, añade una nota auditable por imagen y mantiene la cronología original del job.
Los hallazgos de operador y los resultados que ya declaran `probeVersion: 2` quedan fuera. Una segunda simulación
debe informar cero candidatos.

## Refrescar las huellas de credenciales del corpus entre imágenes

Los resultados antiguos de `fsaudit`, `nvram` y `auxsecrets` pueden preceder a las huellas redactadas que alimentan
`credential_occurrence`. No hace falta repetir la campaña autónoma completa. Comprueba primero el alcance:

```bash
pnpm corpus:refresh-credentials --dry-run
```

Después ejecuta sólo esos tres proveedores y, cuando terminen, reconcilia el corpus desde los resultados ya
persistidos:

```bash
pnpm corpus:refresh-credentials
pnpm corpus:reindex
```

El cliente respeta la cola de jobs, distingue un proveedor ejecutado de una imagen sin entrada y no imprime
valores ni material de clave. `auxsecrets` conserva sus hallazgos históricos si la extracción ya no es legible;
un input ausente no se transforma en un negativo limpio. Usa `--concurrency`, `--poll-ms` y `--job-timeout-ms`
para ajustar una campaña, sin elevar la concurrencia del servidor.

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
| `FIRMLAB_FWHUNT_MODULE_BATCH` | Índice cero-based del lote FwHunt para ejecuciones directas/autónomas (por defecto 0). La ruta HTTP acepta `{"moduleBatch": n}` y, si se omite, reanuda el lote incompleto o avanza al primero pendiente sin aumentar el cap ni el presupuesto temporal; `{"restart": true}` descarta la acumulación anterior y vuelve al lote cero. Sólo acumula lotes si coinciden los hashes del corpus y del ranking, el denominador y la geometría del lote. Un lote con módulos fallidos permanece incompleto y se reintenta. |
| `FIRMLAB_RESEARCH_CACHE_TTL_HOURS` | Frescura de la caché de advisories (por defecto 24). Una entrada caduca se vuelve a consultar, nunca se sirve. |
| `FIRMLAB_ANGR_PYTHON` · `FIRMLAB_FWHUNT_PYTHON` | Intérpretes de sus venv propios. angr y fwhunt-scan **no** pueden compartir cierre de dependencias con chipsec. |
| `FIRMLAB_UEFI_IOC` · `FIRMLAB_DESOCK` | Feeds/preloads opcionales. Vacíos por defecto a propósito: nada fabricado. |
| `FIRMLAB_CAPTURE_AGENT_TOKEN` | Sin él, el canal del agente LAN está cerrado (401). |
| `NVD_API_KEY` | Sube el tope de consultas NVD de 6 a 40 y elimina la espera de cortesía de 6,5 s. |
| `GRYPE_DB_CACHE_DIR` | Dónde vive la base de vulnerabilidades de grype. Por defecto `$FIRMLAB_DATA_DIR/grype-db` — bajo el volumen de datos, no en `~/.cache`, para que sobreviva a un redespliegue. Es la de grype, respetada tal cual si el operador la fija. |

Nota: desde 2026-07-28 los flags de las lanes de red (`FIRMLAB_AGENT`, `FIRMLAB_RESEARCH`, `FIRMLAB_CAPTURE`…)
se **persisten en la base de datos** desde Ajustes › Privacidad. Que la variable no esté en el entorno no dice
nada del estado de la lane — consulta `/api/settings/flags` (campo `source`) o `/api/research/status`. La
precedencia y el valor por omisión de cada flag están en la sección siguiente.

## Política de red (decisión del operador, 2026-10-04)

**La investigación saliente de confianza está autorizada de forma habitual.** `FIRMLAB_RESEARCH` es la única lane
saliente que está **encendida cuando nadie dice nada** (`defaultOn` en `apps/api/src/flags.ts`): un despliegue que
no menciona la variable tiene el carril research activo. Hasta esta fecha la ausencia significaba apagado.

Lo que **no** cambia, y es lo que hace defendible ese valor por omisión:

- **Exposición**: la API escucha en loopback (compose del repo: `127.0.0.1:8799`) o detrás del router de Traefik
  con SSO (homelab). Nada de esta decisión abre un listener.
- **Destinos**: sólo la allowlist de `research/config.ts` (`api.osv.dev`, `services.nvd.nist.gov`, `www.cisa.gov`)
  más lo que el operador añada en `FIRMLAB_RESEARCH_ALLOWLIST`.
- **Qué sale**: nombres y versiones de componentes; nunca bytes del firmware, secretos ni claves. El ledger de
  egress declara un techo antes de cada ejecución y la reconcilia después.
- **Cuándo**: estar encendido autoriza una ejecución; no la lanza. Cada ejecución sigue siendo un `POST` por imagen.
- **Lanes que envían más**: `FIRMLAB_HASH_LOOKUP` (manda hashes sacados del firmware a terceros) y
  `FIRMLAB_CAPTURE` (adquisición activa en el cable) siguen siendo opt-in separados y atribuibles. El hash lookup
  además exige research **declarado** (`FIRMLAB_RESEARCH=1` en el entorno o un `1` guardado en Ajustes): el valor
  por omisión no cuenta como el primer consentimiento, y con research sin declarar el lookup queda *en espera*
  (`inertReason: 'parent_default'`).
- **Invitado emulado**: `FIRMLAB_EMU_ISOLATE` sigue encendido por omisión; un firmware emulado no recibe salida.

**Precedencia, para todas las lanes**: ajuste guardado (Ajustes › Privacidad) › entorno › valor por omisión del
catálogo. Cualquier valor declarado distinto de `1` es apagado. `/api/settings/flags` informa de cuál de los tres
decidió (`source: override | environment | default`) y de lo que diría el entorno sin el ajuste
(`environmentValue`). Para apagar research: `FIRMLAB_RESEARCH=0` en el compose, o el interruptor de Ajustes (que
guarda un `0` y gana al entorno).

**Estado efectivo del homelab**, leído el 2026-10-04 con `docker inspect firmlab` y `GET /api/settings/flags`
(build `7b6113e`, sin cambiar nada):

| Flag | Efectivo | Decidido por |
|---|---|---|
| `FIRMLAB_RESEARCH` | on | entorno (`1` en el compose) — el nuevo valor por omisión no cambia nada aquí |
| `FIRMLAB_HASH_LOOKUP` | on | ajuste guardado el 2026-07-28 (allowlist efectiva de cinco hosts) |
| `FIRMLAB_CAPTURE` · `FIRMLAB_CAPTURE_GATEWAY` | on | entorno |
| `FIRMLAB_AGENT` | on | entorno |
| `FIRMLAB_EMU_ISOLATE` | on | ajuste guardado `1` el 2026-09-29 (coincide con el valor por omisión) |
| `FIRMLAB_EMU_CONSOLE` | **off** | ajuste guardado `0` el 2026-09-05, aunque el compose diga `1` |
| `FIRMLAB_EMU_REPAIR` | off | valor por omisión |

Hash lookup y captura están encendidos en este despliegue por decisión previa del operador, no por esta política;
ésta no los activa ni los desactiva.

**Migración para otros despliegues.** Ninguna fila guardada se reescribe. Un `0` guardado o un `FIRMLAB_RESEARCH=0`
en el entorno siguen apagando el carril. Lo único que cambia de comportamiento es un despliegue **sin nada
declarado**, que pasa de apagado a encendido; si se quiere seguir sin red, hay que declararlo
(`FIRMLAB_RESEARCH=0`). Borrar un ajuste guardado de research ahora devuelve la lane a **encendido**, no a apagado.
Dos consecuencias más, cerradas en el commit siguiente:

- `dbUpdateAllowed` (`providers/sbom-db.ts`) decide con el mismo `decideFlag` que `loadResearchConfig`. Un
  despliegue sin nada declarado y sin base de grype aprovisionada **descarga** la base (varios GB, desde
  `grype.anchore.io`) en su primer job de SBOM; el log del job lo dice antes, y lo evitan una base aprovisionada o
  `FIRMLAB_RESEARCH=0`.
- Un `FIRMLAB_HASH_LOOKUP=1` (entorno o ajuste guardado) junto a research **sin declarar** estaba inerte antes del
  cambio y sigue inerte después: no sale ningún hash hasta que research se declare `1`. Ajustes lo muestra como
  «en espera» con un botón que guarda ese `1`. En el homelab research está declarado en el compose, así que su hash
  lookup sigue armado como antes.

## El carril SBOM no toca la red

`grype` viene con `db.auto-update: true` y `syft` y `grype` consultan si hay una versión nueva **de sí mismos**
en cada invocación. Medido el 2026-09-16 sobre el contenedor desplegado, con `FIRMLAB_RESEARCH`, `FIRMLAB_AGENT`
y `FIRMLAB_CAPTURE` sin poner: el contenedor arrancó a las 07:27 y a las 07:28 `import.json` de la caché de
grype registraba una base de 2 204 512 256 bytes traída de `grype.anchore.io`. La promesa «con todos los flags
apagados: sin red» era falsa.

Desde `providers/sbom-db.ts` los dos binarios corren con la actualización automática y el sondeo de versión
apagados, y con el carril research apagado grype sólo correlaciona contra una base **ya presente en disco**. Si no
la hay, el trabajo devuelve el SBOM completo y declara por escrito que la correlación no se intentó, con las dos
salidas. Nunca la descarga por su cuenta.

Aprovisionarla una vez (la descarga son varios GB; queda en el volumen y sobrevive al redespliegue):

```bash
docker exec firmlab sh -lc 'GRYPE_DB_CACHE_DIR=$FIRMLAB_DATA_DIR/grype-db grype db update'
docker exec firmlab sh -lc 'GRYPE_DB_CACHE_DIR=$FIRMLAB_DATA_DIR/grype-db grype db status'   # verificación
```

La alternativa es el carril research encendido, que autoriza a grype a descargarla desde `grype.anchore.io`. Basta
el valor por omisión: sin nada declarado, el primer job de SBOM sin base aprovisionada la descarga y el log del job
lo dice antes (ver la política de red); sólo `FIRMLAB_RESEARCH=0` o un `0` guardado en Ajustes lo impiden. Lo que
exige research **declarado** es el hash lookup, no esta descarga. Es una descarga de un sentido —no sale nada del
firmware, igual que el catálogo KEV—, y por eso no tiene flag propio: ese carril es el único que puede salir a
internet.

Una base vieja **se usa**, no se rechaza (`GRYPE_DB_VALIDATE_AGE=false`: grype descarta por defecto cualquiera de
más de cinco días), y su fecha de compilación viaja al resultado y a la tabla de la web. Cero CVE contra una base
de hace ocho meses no es la misma afirmación que cero CVE contra la de hoy.

## Red del host, captura y aislamiento del firmware emulado (2026-09-28)

> **Esto NO es lo que corre hoy.** Revisado el 2026-10-04: `~/homelab/firmlab/docker-compose.yml` (modificado por
> última vez el 2026-09-18) y el contenedor desplegado usan la red bridge **`proxy_net`**, sin `NET_ADMIN`/`NET_RAW`,
> sin `security_opt` (no hay `seccomp-firmlab.json` junto al compose), con `FIRMLAB_HOST=0.0.0.0` detrás de
> Traefik y sin puertos publicados en el host. Consecuencias medidas en ese contenedor:
>
> - `docker exec firmlab unshare -rn sh -c "ip -o link | wc -l"` devuelve `unshare failed: Operation not
>   permitted`. `isolate.ts` cae a sólo `prlimit` y un binario que ejecute el agente tiene la red del contenedor,
>   que sí sale a internet; por eso el aislamiento se declara `partial` y toda ejecución dinámica del agente
>   sigue esperando aprobación humana.
> - El aislamiento del invitado de emulación completa (`FIRMLAB_EMU_ISOLATE`, `restrict=on` de qemu) no depende
>   de `unshare` y sigue vigente.
> - La captura está encendida por entorno pero, en un bridge, no ve la LAN física; `FIRMLAB_CAPTURE_GATEWAY=1` es
>   una afirmación falsa mientras no exista ese enrutado (el propio compose lo advierte).
> - No hay ninguna variable `FIRMLAB_ISOLATE_*` en el entorno: rigen los valores por omisión de `isolate.ts`
>   (30 s de CPU, 512 MB, 64 MB por fichero, 45 s de reloj), no los límites subidos que se citan abajo.
>
> Lo que sigue describe la configuración en modo host documentada el 2026-09-28 — el objetivo si se quiere que la
> captura vea el segmento — y las dos condiciones sin las cuales el aislamiento queda parcial. Aplicarla es un
> cambio de despliegue del operador, no algo que haga esta documentación.

En modo host, el despliegue de esta estación correría con **`network_mode: host`** y
`NET_ADMIN`/`NET_RAW`, porque el carril de captura (descubrimiento LAN, spoof ARP/DNS, proxy OTA) necesita ver el
segmento de red; en una red bridge nunca lo ve. La API se fija a **`FIRMLAB_HOST=127.0.0.1`**: con red de host,
`0.0.0.0` la expondría a la LAN y a Tailscale. Comprobado entonces: por `192.168.1.175` y por la IP de Tailscale la
conexión se rechazaba; sólo respondía loopback. `deploy.sh` y `ui-expose.sh` reconocen el modo host (el que
escucha en `:8799` es el propio contenedor, y el sidecar de `:8899` reenvía a loopback).

Eso vuelve crítico el aislamiento de lo que el agente ejecuta (`providers/isolate.ts`): el proceso corre como root
con las capacidades de red del contenedor. El aislamiento de red es `unshare -rn` (un espacio de red vacío dentro de
un espacio de usuario: sólo `lo`, sin capacidades fuera). Docker lo impide por defecto por dos vías, y ambas se
resolvieron sin `CAP_SYS_ADMIN` —que haría del binario emulado un root con SYS_ADMIN—:

- **seccomp**: `seccomp-firmlab.json` junto al compose es el perfil por defecto de Docker (`moby/profiles`) más una
  única regla que permite `unshare`. Sin ella, `unshare` exige `CAP_SYS_ADMIN`.
- **AppArmor**: `unconfined`. `docker-default` deniega escribir el mapa de UID; un perfil propio requiere cargarlo
  como root en el host (`apparmor_parser`), pendiente.

**Si falta cualquiera de las dos, `isolate.ts` cae a sólo `prlimit` y el binario emulado tiene la red de la
máquina** — y la UI sigue diciendo `partial` en ambos casos. Verificación: `docker exec firmlab unshare -rn sh -c
"ip -o link | wc -l"` debe imprimir `1`. Límites por ejecución subidos a 120 s de CPU, 2 GB de espacio de direcciones,
256 MB por fichero y 180 s de reloj (`FIRMLAB_ISOLATE_*`): con 512 MB, `qemu-user` puede morir antes de arrancar.

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
