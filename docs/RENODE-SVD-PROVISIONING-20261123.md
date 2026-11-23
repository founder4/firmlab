# Aprovisionamiento local de los SVD de Renode (2026-11-23)

Cierra el trabajo del backlog *"Pre-aprovisionar localmente los 13 SVD que las plataformas de Renode piden por
HTTPS"*. Desde 2026-10-02 Renode corre bajo `OFFLINE_RENODE_ENV`, así que el `ApplySVD @https://dl.antmicro.com/…`
de las plataformas se rechaza y se nombra en el resultado. Ahora esas plataformas pueden recibir su SVD **sin red en
tiempo de ejecución**, siempre que un operador lo haya aprovisionado antes y el fichero siga verificando.

## Qué cambia

- **`scripts/renode-svd-provision.mjs`** (nuevo, explícito, nunca implícito). Dado el directorio `platforms/` de
  Renode, encuentra cada `ApplySVD @http(s)://…` (los comentarios no cuentan), descarga cada SVD **de la URL exacta
  que nombra la plataforma** (solo `https:`, lista de hosts permitidos con `dl.antmicro.com` por defecto,
  redirecciones rechazadas, tope de 64 MiB) y lo guarda en `$FIRMLAB_DATA_DIR/renode-svd/` con un `manifest.json`
  (`url`, `file`, `sha256`, `size`, `contentType`, `fetchedAt`, `referencedBy`). Una entrada ya presente que sigue
  verificando se conserva sin volver a descargarla (`--refresh` fuerza la descarga); una descarga fallida se informa
  y **no** entra en el manifiesto. Las URL con la convención de Renode `-s_<tamaño>-<sha1>` (hoy, `S32K118`) se
  comprueban contra ese tamaño y SHA-1 — el único digest de origen disponible — y se rechazan si no coinciden.
  `--dry-run` lista referencias sin descargar ni escribir.
- **`apps/api/src/providers/renode-svd.ts`** (nuevo, puro salvo lecturas del manifiesto y escrituras en el
  directorio de trabajo de la ejecución; sin `store.js`). En cada ejecución recorre la cadena de `using` de la
  plataforma elegida con la misma regla que `scanRemoteResources`, decide cada URL contra el manifiesto y:
  - `local` **solo** si hay entrada, su `file` es un nombre de fichero simple dentro de `renode-svd/`, y el
    fichero, re-hasheado en esa ejecución, da el `sha256` del manifiesto. Entonces escribe en el directorio de
    trabajo de la ejecución una **copia** de los bytes verificados (lo que carga Renode es lo que se hasheó) y una
    copia de cada fichero de la cadena que tiene que cambiar — el que contiene el `ApplySVD` y los que lo incluyen —
    con el `ApplySVD` apuntando a la copia local y todos sus `using` reescritos a rutas absolutas (un fichero movido
    ya no puede resolver `./x`). Las plataformas instaladas no se tocan.
  - `missing` (sin manifiesto, sin entrada, o fichero ausente), `mismatch` (el hash no coincide) o `unusable`
    (nombre de fichero no seguro, tamaño sobre el tope, o una ruta que Renode no aceptaría sin comillas): se
    mantiene el comportamiento de hoy — la URL sigue en la plataforma, Renode intenta, el proxy loopback lo rechaza
    y el resultado lo nombra.
  - Nunca descarga.
- **`renode.ts` (`runRenode`) y `renode-ram.ts` (`runRenodeRamCapture`)** cargan `overlay.platformPath`.
  `remoteResourcesRefused` ya no incluye lo servido en local. Campo nuevo **`svdResolution?: SvdResolution[]`** (una
  fila por URL `ApplySVD` de la cadena: `url`, `status`, `reason?`, `expectedSha256?`, `observedSha256?`),
  **opcional para siempre**: un resultado almacenado antes no lo trae, y eso no significa "nada aprovisionado". La
  razón de la ejecución gana una frase que dice qué se sirvió en local y por qué lo demás no; la fila de hallazgos
  de Renode lleva `svdResolution` en `evidence` cuando no está vacía. El estado de prueba no cambia: sigue decidido
  por la salida UART real.
- Web: sin cambios. La razón (ya mostrada) lleva la información; no hacía falta un campo visible nuevo.

## Lo que no afirma

- `local` significa "los bytes aprovisionados, sin alterar", **no** "auténticos": salvo `S32K118` (SHA-1 y tamaño
  en la URL), antmicro no publica digest de estos ficheros. El `sha256` fija lo que el operador aceptó al
  aprovisionar.
- `local` habla de una **referencia en la cadena**, no de lo que Renode aplicó. Un fichero que redefine
  `sysbus: init:` sustituye el bloque `init` del que incluye. Medido: `cpus/stm32f429.repl` incluye `stm32f4.repl` y
  Renode solo aplica `STM32F429x` (el original solo intenta descargar ese); `cpus/stm32f412.repl` incluye
  `stm32f4.repl`, no aplica ningún SVD y el original no intenta ninguna descarga. Es el mismo alcance que la lista de
  rechazados ha tenido siempre (`scanRemoteResources` también los cuenta), y queda como sobre-informe conocido.
- Qué cambia el SVD en el comportamiento de periféricos o en el arranque **no se ha medido** (sin firmware real en
  esta tarea).

## Inventario medido (Renode 1.17.0 en `firmlab-firmware:latest`, revisión `da3d24f`)

El backlog decía 13 (contado con Renode 1.16.1). En la instalación actual: **15 ficheros de plataforma** con
`ApplySVD`, **14 URL distintas** (`STM32F7x6` lo comparten `stm32f746` y `stm32f777`); siguiendo `using`,
**25 plataformas** del catálogo (229 `.repl`) referencian alguna, y **24** la intentan descargar al cargar
(`stm32f412` no, ver arriba).

Descargado el 2026-11-23 desde `https://dl.antmicro.com/projects/renode/` (dos descargas independientes, en el host
y dentro de un contenedor desechable, dieron los mismos 14 sha256):

| URL (relativa) | bytes | sha256 | referida por |
|---|---|---|---|
| `S32K118.svd-s_4356973-8b6f35da75a942816cd0d662d28a690e8b3484e3` | 4356973 | `7f602fcd050449c39b1bb04fb651b657dbc775737d7ab7d54442cd9c24848ea6` | `cpus/s32k118.repl` (SHA-1+tamaño de la URL verificados) |
| `svd/ATSAME70Q21.svd` | 6211467 | `2906bec73828b9e7eeb6d66d23b612bc07529cfc985242d0fb2effcfa33e26bb` | `cpus/sam_e70.repl` |
| `svd/FE310.svd.gz` | 5786 | `a7d96f7f152eeb9f078c00909160d5902527e67aa54313da2895b8f9780fc333` | `cpus/sifive-fe310.repl` |
| `svd/MAX32650.svd.gz` | 72918 | `8e7a8c936b9d67ac3943dd49fa2bbc4e4551b9bcd32841f489ceda6dd3dab8f3` | `cpus/max32652.repl` |
| `svd/MK64F12.svd.gz` | 193508 | `081039ece2b33e25669cff2872d3513b18fd705348d67d019e6d819927250c01` | `cpus/nxp-k6xf.repl` |
| `svd/NRF52840.svd.gz` | 99060 | `e5249c6a4a4bc66adbf644b97cff3b497cfdb9727eac0b3f77be576d2edd7db4` | `cpus/nrf52840.repl` |
| `svd/STM32F103.svd.gz` | 47847 | `c8f03172f4dee4c233b450a7ac49d7e44e75fb4097e8c462b0d028489a39b5ec` | `cpus/stm32f103.repl` |
| `svd/STM32F40x.svd.gz` | 74195 | `d71b3e11c870ec83346eb994e98a57c5eacdf0082d2949ed495d7a3828bf41ec` | `cpus/stm32f4.repl` |
| `svd/STM32F429x.svd.gz` | 80817 | `d0a24f24db3b0f8a5918f034b18bbf696d8a48dec6755f16dfdf748cff3781fc` | `cpus/stm32f429.repl` |
| `svd/STM32F7x6.svd.gz` | 98356 | `4e7103fe3543ba690fb2a99436d7464442dee9a4edc4bf9274f1807dc60214d8` | `cpus/stm32f746.repl`, `cpus/stm32f777.repl` |
| `svd/STM32L0x1.svd` | 588308 | `34080feee6ba2ea5f4b66a5148e76b48f76be2cdb7b5f84748dd195ad2018b28` | `cpus/stm32l071.repl` |
| `svd/STM32L1xx.svd.gz` | 35312 | `a0efa57cc3efa18746e5f1c0d10e36add6efbf6f8fdf04e0d575167db9a00b31` | `cpus/stm32l151.repl` |
| `svd/STM32L552.svd` | 2964972 | `5974f84507f310518d636bb8eacfcad04bd329dba5e9642cf71a12ccfe47e4d5` | `cpus/stm32l552.repl` |
| `svd/STM32W108.svd.gz` | 11469 | `2363c5a7d9b749c09048b8b7a2914b2b46bb8343374bfafa3235e1279baf226d` | `cpus/stm32w108.repl` |

Plataformas cuya cadena llega a alguna: `boards/{arduino_nano_33_ble, max32652-evkit, nrf52840dk_nrf52840,
nucleo_f767zi, ramn, stm32f4_discovery-kit, stm32f4_discovery, stm32f7_discovery-bb}` y `cpus/{max32652, nrf52840,
nxp-k6xf, s32k118, sam_e70, sifive-fe310, stm32f103, stm32f4, stm32f412, stm32f429, stm32f746, stm32f777, stm32l071,
stm32l072, stm32l151, stm32l552, stm32w108}`.

### Licencias (según lo que declara cada fichero)

Origen: el espejo de antmicro; los ficheros son los SVD de los fabricantes. Declaran licencia en el propio fichero:
`MK64F12` (Freescale) y `S32K118` (NXP) — BSD-3-Clause en `<licenseText>`; `NRF52840` — `<licenseText>` de Nordic
Semiconductor; `ATSAME70Q21` — "SAM Software Package License" de Atmel en la cabecera (redistribución con aviso);
`STM32L552` — `SPDX-License-Identifier: Apache-2.0`, STMicroelectronics 2024. Los demás (`STM32F103`, `STM32F40x`,
`STM32F429x`, `STM32F7x6`, `STM32L0x1`, `STM32L1xx`, `STM32W108`, `MAX32650`, `FE310`) **no declaran licencia** en las
primeras líneas ni en `<licenseText>`. Se guardan en el volumen de datos para uso local de Renode; no se redistribuyen
ni se añaden al repositorio.

## Qué se validó

Todo contra `firmlab-firmware:latest` (`da3d24f`, Renode 1.17.0) en contenedores `docker run --rm --network none`
con el `dist` candidato de la API montado de solo lectura sobre `/app/apps/api/dist`, el directorio de datos de
prueba montado en `/data` (solo lectura) y un listener Node en `127.0.0.1:9` — el puerto al que `OFFLINE_RENODE_ENV`
apunta todos los proxies — que registra cada conexión y su primera línea (el método del 2026-10-02). Ni la imagen
ni el contenedor `firmlab` ni su volumen se tocaron; no se construyó ninguna imagen.

1. **Matriz de carga, 25 plataformas, con lo aprovisionado**: `prepareSvdOverlay` real + `offlineRenodeEnv` real +
   `mach create; machine LoadPlatformDescription @<overlay>; quit`. Las 25 cargaron la copia reescrita; 24
   imprimieron `sysbus: Loaded SVD: … Name: <SVD esperado>` (las `.gz` las descomprime Renode a un temporal propio);
   `stm32f412` ninguno (igual que el original). **0 líneas `Downloading`, 0 `[ERROR]`, 0 conexiones al listener.**
2. **La misma matriz sin aprovisionar** (directorio de datos vacío): 24 plataformas con 5 `Downloading` y 3
   `[ERROR]` cada una y **3840 líneas en el listener** (`CONNECT dl.antmicro.com:443`, 80 por plataforma);
   `stm32f412`, 0. Es decir, el comportamiento de hoy, intacto cuando no hay nada aprovisionado.
3. **Hash alterado** (un byte añadido a `STM32F40x.svd.gz`): `stm32f4_discovery` → `mismatch`, carga el original,
   160 líneas en el listener (rechazado como hoy); `stm32f429` → `STM32F429x` `local` y `STM32F40x` `mismatch`;
   `stm32l071` → `local`.
4. **`runRenode` real de punta a punta** (`stm32f4_discovery` explícita, firmware de relleno de 1 KiB — no es una
   imagen, así que no se espera ni se afirma arranque; `blocked_by_platform`, aislamiento `partial`): con lo
   aprovisionado, `svdResolution: [{status:'local', expectedSha256 = observedSha256 = d71b3e11…}]`,
   `remoteResourcesRefused: []`, 0 conexiones; con el hash alterado, `mismatch` con ambos hashes,
   `remoteResourcesRefused` con la URL y 160 líneas en el listener.
5. **La receta del operador** en un contenedor desechable de la misma imagen (red por defecto, volumen de datos de
   prueba): 14 descargadas, 0 fallos, mismos 14 sha256 que en el host.

Tests: `apps/api/src/providers/renode-svd.test.ts` (vitest: parseo, comentarios, reescritura, manifiesto, decisión
local/missing/mismatch/unusable, overlay con cadena raíz-relativa y `./`, mismatch parcial, ruta con espacios,
frases, evidencia) y `scripts/renode-svd-provision.test.mjs` (`node --test`, `fetch` inyectado: URL exactas,
`redirect: 'error'`, lista de hosts, entrada verificada conservada, fichero alterado re-descargado, fallo fuera del
manifiesto, `--dry-run`, digest `-s_<tamaño>-<sha1>`).

## Qué NO se validó

- Ningún arranque de firmware real con el SVD aplicado (el Zephyr STM32L072 del corpus no estaba disponible aquí):
  qué cambia el SVD en periféricos/registro de Renode sigue **sin medir**.
- `runRenodeRamCapture` no se ejecutó en contenedor; comparte `prepareSvdOverlay` y queda cubierto por los tests
  unitarios y por la revisión de tipos.
- Conexiones directas que ignoren los proxies: bajo `--network none` fallarían en silencio y no se contaron (misma
  limitación que el 2026-10-06).
- El despliegue: **no se aprovisionó** nada en el contenedor desplegado ni en su volumen. Es un paso de operador.

## Paso de operador (despliegue)

El script no viaja en la imagen (`scripts/` no se copia a `firmlab-firmware`), así que se copia al contenedor y se
ejecuta contra su propio Renode y su propio `FIRMLAB_DATA_DIR` (`/data`, el volumen). Descarga ~15 MB desde
`dl.antmicro.com` una sola vez; no envía nada del firmware.

```bash
docker cp scripts/renode-svd-provision.mjs firmlab:/tmp/renode-svd-provision.mjs
docker exec firmlab sh -lc 'node /tmp/renode-svd-provision.mjs --platforms /opt/renode/platforms --data-dir "$FIRMLAB_DATA_DIR"'
docker exec firmlab sh -lc 'cat "$FIRMLAB_DATA_DIR/renode-svd/manifest.json"'   # verificación: 14 entradas
```

No necesita reinicio: cada ejecución de Renode lee el manifiesto y re-hashea. Para revertir basta borrar
`$FIRMLAB_DATA_DIR/renode-svd/` (todo vuelve a `missing`, es decir, al rechazo de hoy). Tras actualizar Renode,
repetir el comando: las URL nuevas se descargan y las ya verificadas se conservan.
