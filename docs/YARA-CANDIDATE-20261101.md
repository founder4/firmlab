# Evaluación YARA Forge Core 20261101 (y 20261103) frente al lock 20261011

Evaluado el 2026-11-03 desde la estación Kali (no el homelab). **Lock intacto: la evidencia no autoriza promover.**

## Versiones y digests (verificados localmente con `sha256sum`)

| Release | Publicada | ZIP sha256 | ZIP bytes | `.yar` sha256 | `.yar` bytes | Reglas (contadas = declaradas) |
|---|---|---|---|---|---|---|
| 20261011 (lock) | 2026-10-11 | `bf0cc68e…035147` | 1748575 | `f871f618…ab8c12` | 7889825 | 5145 |
| 20261101 (detectada el 02-11) | 2026-11-01T06:20Z | `c6d6915f8253bb8e9a8e282e67ae9a45d42587c1349f8bd7f7167bee651c783b` | 1744645 | `ce1ee2bea8a199a1c4cc383729126801748de42583655c9194b3dbad7a4633f0` | 7846061 | 5134 |
| 20261103 (latest hoy) | 2026-11-03T13:51Z | `be0d5a49d2a8cd37713f5a8c4e5a3c4235061242bc12240e18c69934fa47bb59` | 1744269 | `4f5cca2cfce626518a0eb0d5af26749f73b79a6bf92f8630b1772dc2b5f4c5a2` | 7844186 | 5133 |

La baseline 20261011 descargada coincide byte a byte con `ops/yara/corpus.lock.json`. Las candidatas coinciden
con el digest que publica GitHub. 20261103 = 20261101 menos `MALPEDIA_Win_Triback_Loader_Auto`; cualquier
promoción debería apuntar a la más reciente.

## Diferencias 20261011 → 20261101

Por nombre y por `meta.logic_hash` (hash de strings+condición que emite YARA Forge; separa lógica de metadatos):
**103 añadidas, 114 eliminadas, 37 con lógica cambiada** (→ 20261103: 103 / 115 / 37).

- Eliminadas por fuente: 48 SIGNATURE_BASE, 48 LOLDRIVERS (drivers Windows), 7 TRELLIX_ARC, 4 CAPE, 3 COD3NYM,
  2 DITEKSHEN, 1 SEKOIA, 1 RUSSIANPANDA. Varias SIGNATURE_BASE son renombrados (`*_1` → sin sufijo).
- Añadidas: 46 VOLEXITY, 42 SIGNATURE_BASE, 6 CAPE, 5 COD3NYM, 3 RUSSIANPANDA, 1 SEKOIA.
- Relevantes para Linux/ELF: lógica cambiada en `AVASTTI_Manjusaka_Payload_Elf`; añadida
  `VOLEXITY_Webshell_Php_Icescorpion`. Ninguna regla Mirai/Gafgyt/IoT añadida ni eliminada.

## Controles positivos — BLOQUEANTE

| Control | 20261011 | 20261101/20261103 |
|---|---|---|
| `TRELLIX_ARC_Malw_Eicar` | `564b0592…` | **eliminada** |
| `SEKOIA_Generic_Php_Webshell` | `617264a7…` | idéntica |
| `SIGNATURE_BASE_MAL_ARM_LNX_Mirai_Mar13_2022` | `a44a6174…` | idéntica |

Las 7 TRELLIX_ARC eliminadas comparten `modified = 2020-08-14`, quality 70 y score 75 (en el umbral): salen por
la selección de YARA Forge, no por un cambio de lógica. La única regla EICAR restante es
`ELCEEF_EICAR_Encrypted_ZIP`, que no dispara sobre el EICAR plano. Por tanto `scripts/test-yara-external.sh`
**fallará** con cualquiera de las dos candidatas hasta elegir y justificar un control EICAR sustituto (o retirar
ese control con razón escrita). No se ha cambiado el script: elegir el control es una decisión de revisión.

## A/B sobre corpus real — NO EJECUTADO

El A/B obligatorio (README) se hace en el homelab (`/Users/agfil/homelab`, contenedor `firmlab`, API `:8899`), que
no es esta máquina: aquí no hay contenedor en marcha ni `~/homelab`. Existe un corpus local en el volumen
`firmlab_firmlab-data` (9 extracciones, 436 MB, sin modificar desde 2026-09-28) y la imagen
`firmlab-firmware:latest` (rev `8cb2e1c`, YARA 4.2.3), pero no se ha escaneado por falta de tiempo; no es un
resultado negativo.

## Defecto del evaluador encontrado (sin corregir)

`scripts/evaluate-yara-candidate.sh` enumera rootfs con `for id in $(curl … "$API_BASE/images" …)`. `set -e` no
cubre la sustitución en la lista de un `for` (reproducido: `for x in $(false)` continúa), así que con la API caída
el informe dice «Rootfs A/B: 0 · matches 0/0 · nuevos/perdidos 0/0», indistinguible de una comparación limpia.
Además toma la baseline de `~/homelab/...` y de `/opt/firmlab-yara` sin verificarla contra el lock, y sólo compara
nombres (no ve las 37 reglas con lógica cambiada). Registrado en `docs/BACKLOG.md`.

## Comandos

```bash
scripts/check-yara-release.sh --no-fail      # latest=20261103, ruleDelta=-12
curl -fsS 'https://api.github.com/repos/YARAHQ/yara-forge/releases?per_page=8'   # digests y totales Core
curl -fsSL https://github.com/YARAHQ/yara-forge/releases/download/<tag>/yara-forge-rules-core.zip -o core.zip
unzip -p core.zip packages/core/yara-rules-core.yar > core.yar && sha256sum core.zip core.yar
# nombre<TAB>logic_hash por regla; comm/join entre releases para añadidas/eliminadas/lógica cambiada
awk 'match($0,/^[[:space:]]*rule[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/){n=$2} /logic_hash =/{v=$3; gsub(/"/,"",v); print n "\t" v}' core.yar | sort -u
```
