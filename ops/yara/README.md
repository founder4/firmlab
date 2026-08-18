# Corpus YARA operativo de FirmLab

Este directorio define el corpus del **operador**; FirmLab sigue sin incorporar firmas en su imagen. El despliegue
monta dos ficheros de solo lectura y los declara explícitamente en `FIRMLAB_YARA_RULES`:

1. **YARA Forge Core 20260816** — 5.034 reglas comunitarias normalizadas, deduplicadas y filtradas por YARA Forge.
2. **FirmLab operator firmware policy 1.0.0** — 6 heurísticas defensivas para scripts de firmware Linux.

Total fijado: **5.040 reglas en 2 ficheros**. El lock registra URL, versión, tamaños y SHA-256 tanto del ZIP como
del `.yar` extraído. `sync-yara-corpus.sh` no consulta `latest`, rechaza cualquier byte distinto y conserva el
directorio anterior al actualizar.

## Por qué Core y no Extended/Full

YARA Forge describe Core como el perfil de mayor precisión y menor impacto. Su configuración exige calidad ≥70,
score ≥65 y descarta reglas antiguas o de baja importancia; Extended y Full amplían hunting y cobertura a cambio de
más falsos positivos y coste. En un rootfs de firmware, donde abundan BusyBox, utilidades antiguas, SDKs y cadenas
reutilizadas, empezar por Full produciría más ruido que evidencia. La ampliación a Extended debe hacerse como un
experimento medido, no como actualización silenciosa del perfil de producción.

## Qué significan los matches

- Una regla de YARA Forge conserva `author`, `reference`, `source_url`, `license_url`, `score` y `quality` cuando la
  fuente los ofrece. FirmLab confirma el match de bytes y lo atribuye; **no confirma la familia de malware**.
- Las reglas externas sin un `meta.severity` soportado se muestran como `info` con `severityTriage=pending`. El
  match sigue confirmado en bytes, pero FirmLab no transforma la ausencia de una valoración upstream en `high`.
- Una regla `FIRMLAB_FW_*` es una heurística de política, no inteligencia de amenazas. Requiere señales compuestas,
  incluye `severity`, `confidence`, `scope` y `false_positive`, y debe revisarse en contexto.
- “0 matches” significa que estas reglas no dispararon sobre los ficheros cubiertos. No significa “firmware limpio”.
  La UI conserva `rulesDeclared/rulesApplied/rulesLost` y `filesFound/filesScanned` para que esa limitación sea visible.
- YARA Forge agrega reglas con licencias distintas; algunos upstream no declaran licencia y aparecen como
  `license_url = "N/A"`. Este corpus se usa de forma privada en el homelab. Antes de redistribuirlo o incluirlo en
  un producto, hay que revisar la licencia de cada fuente en los metadatos del bundle.

## Instalación y actualización

```bash
scripts/sync-yara-corpus.sh /Users/agfil/homelab/firmlab/yara-rules
```

El compose monta ese directorio en `/opt/firmlab-yara:ro` y configura exactamente:

```text
/opt/firmlab-yara/external/yara-forge-core.yar:/opt/firmlab-yara/local/operator-firmware-policy.yar
```

Para actualizar, primero se cambia `corpus.lock.json` con una release concreta, sus hashes, tamaños y denominadores;
después se ejecutan los tests y se revisan los deltas de matches sobre el corpus real antes de desplegar. Nunca se
acepta una descarga cuyo hash no coincida.

La vigilancia semanal `.github/workflows/yara-corpus-watch.yml` solo compara la release fijada con la última y deja
un artefacto JSON. Una novedad hace fallar el check para pedir revisión; **no modifica el lock ni despliega**. La
evaluación A/B completa se ejecuta deliberadamente en el homelab, donde existen YARA y los rootfs reales:

```bash
scripts/check-yara-release.sh --no-fail
scripts/evaluate-yara-candidate.sh latest /tmp/yara-candidate-report.md
```

El segundo comando verifica el digest publicado por GitHub, compila la candidata, exige tres positivos inertes,
compara identificadores añadidos/eliminados y escanea los mismos rootfs con corpus actual y candidato. Solo genera
un informe; promover una candidata sigue requiriendo editar el lock y ejecutar `sync-yara-corpus.sh` manualmente.

## Validación obligatoria

```bash
scripts/test-yara-policy.sh
scripts/test-yara-external.sh /ruta/yara-forge-core.yar
yara -w -e /ruta/yara-forge-core.yar /dev/null
```

Los fixtures exigen un match exacto para cada una de las seis heurísticas y cero matches en tres controles benignos.
El corpus externo debe disparar además sobre tres objetos inertes generados en `/tmp`: EICAR, un fragmento PHP que
activa una regla de webshell genérico y un fichero no ejecutable con forma ELF e indicadores Mirai publicados.
Además, la release se compila con el mismo YARA 4.2.3 del contenedor y se escanea contra varios rootfs reales. Los
matches reales se triagean antes de decidir si una regla se mantiene, baja de severidad o se retira.

## Fuentes y criterios

- YARA y su sintaxis de reglas, metadatos, tags, privadas y módulos: <https://github.com/VirusTotal/yara/blob/master/docs/writingrules.rst>
- YARA Forge, releases semanales y QA: <https://github.com/YARAHQ/yara-forge>
- Umbrales de Core/Extended/Full: <https://github.com/YARAHQ/yara-forge/blob/master/yara-forge-config.yml>
- MITRE ATT&CK T1105, T1059.004, T1095 y T1574.006 para transferencia, shell, protocolos y preload.
- MITRE CWE-78, CWE-295 y CWE-306 para inyección de comandos, validación TLS y autenticación ausente.

Blogs y foros sirven para descubrir indicadores, pero no entran directamente en producción: una regla nueva necesita
una referencia trazable, licencia revisada, fixture positivo, control negativo, compilación y medición sobre firmware
real. Esa barrera evita que un ejemplo copiado de un post se convierta en una alarma de alta severidad.
