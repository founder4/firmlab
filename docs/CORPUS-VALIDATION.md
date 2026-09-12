# Corpus de validación

Éste es el **corpus de validación**: el conjunto bloqueado de muestras sobre el que se mide la cobertura. No es el
corpus persistente entre imágenes (`apps/api/src/corpus.ts`, que devuelve *priors*) ni el corpus de reglas YARA;
los tres están desambiguados en `ARCHITECTURE.md`.

La cobertura del corpus se mide desde el mismo plan que ejecuta `opacidad`; no se mantiene una lista paralela de
proveedores en una hoja de cálculo. El comando siguiente cruza cada muestra viva con todas sus etapas aplicables,
distingue ejecución con hallazgos, ejecución vacía, degradación, falta de entrada, proveedor no construido y etapa
no ejecutada:

```bash
pnpm corpus:matrix --manifest ops/corpus/validation-samples.lock.json
```

Para convertir mínimos o estados en un gate:

```bash
pnpm corpus:matrix \
  --manifest ops/corpus/validation-samples.lock.json \
  --require-class uefi-bios=4 \
  --require-class rtos=4 \
  --forbid-status not-built
```

`ops/corpus/validation-samples.lock.json` fija tamaño, SHA-256, URL oficial y expectativa de identidad de las
muestras añadidas expresamente para regresión. Los blobs no se versionan en Git: viven en el corpus persistente del
despliegue y el manifiesto permite volver a obtener y verificar exactamente los artefactos públicos.

## Campaña de cobertura: qué merece ejecutarse

La matriz mide; no prioriza. El planificador lee la matriz viva y reparte cada celda sin cubrir según lo que la
propia etapa DECLARA que la cambiaría (`remedy`, de `apps/api/src/opacidad-remedy.ts`), nunca leyendo su nota en
prosa:

```bash
pnpm corpus:campaign                      # imprime el plan (Markdown; --format json para automatizar)
pnpm corpus:campaign --execute --limit 5  # ejecuta la cola, un escaneo autónomo cada vez, en el orden impreso
pnpm corpus:campaign --matrix m.json      # planifica sobre una matriz guardada (no permite --execute)
```

Las siete disposiciones y lo que significan para una campaña:

| Remedio | Disposición | ¿Lo resuelve una corrida? |
|---|---|---|
| `retry` | la corrida se rompió (fallo del arnés, campaña dedicada en curso, ejecutor que lanzó) | sí |
| `raise-bound` | un tope truncó una búsqueda que SÍ puede terminar | no tal cual: hay que subir el tope (o, en FwHunt, correr su campaña dedicada) |
| `install-tool` | falta la herramienta, el venv o el corpus de reglas en este despliegue | sí, tras cambiar el despliegue |
| `reacquire-input` | la entrada no está en estos bytes | no: hace falta otro artefacto |
| `settled` | miró donde podía y ésa es la respuesta para esta imagen | no, y no es un defecto |
| `unbounded-search` | inconcluyente por construcción (exploración simbólica, timeout por módulo) | no: «terminado» no es un estado que tenga |
| `defect` | la degradación es de FirmLab, no de la imagen | no: es código |

Tres reglas que el planificador sostiene, y conviene leerlas antes que cualquier número que imprima:

1. **Un remedio sin declarar es DESCONOCIDO, nunca `settled`.** Todo resultado persistido antes del campo no
   declara nada; esa celda se programa una vez, porque medirla es ejecutarla. Si tras una corrida que sí declara
   sigue sin declararlo, es un sitio que no puede decirlo — una cuestión de código, no deuda de campaña. Que la
   corrida declare o no se LEE de `remedySchema` en el resultado guardado; inferirlo de las celdas es incorrecto,
   porque la celda de FwHunt se recompone desde su campaña durable y haría parecer declarante a una corrida vieja.
2. **Una celda `no-input` se atribuye, no se cuenta.** Todas cuelgan de la extracción, y que sean ejecutables o no
   es un hecho sobre la celda de extracción de esa misma imagen. La etapa se localiza por su `provider`, no por el
   nombre visible, que cambia con el idioma de la interfaz.
3. **La unidad de trabajo es una imagen.** El escaneo autónomo recorre la cadena completa, así que una corrida
   resuelve a la vez todas las celdas ejecutables de esa muestra. El orden es clase → celdas ejecutables → coste
   MEDIDO (la duración real del último escaneo de esa imagen; una imagen sin coste medido va al final de su
   grupo, nunca con una media inventada).

Sólo `retry`, las etapas nunca ejecutadas y las celdas sin remedio declarado entran en la cola. `raise-bound` NO:
medido en la primera campaña real, el tope de pasos dinámicos de W9 devuelve la misma celda en cada corrida, así
que encolarla dejaría la imagen en la cola para siempre y el bucle se leería como progreso. Va en su propia
sección, con la etapa que nombra el tope.

Una imagen que falla no aborta la cola: se registra, se informa al final y el código de salida es 2.

### La campaña del 12 de septiembre de 2026 — lo que midió

Primera ejecución completa, contra el despliegue y las 26 muestras vivas. Antes: 411 celdas aplicables, 85
`degraded`, 33 `no-input`, 21 `not-run` — 106 celdas que una lectura ingenua contaría como deuda ejecutable.
Después de 26 escaneos (24 en la cola rankeada, ~30 min, más dos re-ejecuciones por corrección de build):

| Disposición | Celdas |
|---|---:|
| `covered` | 296 |
| `settled` | 37 |
| `open-ended` | 34 |
| `blocked-upstream` | 33 |
| `reacquire` | 7 |
| `undeclared` | 6 |
| `raise` | 5 |
| `defect` | 2 |
| `scan` (EJECUTABLE) | **1** |

La respuesta a «prioriza las degradadas desbloqueables» resultó ser que casi ninguna lo es: de 92 celdas
degradadas queda **una** que una corrida pueda cambiar (Tenda-Camera, `W5 · Reproduce (hw_test:system)`, donde
gdb no llegó a enlazar). Ninguna celda declara `install-tool`: a este despliegue no le falta ninguna herramienta.
Las 33 `no-input` cuelgan, las 33, de los tres artefactos que necesitan reacquisición —BeanView, Asus,
AliExpress, 11 celdas cada uno— y ninguna se desbloquea re-ejecutando.

Las 6 `undeclared` son las dos preguntas de código que el propio barrido levantó, y están en el backlog: tres
extracciones cuyo veredicto sólo distingue en prosa una brecha de extractor de un volumen truncado, y tres
rootfs sin `.ko` donde un kernel monolítico y un tallado incompleto son indistinguibles.

**El coste medido predice mal entre builds.** El plan presupuestó 213 min a partir de la duración real del último
escaneo de cada imagen y la cola tardó ~30. No es un fallo de la medida: DVRF tardó 1.261 s en su corrida de
septiembre y 217 s en ésta, sobre otra build. El número es honesto sobre lo que midió —la corrida anterior— y no
es una predicción de la siguiente.

Contra la baseline previa, el gate reporta **una** regresión de ejecución: `W5 · Binary-vuln (httpd)` de
TP-Link-WR940Nv6 pasa de `found` a `degraded`. No se perdió capacidad: la corrida nueva declara que sólo
300 de 3.047 imports estaban disponibles, así que la ausencia de taint no está establecida. La celda dice ahora
lo que la anterior callaba, y la regla del gate —que es deliberadamente conservadora— lo cuenta como regresión.

## Comparación entre campañas

Guarda la matriz JSON antes de ejecutar una campaña y compara los resultados posteriores con ese archivo:

```bash
pnpm corpus:matrix --format json --out /private/tmp/corpus-before.json
# Ejecutar la campaña prevista y esperar a que termine.
pnpm corpus:matrix --baseline /private/tmp/corpus-before.json --fail-on-regression \
  --out /private/tmp/corpus-comparison.md
```

La comparación usa SHA-256 de la imagen y nombre de etapa (`worker`), independientemente del ID, nombre de fichero
o posición. Acepta matrices de esquema 1; rechaza esquemas incompatibles, hashes ausentes y claves duplicadas para
evitar emparejamientos ambiguos. Un cambio de nombre de etapa aparece como retirada y alta, sin inferir equivalencia.

`--baseline` añade la comparación al Markdown o al campo `comparison` del JSON. Conserva todos los cambios de
estado y recuento, y distingue muestras nuevas/retiradas de etapas nuevas/retiradas en muestras comunes. Sólo las
transiciones de `found` o `ran-empty` a `degraded`, `no-input`, `not-run` o `not-built` son regresiones de ejecución.
`--fail-on-regression` requiere baseline y devuelve código 2 si existe alguna; sin ese flag, la comparación informa
sin bloquear. Entradas inválidas producen código 1. Los gates existentes de manifiesto/clase/estado siguen aplicándose.

Más hallazgos no demuestra mejora y menos hallazgos no demuestra regresión: pueden reflejar correcciones de falsos
positivos, cambios de reglas o pérdida de detección. Los recuentos ausentes permanecen desconocidos. Las retiradas
se muestran para revisión, pero no activan este gate; usa además `--manifest` para exigir las muestras bloqueadas.
Esta comparación detecta pérdida de ejecución, no demuestra exactitud semántica ni que todas las etapas se hayan
recalculado: se comparan los últimos resultados persistidos. Usa el mismo idioma y contrato de etapas en ambas campañas.

## Ampliación del 23 de agosto de 2026

| Muestra | Procedencia | Comprobación | Propósito |
|---|---|---|---|
| Framework Laptop 13 BIOS 3.04 capsule | [ZIP oficial de Framework](https://downloads.frame.work/bios/Framework_Laptop_13_Intel_Core_Ultra_Series1_capsule_signed_allsku_3.03_3.04_EFI.zip) | SHA-256 del ZIP y del miembro `.cap` | UEFI real de fabricante, no sólo OVMF |
| Contiki para STM32F4 Discovery | [escenario oficial de Renode](https://github.com/renode/renode/blob/master/scripts/single-node/stm32f4_discovery.resc) | tamaño y SHA-1 codificados en la URL, más SHA-256 local | detección RTOS y plataforma Cortex-M conocida |
| Zephyr button para STM32L072 | [prueba oficial de Renode](https://github.com/renode/renode/blob/master/tests/unit-tests/precise-pause.robot) | tamaño y SHA-1 codificados en la URL, más SHA-256 local | segunda familia RTOS y segundo MCU |
| Framework QMK ANSI 0.3.1 | [release oficial de Framework](https://github.com/FrameworkComputer/qmk_firmware/releases/tag/v0.3.1) | SHA-256 publicado en la release | firmware monolítico de hardware; regresión del clasificador |

El QMK se incorporó inicialmente como `unknown` para que el corpus conservara el fallo en vez de ocultarlo con una
etiqueta manual. El clasificador ya cierra esa regresión a partir de estructura binaria RP2040 (`boot2` con CRC y
vector XIP Cortex-M0+) y marcadores QMK corroborados: la expectativa bloqueada es ahora `rtos`/`arm`.

## Campaña FwHunt del BIOS Framework

La campaña se ejecuta y reanuda contra el cursor durable del servidor:

```bash
pnpm fwhunt:campaign --image ebf1c98c
```

La ejecución del 31 de agosto de 2026 asentó los 35/35 lotes: 404/409 módulos produjeron veredictos, 5 agotaron el
límite por módulo y permanecen como desconocidos, y ninguno quedó sin intentar. Corrieron 106/108 reglas; las dos
restantes declaran `target: bootloader` y no son aplicables a los módulos EFI tallados. Los 401 matches pertenecen
a la variante informativa de `BRLY-2022-028 (RsbStuffingCheck)` — indican ausencia del patrón de mitigación que esa
regla espera, no la presencia de un implante. El resultado conserva esa atribución y nunca lo resume como “BIOS
infectada” ni convierte los cinco fallos en negativos.

Cada lote es un job persistido y reanudable. Tras persistir uno nuevo, el servidor elimina el snapshot acumulativo
sustituido y vacía el agregado duplicado; los 51.308 veredictos finales se reconstruyen desde los 35 registros de
lote. Un fallo repetido sólo puede finalizarse si todas las posiciones del lote fueron intentadas, queda marcado
`finalizedWithFailures`, y el modo `--fail-fast` permite exigir parada en vez de continuar.

## Lectura de la matriz

- `✓`: la etapa se ejecutó y registró hallazgos; el sufijo numérico es su recuento.
- `○`: se ejecutó y no registró hallazgos para esa pregunta y ese límite.
- `△`: se ejecutó con cobertura degradada.
- `⊘`: era aplicable, pero faltó la entrada requerida.
- `◇`: era aplicable, pero el proveedor todavía no está construido.
- `·`: era aplicable y no se ejecutó.

La matriz Markdown se puede guardar como artefacto de revisión con `--out`, y `--format json` ofrece la misma fuente
para automatización. Los gates fallan con código 2 y enumeran todas las carencias, no sólo la primera.
