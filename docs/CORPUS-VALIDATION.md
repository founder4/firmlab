# Corpus de validación

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

## Lectura de la matriz

- `✓`: la etapa se ejecutó y registró hallazgos; el sufijo numérico es su recuento.
- `○`: se ejecutó y no registró hallazgos para esa pregunta y ese límite.
- `△`: se ejecutó con cobertura degradada.
- `⊘`: era aplicable, pero faltó la entrada requerida.
- `◇`: era aplicable, pero el proveedor todavía no está construido.
- `·`: era aplicable y no se ejecutó.

La matriz Markdown se puede guardar como artefacto de revisión con `--out`, y `--format json` ofrece la misma fuente
para automatización. Los gates fallan con código 2 y enumeran todas las carencias, no sólo la primera.
