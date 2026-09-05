# FirmLab — matriz de validación del corpus

Generada: 2026-09-05T16:27:09.706Z

25 muestras · 8 clases · 390 celdas de etapa aplicable.

## Leyenda

| Marca | Estado | Significado |
|---:|---|---|
| ✓ | `found` | ejecutada con hallazgos |
| ○ | `ran-empty` | ejecutada sin hallazgos para esta etapa |
| △ | `degraded` | ejecutada con cobertura reducida |
| ⊘ | `no-input` | aplicable, pero sin la entrada requerida |
| ◇ | `not-built` | aplicable, pero el proveedor no está construido |
| · | `not-run` | aplicable y no ejecutada |

Un número tras `✓` es el recuento de hallazgos registrado por esa etapa.

## Resumen

| Estado | Celdas |
|---|---:|
| `found` | 130 |
| `ran-empty` | 142 |
| `degraded` | 85 |
| `no-input` | 33 |
| `not-built` | 0 |
| `not-run` | 0 |

## baremetal

Muestras: `Pico-RP2040-CTF`.

| Etapa | Pico-RP2040-CTF |
|---|---:|
| W7 · Bare-metal / RTOS | ○ |
| Static · Certificates | ○ |
| Static · U-Boot env | ○ |
| Static · Device tree | △ |
| Cross-check · Kernel command line | ○ |
| Recon · FCC-ID | ○ |
| W3 · NVRAM store | ○ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `Pico-RP2040-CTF` | `79cb27d3` | riscv | Pico-RP2040_CTF.bin | 7/7 |

## embedded-linux

Muestras: `AliExpress-Repeater`, `Asus-Router`, `BeanView-Camera`, `DVRF-v03`, `IMOU-Ranger-2C`, `Obsbot-meetse-OA-E-P`, `Tenda-Camera`, `TP-Link-MR3220-v2-3-`, `TP-Link-WDR3600v1-3-`, `TP-Link-WR940Nv6-3-2`.

| Etapa | AliExpress-Repeater | Asus-Router | BeanView-Camera | DVRF-v03 | IMOU-Ranger-2C | Obsbot-meetse-OA-E-P | Tenda-Camera | TP-Link-MR3220-v2-3- | TP-Link-WDR3600v1-3- | TP-Link-WR940Nv6-3-2 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| W1 · Extraction | △ | △ | △ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| W3 · Credentials & secrets | ⊘ | ⊘ | ⊘ | ✓4 | ✓3 | ✓1 | ✓2 | ✓3 | ✓2 | ✓3 |
| W3 · Credential cross-reference | ⊘ | ⊘ | ⊘ | △ | △ | △ | ✓1 | ✓2 | ✓1 | ✓1 |
| W3 · Auxiliary-partition secrets | ○ | ○ | ○ | ✓6 | ✓8 | ○ | ✓4 | ○ | ○ | ✓4 |
| W2 · SBOM / CVE | ⊘ | ⊘ | ⊘ | ✓18 | ✓24 | ○ | ○ | ○ | ○ | ○ |
| W2 · Component fingerprint (bundled n-days) | ⊘ | ⊘ | ⊘ | ✓3 | ✓1 | △ | ✓3 | ✓2 | ✓3 | ✓3 |
| Static · YARA rule corpus | ⊘ | ⊘ | ⊘ | ✓1 | ✓1 | ✓1 | ✓1 | ✓1 | ✓1 | ✓1 |
| W2 · Kernel posture | △ | △ | △ | ✓4 | ✓2 | ✓2 | ✓2 | ✓4 | ✓4 | ✓4 |
| Recon · Service enumeration | ⊘ | ⊘ | ⊘ | ○ | ✓2 | ○ | ✓1 | ✓2 | ✓2 | ✓2 |
| Static · Certificates | ○ | ○ | ○ | ✓6 | ✓2 | ○ | ○ | ○ | ○ | ✓2 |
| Static · Component map | ⊘ | ⊘ | ⊘ | ✓1 | ✓1 | ✓1 | ✓1 | ✓1 | ✓1 | ✓1 |
| Static · U-Boot env | ✓2 | ○ | ✓2 | ○ | ✓2 | ○ | ✓2 | ○ | ○ | ○ |
| Static · Device tree | △ | △ | △ | △ | △ | ✓5 | ✓6 | △ | △ | △ |
| Cross-check · Kernel command line | ○ | ○ | ○ | ○ | ○ | ○ | ✓1 | ○ | ○ | ○ |
| Recon · FCC-ID | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| W3 · NVRAM store | ✓15 | ○ | ✓3 | ○ | ✓2 | ○ | ✓2 | ○ | ○ | ○ |
| W4 · Web attack-surface (taint) | ⊘ | ⊘ | ⊘ | △ | △ | △ | △ | △ | △ | △ |
| W5 · Binary-vuln sweep | ⊘ | ⊘ | ⊘ | ✓60 | ✓19 | ○ | ✓40 | ✓49 | ✓60 | ✓49 |
| W5 · Kernel-module surface | ⊘ | ⊘ | ⊘ | ✓2 | △ | △ | △ | ○ | ✓6 | ✓1 |
| W5 · Export reachability | ⊘ | ⊘ | ⊘ | ○ | ✓5 | ✓1 | ✓2 | ○ | ○ | ○ |
| ISTG-FW · Update-path integrity | △ | △ | △ | ✓1 | ✓3 | ✓2 | ✓3 | ✓3 | ✓3 | ✓3 |
| W5 · Reachability (store_domain_sid) | — | — | — | △ | — | — | — | — | — | — |
| W5 · Reachability (store_machine_password) | — | — | — | △ | — | — | — | — | — | — |
| W5 · Reachability (diag_tracertbutton) | — | — | — | △ | — | — | — | — | — | — |
| W5 · Cmd-exec reachability (diagwpsbutton) | — | — | — | ✓1 | — | — | — | — | — | — |
| W5 · Cmd-exec reachability (diag_tracertbutton) | — | — | — | ✓1 | — | — | — | — | — | — |
| W5 · Reproduce (diagwpsbutton:system) | — | — | — | △ | — | — | — | — | — | — |
| W5 · Reproduce (diag_tracertbutton:system) | — | — | — | △ | — | — | — | — | — | — |
| W5 · Binary-vuln (telnetd) | — | — | — | — | ✓2 | — | — | — | — | — |
| W5 · Reachability (mnt_jffs2) | — | — | — | — | △ | — | — | — | — | — |
| W5 · Reachability (mtd2bin) | — | — | — | — | ✓2 | — | — | — | — | — |
| W5 · Reachability (jffs2dump) | — | — | — | — | △ | — | — | — | — | — |
| W5 · Cmd-exec reachability (qr) | — | — | — | — | ✓2 | — | — | — | — | — |
| W5 · Cmd-exec reachability (busybox) | — | — | — | — | △ | — | — | — | — | — |
| W5 · Reproduce (mtd2bin:strcpy) | — | — | — | — | △ | — | — | — | — | — |
| W5 · Reproduce (qr:popen) | — | — | — | — | △ | — | — | — | — | — |
| W5 · Reachability (hw_test) | — | — | — | — | — | — | △ | — | — | — |
| W5 · Reachability (motor_test) | — | — | — | — | — | — | △ | — | — | — |
| W5 · Reachability (wifi_test) | — | — | — | — | — | — | △ | — | — | — |
| W5 · Cmd-exec reachability (factory) | — | — | — | — | — | — | ✓2 | — | — | — |
| W5 · Cmd-exec reachability (hw_test) | — | — | — | — | — | — | ✓1 | — | — | — |
| W5 · Reproduce (factory:system) | — | — | — | — | — | — | △ | — | — | — |
| W5 · Reproduce (hw_test:system) | — | — | — | — | — | — | △ | — | — | — |
| W5 · Binary-vuln (httpd) | — | — | — | — | — | — | — | ✓3 | ✓3 | ✓3 |
| W5 · Reachability (httpd) | — | — | — | — | — | — | — | ✓2 | △ | △ |
| W5 · Reachability (apstart) | — | — | — | — | — | — | — | △ | — | — |
| W5 · Reachability (pktlogconf) | — | — | — | — | — | — | — | ✓2 | ✓2 | — |
| W5 · Cmd-exec reachability (httpd) | — | — | — | — | — | — | — | ✓2 | ✓2 | ✓2 |
| W5 · Cmd-exec reachability (modem_scan) | — | — | — | — | — | — | — | ✓1 | — | — |
| W5 · Reproduce (httpd:strcpy) | — | — | — | — | — | — | — | △ | — | — |
| W5 · Reproduce (pktlogconf:strcpy) | — | — | — | — | — | — | — | △ | △ | — |
| W9 · Re-plan (cap reached) | — | — | — | — | — | — | — | △ | △ | — |
| W5 · Reachability (radartool) | — | — | — | — | — | — | — | — | ✓2 | — |
| W5 · Cmd-exec reachability (radvdctl) | — | — | — | — | — | — | — | — | △ | △ |
| W5 · Reproduce (pktlogconf:sprintf) | — | — | — | — | — | — | — | — | △ | — |
| W5 · Reachability (iwpriv) | — | — | — | — | — | — | — | — | — | △ |
| W5 · Reachability (radvdctl) | — | — | — | — | — | — | — | — | — | ✓2 |
| W5 · Reproduce (radvdctl:strcpy) | — | — | — | — | — | — | — | — | — | △ |
| W5 · Reproduce (httpd:system) | — | — | — | — | — | — | — | — | — | △ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `AliExpress-Repeater` | `e86d7094` | mips | AliExpress-Repeater.bin | 10/21 |
| `Asus-Router` | `106bc83d` | unknown | Asus-Router.bin | 10/21 |
| `BeanView-Camera` | `1ec1802c` | arm | BeanView-Camera.bin | 10/21 |
| `DVRF-v03` | `57c12e70` | mipsel | DVRF_v03.bin | 28/28 |
| `IMOU-Ranger-2C` | `f3618503` | arm | IMOU-Ranger-2C.bin | 29/29 |
| `Obsbot-meetse-OA-E-P` | `4cd8d78c` | arm | Obsbot_meetse_OA_E_PW204_4.6.4.1_release.bin | 21/21 |
| `Tenda-Camera` | `2b5fe786` | arm | Tenda-Camera.bin | 28/28 |
| `TP-Link-MR3220-v2-3-` | `d2587cb0` | mips | TP-Link-MR3220_v2_3.17.1.bin | 30/30 |
| `TP-Link-WDR3600v1-3-` | `398d50ef` | mips | TP-Link-WDR3600v1_3.14.3.bin | 30/30 |
| `TP-Link-WR940Nv6-3-2` | `c42ab6f2` | mips | TP-Link-WR940Nv6_3.20.1.bin | 29/29 |

## encrypted

Muestras: `GE800v1-1-3-3-encryp`.

| Etapa | GE800v1-1-3-3-encryp |
|---|---:|
| W8 · Encrypted-blob | ✓3 |
| Static · Certificates | ○ |
| Static · U-Boot env | ○ |
| Static · Device tree | △ |
| Cross-check · Kernel command line | ○ |
| Recon · FCC-ID | ○ |
| W3 · NVRAM store | ○ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `GE800v1-1-3-3-encryp` | `502fe7a7` | unknown | GE800v1_1.3.3_encrypted-OTA.bin | 7/7 |

## esp-soc

Muestras: `ESP32-DevBoard-esp32`.

| Etapa | ESP32-DevBoard-esp32 |
|---|---:|
| W6 · ESP / IoT-SoC | ✓4 |
| Static · Certificates | ○ |
| Static · U-Boot env | ○ |
| Static · Device tree | △ |
| Cross-check · Kernel command line | ○ |
| Recon · FCC-ID | ○ |
| W3 · NVRAM store | ○ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `ESP32-DevBoard-esp32` | `9858853b` | xtensa | ESP32-DevBoard_esp32_dump.bin | 7/7 |

## openwrt-fit-ubi

Muestras: `GL-iNet-BE3600-4-9-0`.

| Etapa | GL-iNet-BE3600-4-9-0 |
|---|---:|
| W1 · Extraction | ○ |
| W3 · Credentials & secrets | ✓4 |
| W3 · Credential cross-reference | △ |
| W3 · Auxiliary-partition secrets | ○ |
| W2 · SBOM / CVE | ✓484 |
| W2 · Component fingerprint (bundled n-days) | ✓4 |
| Static · YARA rule corpus | ✓1 |
| W2 · Kernel posture | ✓5 |
| Recon · Service enumeration | ✓4 |
| Static · Certificates | ✓148 |
| Static · Component map | ✓1 |
| Static · U-Boot env | ○ |
| Static · Device tree | ✓2 |
| Cross-check · Kernel command line | ○ |
| Recon · FCC-ID | ○ |
| W3 · NVRAM store | ○ |
| W4 · Web attack-surface (taint) | ✓4 |
| W5 · Binary-vuln sweep | ✓60 |
| W5 · Kernel-module surface | ✓29 |
| W5 · Export reachability | ○ |
| ISTG-FW · Update-path integrity | ✓6 |
| W5 · Binary-vuln (dnsmasq) | ○ |
| W5 · Binary-vuln (dropbear) | ○ |
| W5 · Binary-vuln (uhttpd) | ○ |
| W5 · Reachability (dhcpdiscover) | △ |
| W5 · Reachability (dumpimage) | △ |
| W5 · Reachability (mkimage) | △ |
| W5 · Cmd-exec reachability (carrier-monitor) | △ |
| W5 · Cmd-exec reachability (askfirst) | ✓1 |
| W9 · Re-plan (cap reached) | △ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `GL-iNet-BE3600-4-9-0` | `81154df7` | arm64 | GL.iNet-BE3600_4.9.0.bin | 30/30 |

## rtos

Muestras: `Contiki-STM32F4-Disc`, `dragon-reto-stripped`, `Framework-QMK-ANSI-v`, `Xiaomi-Repeater-2018`, `Xiaomi-Repeater-2023`, `Zephyr-STM32L072-But`.

| Etapa | Contiki-STM32F4-Disc | dragon-reto-stripped | Framework-QMK-ANSI-v | Xiaomi-Repeater-2018 | Xiaomi-Repeater-2023 | Zephyr-STM32L072-But |
|---|---:|---:|---:|---:|---:|---:|
| W7 · Bare-metal / RTOS | ✓1 | ○ | ✓1 | ✓1 | ✓1 | ✓1 |
| Static · Certificates | ○ | ○ | ○ | ○ | ○ | ○ |
| Static · U-Boot env | ○ | ○ | ○ | ✓1 | ✓1 | ○ |
| Static · Device tree | △ | △ | △ | △ | △ | △ |
| Cross-check · Kernel command line | ○ | ○ | ○ | ○ | ○ | ○ |
| Recon · FCC-ID | ○ | ○ | ○ | ○ | ○ | ○ |
| W3 · NVRAM store | ○ | ○ | ○ | ✓3 | ✓3 | ○ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `Contiki-STM32F4-Disc` | `6e9ebc3d` | arm | Contiki-STM32F4-Discovery.elf | 7/7 |
| `dragon-reto-stripped` | `71a559fd` | unknown | dragon_reto_stripped.elf | 7/7 |
| `Framework-QMK-ANSI-v` | `b0cd7770` | arm | Framework-QMK-ANSI-v0.3.1.bin | 7/7 |
| `Xiaomi-Repeater-2018` | `550b279d` | mipsel | Xiaomi-Repeater_2018_zxrouter.bin | 7/7 |
| `Xiaomi-Repeater-2023` | `d3dc23fe` | mipsel | Xiaomi-Repeater_2023_hwread.bin | 7/7 |
| `Zephyr-STM32L072-But` | `22c69f6e` | arm | Zephyr-STM32L072-Button.elf | 7/7 |

## uefi-bios

Muestras: `Framework-Laptop-13-`, `OVMF-CODE-4M-secboot`, `OVMF-VARS-4M-ms`, `OVMF-VARS-4M-snakeoi`.

| Etapa | Framework-Laptop-13- | OVMF-CODE-4M-secboot | OVMF-VARS-4M-ms | OVMF-VARS-4M-snakeoi |
|---|---:|---:|---:|---:|
| UEFI · chipsec | ✓2 | ✓2 | ✓1 | ✓1 |
| UEFI · FwHunt implant scan | △ | △ | △ | △ |
| Static · Certificates | ○ | ○ | ○ | ○ |
| Static · U-Boot env | ○ | ○ | ○ | ○ |
| Static · Device tree | △ | △ | △ | △ |
| Cross-check · Kernel command line | ○ | ○ | ○ | ○ |
| Recon · FCC-ID | ○ | ○ | ○ | ○ |
| W3 · NVRAM store | ○ | ○ | ○ | ○ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `Framework-Laptop-13-` | `ebf1c98c` | unknown | Framework_Laptop_13_Intel_Core_Ultra_Series1_capsule_signed_allsku_3.04.cap | 8/8 |
| `OVMF-CODE-4M-secboot` | `c8011fc8` | unknown | OVMF_CODE_4M.secboot.fd | 8/8 |
| `OVMF-VARS-4M-ms` | `a0c853a0` | unknown | OVMF_VARS_4M.ms.fd | 8/8 |
| `OVMF-VARS-4M-snakeoi` | `a1417fd0` | unknown | OVMF_VARS_4M.snakeoil.fd | 8/8 |

## unknown

Muestras: `dragon-reto`.

| Etapa | dragon-reto |
|---|---:|
| W1 · Extraction | △ |
| Static · Certificates | ○ |
| Static · U-Boot env | ○ |
| Static · Device tree | △ |
| Cross-check · Kernel command line | ○ |
| Recon · FCC-ID | ○ |
| W3 · NVRAM store | ○ |

| Etiqueta | ID | Arquitectura | Fichero | Cobertura |
|---|---|---|---|---:|
| `dragon-reto` | `d24f3624` | unknown | dragon_reto.hex | 7/7 |
