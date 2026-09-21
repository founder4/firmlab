# ARQUITECTURA OBJETIVO: SUPERACIÓN DE LA FRONTERA DE EMULACIÓN DINÁMICA (FSTM-7 / GAP-01)

**Estado:** Documento de Diseño Técnico / Especificación de Arquitectura — *visión*, no plan cerrado.
**Materia:** Enfoque técnico y hoja de ruta para la emulación dinámica interactiva de firmware embebido sin dependencia de hardware físico.
**Realineado:** 2026-09-22 contra los invariantes del repo — disciplina de proof-state (`confirmed_in_emulation` nunca afirma el dispositivo), premisa *sin hardware físico*, y la regla de *encadenar providers existentes* en vez de añadir análisis propio. Los cambios respecto al borrador se anotan como *Nota de realineado* donde tocan.

**Referencias en el Repositorio:**
- Arnés de emulación actual: `apps/api/src/providers/emulate-system.ts`
- Sonda dinámica HTTP/HTTPS: `apps/api/src/providers/webprobe.ts`
- Mapeo de puertos del huésped: `apps/api/src/providers/portmap.ts`
- Clasificador de clases y firmas: `packages/core/src/signatures.ts`
- Vocabulario de proof-state: `packages/core/src/types.ts` (`ProofState`)
- Registro de brechas metodológicas: `docs/METHODOLOGY-GAPS.md`
- Lista única de pendientes técnicos: `docs/BACKLOG.md`

---

## 1. DEFINICIÓN DEL PROBLEMA RAÍZ: LA BARRERA DEL HIPERVISOR GENÉRICO

La limitación crítica observada en la fase 7 de OWASP FSTM (Dynamic Analysis) dentro de los bancos de trabajo de análisis de firmware (incluyendo Firmadyne, FirmAE y el arnés actual de FirmLab basado en QEMU `-M malta`) reside en la **divergencia del silicio no estandarizado**:

```
                ARQUITECTURA CONVENCIONAL (FALLA)                  ARQUITECTURA OBJETIVO (SÍNTESIS TOTAL)
           ┌──────────────────────────────────────────┐      ┌──────────────────────────────────────────────┐
           │ Kernel Embebido Real (Binario del Vendor)│      │ Kernel Embebido Real (Binario del Vendor)    │
           └────────────────────┬─────────────────────┘      └──────────────────────┬───────────────────────┘
                                │                                                   │
                   Sonda MMIO a hardware real                          Sonda MMIO / Bus SPI / I2C
                                │                                                   │
                                ▼                                                   ▼
           ┌──────────────────────────────────────────┐      ┌──────────────────────────────────────────────┐
           │ Hipervisor Genérico (QEMU -M malta)      │      │ Motor de Síntesis JIT de Periféricos (PANDA) │
           │ - Registro físico: NO MAPEADO            │      │ - Inferencia de polling loops en microcódigo │
           │ - Switch Ethernet: NO EXISTE             │      │ - Emulador DSA/VLAN con driver sintético     │
           └────────────────────┬─────────────────────┘      │ - Bus SPI sintético (lectura de NVRAM pura)  │
                                │                                                   │
                                ▼                                                   ▼
           ┌──────────────────────────────────────────┐      ┌──────────────────────────────────────────────┐
           │ RESULTADO: Kernel Panic / Loopback Only  │      │ RESULTADO: LAN/WAN Up, Daemons 80/443/UPnP   │
           │ (FSTM-7 Bloqueado, Cobertura 0% en Red)  │      │ (Explotabilidad Dinámica de Extremo a Extremo│
           └──────────────────────────────────────────┘      └──────────────────────────────────────────────┘
```

> **Nota de realineado — el punto de partida no es ingenuo.** El arnés actual (`emulate-system.ts`) no es un `qemu -M malta` desnudo: ya hace `hostfwd` múltiple, configuración de red slirp, captura `filter-dump` (pcap) del netdev del huésped, parseo de marcadores de arranque, y maneja el `romfile=` del e1000 (uno de los "cuatro fallos apilados" documentados en `CLAUDE.md`). Es más: el propio arnés **ya fingerprintea la Capa II de este documento como su causa de fallo** — `emulate-system.ts` (~L529) anota que el camino del switch Atheros *"does not exist under `-M malta` with an e1000, so `eth0` has no address"*. Este documento describe qué falta sobre esa base, no parte de cero.

### 1.1. Colapso por Bucles de Espera (*Polling Loops*) en MMIO
Los controladores propietarios de los fabricantes ejecutan lecturas continuas sobre registros mapeados en memoria física (`ioremap` en direcciones no coincidentes con el bus PCI/ISA estándar). Al retornar `0xFFFFFFFF` o provocar una excepción de acceso no manejado (*unhandled bus fault*), el kernel se detiene en un bucle infinito o genera un pánico del sistema antes de completar la secuencia de inicio y montar el sistema de archivos raíz (`rootfs`).

### 1.2. Inexistencia de Interfaces de Conmutación Ethernet (*Switch Chips*)
Los equipos de red residenciales y pasarelas IoT no conectan la interfaz de red del SoC a una tarjeta Ethernet convencional; la interconectan a un circuito de conmutación dedicado (chips Realtek RTL83xx, Broadcom BCM53xx, Qualcomm/Atheros QCA8337) mediante interfaces MII/RGMII con esquemas de etiquetado propietario (Distributed Switch Architecture - DSA).
Al fallar el sondeo MDIO/PHY, el controlador del switch no inicializa las interfaces `eth0`, `br0` o `br-lan`. Como resultado, los scripts de inicialización (`rcS`, `inittab`) abortan la ejecución de los servidores web y demonios de administración, o configuran exclusivamente el bucle local (`lo` / `127.0.0.1`), aislando la superficie de ataque del exterior.

### 1.3. Fragilidad Estructural de la Intercepción en Espacio de Usuario
Los enfoques tradicionales que recurren a librerías de sustitución (`libnvram.so` mediante `LD_PRELOAD` en chroot) fracasan sistemáticamente cuando el firmware incorpora:
- Binarios enlazados estáticamente (`musl`, `uClibc` sin cargador dinámico).
- Servicios desarrollados en Go o Rust que ejecutan llamadas directas al kernel (`syscall`).
- Demonios que leen particiones flash crudas accediendo directamente a nodos de dispositivo de bloques (`/dev/mtdblockX`).

---

## 2. ARQUITECTURA OBJETIVO: "DETERMINISTIC HARDWARE SYNTHESIS ENGINE"

La arquitectura objetivo para FirmLab reemplaza la modificación destructiva de kernels por un modelo de virtualización transparente estructurado en capas cooperativas:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ CAPA V: RECORD / REPLAY & DETERMINISTIC FORK (Time-Travel Engine)                      │
│ - Snapshot inmutable de memoria y registros de CPU tras el arranque exitoso.          │
│ - Fuzzing masivo y reanudación instantánea (cientos–miles de ejecuciones/segundo).     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ CAPA IV: REHOSTING HÍBRIDO ASISTIDO (Avatar2 Hardware Snapshot & Detach)               │
│ - FUERA DE ALCANCE: requiere hardware físico (JTAG/SWD). Ver §2.4.                     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ CAPA III: EMULACIÓN DE BUS DE SILICIO (Hardware-Level NVRAM & Flash MTD)               │
│ - Virtualización transparente de transacciones en buses SPI/I2C.                       │
│ - Exposición fiel de particiones MTD y bloques de configuración originales.            │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ CAPA II: ARQUITECTURA DE CONMUTACIÓN SINTÉTICA (Universal Virtual DSA Switch)          │
│ - Switch de capa 2 en espacio de hipervisor con decodificación de trailers/etiquetas.  │
│ - Emulador de registros MDIO/PHY que fuerza estado autoritativo Link Up 1000 Mbps.     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ CAPA I: SÍNTESIS JIT DE PERIFÉRICOS MMIO (integrar Fuzzware/µEmu, no motor propio)      │
│ - Modelado MMIO y resolución de bucles de sondeo vía herramienta de investigación.      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

> **Nota de realineado — alcance real.** Las Capas I, II, III y V son el objetivo de FirmLab. La **Capa IV queda FUERA DE ALCANCE**: su mecanismo (arrancar en placa física por JTAG/SWD y desacoplar) contradice la premisa *sin hardware físico* del propio documento y la identidad local-first del proyecto. Se documenta como escape de investigación para el caso límite de criptografía en ROM de máscara, **no** como capa de la arquitectura estándar. Por eso no aparece en el plan de §4.

### 2.1. Capa I: Síntesis Just-In-Time de Periféricos MMIO — vía integración, no motor propio
El objetivo es que una lectura/escritura sobre un rango MMIO sin periférico formal no cuelgue el kernel, sino que se resuelva satisfaciendo el bucle de sondeo (`while ((REG & MASK) == 0)`).

> **Nota de realineado — integrar, no construir.** El borrador proponía escribir un plugin TCG nuevo de *trap & satisfy* en 8-12 semanas. Eso **es** rehacer µEmu / P2IM / Fuzzware, sistemas de investigación de varios años. La arquitectura de FirmLab *"chains existing providers rather than adding analysis"*, y `docs/BACKLOG.md` ya nombra Fuzzware/µEmu/P2IM como la frontera. La jugada correcta es **integrar Fuzzware** (open source: Rust + Ghidra + QEMU) como `ToolSpec` en `apps/api/src/tools.ts`, detectado en runtime y expuesto como provider, degradando honestamente si el binario no está.

- **Captura de Excepciones:** toda lectura/escritura en un rango de memoria física no asignado activa una interrupción en el motor de traducción dinámica (QEMU TCG / la herramienta integrada).
- **Resolución de Bucles de Sondeo:** la herramienta desensambla el patrón condicional iterativo y modela la transición requerida para satisfacer la guarda.
- **Persistencia de Perfiles de Hardware (clave para el determinismo):** la síntesis en su **primera pasada NO es determinista** (µEmu/Fuzzware usan fuzzing/ejecución simbólica). El determinismo del proyecto se preserva **pineando el perfil sintetizado** (mapa de registros, máscaras y valores) como artefacto reproducible; auditorías posteriores replayean ese perfil fijo sin coste ni variación. El determinismo se logra por el *pin*, no porque el modelado lo sea.

### 2.2. Capa II: Arquitectura de Conmutación Sintética (*Universal Virtual DSA Switch*)
- **Switch Multiprotocolo Integrado:** un módulo de red L2 desacoplado dentro del hipervisor que reconoce los formatos de encapsulación comunes:
  - Broadcom BCM53xx (etiquetas de 4 bytes en cola de trama).
  - Realtek RTL83xx (etiquetado basado en VLAN interna).
  - Qualcomm/Atheros QCA8337 (cabeceras de puerto embebidas).
- **Emulador Estructural PHY/MDIO:** responde autoritativamente a las consultas sobre el bus de gestión MII (IEEE 802.3 Clause 22), reportando estado activo (`BMSR_LSTATUS = 1`), lo que previene que los controladores del kernel deshabiliten las interfaces `eth0`/`br0` por ausencia de enlace físico.

> **Nota de realineado — la detección de familia de switch NO existe aún.** Este switch necesita saber qué silicio hay presente para decodificar el etiquetado correcto, y hoy `packages/core/src/signatures.ts` **no** identifica RTL83xx/BCM53xx/QCA8337 (solo contenedores TRX y el bootloader CFE de Broadcom). Antes de la Capa II hace falta un input de detección nuevo (device-tree, strings del kernel, módulos cargados) que nombre la familia del switch. Es una dependencia real, no un dato ya disponible.

### 2.3. Capa III: Emulación de Bus a Nivel de Silicio para NVRAM y Almacenamiento MTD
- **Virtualización de Controladoras de Bus SPI/I2C:** se interceptan las operaciones a nivel de bus de hardware. El controlador emulado sirve directamente las regiones de datos correspondientes a las particiones de configuración (`ART`, `NVRAM`, `uboot-env`) extraídas del binario original.
- **Transparencia Total en Espacio de Usuario:** los binarios de gestión acceden a `/dev/mtdblockX` o `/dev/nvram` leyendo los bytes legítimos sin requerir bibliotecas intermediarias ni dependencias de `LD_PRELOAD`.

### 2.4. Capa IV (FUERA DE ALCANCE): Rehosting Híbrido Asistido (*Avatar2 Hardware Snapshot & Detach*)
Documentada por completitud, **excluida del alcance de FirmLab** porque rompe la premisa *sin hardware físico*. Aplicable solo al caso límite de procesadores con enclave seguro o inicialización criptográfica cerrada en ROM de máscara, y solo cuando se dispone del dispositivo físico:
- **Ejecución Asistida Inicial:** el firmware inicia conectado a una placa de evaluación física mediante sondas JTAG/SWD.
- **Desacoplamiento Transaccional:** al transferir el control a espacio de usuario (`sys_execve("/sbin/init")`) se congela el estado completo de registros y memoria y se transfiere al hipervisor virtual, continuando la emulación en software.

Si algún día se aborda, vive como lane opt-in con hardware declarado, nunca en la ruta por defecto.

### 2.5. Capa V: Motor de Instantáneas Temporales (*Time-Travel Record/Replay*)
- **Bifurcación Instantánea del Estado:** al momento en que el primer demonio de red (`httpd`, `uhttpd`, `miniupnpd`) ejecuta una llamada `listen()` o `accept()`, se genera un punto de control inmutable (*checkpoint*) con `savevm`/`loadvm` nativos de QEMU.
- **Fuzzing Diferencial Masivo:** las herramientas de auditoría dinámica (`apps/api/src/providers/webprobe.ts`) inyectan mutaciones de payloads y restauran el estado del sistema, eliminando los minutos que requiere un reinicio completo del sistema operativo. El régimen realista para snapshot full-system es de cientos a miles de restauraciones por segundo (la cifra de decenas de miles corresponde a *persistent-mode* en espacio de usuario, no a snapshot de sistema completo).

---

## 3. IMPACTO EN COBERTURA METODOLÓGICA Y DETECCIÓN DE VULNERABILIDADES

La materialización de este modelo transforma la visibilidad de vulnerabilidades en el marco OWASP FSTM. **El techo de prueba es `confirmed_in_emulation`, no `confirmed_full_system` ni "idéntico al físico"**: un entorno sintetizado es deliberadamente *permisivo* (la Capa I satisface guardas, la Capa II fuerza `Link Up`), así que prueba el sandbox, nunca el dispositivo — `packages/core/src/types.ts` define que `confirmed_full_system` *"stops at full-system emulation and never claims the device"*.

| Vector de Ataque / Superficie | Cobertura en Hipervisor Convencional | Cobertura Bajo la Arquitectura Objetivo | Techo de prueba honesto |
| :--- | :--- | :--- | :--- |
| **Inyección de Comandos en Portales Web (CGI/Lua)** | Parcial (restringida a `127.0.0.1`, alterada por scripts de inicio incompletos). | Interfaces LAN/WAN sintéticas operativas y enrutadas. | `confirmed_in_emulation` sobre daemons de red antes inalcanzables — reproduce el vector en el sandbox, no certifica el dispositivo físico. |
| **Desbordamientos en Servicios UDP/Multicast (UPnP, DNS, DHCP)** | Nula (los demonios fallan al bindear interfaces físicas inexistentes). | Auditable de extremo a extremo en emulación. | `confirmed_in_emulation`: corrupción de memoria observada en el emulador vía paquetes broadcast/multicast legítimos. |
| **Bypass de Autenticación por Parámetros NVRAM** | Indeterminada (claves arbitrarias en mocks de `libnvram`). | Fidedigna respecto a la flash MTD original, y determinista **una vez pineado el perfil** (Capa I). | `confirmed_in_emulation`: acceso indebido reproducido leyendo la configuración de fábrica real, no un mock. |

> El salto de valor es pasar de *0% de cobertura de red* a `confirmed_in_emulation` de servicios de red — hoy imposible porque `eth0`/`br-lan` nunca suben. Reportar `confirmed_full_system` para un boot que solo alcanzó la aceptación *sintética* del emulador sería exactamente el trap del puerto fijo que `CLAUDE.md` ya pagó.

---

## 4. PLAN DE IMPLEMENTACIÓN ESTRATÉGICA PARA FIRMLAB

Para incorporar estas capacidades sin comprometer el principio de determinismo local establecido en `CLAUDE.md`, se define la siguiente secuencia. **La Capa IV (Avatar2/JTAG) queda deliberadamente fuera del plan** (§2.4).

| Fase | Denominación del Entregable | Alcance Técnico | Esfuerzo Estimado | Viabilidad |
| :--- | :--- | :--- | :--- | :--- |
| **Fase 1** | *Universal Virtual DSA Switch* (Capa II) | Driver de conmutación en espacio de QEMU para tramas etiquetadas Realtek, Broadcom y Qualcomm. Resuelve el grueso de los fallos de interfaz en routers SOHO. **Depende de** una detección de familia de switch que aún no existe (§2.2). | **4 - 6 semanas** (+ detección previa) | **Alta** (se integra en la cadena de scripts de inicio de QEMU). |
| **Fase 2** | *Integración de modelado MMIO* (Capa I) | Integrar **Fuzzware/µEmu como provider detectado en runtime** (`ToolSpec` en `tools.ts`), no un motor TCG propio: modelado MMIO y resolución de bucles de espera, con perfil de hardware pineado para replay determinista. | **integración + validación** | **Media-Alta** (reusa investigación validada P2IM/Fuzzware; encaja con el *chaining* de providers). |
| **Fase 3** | *Snapshot & Fork Pipeline* (Capa V) | Persistencia de memoria tras el arranque de servicios de red (`savevm`/`loadvm`), enlazada con `webprobe.ts` y fuzzing AFL++. | **2 - 3 semanas** | **Muy Alta** (comandos nativos de guardado de estado de QEMU). |

> **Capa III** (NVRAM/MTD por bus SPI/I2C) se intercala entre Fase 1 y 2 según qué corpus la exija; **Capa IV** no se planifica.
