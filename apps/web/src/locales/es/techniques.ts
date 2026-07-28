import type { Messages } from '../en';

/**
 * techniques — castellano.
 *
 * **Lo que NO se traduce, nunca.** `OWASP FSTM`, `ISTG` y los números de etapa de los encabezados son los nombres
 * publicados de una metodología externa, y esta pantalla existe precisamente para que quien lea pueda ponerla al
 * lado de la metodología publicada y cuadrar fila con fila. Traducir un identificador convierte el mapeo en otra
 * cosa. Lo mismo vale para los nombres de herramientas (`binwalk`, `angr`, `AFL++`, `FwHunt`, `Ghidra`, `chipsec`,
 * `Renode`, `mitmproxy`), que viajan literales dentro del nombre de la técnica.
 *
 * La columna de notas está partida en dos por esa misma razón: cuando la nota es un PUNTERO a este repositorio
 * (`providers/report`, `core/mcu + renode`) no pasa por este catálogo — vive junto a la lista, se pinta en `mono` y
 * es idéntica en los dos idiomas. Aquí sólo están las notas que son prosa, y de una nota que es prosa ALREDEDOR de
 * un identificador (`providers/chipsec (offline)`) se traduce sólo la prosa.
 *
 * **Las cuatro palabras de estado son lo delicado.** Cada fila es una afirmación sobre lo que este banco de trabajo
 * hace y lo que no, así que un estado que suene más fuerte de lo que es convierte una lista de cobertura en un
 * folleto de venta. Por eso:
 *   • `hecha` sólo para lo que ya ejecuta un proveedor o el agente;
 *   • `parcial` no puede leerse como terminada — es medio camino, y la nota dice qué mitad falta;
 *   • `prevista` no puede leerse como disponible: es un hueco real que se pretende construir;
 *   • `no aplica` / `fuera de alcance` es una FRONTERA deliberada — explotación armada, chip-off, radio — y no
 *     un descuido ni un hueco. Ni «hecha» ni «pendiente»: son cosas que este banco se niega a reclamar.
 *
 * La insignia de cada fila es corta porque va en una columna estrecha; el resumen de arriba lleva la forma larga,
 * igual que el inglés reparte `n/a` y `out of scope`. Las cuatro concuerdan en femenino porque cada fila es una
 * técnica.
 */
export const techniques: Messages['techniques'] = {
  title: 'Cobertura de técnicas',

  sub: {
    beforeDoc: 'Técnicas de pentest de firmware / IoT (OWASP FSTM + ISTG) frente a lo que FirmLab hace. Consulta',
    afterDoc: 'para el análisis completo.',
  },

  summary: {
    done: (n: number) => `${n} hechas`,
    partial: (n: number) => `${n} parciales`,
    planned: (n: number) => `${n} previstas`,
    outOfScope: (n: number) => `${n} fuera de alcance`,
  },

  status: {
    done: 'hecha',
    partial: 'parcial',
    planned: 'prevista',
    'out-of-scope': 'no aplica',
  },

  areas: {
    recon: 'Reconocimiento y adquisición (FSTM 1–2)',
    static: 'Análisis estático (FSTM 3–5)',
    emulation: 'Emulación (FSTM 6)',
    dynamic: 'Dinámico y en ejecución (FSTM 7–8)',
    comparison: 'Comparativa / localización de n-days',
    uefi: 'Análisis profundo de UEFI / BIOS',
    rtos: 'Análisis profundo de RTOS / bare-metal',
    reporting: 'Informes y divulgación',
    hardware: 'Hardware / radio y explotación',
  },

  items: {
    provenance: { name: 'Huella de procedencia (fabricante / modelo / versión)' },
    osint: { name: 'Correlación OSINT de vulnerabilidades — OSV + NVD + CISA KEV' },
    securityTxt: { name: 'Descubrimiento del contacto de divulgación (RFC 9116 security.txt)' },
    fccId: { name: 'Consulta de FCC-ID (expedientes públicos)' },
    upload: { name: 'Subida de firmware' },
    lanDiscovery: { name: 'Descubrimiento de dispositivos en la LAN + detección del backend de captura' },
    otaIntercept: { name: 'Interceptación OTA + extracción del firmware del flujo + ingesta automática' },

    identity: { name: 'Entropía / mapa de estructura / identidad de clase y arquitectura' },
    extraction: { name: 'Extracción del sistema de ficheros (squashfs/jffs2/ubifs/cramfs/cpio)' },
    secrets: { name: 'Barrido de secretos y credenciales (+ gitleaks a fondo)' },
    sbom: { name: 'SBOM y CVEs (syft → OSV/NVD/grype)' },
    hardening: { name: 'Endurecimiento de binarios (NX / canary / PIC / RELRO)' },
    decompile: { name: 'Triaje con Ghidra / radare2 + andamiaje de taint' },
    fsaudit: { name: 'Heurísticas de scripts de arranque y de configuración (estilo firmwalker)' },
    certs: { name: 'Análisis de certificados y material de claves' },
    compmap: { name: 'Mapa de dependencias de componentes (binarios/bibliotecas/scripts)' },
    uboot: { name: 'Gestor de arranque / entorno U-Boot + bootargs por defecto' },

    qemuUser: { name: 'QEMU en modo usuario (un solo binario)' },
    chroot: { name: 'Servicio en chroot + shim libnvram' },
    fullSystem: { name: 'Arranque de sistema completo (kernel firmadyne)' },
    renode: { name: 'Renode para RTOS / Cortex-M' },
    chipsec: { name: 'chipsec (decodificación de UEFI/BIOS sobre la imagen)' },
    servicemap: { name: 'Enumeración de servicios (superficie de ataque al arrancar)' },
    presets: { name: 'Recetas de emulación guardadas' },
    interactiveShell: { name: 'Ejecutar órdenes en la emulación / consola interactiva' },

    fuzzing: { name: 'Fuzzing guiado por cobertura (AFL++ fichero/stdin/red)' },
    isolation: { name: 'Ejecución automática bajo aislamiento con primitivas del SO' },
    webprobe: { name: 'Ejercitar el servicio emulado — inyección de órdenes + salto de directorio' },
    webAuthBypass: { name: 'Elusión de autenticación web / credenciales por defecto / inyección en el cuerpo POST' },
    interactiveGdb: { name: 'GDB interactivo en la emulación (puntos de ruptura en funciones inseguras)' },
    symreach: { name: 'Alcanzabilidad simbólica de las pistas de taint (angr)' },
    crossBinary: { name: 'Flujo de datos entre binarios / disposición de pila y globales' },
    cmplog: { name: 'cmplog / compcov + generación automática de arneses' },

    treeDiff: { name: 'Diff del árbol de firmware y de los binarios entre versiones' },
    functionDiff: { name: 'Diff de decompilación a nivel de función (estilo BinDiff)' },
    kernelModuleCve: { name: 'Correlación de CVEs en los módulos del kernel (.ko)' },

    efiInventory: { name: 'Inventario de volúmenes de firmware y módulos EFI' },
    bootkitLead: { name: 'Pista de bootkit en aplicaciones embebidas' },
    iocFeed: { name: 'Enganche para fuentes de IOC (FIRMLAB_UEFI_IOC)' },
    secureBoot: { name: 'Postura de Secure Boot / NVRAM + detección de claves de prueba' },
    fwhunt: { name: 'Barrido con reglas de amenaza (patrones de código FwHunt)' },
    logofail: { name: 'Analizadores de LogoFAIL / análisis de callouts SMM' },

    mcuFingerprint: { name: 'Huella del MCU + selección de plataforma del catálogo real' },
    bootLiveness: { name: 'Prueba de vida del arranque (el éxito lo decide la UART)' },
    vectorTable: { name: 'Tabla de vectores / dirección base / mapa de memoria + detección del kernel RTOS' },
    mmioFuzzing: { name: 'Fuzzing de periféricos / MMIO (Fuzzware / µEmu)' },

    htmlReport: { name: 'Informe de análisis en HTML autocontenido' },
    disclosureDraft: { name: 'Borrador de divulgación coordinada en Markdown' },
    intelBrief: { name: 'Informe de inteligencia externa con citas (LLM)' },
    pdfExport: { name: 'Exportación a PDF' },

    uartBridge: { name: 'Puente de consola UART al dispositivo real (en el anfitrión)' },
    jtag: { name: 'Extracción por JTAG / SWD / SPI · chip-off' },
    bleDfu: { name: 'Reensamblado de DFU BLE (Nordic)' },
    zigbeeOta: { name: 'Reensamblado del clúster OTA de Zigbee (0x0019)' },
    wifiSdr: { name: 'Captura Wi-Fi / SDR' },
    sideChannel: { name: 'Canal lateral / inyección de fallos (glitching)' },
    weaponization: { name: 'Explotación armada (ROP / shellcode / PoC)' },
  },

  notes: {
    osint: 'research/ (lista blanca, con citas)',
    upload: 'ingesta manual',
    lanDiscovery: 'Fase 6.0 (capture/)',
    otaIntercept: 'Fase 6.1: proxy→puntuación→extracción→ingesta (captura en vivo al desplegar)',
    interactiveShell: 'introspección en vivo',
    webAuthBypass: 'continuación de webprobe',
    interactiveGdb: 'hueco en ejecución',
    symreach: 'demuestra la alcanzabilidad',
    crossBinary: 'extensión de taint',
    cmplog: 'profundidad del fuzzing',
    functionDiff: 'localiza el parche',
    kernelModuleCve: 'más allá del SBOM de espacio de usuario',
    bootkitLead: 'barrido de chipsec',
    iocFeed: 'IOCs por GUID/nombre que aporta el operador',
    secureBoot: 'providers/chipsec (sobre la imagen)',
    fwhunt: 'integrar fwhunt-scan',
    logofail: 'del tipo de efiXplorer',
    mmioFuzzing: 'ejercitar la HAL',
    pdfExport: 'comodidad',
    uartBridge: 'transporte de la fase 6',
    jtag: 'laboratorio de hardware',
    bleDfu: 'Fase 6.4: reensamblado hecho; escucha en vivo = dongle nRF',
    zigbeeOta: 'Fase 6.5: reensamblado y desempaquetado hechos; escucha en vivo = CC2531/ConBee',
    wifiSdr: 'dongle de la fase 6',
    sideChannel: 'hardware de laboratorio',
    weaponization: 'defensivo por diseño',
  },
};
