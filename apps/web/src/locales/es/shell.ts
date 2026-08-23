import type { Messages } from '../en';

/**
 * shell — castellano. El marco que rodea a los paneles: la cadena de etapas, las capacidades del despliegue, los
 * proveedores de análisis profundo y el historial de ejecuciones.
 *
 * Las etiquetas de las etapas NO están aquí: los ids de etapa son ids de sección y el espacio de nombres de
 * secciones ya las nombra. Duplicarlas haría que una misma pantalla acabara con dos nombres distintos.
 *
 * La frase que no puede ablandarse en ninguna de las dos superficies de proveedores: una herramienta ausente es una
 * RESPUESTA ausente. La pregunta no llegó a hacerse, y una fila apagada habla de esta máquina, no del firmware.
 * «No pudimos mirar» traducido con suavidad se lee como «miramos y estaba limpio», que es justo lo contrario.
 *
 * Los nombres de herramienta (`binwalk`, `radare2`, `qemu`, `Ghidra`, `AFL++`, `Renode`, `chipsec`), los tipos de
 * trabajo, las arquitecturas, las variables de entorno y las rutas son identificadores: se pintan tal cual.
 */
export const shell: Messages['shell'] = {
  timeline: {
    label: 'Cadena de análisis',
    /** Estados de la interfaz, no estados de prueba: `blocked_by_platform` sigue siendo el identificador. */
    state: {
      done: 'hecha',
      running: 'en curso',
      blocked: 'bloqueada',
      pending: 'pendiente',
    },
    stepTitle: (section: string, state: string) => `${section} — ${state}`,
    blocked: 'bloqueada',
  },

  capabilities: {
    engineLead: 'El motor estático de FirmLab (mapa de estructura, entropía, cadenas, identidad) no necesita',
    engineStrong: 'ninguna herramienta externa',
    engineTail: [
      'Las de abajo son mejoras opcionales — construye la imagen Docker de firmware para habilitar la extracción,',
      'la descompilación, SBOM/CVEs y la emulación.',
    ].join(' '),

    title: 'Herramientas detectadas',
    probing: 'Sondeando…',
    counted: (available: number, total: number) => `${available} de ${total} disponibles en este despliegue`,
    absentAnswer: [
      'Una herramienta que falte aquí es una RESPUESTA ausente, no un problema ausente: los proveedores que la',
      'necesitan se declaran no disponibles y dicen por qué, y ninguno devuelve un resultado limpio que no se haya',
      'ganado.',
    ].join(' '),
    notFound: 'no encontrada',

    group: {
      extract: 'Extracción',
      analyze: 'Análisis de binarios',
      sbom: 'SBOM y CVEs',
      secrets: 'Búsqueda de secretos',
      emulate: 'Emulación',
    },
  },

  deep: {
    title: 'Análisis profundo',
    sub: [
      'Proveedores offline que enriquecen el dosier. Los hallazgos se añaden al registro de hallazgos de la imagen;',
      'cada uno se degrada con honestidad cuando le falta su entrada o su herramienta — informa de la pregunta que',
      'no pudo hacer en vez de devolver un resultado vacío que se lea como limpio.',
    ].join(' '),

    group: {
      boot: 'Arranque y plataforma',
      filesystem: 'Sistema de ficheros y configuración',
      update: 'Actualización y cadena de suministro',
      device: 'Dispositivo y radio',
    },

    provider: {
      uboot: {
        title: 'U-Boot / gestor de arranque',
        desc: [
          'Descodifica el entorno de U-Boot y audita la postura de arranque (argumentos de shell de root, autoboot',
          'interrumpible, arranque por red).',
        ].join(' '),
      },
      devicetree: {
        title: 'Árbol de dispositivos',
        desc: [
          'Lee la descripción de placa que lleva la imagen — SoC, mapa de flash, periféricos y la línea de órdenes',
          'del kernel.',
        ].join(' '),
      },
      kernel: {
        title: 'Postura del kernel',
        desc: [
          'Versión y antigüedad del kernel, más KASLR, /dev/kmem, firma de módulos y RWX — cada uno respondido como',
          'activo, inactivo o no determinable.',
        ].join(' '),
      },
      fsaudit: {
        title: 'Auditoría de seguridad del rootfs',
        desc: [
          'Comprobaciones al estilo firmwalker: credenciales débiles o vacías, shells de root, telnetd,',
          'configuraciones de servicio permisivas, material de claves.',
        ].join(' '),
      },
      certs: {
        title: 'Certificados (X.509)',
        desc: 'Analiza los certificados embebidos — caducados, RSA débil, de prueba o autofirmados, CA embebida.',
      },
      services: {
        title: 'Enumeración de servicios',
        desc: [
          'Mapea los demonios de red que el rootfs arranca por configuración (scripts de init, inetd, systemd) — la',
          'superficie de ataque.',
        ].join(' '),
      },
      updatepath: {
        title: 'Integridad de la vía de actualización',
        desc: [
          '¿Lleva firma la imagen, verifica algo el actualizador, hay protección contra reversión a versiones',
          'anteriores?',
        ].join(' '),
      },
      compmap: {
        title: 'Mapa de componentes',
        desc: 'Asocia cada ELF del rootfs con sus dependencias de bibliotecas compartidas (necesita radare2).',
      },
      rtos: {
        title: 'RTOS / blob bare-metal',
        desc: 'Recupera la tabla de vectores Cortex-M y el mapa de memoria, y detecta el núcleo RTOS.',
      },
      fcc: {
        title: 'Consulta de FCC ID',
        desc: [
          'Extrae los FCC ID y enlaza con los expedientes públicos del dispositivo (fotos, manuales, fotos internas,',
          'informes de ensayo).',
        ].join(' '),
      },
    },

    findings: (n: number) => `${n} hallazgo${n === 1 ? '' : 's'}`,
    noFindings: 'ningún hallazgo',
    overviewLabel: 'Cobertura del análisis profundo',
    overview: (ran: number, total: number): string => `${ran} de ${total} con respuesta guardada`,
    running: (n: number): string => `${n} en curso`,
    errors: (n: number): string => `${n} con error`,
    pending: (n: number): string => `${n} sin ejecutar`,
    loading: 'Leyendo ejecuciones anteriores…',
    runningBody: 'El resultado aparecerá aquí cuando termine el proveedor.',
    notRun: 'Sin ejecutar',
    notRunBody: 'Todavía no hay una respuesta guardada para esta pregunta.',
    completed: 'completada',
    runAgain: 'Repetir',
    runProvider: (name: string): string => `Ejecutar ${name}`,
    runAgainProvider: (name: string): string => `Repetir ${name}`,
    runningProvider: (name: string): string => `${name} está en curso`,
    resultDetails: 'Datos obtenidos',
    details: {
      yes: 'sí',
      no: 'no',
      unknown: 'desconocido',
      environment: 'Variables de entorno',
      variable: 'Nombre de variable',
      variables: 'Variables encontradas',
      value: 'Valor',
      bootScript: 'Lectura del script de arranque',
      roots: 'Variables de entrada',
      variants: 'Líneas de órdenes del kernel construidas',
      via: 'mediante',
      conditional: 'rama condicional',
      searched: 'Lugares examinados',
      rejected: 'Candidatos de árbol de dispositivos rechazados',
      trees: 'Árboles de dispositivos',
      origin: 'Origen',
      model: 'Modelo',
      compatible: 'Compatibilidad',
      bootargs: 'Línea de órdenes del kernel',
      partitions: 'Particiones flash',
      peripherals: 'Periféricos',
      kernelSummary: 'Resumen del kernel',
      version: 'Versión',
      age: 'Antigüedad de la rama',
      years: (n: number): string => `${n} años`,
      modules: 'Módulos',
      signed: 'firmados',
      controls: 'Controles de postura',
      option: 'Opción de seguridad',
      verdict: 'Veredicto',
      evidence: 'Evidencia',
      coverage: 'Cobertura',
      files: 'Ficheros',
      bytes: 'Bytes leídos',
      certificates: 'Certificados',
      subject: 'Sujeto',
      issuer: 'Emisor',
      validity: 'Validez',
      key: 'Clave',
      bits: (n: number): string => `${n} bits`,
      selfSigned: 'Autofirmado',
      services: 'Servicios configurados',
      name: 'Nombre',
      binary: 'Binario',
      source: 'Configurado en',
      network: 'Expone red',
      autostart: 'Inicio automático',
      port: 'Puerto',
      updateCoverage: 'Cobertura de la vía de actualización',
      container: 'Contenedor',
      integrity: 'Mecanismos de integridad de imagen',
      updaters: 'Candidatos de actualización',
      rollback: 'Protección contra reversión',
      digests: 'Rutinas de resumen',
      signatureChecks: 'Comprobaciones de firma',
      componentSummary: 'Resumen del mapa de componentes',
      binaries: 'ELF examinados',
      dependencies: 'Aristas de dependencia',
      unresolved: 'Bibliotecas sin resolver',
      symlinks: 'Enlaces simbólicos indexados',
      orphaned: 'Binarios sin referencias',
      openComponentMap: 'Abrir el mapa de componentes completo',
      rtosSummary: 'Lectura RTOS / bare-metal',
      cortexM: 'Imagen Cortex-M',
      rtosKernel: 'Núcleo RTOS',
      initialSp: 'Puntero de pila inicial',
      resetHandler: 'Manejador de reset',
      flashBase: 'Base de flash',
      ramBase: 'Base de RAM',
      fccIds: 'Identificadores FCC',
      filing: 'Expediente FCC',
      mirror: 'Ficheros públicos',
      findings: 'Hallazgos registrados',
      proof: 'Estado de prueba',
      noItems: 'No se registró ninguno.',
      notRecorded: 'Esta ejecución no lo registró.',
      countMore: (shown: number, total: number): string =>
        `Se muestran ${shown} de ${total}; usa la vista específica para consultar el grafo completo.`,
    },
    lastRun: (when: string): string => `última ejecución ${when}`,
    refreshFailed: (error: string): string => `No se pudieron actualizar los resultados anteriores: ${error}`,
    failed: 'falló',
  },

  runHistory: {
    /**
     * La frase entera, construida aquí. El castellano concuerda en número («1 ejecución» / «2 ejecuciones») y pide
     * la preposición que el inglés no tiene, así que no puede salir de un hueco dentro de la gramática inglesa: eso
     * es exactamente lo que producía «2 análisis profundo runs on this image».
     */
    heading: (n: number, kind: string) => `${n} ejecuci${n === 1 ? 'ón' : 'ones'} de ${kind} sobre esta imagen`,
    show: 'ver el historial — el panel de arriba sólo muestra la más reciente',
    hide: 'ocultar el historial — el panel de arriba sólo muestra la más reciente',

    kind: {
      deepAnalysis: 'análisis profundo',
    },

    outcome: {
      proven: { label: 'probado', means: 'Se estableció un hecho.' },
      lead: { label: 'pista', means: 'Merece la pena seguirla. Todavía no hay nada probado.' },
      empty: {
        label: 'sin resultados',
        means: [
          'Esta ejecución no encontró nada — para su entrada, su presupuesto y su pregunta. No es un certificado de',
          'que esté limpio.',
        ].join(' '),
      },
      blocked: {
        label: 'bloqueada',
        means: 'La pregunta se hizo y este despliegue no pudo responderla. NO es un resultado negativo.',
      },
      failed: { label: 'falló', means: 'El arnés se rompió. No dice nada en ningún sentido.' },
      running: { label: 'en curso', means: 'Sigue en marcha.' },
    },

    ago: {
      seconds: (n: number) => `hace ${n} s`,
      minutes: (n: number) => `hace ${n} min`,
      hours: (n: number) => `hace ${n} h`,
      days: (n: number) => `hace ${n} d`,
    },
  },
};
