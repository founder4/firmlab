import type { Messages } from '../en';

/** settings — Spanish. Typed against the English catalogue, so an untranslated key cannot ship silently. */
export const settings: Messages['settings'] = {
  eyebrow: 'Sistema',
  title: 'Ajustes',
  desc: 'La apariencia la decides tú aquí. El análisis, la privacidad y los límites del agente reflejan la configuración real de este despliegue.',

  tabs: {
    appearance: 'Apariencia',
    analysis: 'Análisis',
    tools: 'Herramientas',
    agent: 'IA y agente',
    privacy: 'Privacidad',
    storage: 'Almacenamiento',
    help: 'Ayuda',
  },

  appearance: {
    title: 'Apariencia',
    sub: 'Se aplica al instante y se recuerda en este dispositivo.',
    theme: 'Tema',
    themeLight: 'Claro',
    themeSystem: 'Sistema',
    themeDark: 'Oscuro',
    density: 'Densidad',
    densityComfortable: 'Cómoda',
    densityCompact: 'Compacta',
    densityHint:
      'La densidad compacta reduce el alto de las filas y los espaciados, para sesiones densas en pantallas grandes.',
  },

  language: {
    row: 'Idioma',
    hint: 'Cambia la interfaz del banco de trabajo y los informes que genera. Se aplica al instante y se recuerda en este dispositivo.',
    scope:
      'Los hallazgos conservan la redacción con la que el análisis los registró. Esas frases se almacenan junto a la imagen como evidencia, así que se muestran tal y como se escribieron en lugar de volver a traducirse.',
  },

  /**
   * El marco de los interruptores de carril. Lo que enciende cada uno y lo que sale de la máquina lo compone la
   * API en el idioma que pide esta página. `leavingNow` va en presente porque el carril YA está encendido y el
   * tráfico está ocurriendo; `ifEnabled` es condicional. Juntarlos dejaría que un carril encendido se leyera como
   * una hipótesis.
   */
  lanes: {
    title: 'Carriles',
    sub: [
      'Todo lo que puede salir de este proceso. Apagado es lo predeterminado, y el motor determinista no necesita',
      'ninguno. Un cambio surte efecto en la siguiente ejecución — sin reiniciar.',
    ].join(' '),
    loading: 'Cargando carriles…',
    leavingNow: 'Sale de esta máquina: ',
    ifEnabled: 'Si se activa: ',
    followEnvironment: 'fijado aquí · seguir al entorno',
    followEnvironmentHint: (environmentValue) =>
      `El entorno del contenedor lo tiene ${environmentValue ? 'encendido' : 'apagado'}. Vuelve a seguirlo.`,
    inertLead: 'Encendido, pero sin hacer nada — ',
    inertTail: ' está apagado, y esto sólo actúa dentro de ese carril.',
  },

  panels: {
    privacyTitle: 'Privacidad y conectividad',
    externalAgent: 'Copiloto / agente externo',
    humanApproval: 'Requiere aprobación humana',
    storageTitle: 'Almacenamiento y retención',
    localAnalysis: 'Análisis local',
    helpSub: 'Aprende a moverte por el banco, o vuelve a ver la introducción.',
  },

  state: {
    enabled: 'Activado',
    disabled: 'Desactivado',
  },

  /**
   * La pestaña de análisis. Nada de aquí es una preferencia: todo lo que nombra son ajustes del despliegue que se
   * leen del entorno, y la línea de cierre del panel lo dice. Los nombres de las variables van AL LADO de estas
   * frases, nunca dentro: quien busca `FIRMLAB_MAX_UPLOAD` en un fichero de compose tiene que encontrarlo.
   */
  analysis: {
    title: 'Análisis',
    sub: [
      'El motor determinista se ejecuta en cada subida sin ninguna configuración. La profundidad la aportan las',
      'herramientas externas y los límites del despliegue, que se fijan en el servidor.',
    ].join(' '),
    externalTools: 'Herramientas externas',
    viewTools: 'Ver las herramientas detectadas',
    toolsHint: [
      'binwalk, radare2/Ghidra, syft/grype, gitleaks y QEMU habilitan extracción, triaje, SBOM y CVE, escaneo',
      'profundo de secretos y emulación cuando están presentes.',
    ].join(' '),
    uploadLimit: 'Límite de subida',
    uploadLimitLead: 'El tamaño máximo de imagen se fija con',
    uploadLimitTail: '(500 MB por defecto).',
    jobConcurrency: 'Concurrencia de trabajos',
    concurrencyLead: 'Las herramientas pesadas se limitan con',
    concurrencyTail: '(2 por defecto) para que una ráfaga no agote la máquina.',
    deploymentNote: [
      'Son ajustes del despliegue y no preferencias de sesión, así que viven en el entorno y no aquí — este panel',
      'se limita a reflejarlos con honestidad.',
    ].join(' '),
  },

  /**
   * El marco de la pestaña de privacidad. Las palabras de la postura de red son un veredicto sobre ESTE despliegue,
   * recalculado en cada carga: `Sólo local` afirma que el firmware no sale de la máquina, y suavizar `Expuesto a la
   * red` invertiría esa afirmación. `Desconocida` es un estado propio a propósito — una API inalcanzable no es una
   * API local, y el panel nunca debe suponer en la dirección tranquilizadora.
   */
  privacy: {
    sub: 'FirmLab está pensado para ejecutarse en local. Las imágenes de firmware se analizan en esta máquina y no se suben a ningún sitio.',
    networkPosture: 'Postura de red',
    bindAddress: 'Dirección de escucha',
    posture: {
      unknown: 'Desconocida',
      unknownNote: 'La API no responde.',
      proxy: 'Proxy con autenticación',
      proxyNote: 'Sólo se llega a ella a través de un proxy inverso que autentica.',
      exposed: 'Expuesto a la red',
      exposedNote: 'Se llega a la API más allá de loopback. Conviene restringirla.',
      local: 'Sólo local',
      localNote: 'Escucha en loopback — el firmware no sale de esta máquina.',
    },
    agentSentTo: [
      'Cuando ejecutas el copiloto o una sesión del agente, el contexto determinista del análisis (hallazgos,',
      'metadatos de binarios, referencias cruzadas del corpus) se envía a',
    ].join(' '),
    agentNoBytes:
      'No se envía ningún byte del firmware en crudo. La emulación sigue la política indicada en IA y agente.',
    agentOffLead: 'No hay ningún modelo externo configurado. No se envía nada fuera de la máquina. Actívalo con',
    agentOffTail: 'y una clave de API.',
    banner: [
      'El motor (@firmlab/core) es determinista y no necesita red. Las herramientas externas y el copiloto opcional',
      'son lo único que puede salir de este proceso.',
    ].join(' '),
  },

  agent: {
    title: 'Proveedor de IA',
    sub: [
      'Un LLM da servicio al copiloto y a los nodos de decisión del agente consciente. Es opcional — sin ninguna',
      'clave configurada, FirmLab sigue siendo completamente determinista y local. El proveedor y la clave se fijan',
      'en el servidor; esto sólo los refleja.',
    ].join(' '),
    activeProvider: 'Proveedor activo',
    noneConfigured: 'ninguno configurado',

    edit: {
      title: 'Proveedor',
      sub: 'Configúralo aquí, o en el entorno del despliegue. Cada campo dice cuál de los dos manda.',
      provider: 'Proveedor',
      model: 'Modelo',
      modelHint: 'Un id de modelo, tal como lo nombra el proveedor. Aquí no se valida — la autoridad es el proveedor.',
      baseUrl: 'URL base',
      baseUrlHint: 'Cámbiala sólo para alcanzar un endpoint compatible en otro sitio. Ahí es donde van los prompts.',
      apiKey: 'Clave de API',
      keySet: 'hay una clave',
      keyMissing: 'sin clave',
      keyPlaceholder: 'pega una clave para sustituir la guardada',
      keyNeverShown: 'Una clave guardada no vuelve nunca a esta página — se puede sustituir, no leer.',
      keyWarning:
        'Guardar una clave aquí significa que queda almacenada en la base de datos de este despliegue y ya no sólo en su entorno. Se te factura a ti, y en los carriles de agente e inteligencia externa recibe prompts construidos con el firmware que analizas.',
      keyInEnv: (envVar) => `O deja esto vacío y pon la clave en ${envVar}, que el servidor también lee.`,
      save: 'Guardar',
      clear: 'Borrar',
      fromEnv: 'del entorno',
      fromOverride: 'puesto aquí',
      fromDefault: 'defecto del proveedor',
      ready: 'listo',
      notReady: 'sin configurar',
      saved: 'Guardado',
      cleared: 'Borrado — este campo vuelve a seguir al entorno',
    },
    governorTitle: 'Gobernador del agente',
    governorSub: [
      'El agente razona dentro de un esqueleto determinista y se detiene a pedir aprobación antes de emular. Estos',
      'límites son techos estrictos del gobernador, no una lista que la ejecución deba completar. Se fijan mediante variables de entorno.',
    ].join(' '),
    status: 'Estado',
    model: 'Modelo',
    stepBudget: 'Máximo de turnos LLM',
    tokenBudget: 'Presupuesto de tokens',
    costCeiling: 'Techo de coste',
    unbounded: 'sin acotar',
    timeBudget: 'Presupuesto de tiempo',
    emulation: 'Emulación',
    approvalTitle: 'Política de autorización para futuras sesiones del agente',
    approvalManual: 'Preguntar en cada sesión',
    approvalAll: 'Preautorizar todo',
    approvalScope:
      'Se aplica a sesiones futuras y sólo a objetivos de emulación ya propuestos y acotados por la comprobación determinista. No autoriza fuzzing, mensajes externos ni comandos arbitrarios.',
    approvalWarning:
      'Las ejecuciones podrán comenzar sin supervisión incluso si este host sólo ofrece aislamiento parcial. Actívalo únicamente para firmware e infraestructura que estés autorizado a probar.',
    approvalFromOverride: 'Fijado aquí. ',
    approvalFromEnvironment: 'Sigue FIRMLAB_AGENT_PREAPPROVE del entorno.',
    approvalFromDefault: 'Valor seguro por defecto: aprobación manual.',
    approvalFollowEnvironment: 'Seguir el entorno',
    offLead: 'Define',
    offTail: [
      'y una clave de API de LLM para habilitar los nodos de decisión. Con el interruptor apagado, FirmLab sigue',
      'siendo local y determinista.',
    ].join(' '),
  },

  storage: {
    sub: 'Las imágenes subidas y los rootfs extraídos viven bajo el directorio de datos de esta máquina.',
    onDisk: 'En disco',
    quotaOf: (p) => `${p.used} de ${p.quota} de cuota`,
    images: 'Imágenes',
    retention: 'Retención',
    evictedAfter: (days) => `Se desalojan las imágenes con más de ${days} día(s).`,
    noAgeLimit: 'Sin límite de antigüedad.',
    oldestFirst: 'Al superar la cuota se desalojan primero las imágenes más antiguas.',
    noQuota: 'Sin cuota de tamaño.',
    manageLead: 'Gestiona o borra imágenes en bloque desde',
    manageMid: '. Los límites de retención se configuran con',
    manageAnd: 'y',
  },

  help: {
    title: 'Ayuda',
    tour: 'Recorrido del producto',
    restartTour: 'Repetir el recorrido',
    keyboard: 'Teclado',
    keyboardHint: 'Navega con Tab y Mayús+Tab; activa con Intro o Espacio; cierra las capas con Esc.',
    documentation: 'Documentación',
    documentationHint:
      'Consulta el README del proyecto y docs/ para la arquitectura, la escalera de emulación y el diseño del agente.',
    about: 'Acerca de',
    aboutHint:
      'FirmLab — banco de análisis de firmware que sólo se ejecuta en local. Motor determinista, profundidad opcional apoyada en herramientas.',
  },
};
