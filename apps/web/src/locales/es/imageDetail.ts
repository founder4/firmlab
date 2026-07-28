import type { Messages } from '../en';

/**
 * imageDetail — español. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse.
 *
 * Aquí la prosa es el producto, no adorno. Tres afirmaciones no se pueden ablandar al traducirlas:
 *
 *   - una etapa **bloqueada** significa que la pregunta SÍ se hizo y este despliegue no pudo responderla; jamás
 *     «sin problemas»;
 *   - una lista de hallazgos vacía no es «limpio», y una pista no es un veredicto;
 *   - la emulación prueba el entorno aislado, **nunca** el dispositivo físico.
 *
 * Los códigos de estado de prueba, las gravedades, los nombres de herramienta (`binwalk`, `syft`, `radare2`), las
 * variables de entorno y las rutas no se traducen: son identificadores o valores literales. El texto que llega de
 * la API (títulos y razonamientos de hallazgos, el `reason` de un proveedor) se muestra tal cual se registró; sólo
 * el texto de respaldo que escribe esta pantalla vive aquí.
 *
 * Registro: técnico y neutro, del mismo tono que `docs/DEPLOYMENT.md`. Se evita el anglicismo gratuito, pero se
 * conservan los términos que el oficio usa en inglés y que traducirlos volvería ambiguos (rootfs, firmware, SBOM).
 */
export const imageDetail: Messages['imageDetail'] = {
  header: {
    eyebrow: (arch: string) => `Firmware · ${arch}`,
    unknownArch: 'arquitectura desconocida',
    report: 'Informe',
    disclosure: 'Divulgación',
    disclosureTitle: 'Borrador de divulgación coordinada (Markdown) — revísalo antes de enviarlo',
  },

  emptyAnalysis: {
    title: 'Sin análisis estático',
    body: (dashboard: string) =>
      `Esta imagen aún no se ha analizado, o el análisis falló. Vuelve a subirla desde la sección ${dashboard}.`,
  },

  findingsTab: {
    operatorPrompt:
      '¿Sabes algo que el banco no puede medir — un resultado del dispositivo físico, un aviso del fabricante?',
  },

  dossier: {
    signalTitle: 'Cinta de señal',
    signalSub:
      'Traza de entropía sobre el corte por estructura, con los hallazgos anclados a su desplazamiento. Desplázate para leer cualquier rango de bytes.',

    statBinaries: 'Binarios',
    statBinariesValue: (total: number, triaged: number) => `${total} (${triaged} triados)`,
    statFindings: 'Hallazgos',
    statStrategy: 'Estrategia de ejecución',

    copilotTitle: 'Análisis del copiloto',
    copilotModelTitle: 'LLM que respalda al copiloto',
    copilotAnalyzing: 'Analizando…',
    copilotRerun: 'Volver a ejecutar',
    copilotAnalyze: 'Analizar',
    copilotSub:
      'Interpretación sobre los hallazgos citados — antecedentes y estados de prueba, no verdades nuevas. El copiloto no ejecuta nada y no inventa nada.',

    coverageTitle: 'Cobertura',
    coverageSub: 'Lo que se ha ejecutado hasta ahora — el expediente nunca da por completo lo que no lo está.',
    stageStatic: 'Análisis estático',
    stageExtract: 'Extracción',
    stageSbom: 'SBOM y CVE',
    stageSecrets: 'Secretos profundos (gitleaks)',
    stageTriage: 'Triaje de binarios',
    stageEmulation: 'Emulación',
    preflight: 'Comprobación previa de ejecución',
    proofCeiling: 'Techo de prueba',

    corpusTitle: (n: number) => `Referencias cruzadas del corpus (${n})`,
    corpusSub:
      'Cosas de esta imagen que el corpus ha visto en otras — antecedentes que conviene revisar, no conclusiones.',
    corpusCredentialFallback: 'credencial',
    corpusCredential: (kind: string) => `${kind} — también en`,
    corpusComponent: (name: string, version: string, cveCount: number) =>
      `${name} ${version}${cveCount > 0 ? ` (${cveCount} CVE)` : ''} — también en`,
    corpusArtifact: (path: string) => `${path} — el mismo binario en`,
  },

  structure: {
    title: 'Mapa de estructura',
    sub: (segments: number) => `Disposición tallada por firmas a lo largo de la imagen (${segments} segmentos)`,
  },

  entropy: {
    title: 'Perfil de entropía',
    sub: 'Entropía de Shannon a lo largo de la imagen — las bandas altas están comprimidas o cifradas',
    colRegion: 'Región de entropía alta',
    colMeanH: 'H media',
    colSize: 'Tamaño',
  },

  secrets: {
    title: 'Secretos y credenciales',
    sub: 'Coincidencias heurísticas en la imagen en bruto (los valores mostrados son previos a la extracción)',
    empty: 'No se ha detectado ninguna cadena con aspecto de secreto en la imagen en bruto.',
    colSeverity: 'Gravedad',
    colKind: 'Tipo',
    colOffset: 'Desplazamiento',
    colValue: 'Valor',
  },

  gitleaks: {
    title: 'Escaneo profundo de secretos (gitleaks)',
    sub: 'Escanea el rootfs extraído en busca de claves, tokens y credenciales dentro de los ficheros.',
    scanning: 'Escaneando…',
    rescan: 'Volver a escanear el rootfs',
    scan: 'Escanear el rootfs',
    unavailable: 'gitleaks no disponible — ejecuta primero la extracción, o instala gitleaks.',
    count: (n: number) => `${n} hallazgo${n === 1 ? '' : 's'} en el rootfs.`,
    colRule: 'Regla',
    colFile: 'Fichero',
    colLine: 'Línea',
    colMatch: 'Coincidencia',
  },

  filesystem: {
    statFiles: 'Ficheros',
    statDirs: 'Directorios',
    statSetuid: 'binarios setuid',
    rootfsTitle: 'Sistema de ficheros raíz',
    title: 'Extracción del sistema de ficheros',
    sub: 'Talla la imagen con binwalk y modela el rootfs recuperado.',
    extracting: 'Extrayendo…',
    run: 'Ejecutar la extracción',
    noRootfs: 'La extracción no produjo ningún rootfs (binwalk no disponible, o no se encontró sistema de ficheros).',
  },

  job: {
    failed: 'El trabajo falló',
  },

  sbom: {
    title: 'Lista de materiales de software (SBOM) + CVE',
    sub: 'syft inventaría el rootfs extraído; grype correlaciona los CVE conocidos (N-day).',
    scanning: 'Escaneando…',
    rescan: 'Volver a escanear',
    generate: 'Generar SBOM y escanear CVE',
    unavailable: 'SBOM no disponible — ejecuta primero la extracción, o instala syft.',
    statPackages: 'Paquetes',
    statVulns: 'Vulnerabilidades',
    statCritHigh: 'Críticas / altas',
    grypeMissing: 'grype no está presente — el SBOM se generó, pero la correlación con CVE no llegó a ejecutarse.',
    graphTitle: 'Grafo de componentes',
    graphSub:
      'El rootfs y sus componentes, agrupados por ecosistema alrededor del anillo y coloreados por el CVE más grave que afecta a cada uno. Pasa el cursor por un nodo para ver su versión y sus CVE.',
    cvesTitle: 'CVE',
    colSeverity: 'Gravedad',
    colPackage: 'Paquete',
    colVersion: 'Versión',
    colFixedIn: 'Corregido en',
    packagesTitle: (n: number) => `Paquetes (${n})`,
    colName: 'Nombre',
    colType: 'Tipo',
    runLabel: 'SBOM',
  },

  binaries: {
    listTitle: (n: number) => `Binarios (${n})`,
    listSub:
      'Todos los ELF del rootfs extraído, con la arquitectura leída de su cabecera. Selecciona uno para triarlo.',
    colPath: 'Ruta',
    colArch: 'Arq.',
    colHardening: 'Endurecimiento',
    colImports: 'Importaciones notables',
    colNet: 'Red',
    triageTitle: 'Triaje de binarios (radare2)',
    triageSub: 'Triaje estático de un binario del rootfs extraído: cabeceras, importaciones, símbolos y cadenas.',
    noRootfs: (section: string) =>
      `Todavía no hay ningún rootfs extraído — ejecuta antes la extracción en la pestaña ${section}.`,
    pathPlaceholder: 'ruta relativa al rootfs, p. ej. bin/busybox',
    triaging: 'Haciendo triaje…',
    triage: 'Hacer triaje del binario',
    unavailable: 'Triaje no disponible — comprueba la ruta, o instala radare2.',
    nx: (on: boolean) => `NX ${on ? 'activo' : 'inactivo'}`,
    // `canary` es el nombre de la mitigación, no una palabra a traducir; sólo se localiza su estado.
    canary: (on: boolean) => `canary ${on ? 'activo' : 'inactivo'}`,
    pic: (on: boolean) => `PIC ${on ? 'sí' : 'no'}`,
    funcs: (n: number) => `${n} funciones`,
    importsTitle: (n: number) => `Importaciones (${n})`,
    colSymbol: 'Símbolo',
    colLibrary: 'Biblioteca',
    symbolsTitle: (n: number) => `Símbolos (${n})`,
    colSymbolName: 'Nombre',
    colSymbolType: 'Tipo',
    stringsTitle: (n: number) => `Cadenas (${n})`,
    colAddress: 'Dirección',
    colValue: 'Valor',
  },

  ghidra: {
    title: 'Descompilación (Ghidra)',
    sub: 'Pseudocódigo completo con Ghidra headless — necesita la capa opcional de Ghidra en la imagen.',
    decompiling: 'Descompilando…',
    decompile: 'Descompilar con Ghidra',
    unavailable: 'Ghidra no está instalado — construye la imagen con su capa opcional.',
    decompiled: (n: number, binary: string) => `${n} funciones descompiladas de ${binary}.`,
  },

  diff: {
    title: 'Comparar firmware',
    sub: 'Compara identidad, paquetes y CVE (necesita SBOM en ambas) y ficheros del rootfs (necesita extracción).',
    needSecond: 'Sube una segunda imagen con la que comparar.',
    selectPlaceholder: 'Elige una imagen con la que comparar…',
    comparing: 'Comparando…',
    compare: 'Comparar',
    identityTitle: 'Identidad',
    identityNone: 'Sin diferencias de identidad.',
    colField: 'Campo',
    packagesTitle: 'Paquetes',
    packagesNeedSbom: 'Ejecuta SBOM en ambas imágenes para comparar paquetes.',
    statAdded: 'Añadidos',
    statRemoved: 'Eliminados',
    statVersionChanged: 'Con la versión cambiada',
    colPackage: 'Paquete',
    cvesTitle: 'CVE',
    cvesNeedSbom: 'Ejecuta SBOM en ambas imágenes para comparar CVE.',
    added: (n: number) => `+${n} añadidos`,
    removed: (n: number) => `−${n} eliminados`,
    bySeverity: (n: number, severity: string) => `+${n} ${severity}`,
    noNewCves: 'Ningún CVE nuevo respecto a la otra imagen.',
    filesTitle: 'Sistema de ficheros raíz',
    filesNeedExtract: 'Ejecuta la extracción en ambas imágenes para comparar ficheros.',
    statFilesChanged: 'Cambiados (tamaño)',
    runLabel: 'comparativa',
  },

  research: {
    offTitle: 'Inteligencia externa',
    offBadge: 'desactivada',
    offBodyBefore: 'La única función que sale de esta máquina. Actívala con ',
    offBodyAfter:
      ' para correlacionar el SBOM con avisos públicos (OSV) y redactar notas de divulgación responsable. Desactivada por defecto — FirmLab sigue siendo sólo local.',

    title: 'Inteligencia externa',
    sourceBadge: 'fuentes públicas',
    sourceTitle: 'Correlacionado desde fuentes públicas; alcanzabilidad sin verificar',
    researching: 'Investigando…',
    rerun: 'Volver a ejecutar',
    run: 'Ejecutar la investigación',
    sub: 'Envía únicamente nombres y versiones de componentes a las bases de datos de vulnerabilidades (OSV, NVD); descarga el catálogo KEV de CISA para marcar localmente los CVE con explotación conocida. Nunca bytes del firmware, secretos ni claves. Un aviso publicado para un componente presente es una pista, no un fallo confirmado (la alcanzabilidad se decide imagen a imagen).',

    osvBadge: (n: number) => `OSV: ${n} consultados`,
    osvBadgeTitle: 'OSV: componentes del SBOM que pudieron mapearse a un ecosistema y se consultaron',
    osvAdvisories: (n: number) => `${n} avisos de OSV`,
    nvdBadge: (queried: number, advisories: number) => `NVD: ${queried} consultados · ${advisories} avisos`,
    nvdTitleUnknown:
      'NVD, para los componentes que OSV no pudo mapear. Este resultado es anterior a la separación CPE/palabra clave, así que no se registró qué pregunta lo produjo — vuelve a ejecutar la investigación para saberlo.',
    nvdTitle: (cpe: number, keyword: number) =>
      `NVD, para los componentes que OSV no pudo mapear: ${cpe} preguntados por coincidencia de versión CPE y ${keyword} por palabra clave. Una respuesta por palabra clave sólo coincide con el texto de la descripción del CVE — que venga vacía no prueba que el componente no esté afectado.`,
    kevBadge: (n: number) => `KEV: ${n} con explotación conocida`,
    kevBadgeTitle: 'CISA Known Exploited Vulnerabilities — explotadas activamente',
    vendorTitle: 'Pista de procedencia (fabricante)',

    kevHeading: '⚠ Con explotación activa conocida (CISA KEV) · aquí la alcanzabilidad sigue sin verificar',
    ransomware: 'usada en ransomware',
    ransomwareTitle: 'Usada en campañas de ransomware conocidas',
    kevAdded: (date: string) => `añadida el ${date}`,

    colComponent: 'Componente',
    colAdvisories: 'Avisos (alcanzabilidad sin verificar)',

    nvdHeading:
      'NVD · componentes que OSV no pudo mapear (coincidencia por versión afectada; alcanzabilidad sin verificar)',
    uncheckedBefore: (name: string, version: string) =>
      `${name} ${version} volvió vacío bajo su identidad CPE principal. NVD también lo registra como `,
    uncheckedAfter:
      ', que no se consultó — el cero está acotado a la identidad por la que se preguntó, no al componente.',
    colAskedBy: 'Preguntado por',
    colCves: 'CVE (NVD)',
    askedCpe: 'versión CPE',
    askedKeyword: 'palabra clave',
    askedUnknown: 'sin registrar',
    askedCpeTitle: 'Coincidencia por versión CPE — NVD resolvió esta versión contra el rango afectado de cada CVE.',
    askedKeywordTitle:
      'Palabra clave — coincidió con el texto de la descripción del CVE, que nombra la versión CORREGIDA y no la vulnerable. La más débil de las dos preguntas.',
    askedUnknownTitle:
      'Este resultado es anterior a la separación CPE/palabra clave, así que no se registró qué pregunta lo produjo. Vuelve a ejecutar la investigación para saberlo.',
    shownOf: (shown: number, total: number) => `se muestran ${shown} de ${total}`,
    shownOfTitle: (shown: number, total: number, name: string, version: string) =>
      `Esta fila lista ${shown}. NVD tiene ${total} CVE para ${name} ${version}; el resto no se muestra aquí.`,

    keyHeading: 'Material de clave · una clave embebida es, a efectos prácticos, pública',
    effectivelyPublic: 'públicas en la práctica',
    effectivelyPublicTitle: 'Extraíble de cualquier dispositivo que ejecute este firmware',
    reusedIn: (n: number) => `reutilizada en ${n} imagen(es) más`,

    contactsHeading: 'Divulgación responsable · security.txt',
    noSecurityTxt: 'sin security.txt',
    brief: (provider: string, model: string) => `Resumen · ${provider} · ${model}`,
    runLabel: 'investigación',
  },

  agent: {
    sessionStatus: {
      running: 'en curso',
      awaiting_approval: 'esperando aprobación',
      done: 'terminada',
      error: 'fallida',
      halted: 'detenida (gobernador)',
    },
    node: {
      triage: '① Triaje',
      extraction: 'Extracción (determinista)',
      preflight: 'Comprobación previa (determinista)',
      'target-selection': '② Selección de objetivos',
      emulation: 'Emulación',
      error: 'Fallo',
    },

    triageClass: 'clase',
    triageExtract: 'extracción:',
    cascade: (chain: string) => `cascada ${chain}`,
    attackSurface: (surface: string) => `superficie de ataque: ${surface}`,
    strategy: 'estrategia',
    ceiling: 'techo',
    rootfsYes: '✓ rootfs recuperado',
    rootfsNo: '○ sin rootfs',
    arch: 'arq.',
    files: (n: string) => `${n} ficheros`,
    noTargets: 'ningún objetivo seleccionado',
    ran: 'ejecutado',
    exit: 'salida',
    proofState: 'estado de prueba',
    tokens: (n: number) => `${n} tok`,
    audit: 'auditoría: entradas y decisión',

    budgetSteps: 'pasos',
    budgetTokens: 'tokens LLM',
    budgetCost: 'coste',
    budgetTime: 'tiempo',

    disabledTitle: 'Agente — autonomía consciente',
    disabledBefore: 'Desactivado. Define ',
    disabledAfter:
      ' y una clave de API de un LLM para habilitar los nodos de decisión. Con la bandera apagada, FirmLab sigue siendo sólo local, determinista, sin red y sin coste.',

    sessionTitle: 'Sesión del agente',
    running: 'Ejecutando…',
    newSession: 'Nueva sesión',
    startSession: 'Comenzar sesión',
    sub: 'El agente razona dentro de un esqueleto determinista: elige ramas (triaje ①, selección de objetivos ②) e interpreta — cada paso mecánico es determinista, y la emulación espera tu aprobación. Un gobernador acota la ejecución.',

    approvalTitle: 'Se requiere aprobación — emulación propuesta',
    approvalSub:
      'El agente propone ejecutar esto bajo emulación. La emulación prueba el entorno aislado, no el dispositivo; nada se ejecuta sin tu aprobación.',
    approve: 'Aprobar y ejecutar',
    declineAll: 'Rechazar todo',
    noSession: 'Todavía no hay ninguna sesión del agente. Inicia una para que triee y seleccione objetivos.',
  },
};
