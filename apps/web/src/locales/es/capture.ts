import type { Messages } from '../en';

/**
 * capture — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse.
 *
 * Ésta es la pantalla donde suavizar una frase tiene consecuencias fuera del navegador: cada cadena dice qué sale
 * de esta máquina, qué se toca en la red de alguien y bajo qué reconocimiento. La casilla de autorización, el «no
 * se intercepta nada» del barrido y el callejón sin salida del TLS fijado se traducen con el mismo énfasis que en
 * inglés — un castellano más suave afirmaría menos de lo que realmente ocurre.
 *
 * No se traducen: los nombres de herramienta (`arp-scan`, `nmap`, `mitmproxy`, Frida), la variable de entorno y el
 * flag de Docker, los transportes y los techos de adquisición (`captured_plaintext`, `blocked_by_pinning`), los ids
 * de backend, las MAC, las IP y las URL.
 */
export const capture: Messages['capture'] = {
  eyebrow: 'Adquisición',
  title: 'Proxy / Actualizaciones',
  desc: 'Ponte en la ruta de un dispositivo, intercepta su actualización OTA, extrae el firmware del tráfico capturado e ingéstalo — y sigue cómo cambian sus versiones con el tiempo. El segundo carril de FirmLab que toca la red.',

  laneOn: {
    discover: 'Descubre',
    mid: 'los dispositivos de abajo; después',
    capture: 'Captura',
    tail: 'activa un proxy en ruta sobre un objetivo: dispara su OTA y FirmLab puntúa los flujos capturados en busca de firmware y ofrece el blob extraído para ingestarlo con un clic. El reenvío interactivo de peticiones (un repetidor HTTP completo) está en la hoja de ruta — necesita un endpoint de reenvío en el servidor.',
  },

  laneOff: {
    lead: 'El carril de captura está',
    word: 'desactivado',
    set: 'Define',
    enable: 'para activarlo (tiene su propio flag, igual que',
    detection:
      'La detección de abajo sigue ejecutándose — es de sólo lectura — pero armar un escaneo queda deshabilitado hasta que el carril esté activo.',
    docker: 'En Docker, el descubrimiento necesita además',
  },

  backends: {
    title: 'Backends de captura',
    sub: 'Cómo podría este despliegue ponerse en la ruta y qué podría leer. Conecta hardware → se enciende un backend. Techo de captura ahora mismo:',
    none: 'todavía no hay nada capturable',
    colBackend: 'Backend de captura',
    colRole: 'Función',
    colUnlocks: 'Qué desbloquea / qué hace falta',
  },

  roles: {
    positioning: 'Posicionamiento',
    interception: 'Interceptación',
    radio: 'Radiofrecuencia',
    physical: 'Físico',
  },

  discover: {
    title: 'Descubrir dispositivos',
    sub: 'Un barrido pasivo de hosts (arp-scan / nmap) construye el inventario de abajo. No se intercepta nada — el descubrimiento sólo enumera quién está en la red.',
    ack: 'Confirmo que estos dispositivos y redes son míos o que tengo autorización para probarlos.',
    subnetPlaceholder: 'subred (p. ej. 192.168.1.0/24) — en blanco = detección automática',
    subnetLabel: 'Subred que escanear',
    scan: 'Escanear la red',
    scanning: 'Escaneando…',
    failed: 'El descubrimiento falló',
  },

  radar: {
    title: 'Radar de dispositivos',
    sub: (n) =>
      `${n} dispositivo${n === 1 ? '' : 's'} en el inventario. Las conjeturas de tipo son heurísticas (formuladas como preguntas), nunca afirmaciones.`,
    scannedTitle: 'Barrido completado — no respondió ningún dispositivo',
    scannedBody:
      'El barrido se ejecutó y no contestó nadie. En Docker el descubrimiento necesita --network host; comprueba también que arp-scan o nmap estén instalados.',
    noScanTitle: 'Todavía no se ha escaneado',
    noScanBody: 'Arma arriba un escaneo de descubrimiento para construir el inventario de la LAN.',
    colVendor: 'Fabricante',
    colGuess: 'Conjetura de tipo',
    colSeen: 'Visto',
    preflight: 'Viabilidad',
    capture: 'Capturar',
    captureReady: 'Armar una captura de OTA para este dispositivo',
    captureBlocked: 'Reconoce antes la autorización',
    seconds: (n) => `hace ${n} s`,
    minutes: (n) => `hace ${n} min`,
    hours: (n) => `hace ${n} h`,
  },

  preflight: {
    ceiling: 'Techo:',
    unpin: 'descargar el unpin de Frida →',
  },

  session: {
    title: 'Sesión de captura',
    target: 'Objetivo',
    status: 'estado',
    ceiling: 'techo',
    trigger:
      'Dispara ahora la OTA del dispositivo; los flujos con aspecto de firmware se resaltan y pueden ingestarse.',
    pinned:
      'El dispositivo fija el certificado TLS — la OTA no puede descifrarse a través del proxy. Ejecuta el script de unpin incluido en un teléfono rooteado:',
    stop: 'Parar y desmontar',
    noFlows: 'Todavía no hay flujos — esperando tráfico a través del proxy.',
    colScore: 'Puntuación',
    colType: 'Tipo',
    colSize: 'Tamaño',
    colInspection: 'Inspección del cuerpo',
    inspectionComplete: (n) => `${n} inspeccionados`,
    inspectionPartial: (seen, total) => `${seen} de ${total} inspeccionados — puntuación acotada`,
    inspectionUnavailable: 'Cuerpo no conservado — la puntuación usó solo metadatos',
    inspectionLegacy: 'No se registró la cobertura de este flujo',
    ingest: 'Ingestar',
    ingested: 'ingestada →',
  },

  learning: {
    title: 'Aprendizaje de OTA',
    sub: 'Lo que el corpus entre imágenes ha aprendido entre versiones capturadas — una línea temporal de OTA por familia, cómo distribuye cada fabricante y qué CDN sirve a quién. Captura el mismo dispositivo dos veces para desbloquear una comparativa entre versiones.',
    emptyTitle: 'Todavía no hay versiones capturadas',
    emptyBody: 'Ingesta una captura (arriba) — su procedencia siembra aquí la línea temporal de OTA.',
    priors: 'Antecedentes por fabricante:',
    ships: 'distribuye',
    fromCdns: (cdns) => `desde ${cdns}`,
    versions: (n) => `${n} ${n === 1 ? 'versión' : 'versiones'}`,
    open: 'abrir →',
    diffPrev: 'comparar con la anterior',
  },

  wireless: {
    panelTitle: 'Reconstruir firmware desde una captura inalámbrica',
    panelSub:
      'Reconstruye un firmware a partir de escrituras DATA de Bluetooth Low Energy (Nordic DFU) o de bloques de imagen de Zigbee OTA (clúster 0x0019) para crear una imagen ingestable.',
    tabBle: 'DFU de BLE',
    tabZigbee: 'OTA de Zigbee',
    ack: 'Reconozco la autorización para reconstruir el firmware de estas tramas inalámbricas capturadas.',
    ackRequired: 'Se requiere el reconocimiento del operador antes de crear una sesión o enviar capturas.',
    disabledWarning:
      'La reconstrucción inalámbrica requiere el carril de captura: define FIRMLAB_CAPTURE=1 para activarlo (en Docker usa además --network host).',
    targetDevice: 'Dispositivo objetivo (opcional)',
    deviceSelectPlaceholder: 'Selecciona un dispositivo o déjalo sin asignar',
    deviceIdLabel: 'Identificador del dispositivo objetivo',
    sessionTitle: 'Sesión de captura',
    sessionIdLabel: 'Identificador de sesión',
    sessionIdPlaceholder: 'ID de sesión (crea una nueva o introduce una existente)',
    createSession: 'Crear sesión',
    creatingSession: 'Creando sesión…',
    sessionCreated: (id) => `Sesión ${id} activa`,
    sessionRequired: 'Se requiere un ID de sesión válido. Crea o especifica uno arriba.',
    filenameLabel: 'Nombre del archivo de firmware',
    filenamePlaceholder: 'ej. ble-dfu.bin o zigbee-ota.bin',
    filesLabel: 'Archivo(s) de captura',
    filesHintBle:
      'Sube un archivo JSON ({ chunks: ["base64…"] }), un archivo de texto (líneas base64/hex) o múltiples fragmentos binarios.',
    filesHintZigbee:
      'Sube un archivo JSON ({ blocks: ["base64…"] }), un binario OTA o múltiples fragmentos de Image-Block.',
    filesRequired: 'Se requiere al menos un archivo de captura o fragmento de datos.',
    initPacketLabel: 'Paquete init de Nordic DFU (.dat, opcional)',
    initPacketHint: 'Se usa para verificar el tamaño declarado frente al flujo de bytes reconstruido.',
    autoIngest: 'Ingestar automáticamente la imagen extraída en el banco de trabajo',
    submitBle: 'Reconstruir DFU de BLE',
    submitZigbee: 'Reconstruir OTA de Zigbee',
    processing: 'Reconstruyendo firmware…',
    readingFiles: 'Leyendo y analizando archivos…',
    resultsTitle: 'Resultado de la reconstrucción',
    statusComplete: 'Reconstrucción completa',
    statusIncomplete: 'Captura incompleta',
    statusUnknown: 'Tamaño esperado desconocido',
    statusLegacy: 'El servidor no proporcionó veredicto de completitud (versión de servidor anterior)',
    statusError: 'Error de reconstrucción',
    reconstructedBytes: 'Bytes reconstruidos:',
    chunksCount: (n) => `${n} fragmento${n === 1 ? '' : 's'}`,
    blocksCount: (n) => `${n} bloque${n === 1 ? '' : 's'}`,
    expectedBytes: 'Tamaño esperado:',
    expectedUnknown: 'Desconocido',
    missingGaps: 'Huecos y bloques ausentes:',
    noGaps: 'Ninguno — el flujo de bytes es contiguo y completo',
    missingBytesCount: (missing, expected) =>
      `Faltan ${missing} bytes (${((missing / expected) * 100).toFixed(1)} % ausente de ${expected} bytes declarados)`,
    missingChunksNamed: (chunks) => `Secuencia(s) de fragmentos ausentes: ${chunks}`,
    integrity: 'Verificación de integridad:',
    integrityValidZigbee: (mfr, imgType, ver) =>
      `Cabecera Zigbee OTA válida (0x0BEEF11E) · Fabricante: ${mfr} · Imagen: ${imgType} · Versión de fichero: ${ver}`,
    integrityValidBle: (size) => `Coincide con el tamaño declarado en el paquete init (${size})`,
    integrityNone: 'No se suministró paquete init ni cabecera de contenedor para verificación',
    flowStaged: (score) => `Flujo de firmware extraído generado (puntuación de firmware: ${score})`,
    ingestButton: 'Ingestar en el banco de trabajo',
    ingesting: 'Ingestando…',
    imageIngested: (id) => `Firmware ingestada como imagen ${id}`,
    openOverview: 'Abrir vista general de la imagen →',
    emptyTitle: 'Ninguna reconstrucción realizada aún',
    emptyBody:
      'Selecciona una sesión de captura, sube los fragmentos BLE DFU o bloques Zigbee OTA e inicia la reconstrucción.',
  },
};
