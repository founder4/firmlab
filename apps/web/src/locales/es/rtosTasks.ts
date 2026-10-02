import type { Messages } from '../en';

/** rtosTasks — español. Tipado contra el catálogo inglés. */
export const rtosTasks: Messages['rtosTasks'] = {
  title: 'Instantánea de tareas FreeRTOS',
  sub: 'Recorre las listas de tareas listas y pxCurrentTCB en una instantánea de RAM capturada en otro sitio (un volcado del depurador, una imagen de fallo). Aquí no se lee el dispositivo: declaras la dirección base, el orden de bytes y el ancho de puntero, y las direcciones de las listas que se recorren, que puedes rellenar desde la tabla de símbolos ELF de la propia imagen cuando la tiene.',
  collapsedHint:
    'Plegado porque esta imagen no está clasificada como RTOS ni bare-metal. Ábrelo para recorrer una instantánea de RAM igualmente.',

  field: {
    file: 'Instantánea de RAM (bytes en bruto)',
    fileHint: (maxKiB) => `Memoria en bruto, sin contenedor. Como máximo ${maxKiB} KiB.`,
    fileLoaded: (bytes) => `${bytes.toLocaleString('es')} bytes cargados`,
    base: 'Dirección base de la memoria',
    addressHint: 'Decimal, o hexadecimal con el prefijo 0x.',
    endian: 'Orden de bytes',
    endianChoose: 'Elige…',
    little: 'little-endian (byte bajo primero)',
    big: 'big-endian (byte alto primero)',
    pointerWidth: 'Ancho de puntero',
    pointerChoose: 'Elige…',
    bytes: (n) => `${n} bytes`,
    layoutHint:
      'Hay que declarar ambos: un valor por defecto erróneo lee basura con apariencia plausible, así que la API no tiene ninguno.',
    pxCurrentTCB: 'Dirección de pxCurrentTCB (opcional)',
    readyLists: 'Listas de tareas listas (pxReadyTasksLists[prioridad])',
    readyListsHint: (max) => `Opcional, hasta ${max}. Cada prioridad una sola vez.`,
    readyArray: 'O el array completo de listas de tareas listas (pxReadyTasksLists)',
    readyArrayHint:
      'En lugar de listas sueltas: la dirección del array y los dos números que declara tu compilación. Se recorre entonces cada prioridad. sizeof(List_t) se contrasta con el único formato que lee el recorrido (20 bytes con punteros de 4 bytes, 40 con 8); nunca se usa a ciegas. El st_size del símbolo, en bytes, es una comprobación opcional.',
    arrayBase: 'Dirección de pxReadyTasksLists',
    maxPriorities: 'configMAX_PRIORITIES',
    listSize: 'sizeof(List_t)',
    symbolSize: 'st_size (opcional)',
    priority: 'Prioridad',
    address: 'Dirección de la lista',
    addList: 'Añadir lista',
    removeList: (i) => `Quitar la lista ${i}`,
    stateLists: 'Otras listas de estado de tareas (opcional)',
    stateListsHint:
      'Cada una es la dirección de un List_t, como una lista de tareas listas. Deja un campo vacío para omitir esa lista: el resultado la nombra entonces como no recorrida, nunca como vacía.',
    delayedList: 'Lista de retardadas (el List_t al que apunta pxDelayedTaskList)',
    overflowDelayedList: 'Lista de retardadas por desbordamiento (el List_t al que apunta pxOverflowDelayedTaskList)',
    suspendedList: 'Lista de suspendidas (xSuspendedTaskList)',
    pendingReadyList: 'Lista de pendientes de pasar a listas (xPendingReadyList)',
    terminatedList: 'Lista de pendientes de terminar (xTasksWaitingTermination)',
    delayedHint:
      'xDelayedTaskList1 y xDelayedTaskList2 intercambian sus papeles cada vez que el contador de ticks da la vuelta. Lee los dos punteros en la instantánea para saber cuál es la lista actual y cuál la de desbordamiento.',
  },

  error: {
    fileMissing: 'Elige el archivo con la instantánea de RAM.',
    fileEmpty: 'El archivo está vacío; una instantánea vacía no responde nada.',
    fileTooLarge: (bytes, maxKiB) =>
      `El archivo tiene ${bytes.toLocaleString('es')} bytes; la API acepta como máximo ${maxKiB} KiB.`,
    fileRead: (message) => `No se pudo leer el archivo: ${message}`,
    base: 'Introduce la dirección base como entero no negativo (decimal, o hexadecimal con 0x).',
    baseRange: (bits) => `La dirección base y la instantánea deben caber en un espacio de direcciones de ${bits} bits.`,
    endian: 'Declara el orden de bytes.',
    pointerWidth: 'Declara el ancho de puntero.',
    address: (bits) => `Introduce una dirección menor que 2^${bits} (decimal, o hexadecimal con 0x).`,
    priority: 'Introduce una prioridad entera no negativa.',
    priorityRepeated: (p) => `La prioridad ${p} ya está en la lista; cada prioridad se recorre una vez.`,
    tooManyLists: (max) => `Como máximo ${max} listas.`,
    addressRepeated: (address) => `${address} ya está en la lista; cada lista se recorre una vez.`,
    arrayAndLists: 'Declara el array de listas o listas sueltas, no ambos: cada lista se recorre una vez.',
    arrayBase: 'El array necesita su dirección; tómala del símbolo pxReadyTasksLists.',
    maxPriorities: (max) => `Introduce configMAX_PRIORITIES como un entero de 1 a ${max}.`,
    listSize: (expected) =>
      `El recorrido lee un List_t de ${expected} bytes con este ancho de puntero. Una compilación con bytes de integridad de lista o un tipo de tick más ancho tiene otro formato, que este recorrido rechaza en vez de leerlo mal.`,
    listSizeNumber: 'Introduce sizeof(List_t) como un número entero positivo de bytes.',
    symbolSize: 'Introduce st_size como un número entero de bytes, o déjalo vacío.',
    arrayOverflow: (base, bytes, bits) =>
      `Un array en ${base} que ocupa ${bytes} bytes no cabe en el espacio de direcciones de ${bits} bits.`,
    symbolSizeMismatch: (size, n, list) =>
      `st_size es ${size} bytes pero ${n} × ${list} son ${n * list}; uno de los tres números es erróneo.`,
    fixFields: 'Corrige los campos marcados antes de recorrer la instantánea.',
  },

  run: 'Recorrer instantánea',
  rerun: 'Recorrer de nuevo',
  running: 'Recorriendo…',
  notRun:
    'No se ha recorrido ninguna instantánea para esta imagen. Eso es «no ejecutado», no «sin tareas»: aporta una instantánea de RAM arriba para leer sus listas de tareas.',
  refusedHeading: 'La API rechazó esta instantánea',
  refusedHint: 'No se recorrió nada. Corrige la declaración y envíala de nuevo.',
  runFailedHeading: 'El recorrido falló',
  runFailed: 'El recorrido de la instantánea no terminó.',
  runFailedHint: 'El trabajo arrancó y no terminó. Es un fallo de este banco, no una propiedad de la instantánea.',

  result: {
    heading: 'Último recorrido',
    coverage: 'Cobertura',
    coverageValue: { complete: 'completa', partial: 'parcial', none: 'ninguna' },
    proofLead:
      'Siempre es una pista: la instantánea la aporta el analista, no son bytes de esta imagen, y nada demuestra que corresponda a un dispositivo en marcha.',
    snapshot: (base, endian, width, bytes) =>
      `Instantánea en ${base}, ${endian}, punteros de ${width} bytes, ${bytes.toLocaleString('es')} bytes.`,
    lanes: 'Carriles',
    col: {
      lane: 'Carril',
      priority: 'Prioridad',
      coverage: 'Cobertura',
      nodes: 'Nodos (hechos / intentados)',
      bytes: 'Bytes (leídos / intentados)',
      tasks: 'TCB de tareas',
      state: 'Estado',
    },
    stateLanes: 'Listas de estado',
    stateLane: (name, address) => `${name} en ${address}`,
    kind: {
      ready: 'lista',
      delayed: 'retardada',
      delayed_overflow: 'retardada (desbordamiento)',
      suspended: 'suspendida',
      pending: 'pendiente de pasar a lista',
      terminated: 'pendiente de terminar',
    },
    secondDelayed: 'la segunda lista de retardadas',
    wakeTick: (tcb, tick) => `${tcb} despierta en el tick ${tick}`,
    notWalked: (kinds) =>
      `No recorridas, porque no se aportaron: ${kinds}. Las tareas en esos estados no están en este resultado.`,
    severalLists: (n, tcbs) =>
      `${n} TCB aparecen en más de una lista de estado (${tcbs}). Una instantánea coherente no puede producir eso; puede estar desgarrada.`,
    currentLane: 'pxCurrentTCB (tarea en curso)',
    readyLane: (address) => `lista en ${address}`,
    noListSupplied: 'no se aportó ninguna lista',
    readyArrayUnresolved: 'array de listas declarado, dirección sin resolver',
    readyArray: (base, n, size, checked) =>
      `Listas de tareas listas derivadas de pxReadyTasksLists @ ${base}: ${n} prioridades declaradas × ${size} bytes. ${
        checked
          ? 'El st_size del símbolo concuerda.'
          : 'No se aportó st_size, así que el número de prioridades descansa solo en la declaración.'
      }`,
    noTasks: 'ninguna',
    limits: (maxKiB, maxItems, maxLists) =>
      `Límites aplicados: instantánea ≤ ${maxKiB} KiB, ≤ ${maxItems} nodos recorridos por lista, ≤ ${maxLists} listas.`,
    notRecorded: 'no registrado',
  },

  elfSymbols: {
    heading: 'Direcciones desde el ELF de esta imagen (opcional)',
    intro:
      'Lee las direcciones de las listas del kernel en la tabla de símbolos estática de la propia imagen y rellena los campos de abajo. Son direcciones de enlazado, no prueba en ejecución: la instantánea de RAM la sigues aportando tú y todo campo rellenado sigue siendo editable.',
    read: 'Leer símbolos del ELF',
    reread: 'Volver a leer los símbolos del ELF',
    reading: 'Leyendo símbolos…',
    fill: 'Rellenar el formulario con esta lectura',
    notRun:
      'Aún no se han leído los símbolos ELF de esta imagen. Todas las direcciones de abajo se pueden seguir escribiendo a mano.',
    failed: 'La lectura de símbolos no terminó.',
    filled: (names) => `Rellenado con símbolos resueltos: ${names}. Revísalos antes de recorrer.`,
    filledNone: 'No se rellenó nada: ningún campo de lista se resolvió a una única dirección.',
    verdict: {
      'symbols-read': 'Tabla de símbolos estática leída.',
      'no-section-headers':
        'El ELF no tiene tabla de cabeceras de sección, así que no se puede localizar ninguna tabla de símbolos. Eso no indica que la imagen carezca de FreeRTOS.',
      'no-static-symbol-table':
        'El ELF está despojado de símbolos: no tiene tabla de símbolos estática. Eso no indica que la imagen carezca de FreeRTOS.',
      'sections-not-examined':
        'No hay tabla de símbolos estática entre las secciones examinadas, pero algunas quedaron fuera del límite. Sin decidir, no ausente.',
      'static-symbol-table-unreadable':
        'Hay una tabla de símbolos estática, pero no se pudo leer. Eso no indica que la imagen carezca de FreeRTOS.',
      refused:
        'La imagen no se pudo leer como ELF. Un binario en bruto no lleva símbolos, y eso no dice nada sobre FreeRTOS.',
      'file-too-large': 'La imagen supera el límite de lectura y no se leyó, en lugar de leerse a medias.',
      'file-unreadable': 'El fichero de la imagen no se pudo leer en este banco.',
    },
    identity: (elfClass, endian, width, machine) =>
      `El ELF declara ${elfClass}, ${endian}, punteros de ${width} bytes, máquina ${machine}. Declara tú abajo el formato de la instantánea.`,
    symbolsTable: 'Símbolos del kernel FreeRTOS',
    col: { name: 'Símbolo', status: 'Estado', address: 'Dirección', size: 'Tamaño', binding: 'Vinculación' },
    status: {
      resolved: 'resuelto',
      ambiguous: 'ambiguo',
      absent: 'ausente',
      'not-examined': 'sin examinar',
      'undefined-only': 'solo referencias sin definir',
      unavailable: 'no disponible',
    },
    smp: 'variante SMP',
    delayedNotFilled:
      'xDelayedTaskList1 y xDelayedTaskList2 se muestran pero nunca se rellenan: cuál es la actual y cuál la de desbordamiento se lee en los punteros de la instantánea de RAM.',
    notCarried: 'No se trasladan al formulario',
    readyManual:
      'No se rellena ninguna lista de tareas listas por prioridad. Cuando pxReadyTasksLists se resuelve, solo se rellenan la dirección del array y su st_size; configMAX_PRIORITIES y sizeof(List_t) los declaras tú y nunca se deducen del tamaño de un símbolo.',
  },

  ramCapture: {
    heading: 'Instantánea de RAM desde emulación Renode (opcional)',
    intro:
      'Ejecuta el firmware bajo Renode durante un tiempo acotado, pausa la emulación y vuelca la SRAM periférica para analizar estructuras de tareas. La captura es un indicio: prueba lo que escribió el SoC emulado, no que el planificador haya arrancado o que existan tareas.',
    capture: 'Emular y volcar RAM',
    recapture: 'Volver a volcar RAM',
    capturing: 'Emulando y volcando RAM…',
    loadIntoForm: 'Cargar en el formulario',
    loadedIntoForm: 'RAM capturada cargada en el formulario.',
    notRun: 'No se ha capturado ninguna instantánea de RAM con Renode para esta imagen.',
    failed: 'El volcado de RAM falló.',
    capturedHeading: 'RAM capturada con Renode',
    capturedSummary: (name: string, base: string, bytes: number, sec: number) =>
      `Capturados ${bytes.toLocaleString()} bytes del periférico '${name}' (${base}) tras ${sec} s de emulación.`,
    platform: (name: string) => `Plataforma: ${name}`,
    refused: 'Volcado de RAM rechazado:',
    remoteRefused: (count: number) => `${count} petición(es) de recursos remotos rechazada(s) (contención sin red).`,
    notAvailable: 'Renode no está disponible en este banco.',
    secondsLabel: 'Segundos de emulación',
  },
};
