import type { Messages } from '../en';

/** rtosTasks — español. Tipado contra el catálogo inglés. */
export const rtosTasks: Messages['rtosTasks'] = {
  title: 'Instantánea de tareas FreeRTOS',
  sub: 'Recorre las listas de tareas listas y pxCurrentTCB en una instantánea de RAM capturada en otro sitio (un volcado del depurador, una imagen de fallo). Aquí no se lee el dispositivo ni se resuelven símbolos: declaras la dirección base, el orden de bytes y el ancho de puntero, y las direcciones de las listas que se recorren.',
  collapsedHint:
    'Esta imagen no está clasificada como RTOS ni bare-metal, así que el recorrido de la instantánea queda plegado.',

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
    priority: 'Prioridad',
    address: 'Dirección de la lista',
    addList: 'Añadir lista',
    removeList: (i) => `Quitar la lista ${i}`,
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
    },
    currentLane: 'pxCurrentTCB (tarea en curso)',
    readyLane: (address) => `lista en ${address}`,
    noListSupplied: 'no se aportó ninguna lista',
    noTasks: 'ninguna',
    limits: (maxKiB, maxItems, maxLists) =>
      `Límites aplicados: instantánea ≤ ${maxKiB} KiB, ≤ ${maxItems} nodos recorridos por lista, ≤ ${maxLists} listas.`,
    notRecorded: 'no registrado',
  },
};
