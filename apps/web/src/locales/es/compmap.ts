import type { Messages } from '../en';

/**
 * compmap — Spanish.
 *
 * Varias claves componen una sola frase porque `DT_NEEDED`, `rabin2`, `dlopen(3)` y los sonames son identificadores:
 * se pintan en `mono` y no se traducen nunca. Cada clave es el tramo de prosa que va ANTES o DESPUÉS del
 * identificador, en orden de pintado, y el panel vuelve a intercalarlo. El castellano coloca el identificador donde
 * la frase lo pide (`sus entradas DT_NEEDED`, no `sus DT_NEEDED entradas`), que es justo para lo que existe el
 * troceado.
 *
 * La frase por la que existe este espacio es `unresolved.notMissing`. «Sin resolver» habla de un recorrido ACOTADO,
 * no del firmware: los topes de ficheros y de ELF cortan pronto en un rootfs grande y una biblioteca que quede tras
 * el corte se reporta como no resuelta por todos los binarios que la nombran. Traducirlo como «falta» o «ausente» a
 * secas convertiría un límite del análisis en un defecto del firmware, que es exactamente lo contrario de lo que se
 * midió.
 */
export const compmap: Messages['compmap'] = {
  title: 'Mapa de componentes',

  sub: {
    beforeNeeded: 'Cada ELF del rootfs extraído, asignado a los objetos compartidos que nombran sus entradas',
    beforeLinker: '— lo que registró el',
    linker: 'enlazador',
    beforeRabin2: 'y se lee de los bytes con',
    beforeDlopen: '. Una biblioteca que el programa abre con',
    afterDlopen:
      'en tiempo de ejecución no deja esa entrada ni ninguna arista aquí, así que el silencio de este grafo es ' +
      'silencio sobre el enlazado, no sobre la carga. Es estructura, no un veredicto de seguridad.',
  },

  notRun: {
    title: 'Nadie ha construido el mapa de componentes de esta imagen',
    body:
      'Nada ha preguntado contra qué enlaza este rootfs, así que no hay nada que mostrar — y eso es una afirmación ' +
      'sobre este banco de trabajo, no sobre el firmware. Constrúyelo y la respuesta, incluso vacía, lo dirá.',
  },
  noRootfs: {
    title: 'No hay ningún rootfs extraído que mapear',
    body:
      'El mapa se construye recorriendo los ficheros que la extracción escribió en disco, y esta imagen no tiene ' +
      'ninguno que recorrer. Eso es un hueco de la extracción, no un firmware que no enlaza con nada — ejecuta ' +
      'primero la extracción desde la sección Extracción.',
    extractionSays: 'La extracción dice:',
  },
  unavailable: {
    title: 'El mapa no se pudo construir — la pregunta se quedó sin responder.',
    noReason: 'El proveedor se declaró no disponible y no dio ningún motivo.',
    body:
      'Nada de lo de abajo es un hallazgo sobre este firmware: una herramienta ausente es una respuesta ausente, ' +
      'no una dependencia ausente.',
  },
  empty: {
    title: 'El mapa se construyó y el grafo está vacío',
    beforeNeeded: 'El recorrido pasó por el rootfs y volvió sin ningún ELF que llevara entradas',
    afterNeeded:
      'de ningún tipo. Es una respuesta real, y verosímil — un rootfs sólo con busybox o enteramente estático no ' +
      'enlaza nada de forma dinámica. No es lo mismo que si nadie hubiera mirado.',
  },

  stat: {
    walked: 'Binarios ELF recorridos',
    edges: 'Aristas de enlace',
    unresolved: 'Referencias sin resolver',
  },

  basename: {
    lead: 'Un nodo es un',
    word: 'nombre base',
    beforeNeeded: ', porque una referencia',
    beforeExample: 'lo es — dos ficheros llamados',
    afterExample: 'en directorios distintos son un solo nodo.',
    collapse: (files: number, nodes: number) => `Aquí eso reduce ${files} ficheros ELF a ${nodes} nodos.`,
  },
  linksNothing: {
    lead: (n: number) => `${n} de ellos no nombran ningún objeto compartido — enlazados estáticamente, o un ELF que`,
    tail: 'no pudo leer.',
  },

  unresolved: {
    heading: (n: number) => `Bibliotecas sin resolver · ${n}`,
    colSoname: 'Soname referenciado',
    colCount: 'Cuenta',
    colNamedBy: 'Nombrado por',
    notMissing: 'Sin resolver no quiere decir ausente.',
    caveat:
      'Un soname que aporta un enlace simbólico ya se resuelve y se etiqueta como provisto por enlace — el ' +
      'recorrido sigue negándose a seguir un enlace: lee el nombre del destino y lo casa dentro de lo extraído, ' +
      'así que escapar del rootfs sigue siendo imposible. Lo que queda aquí o falta de verdad, o está',
    bounds: 'más allá de los límites del recorrido',
    caveatTail:
      ': los topes de ficheros y de ELF cortan pronto en un rootfs grande, y una biblioteca que quede tras el ' +
      'corte se reporta como no resuelta por los binarios que sí la referencian. Además la resolución es por ' +
      'nombre base y sólo contra lo que se extrajo, así que una extracción parcial, una segunda partición o un ' +
      'overlay montado en el arranque son bibliotecas que el dispositivo tiene y esta imagen no. Abre el ' +
      'explorador de ficheros antes de tratar una fila de aquí como una biblioteca ausente.',
    noneLead: 'Cada referencia',
    noneTail:
      'de este rootfs nombra un fichero que el recorrido también encontró. Eso dice que lo extraído es coherente ' +
      'consigo mismo para los binarios que recuperó — no que la extracción esté completa.',
  },

  shape: {
    heading: 'Forma de las dependencias',
    diagramTitle: 'Diagrama de dependencias de enlace del rootfs',
    diagramLabel:
      'Diagrama de dependencias de enlace del rootfs: los ficheros ELF a la izquierda, los sonames que nombran a ' +
      'la derecha',
    colElf: 'Fichero ELF',
    nodeTitle: (id: string, degree: number, unresolved: number) =>
      `${id} — enlaza ${degree} objeto(s) compartido(s), ${unresolved} sin resolver`,
    libTitle: (id: string, degree: number, present: boolean) =>
      `${id} — nombrado por ${degree} binario(s), ${present ? 'presente en lo extraído' : 'NO presente en lo extraído'}`,
    legendBin: 'fichero ELF en lo extraído',
    legendLib: 'soname que sí se extrajo',
    legendUnres: 'soname que no',
    legendCounts: (bins: number, binsAll: number, libs: number, libsAll: number) =>
      `${bins} de ${binsAll} ficheros que enlazan · ${libs} de ${libsAll} sonames referenciados`,
    rule:
      'Ordenado con las referencias sin resolver primero, luego por número de enlaces, luego por nombre — nunca ' +
      'por el orden del directorio.',
    dropped: (bins: number, libs: number) =>
      [
        `No se dibujan ${bins} fichero${bins === 1 ? '' : 's'} ELF ni ${libs} soname${libs === 1 ? '' : 's'};`,
        'toda referencia sin resolver está en la tabla de arriba, con independencia de lo que cupiera en el dibujo.',
      ].join(' '),
  },

  orphans: {
    heading: (n: number) => `Binarios huérfanos · ${n}`,
    moreAlphabetical: (n: number) => `+${n} más, listados alfabéticamente`,
    lead: 'Ninguna entrada',
    beforeTopLevel:
      'de este rootfs los nombra. Para un programa eso es lo normal y no un veredicto — un demonio, una ' +
      'herramienta de línea de órdenes y un auxiliar que invoca un script de arranque son huérfanos legítimos en ' +
      'un grafo de enlace; lo que da la lista es el conjunto de ejecutables',
    topLevel: 'de primer nivel',
    afterTopLevel: 'que algo de fuera de este grafo tiene que arrancar.',
    libsLead: (n: number) => `${n} de ellos son objetos compartidos, y de esos dice otra cosa: nada los`,
    links: 'enlaza',
    beforeDlopen: 'y eso suele significar que se cargan con',
    afterDlopen:
      '— invisible para este grafo — y de vez en cuando que no los usa nada en absoluto. Esta sección no decide ' +
      'cuál de las dos.',
    none:
      'Cada binario de este grafo lo nombra otro. En un rootfs de cualquier tamaño eso es raro y merece una ' +
      'segunda mirada a los límites del recorrido antes de leerlo como un hecho sobre el firmware.',
  },

  providerLabel: 'Proveedor:',
  build: 'Construir mapa de componentes',
  rebuild: 'Reconstruir mapa',
  needsRootfs: 'Ejecuta primero la extracción — el mapa se construye recorriendo el rootfs',
  jobFailed: 'El trabajo del mapa de componentes falló.',
};
