import type { Messages } from '../en';

/**
 * hardware — Español. Cada frase existe para impedir una inferencia que la pantalla invitaría a hacer, y traducirla
 * a la ligera vuelve a permitirla:
 *
 *  - `console.caveat` — una consola declarada es una UART que el kernel tiene orden de levantar; no dice nada sobre
 *    si los pads están poblados, si hay una tira de pines soldada o si pide credenciales.
 *  - `flash.readOnlyStrong` / `flash.readOnlyBody` — `read-only` es una petición al kernel, no protección contra
 *    escritura.
 *  - `jtag.body` — el árbol de dispositivos no puede responder la pregunta del JTAG, así que la fila nombra la
 *    pregunta en lugar de dejar un silencio que se lea como "aquí no hay JTAG".
 *  - `absence.ranNotParsed` frente a `absence.neverRan` — que un proveedor mirase y volviera vacío es una
 *    afirmación DISTINTA de que nunca se ejecutara. Confundirlas es el defecto que esta pantalla vino a corregir.
 *
 * No se traducen: rutas de nodo, cadenas `compatible`, nombres de tty, baudios, las claves literales `bootdelay` y
 * `read-only` del árbol de dispositivos, ni el valor crudo de `status` de un nodo.
 */
export const hardware: Messages['hardware'] = {
  sub: {
    before: 'Lo que este firmware',
    declares: 'declara',
    middle:
      'sobre las vías físicas de entrada a la placa — leído del árbol de dispositivos, la línea de comandos del kernel y el entorno de U-Boot. FirmLab no se conecta al hardware: todo lo de aquí describe la placa para la que se',
    builtFor: 'compiló la imagen',
    after: ', no la placa que tienes en el banco.',
  },

  loadError: 'No se pudieron leer los resultados guardados de los proveedores.',

  console: {
    heading: 'Consola',
    at: 'a',
    baud: 'baudios',
    fromCmdline: 'La línea de comandos del kernel nombra',
    treeResolvesFirst: 'El árbol de dispositivos resuelve',
    treeResolvesAfter: 'el árbol resuelve',
    to: 'a',
    noBaud:
      'La línea de comandos del kernel no nombra ninguna consola, así que la velocidad en baudios no está declarada en ninguna parte de esta imagen.',
    caveat:
      'Una consola declarada es una UART que el kernel tiene orden de levantar. Si los pads están poblados, si hay una tira de pines soldada o si la consola pide credenciales son tres preguntas más que la imagen no puede responder.',
    noneFound: 'Ni la línea de comandos del kernel ni el árbol de dispositivos nombran una consola para esta imagen.',
    noneParsed:
      'El árbol de dispositivos se leyó y no se pudo analizar ninguno, así que de ahí no se conoce ninguna consola.',
    noneRead: 'Todavía no se conoce ninguna consola — no se ha leído el árbol de dispositivos.',
  },

  prompt: {
    heading: 'Prompt del gestor de arranque',
    open: 'interrumpible',
    none: 'sin ventana',
    disabled: 'prompt desactivado',
    unknown: 'no determinable',
    noBootdelay: 'el entorno no lleva bootdelay',
    noEnv: 'no se decodificó ningún entorno de U-Boot',
  },

  nothingRead: {
    title: 'Todavía no se ha leído nada para esta imagen',
    body: 'Los buses, el mapa de flash y la consola salen todos del árbol de dispositivos y del entorno de U-Boot, y ninguno de los dos se ha ejecutado. Por eso esta pantalla está vacía — no porque el firmware no declare interfaces.',
  },

  buses: {
    heading: 'Buses e interfaces de depuración declarados',
    interface: 'Interfaz',
    node: 'Nodo',
    status: 'Estado',
    console: 'consola',
    enabled: 'habilitado',
    disabled: 'deshabilitado',
    none: 'El árbol de dispositivos no declara ningún nodo de bus que este lector reconozca.',
    dropped: (n: number, rule: string) => `${n} nodo(s) más no se listaron — ${rule}.`,
    droppedDefaultRule: 'se aplicó un tope',
    nested: (n: number) =>
      `${n} nodo(s) anidados bajo otro periférico se excluyeron por ser tablas de soporte de chips del driver, no hardware de la placa.`,
  },

  jtag: {
    body: 'No determinable desde el firmware. Un árbol de dispositivos no describe el puerto de depuración, y si está quemado, protegido por contraseña o abierto es una propiedad del silicio y de la placa — esta fila existe para que su ausencia arriba no se lea como un resultado negativo.',
  },

  flash: {
    heading: 'Mapa de flash declarado',
    partition: 'Partición',
    offset: 'Desplazamiento',
    size: 'Tamaño',
    declaresReadOnly: 'Declara read-only',
    readOnlyStrong: '`read-only` no es protección contra escritura.',
    readOnlyBody:
      'Le pide al kernel que no exponga un nodo mtd escribible. Un gestor de arranque, una vía de recuperación o una escritura SPI directa lo ignoran, y nada de aquí dice que la región esté protegida en hardware.',
    readFrom: 'Leído de',
    none: 'Este árbol de dispositivos no declara ningún mapa de particiones.',
  },

  absence: {
    ranNotParsed:
      'El árbol de dispositivos se leyó para esta imagen y no se pudo analizar ninguno — mira el motivo más abajo.',
    neverRan: 'Todavía no se ha leído ningún árbol de dispositivos para esta imagen, así que no se declara nada.',
  },

  provenance: {
    board: 'Placa:',
    unnamed: 'sin nombre',
    reachedVia: 'alcanzado vía',
    nodes: (n: number) => `${n} nodos`,
    trees: (n: number) => `${n} árboles en esta imagen`,
    selected: ', este seleccionado por la configuración FIT',
    notSelected: ', ninguno declarado como el elegido',
    noneRead: 'No se pudo leer ningún árbol de dispositivos.',
    searched: 'Se buscó en:',
    rejectedTitle: (n: number) =>
      `${n} cabecera${n === 1 ? '' : 's'} FDT válida${n === 1 ? '' : 's'} que no se pudo leer`,
    rejectedMeaning:
      'Los bytes de estos desplazamientos son un árbol de dispositivos según su cabecera, y el árbol no se pudo recorrer hasta el final. Eso es un límite de este lector o de cómo está almacenado el blob, no un hallazgo de que ahí no haya árbol.',
    rejectedMore: (n: number) => `${n} más, en el resultado guardado de la ejecución.`,
    rejectedSize: (n: number) => `${n} bytes`,
  },

  actions: {
    readTree: 'Leer árbol de dispositivos',
    rereadTree: 'Releer árbol de dispositivos',
    readUboot: 'Leer entorno de U-Boot',
    rereadUboot: 'Releer entorno de U-Boot',
  },
};
