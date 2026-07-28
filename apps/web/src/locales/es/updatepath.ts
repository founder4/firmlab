import type { Messages } from '../en';

/**
 * updatepath — Spanish.
 *
 * Dos frases son todo el argumento del panel y tienen que sobrevivir a la traducción intactas.
 *
 * `chain.caveatBefore` … `chain.caveatAfter`: que se acredite a un candidato una verificación obtenida por `source`
 * NO prueba que la comprobación se ejecute. Una arista de `source` resuelta es un único hecho estático: este fichero
 * nombra a ese otro donde un shell POSIX lo leería. Hacer `source` de un fichero define sus funciones, no las llama.
 * El énfasis es un `<strong>` de verdad y la negación tiene que seguir siendo igual de tajante.
 *
 * `chain.followedNone*` frente a `chain.unknownChain*`: «esta ejecución siguió las aristas y no encontró ninguna» es
 * una RESPUESTA sobre estos scripts; «no hay cadena registrada» es un hueco en lo que el resultado guardado sabe.
 * Volver a confundirlas al traducir desharía justo la distinción que costó medirla contra bytes reales.
 *
 * Las rutas, los sonames, `source` / `.` / `include`, `ucert` y los motivos que registró el proveedor son
 * identificadores o evidencia registrada: se pintan en `mono` tal cual, y por eso varias frases llegan troceadas.
 */
export const updatepath: Messages['updatepath'] = {
  title: 'Vía de actualización — qué comprueba el actualizador y dónde vive esa comprobación',
  sub:
    'Los ficheros que este rootfs ejecutaría para instalar firmware nuevo, la verificación que hace cada uno y — ' +
    'porque un punto de entrada delega su comprobación de forma rutinaria en un fichero del que hace source — la ' +
    'cadena que llegó hasta la comprobación.',

  notRun:
    'Nadie ha ejecutado el proveedor de vía de actualización sobre esta imagen. Eso no es una afirmación sobre el ' +
    'firmware: no se ha buscado ningún actualizador, así que aquí no se ha descartado nada. Ejecuta',
  notRunFrom: 'desde Análisis profundo, arriba.',
  unavailable: 'El proveedor de vía de actualización no pudo ejecutarse sobre esta imagen.',
  noUpdaters:
    'El proveedor se ejecutó y no localizó ningún candidato a actualizador. Eso es una afirmación sobre lo que ' +
    'leyó el recorrido, no un veredicto de que el dispositivo no tenga vía de actualización — un actualizador ' +
    'fuera del rootfs extraído, en una segunda partición o tras un límite del recorrido no se llegó a abrir.',

  row: {
    verifies: 'verifica',
    verifiesOwn: 'verifica (en sus propias líneas)',
    signatureCommands: 'autentica el origen',
    signatureFns: 'rutinas de firma',
    digestFns: 'rutinas de resumen',
    missingVerifiers: 'invoca, pero el binario no está en el rootfs',
    flashWrites: 'escribe en la flash',
    rollbackMarkers: 'marcas de reversión',
  },

  candidate: {
    noPath: '(ruta sin registrar)',
    unknownKind: 'tipo desconocido',
  },

  chain: {
    heading: 'Cadena de source',
    noFile: '(el fichero no quedó registrado)',
    physicallyIn: '— el fichero en el que están físicamente estas líneas',
    reached: 'alcanzado:',
    notRecorded: 'la cadena que llegó hasta él no quedó registrada en este resultado',

    creditedLead: (n: number) => `${n} fichero${n === 1 ? '' : 's'} que`,
    creditedReadsWith: 'lee con',
    creditedTail: (n: number) =>
      [
        `se ${n === 1 ? 'ha acreditado' : 'han acreditado'} a este candidato.`,
        'La evidencia se lista bajo el fichero en el que vive, no bajo',
      ].join(' '),
    creditedTailAfter: ', que no contiene ninguna de esas líneas.',

    caveatBefore:
      'Una arista de source resuelta es un único hecho estático: este fichero nombra a ese otro en una posición en ' +
      'la que un shell POSIX lo leería. Que se le acredite una verificación obtenida por source',
    caveatNot: 'no',
    caveatAfter:
      'prueba que la comprobación llegue a ejecutarse — hacer source de un fichero define sus funciones, no las ' +
      'llama, y la llamada puede estar tras una rama, tras un flag que nadie activa, o dentro de una función que ' +
      'devuelve 0 sin verificar nada. Ninguna arista de source sube un estado de prueba.',

    unresolved: (n: number) =>
      [
        `${n} directiva${n === 1 ? '' : 's'} no se ${n === 1 ? 'pudo' : 'pudieron'} convertir en un fichero.`,
        'Adivinarlo sería fabricar; descartarlo en silencio ocultaría que este grafo está incompleto.',
      ].join(' '),
    unresolvedNoFile: '(fichero sin registrar)',
    unresolvedNoSpec: '(sin operando registrado)',
    unresolvedNoReason: 'no se registró ningún motivo',

    bounds:
      'Dónde dejó de seguir. Un límite no es una respuesta: nada de lo que hay más allá se miró, y queda fuera de ' +
      'lo que se le acredita a este candidato en vez de quedar descartado por él.',

    followedNone: 'Ningún candidato de abajo hace source de otro fichero. Esta ejecución siguió las aristas de',
    followedNoneTail: 'y no encontró ninguna — una respuesta sobre estos scripts, no un hueco del análisis.',
    unknownChain:
      'No hay ninguna cadena de source registrada en ningún candidato de abajo. Caben dos lecturas y este ' +
      'resultado no las distingue: o estos scripts no hacen source de nada, o el resultado lo guardó una ' +
      'compilación que no siguió las aristas de',
    unknownChainTail: 'en absoluto. Vuelve a ejecutar el proveedor para saber cuál de las dos.',
  },

  dropped: (n: number) =>
    [
      `El tope de candidatos descartó ${n} candidato(s) más — conservados por evidencia de punto de entrada,`,
      'verificación o escritura en flash, nunca por el orden del directorio — y están ausentes de la lista de',
      'arriba, no descartados por ella.',
    ].join(' '),
};
