import type { Messages } from '../en';

/** kernelPosture — español. Tipado contra el catálogo inglés. */
export const kernelPosture: Messages['kernelPosture'] = {
  title: 'Postura del kernel',
  sub: 'Qué propiedades de endurecimiento tiene este kernel, leídas de una config incluida, del blob del kernel, del juego de módulos o de un sysctl del rootfs — y, para cada pregunta que no pudo cerrar, si la opción podía siquiera existir en esta versión.',
  run: 'Ejecutar postura del kernel',
  rerun: 'Volver a ejecutar',
  running: 'Ejecutando…',
  unknownValue: 'no recuperada',
  unrecorded: 'sin registrar',
  years: (n: number) => `${n} años`,
  modulesValue: (signed: number, inspected: number, total: number, complete: boolean) =>
    `${signed} firmados de ${inspected} inspeccionados${complete && inspected === total ? '' : ` (de ${complete ? total : `≥${total}`})`}`,
  class: {
    bad: 'débil',
    unanswered: 'sin contestar',
    good: 'correcta',
    'not-applicable': 'no aplica aquí',
  },
  census: (c: { total: number; bad: number; unanswered: number; good: number; notApplicable: number }) =>
    `${c.total} pregunta${c.total === 1 ? '' : 's'} — ${c.bad} débil${c.bad === 1 ? '' : 'es'}, ${c.good} correcta${c.good === 1 ? '' : 's'}, ${c.unanswered} sin contestar, ${c.notApplicable} sin aplicación en este kernel.`,
  legend:
    'Sin contestar y sin aplicación no son lo mismo: la primera es una pregunta que esta imagen no cerró, la segunda una que no podía existir para esta versión de kernel — una opción posterior a ella, o una que upstream ya retiró. Ninguna de las dos afirma que el endurecimiento esté desactivado.',
  cveCensus: (c: { total: number; applicable: number; ruledOut: number; unknown: number }) =>
    `${c.total} CVE de kernel curados cuyo rango incluye la versión — ${c.applicable} indicios, ${c.ruledOut} descartados por evidencia de configuración, ${c.unknown} indeterminados.`,
  cveLegend:
    'Un indicio aún exige reproducción y comprobar backports. Descartado significa que se demostró ausente un subsistema requerido; indeterminado significa que la evidencia no pudo decidir y no es un resultado limpio.',
  field: {
    version: 'Versión',
    versionSource: 'Leída de',
    age: 'Edad de la serie',
    configPath: 'Config del kernel',
    modules: 'Módulos',
  },
  col: { state: 'Estado', question: 'Pregunta', option: 'Opción', evidence: 'Evidencia' },
  empty: {
    notRun: 'No se ha ejecutado la postura del kernel para esta imagen, así que aquí no se ha preguntado nada.',
    unavailable: (reason: string) =>
      `Las preguntas se hicieron y este despliegue no pudo contestarlas${reason ? `: ${reason}` : '.'} Eso es un hueco de este banco de trabajo, no una propiedad del firmware.`,
    notLocated: (reason: string) =>
      `No se localizó ningún kernel en esta imagen${reason ? `: ${reason}` : '.'} Eso es un hueco de cobertura, nunca una afirmación de que la imagen no tenga kernel ni de que el suyo sea sólido.`,
    searchedHeading: 'Se buscó en:',
    noQuestions: 'Se localizó un kernel y no se registró ninguna pregunta de postura contra él.',
  },

  vendorVex: {
    unknown: 'sin registrar',
    notRecorded: 'Este resultado no registró la cobertura de búsqueda VEX del fabricante.',
    notAttempted: (reason) => `No se intentó buscar VEX del fabricante: ${reason}`,
    reasonUnknown: 'motivo sin registrar',
    noneMatchedFirmware:
      'Ningún documento VEX del fabricante cumple la regla de búsqueda. Esto no establece si el firmware está afectado o parcheado.',
    walk: (entries, bytes) => `Entradas visitadas: ${entries}; bytes leídos: ${bytes}.`,
    rule: 'Regla de búsqueda',
    selectionRule: 'Orden de selección',
    caps: (files, bytes, document, entries) =>
      `Límites de búsqueda — ficheros: ${files}; bytes totales: ${bytes}; bytes por documento: ${document}; entradas: ${entries}.`,
    unreadable: (n) =>
      `Directorios ilegibles: ${n}. Los ficheros bajo directorios ilegibles no se vieron; las rutas registradas aparecen a continuación.`,
    unmatchable: (n) =>
      `Identidades de producto no interpretables: ${n}. No coinciden con ningún hallazgo; los ejemplos registrados aparecen a continuación.`,
    droppedStatements: 'Declaraciones omitidas por los límites del intérprete',
    droppedProducts: 'Referencias de producto omitidas por los límites del intérprete',
    ignoredNonCve: 'Entradas sin CVE ignoradas',
    unrecognisedStatus: 'Estados no reconocidos o no admitidos omitidos',
    unreadStructures: 'Estructuras de producto no interpretadas (contadas, nunca casadas)',
    unreadStructureRule: 'Regla de estructuras no leídas',
    otherCounter: (key) => `Contador registrado del intérprete (${key})`,
    documentBounds: 'Regla de límites del intérprete',
    author: 'Autor',
    timestamp: 'Fecha del documento',

    heading: 'Documentos VEX del fabricante',
    counts: (found, examined, parsed, refused) =>
      `${found} fichero${found === 1 ? '' : 's'} candidato${found === 1 ? '' : 's'} cumple${found === 1 ? '' : 'n'} la regla de búsqueda; ${examined} examinado${examined === 1 ? '' : 's'}, ${parsed} interpretado${parsed === 1 ? '' : 's'}, ${refused} rechazado${refused === 1 ? '' : 's'}.`,
    noneMatched:
      'Ningún documento VEX del fabricante cumple la regla de búsqueda. Eso no es prueba de nada: ni de que el kernel esté parcheado ni de que esté afectado.',
    nothingRead:
      'La búsqueda no leyó nada, así que no se buscó ninguna declaración del fabricante. Eso no es prueba de nada.',
    parsedHeading: 'Interpretados:',
    document: (path, format, statements) =>
      `${path} — ${format}, ${statements} declaraci${statements === 1 ? 'ón' : 'ones'}`,
    refusedHeading: 'Rechazados, y no usados:',
    droppedFiles: (n, cap) =>
      `${n} candidato${n === 1 ? '' : 's'} más allá del límite de ${cap} ficheros no se ${n === 1 ? 'leyó' : 'leyeron'}.`,
    droppedBytes: (n) =>
      `${n} candidato${n === 1 ? '' : 's'} no se ${n === 1 ? 'leyó' : 'leyeron'}: se alcanzó el límite total de bytes.`,
    walkTruncated: (n) => `La búsqueda se detuvo en ${n} entradas; los ficheros posteriores no se vieron.`,
    symlinks: (n) =>
      `${n} enlace${n === 1 ? '' : 's'} simbólico${n === 1 ? '' : 's'} no se ${n === 1 ? 'siguió' : 'siguieron'}.`,
    assertion:
      'Una declaración que coincide aparece en su fila de CVE en el registro de hallazgos como declaración del fabricante. Nunca cambia un estado de prueba.',
  },
};
