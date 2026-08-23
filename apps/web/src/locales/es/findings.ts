import type { Messages } from '../en';

/**
 * findings — Spanish.
 *
 * La anotación de una disputa es lo delicado de este espacio. Una fila impugnada afirma DOS cosas y tienen que
 * viajar juntas: quién la impugna y con qué base, Y que el estado de prueba que hay al lado es exactamente el que
 * decidió el código — no cambia, no se rebaja y la fila no se retira. Un simple «DISPUTADO» invitaría a descontar la
 * medición, que es justo la anulación que el diseño rechaza: por eso `dispute.recordedAs` … `dispute.stands` son un
 * único bloque, troceado sólo donde se imprimen en `mono` el id de la afirmación y el CÓDIGO del estado de prueba,
 * ambos identificadores y ambos sin traducir.
 *
 * Los títulos, las justificaciones y las fuentes de los hallazgos no están aquí: son el registro que escribieron los
 * proveedores al ejecutarse y se muestran tal cual, en el idioma que los produjo.
 */
export const findings: Messages['findings'] = {
  title: (n: number) => `Hallazgos (${n})`,
  sub: 'Cada uno lleva un estado de prueba explícito — no sólo qué se encontró, sino cuánto está probado.',

  asserted: (n: number) =>
    [
      `De estos, ${n} ${n === 1 ? 'fue afirmado' : 'fueron afirmados'} por una persona`,
      `en lugar de ${n === 1 ? 'medido' : 'medidos'};`,
      'esas filas nombran a su autor y no cuentan para ninguna etapa del análisis.',
    ].join(' '),
  contested: (n: number) =>
    [
      `${n} fila${n === 1 ? '' : 's'} ${n === 1 ? 'está impugnada' : 'están impugnadas'} por un operador`,
      `y ${n === 1 ? 'anotada' : 'anotadas'} en su sitio —`,
      'la anotación deja constancia del desacuerdo y no cambia nada de lo que decidió el código.',
    ].join(' '),

  empty: 'Aún no hay hallazgos. Ejecuta la extracción, el SBOM y los análisis profundos para poblar el registro.',

  cutRule: (shown: number, total: number, omitted: number) =>
    [
      `Mostrando ${shown} de ${total}.`,
      'Las filas se ordenan por gravedad (de mayor a menor, luego por estado de prueba y por título)',
      `y se omiten las ${omitted} peor clasificadas — el corte sigue esa regla,`,
      'nunca el orden en que se escribieron las filas.',
      'Toda fila impugnada se muestra sea cual sea el tope.',
    ].join(' '),
  showAllCount: (n: number) => `Ver los ${n}`,

  col: {
    severity: 'Grav.',
    finding: 'Hallazgo',
    source: 'Fuente',
    proofState: 'Estado de prueba',
  },

  filters: {
    aria: 'Filtrar hallazgos',
    all: 'Todos',
    priority: 'Críticos + altos',
    established: 'Establecidos',
    lead: 'Pistas',
    blocked: 'Bloqueados',
    dismissed: 'Descartados',
    asserted: 'Afirmaciones',
    other: 'Sin clasificar',
    searchLabel: 'Buscar hallazgos',
    searchPlaceholder: 'Buscar título, fuente o estado de prueba…',
    results: (shown, total) => `${shown} de ${total}`,
  },

  census: {
    split: (established, leads, blocked, dismissed, asserted, other) =>
      [
        established ? `${established} establecido${established === 1 ? '' : 's'}` : '',
        leads ? `${leads} pista${leads === 1 ? '' : 's'}` : '',
        blocked ? `${blocked} bloqueado${blocked === 1 ? '' : 's'}` : '',
        dismissed ? `${dismissed} descartado${dismissed === 1 ? '' : 's'}` : '',
        asserted ? `${asserted} afirmado${asserted === 1 ? '' : 's'}` : '',
        other ? `${other} sin clasificar` : '',
      ]
        .filter(Boolean)
        .join(' · '),
    band: (severity, total, established, leads, blocked, dismissed, asserted, other) =>
      `${total} ${severity}: ${findings.census.split(established, leads, blocked, dismissed, asserted, other)}`,
    legend:
      'La gravedad dice lo malo que sería el hallazgo si fuera cierto, nunca que se haya establecido. El censo separa propiedades establecidas, pistas, preguntas bloqueadas, descartes y afirmaciones del operador.',
  },

  mark: {
    established: (severity: string) => `${severity} — establecido`,
    unproven: (severity: string) => `${severity} si fuera cierto — sin establecer`,
  },

  why: 'Por qué este estado',
  whyLabel: 'Mostrar por qué este hallazgo está en este estado de prueba',
  interventionMark: (n: number) =>
    `⚠ obtenido tras ${n} cambio${n === 1 ? '' : 's'} en el firmware — no tal como se envía`,
  assertedBy: (who: string) => `afirmado por ${who}`,
  agentSuffix: ' (agente)',
  withdrawnSuffix: ' — RETIRADA',
  withdrawnBecause: (who: string) => `retirada por ${who}:`,
  withdrawnNoReason: (who: string) => `retirada por ${who} — no se registró motivo.`,
  withdrawnUnknownBy: 'un autor no registrado',
  whyWithdrawn: 'Por qué este estado — de la afirmación que se retiró',
  unrecordedAuthor: 'un autor sin registrar',
  unrecordedDate: 'una fecha sin registrar',

  dispute: {
    heading: 'Impugnado por un operador',
    claim: (author: string, day: string, title: string) =>
      `${author} afirma el ${day} que este hallazgo es incorrecto: “${title}”.`,
    recordedAs: 'Registrado como afirmación del operador',
    stillStates:
      ', y listado íntegro en el registro del operador. Esto es testimonio sobre una medición, no una medición: el ' +
      'estado de prueba de esta fila sigue siendo',
    stands:
      ', decidido por el código a partir de la evidencia, y la disputa no lo cambia, no lo rebaja ni retira la ' +
      'fila. Ambas cosas se sostienen; quien lee las pondera.',
  },

  dangling: {
    lead: (n: number) =>
      [
        `${n} disputa${n === 1 ? '' : 's'} registrada${n === 1 ? '' : 's'} ${n === 1 ? 'nombra' : 'nombran'}`,
        'un hallazgo que no está en este registro.',
        'Volver a ejecutar un proveedor sustituye sus filas por ids nuevos, así que una disputa puede sobrevivir',
        'a la fila contra la que se registró: la afirmación se conserva, y aquello a lo que apuntaba no se puede',
        'anotar aquí.',
      ].join(' '),
    contests: (author: string) => `${author} impugna`,
    quoted: (title: string) => `— “${title}”`,
  },
};
