import type { Messages } from '../en';

/**
 * agents — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse.
 *
 * Aquí la unidad es la EJECUCIÓN, no la imagen, y eso es lo que hay que preservar al traducir: una fila dice qué
 * salió de una ejecución, no en qué estado terminó el proceso. La frase que no se puede suavizar es
 * `runs.incomplete` — un total de hallazgos sacado de un plan incompleto es justo la lectura que este banco existe
 * para impedir.
 *
 * Los ESTADOS (`queued`, `running`, `awaiting_approval`, `error`, `halted`) viajan por la API y se guardan en
 * SQLite: se muestran tal cual. Los nombres de fichero, los ids de worker y el proveedor/modelo también son
 * registros y no se traducen.
 */
export const agents: Messages['agents'] = {
  eyebrow: 'Autonomía',
  title: 'Agentes',
  desc: 'Ejecuciones autónomas sobre cualquier objetivo. Cada una registra qué planificó, qué llegó a ejecutar de verdad y qué no pudo responder — el motor conduce el pipeline, nunca inventa hallazgos.',

  engine: {
    scanName: 'Escaneo autónomo',
    scanKind: 'determinista',
    scanReady: 'siempre disponible',
    scanWhat:
      'Planifica una cadena de workers enrutada por clase, la ejecuta de principio a fin, re-planifica a partir de las pistas y declara sus lagunas.',
    agentName: 'Agente consciente',
    agentOff: 'desactivado',
    agentWhat:
      'LLM sólo en los nodos de decisión, tras una aprobación humana y un gobernador que limita pasos, tokens, coste y tiempo.',
    agentDisabled:
      'Define FIRMLAB_AGENT=1 y una clave de API para activarlo. El escaneo determinista funciona sin ninguna de las dos.',
  },

  runs: {
    title: 'Ejecuciones',
    live: (n) => (n === 1 ? '1 en curso' : `${n} en curso`),
    refresh: 'Actualizar',
    emptyTitle: 'Todavía no se ha ejecutado nada',
    emptyBody:
      'Arranca un escaneo autónomo sobre uno de los objetivos listos de abajo. Las ejecuciones aparecen aquí y se abren en su propia traza.',
    colTarget: 'Objetivo',
    colOutcome: 'Qué salió de ella',
    colWhen: 'Cuándo',
    kindScan: 'escaneo',
    kindAgent: 'agente',

    workers: (ran, total) => `${ran} de ${total} workers`,
    findings: (n) => (n === 1 ? '1 hallazgo' : `${n} hallazgos`),
    incomplete: (n) => (n === 1 ? '1 no completó' : `${n} no completaron`),
    steps: (n) => (n === 1 ? '1 paso' : `${n} pasos`),
    needsYou: 'esperando tu aprobación',
    pending: 'todavía sin resultado registrado',
  },

  run: {
    back: 'Todas las ejecuciones',
    scanTitle: 'Escaneo autónomo',
    agentTitle: 'Sesión de agente',
    openImage: 'Abrir el análisis completo de este firmware',
    openImageHint: 'Sale de Agentes hacia la vista de análisis estático de esta imagen.',
    notFound: 'Ese objetivo no está en este espacio de trabajo.',
  },

  launch: {
    title: 'Arrancar una ejecución',
    ready: (n) => (n === 1 ? '1 lista' : `${n} listas`),
    emptyTitle: 'Todavía no hay objetivos',
    emptyLead: 'Sube firmware en',
    emptyLink: 'Análisis local',
    emptyTail: '— una imagen analizada se convierte aquí en objetivo.',
    scan: 'Escanear',
    agent: 'Agente',
    launched: (filename) => `Escaneo autónomo arrancado sobre ${filename}`,
  },
};
