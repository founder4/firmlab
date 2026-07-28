import type { Messages } from '../en';

/**
 * agents — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse.
 *
 * La frase que no se puede suavizar es la de la cabecera: el agente conduce el pipeline, no inventa hallazgos. Los
 * ESTADOS de ejecución (`queued`, `running`, `awaiting_approval`, `error`, `halted`) viajan por la API y se guardan
 * en SQLite: se muestran tal cual, y aquí sólo se traduce lo que los rodea.
 */
export const agents: Messages['agents'] = {
  eyebrow: 'Autonomía',
  title: 'Agentes',
  desc: 'Lanza y vigila ejecuciones de análisis autónomo sobre cualquier objetivo. Cada ejecución registra sus pasos y conserva el estado de prueba de cada afirmación — el agente conduce el pipeline, nunca inventa hallazgos.',

  scan: {
    title: 'Escaneo autónomo',
    badge: 'determinista',
    sub: 'Un clic planifica una cadena de workers enrutada por clase, la ejecuta de principio a fin y devuelve una traza de razonamiento con sus lagunas declaradas. No hace falta clave de LLM.',
  },

  llm: {
    title: 'Agente consciente',
    off: 'desactivado',
    on: 'Nodos de decisión con LLM, con una aprobación humana antes de emular y un gobernador que limita pasos, tokens, coste y tiempo.',
    disabled:
      'Desactivado — define FIRMLAB_AGENT=1 y una clave de API para las decisiones dirigidas por LLM. El escaneo determinista sigue funcionando.',
  },

  history: {
    title: 'Historial de ejecuciones',
    live: (n) => (n === 1 ? '1 en curso' : `${n} en curso`),
    refresh: 'Actualizar',
    emptyTitle: 'Todavía no hay ejecuciones',
    emptyBody:
      'Lanza un escaneo autónomo sobre uno de los objetivos listos de abajo. Las ejecuciones aparecen aquí con su estado en vivo, y se abren en su transcripción de pasos y sus evidencias.',
    colTarget: 'Objetivo',
    colKind: 'Tipo',
    colStatus: 'Estado',
    colDetail: 'Detalle',
    view: 'Ver',
    kindScan: 'escaneo',
    kindAgent: 'agente',
    findings: (n) => (n === 1 ? '1 hallazgo' : `${n} hallazgos`),
    steps: (n) => (n === 1 ? '1 paso' : `${n} pasos`),
  },

  launch: {
    title: 'Lanzar sobre un objetivo',
    ready: (n) => (n === 1 ? '1 lista' : `${n} listas`),
    emptyTitle: 'Todavía no hay objetivos',
    emptyLead: 'Sube firmware en',
    emptyLink: 'Análisis local',
    emptyTail: '— las imágenes analizadas se convierten aquí en objetivos del agente.',
    scan: 'Escanear',
    agent: 'Agente',
    launched: (filename) => `Escaneo autónomo lanzado sobre ${filename}`,
  },
};
