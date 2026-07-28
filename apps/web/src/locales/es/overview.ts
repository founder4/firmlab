import type { Messages } from '../en';

/**
 * overview — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse.
 *
 * Las palabras de exposición dicen dónde escucha la API, no tranquilizan: «sólo local» significa que está atada a
 * loopback, y «expuesto a la red» que no lo está. Los ids de clase de firmware se muestran tal cual: son datos.
 */
export const overview: Messages['overview'] = {
  eyebrow: 'Espacio de trabajo',
  title: 'Panel',
  desc: 'Todo tu corpus de firmware de un vistazo — flota, capacidad y exposición.',

  stats: {
    images: 'Imágenes',
    imagesSub: (analyzing, errored) => `${analyzing} en análisis · ${errored} con error`,
    onDisk: 'En disco',
    quotaOf: (quota) => `de ${quota}`,
    localStore: 'almacén local',
    tools: 'Herramientas',
    toolsSub: 'disponibles en este despliegue',
    posture: 'Exposición de red',
    postureLocal: 'sólo local',
    postureProxied: 'con autenticación',
    postureExposed: 'expuesto a la red',
  },

  recent: {
    title: 'Imágenes recientes',
    link: 'Análisis local',
    emptyTitle: 'Todavía no hay firmware',
    emptyLead: 'Ve a',
    emptyTail: 'para subir tu primera imagen.',
  },

  byClass: {
    title: 'Flota por clase',
    empty: 'Todavía no hay imágenes.',
  },

  jump: {
    title: 'Ir a',
    analysis: 'Análisis local',
    analysisDesc: 'Sube firmware y léelo como señal',
    agents: 'Agentes',
    agentsDesc: 'Lanza y vigila ejecuciones autónomas',
    capture: 'Proxy / Actualizaciones',
    captureDesc: 'Intercepta y analiza actualizaciones OTA',
    corpus: 'Corpus',
    corpusDesc: 'Recurrencias y reutilización entre imágenes',
  },
};
