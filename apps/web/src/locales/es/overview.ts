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
  desc: 'Todas tus imágenes de firmware de un vistazo — flota, capacidad y exposición.',

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
    unexamined: 'sin examinar',
    findings: (n) => (n === 1 ? 'hallazgo' : 'hallazgos'),
    coverage: (executed, applicable) => `${executed}/${applicable} etapas`,
  },

  byClass: {
    title: 'Flota por clase',
    empty: 'Todavía no hay imágenes.',
  },

  next: {
    title: 'Siguientes pasos',
    none: 'No hay nada pendiente. Sube otra imagen para compararla con esta.',
    upload: 'Sube una imagen de firmware',
    uploadDesc: 'Todavía no hay nada en este banco. El análisis empieza por una imagen.',
    unscanned: (n) => (n === 1 ? '1 imagen sin escanear' : `${n} imágenes sin escanear`),
    unscannedDesc:
      'Sus hallazgos, si los hay, salen de etapas lanzadas a mano. Lanza el escaneo autónomo para cubrir el resto.',
    partial: (n) => (n === 1 ? '1 imagen escaneada a medias' : `${n} imágenes escaneadas a medias`),
    partialDesc: 'Algunas etapas aplicables no se ejecutaron, así que un resultado vacío ahí no significa limpio.',
    tools: (n) => (n === 1 ? 'Falta 1 herramienta' : `Faltan ${n} herramientas`),
    toolsDesc:
      'Las etapas que la necesitan quedarán bloqueadas, no negativas. Mira qué puede ejecutar este despliegue.',
    corpus: 'Compara entre imágenes',
    corpusDesc: 'Todas las imágenes están escaneadas. Busca credenciales reutilizadas y componentes compartidos.',
  },
};
