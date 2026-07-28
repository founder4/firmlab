import type { Messages } from '../en';

/**
 * dashboard — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse.
 *
 * `unexamined` se traduce como «sin examinar», nunca como «limpia» ni como un cero: que no se haya ejecutado nada
 * y que no se haya encontrado nada son cosas distintas, y ésta es la pantalla donde se confunden si el idioma las
 * suaviza. Nombres de fichero, arquitecturas, clases de firmware y estados de trabajo no se traducen: son datos.
 */
export const dashboard: Messages['dashboard'] = {
  eyebrow: 'Espacio de trabajo',
  title: 'Análisis local',
  desc: 'Sube una imagen para analizarla en local, léela como señal, profundiza con trabajos apoyados en herramientas y compárala con el resto de tu corpus.',

  coverage: {
    unexamined: 'sin examinar',
    stages: (executed, applicable) => `${executed}/${applicable} etapas`,
    unexaminedCount: (n, total) => `${n} de ${total} sin examinar`,
    unexaminedTitle: 'Lanza el escaneo autónomo sobre éstas para examinarlas de verdad',
  },

  upload: {
    analyzing: 'Analizando…',
    dropTitle: 'Suelta una imagen de firmware para empezar',
    dropBody:
      'Obtén al instante su identidad, el mapa de estructura, el perfil de entropía y un barrido de secretos — analizado por completo en esta máquina, sin necesidad de toolchain.',
    another: 'Analizar otra imagen',
    anotherHint: 'suelta un fichero, o selecciónalo — nada sale de esta máquina',
    dropOrSelect: 'Soltar o seleccionar',
  },

  list: {
    title: 'Imágenes',
    filterPlaceholder: 'Filtrar por fichero, arquitectura, clase o etiqueta…',
    noMatches: 'Sin coincidencias',
    noMatchesBody: (query, total) => `Ninguna imagen coincide con «${query}». Quita el filtro para ver las ${total}.`,
    clearFilter: 'Quitar el filtro',
    colFilename: 'Fichero',
    colClass: 'Clase',
    colArch: 'Arquitectura',
    colTags: 'Etiquetas',
    colSize: 'Tamaño',
    colCoverage: 'Cobertura',
    colStatus: 'Estado',
    select: (filename) => `Seleccionar ${filename}`,
    addTag: 'Añadir una etiqueta',
    removeTag: 'Quitar la etiqueta',
    tagPlaceholder: 'etiqueta…',
    deleteImage: (filename) => `Eliminar ${filename}`,
  },

  del: {
    confirm: 'Confirmar',
    selected: (n) => `Eliminar la selección (${n})`,
    manyTitle: (n) => `¿Eliminar ${n} ${n === 1 ? 'imagen' : 'imágenes'}?`,
    manyBody: 'Esto elimina cada imagen y cualquier rootfs extraído de ellas. No se puede deshacer.',
    oneTitle: (filename) => `¿Eliminar ${filename}?`,
    oneBody: 'Esto elimina la imagen y cualquier rootfs extraído de ella.',
    done: (n) => (n === 1 ? 'Eliminada 1 imagen' : `Eliminadas ${n} imágenes`),
  },
};
