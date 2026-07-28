import type { Messages } from '../en';

/**
 * corpus — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse.
 *
 * Todo lo que dice esta pantalla es una PISTA: señala dónde se repite una credencial, una versión de componente o
 * una identidad, nunca que algo sea vulnerable. La redacción tiene que seguir diciendo «conviene comprobar» y no
 * deslizarse hacia un veredicto. El esquema de la clave de familia (`vendor:class:arch`) se deja tal cual.
 */
export const corpus: Messages['corpus'] = {
  loading: 'Cargando el corpus…',

  stats: {
    images: 'Imágenes',
    reusedCredentials: 'Credenciales reutilizadas',
    watchlistRules: 'Reglas de vigilancia',
  },

  reuse: {
    title: 'Reutilización de credenciales',
    sub: 'Secretos que aparecen en más de una imagen — una pista que conviene comprobar, no un veredicto. Promociona una recurrente a la lista de vigilancia para marcarla automáticamente en las próximas subidas.',
    empty: 'Todavía no hay ninguna credencial que aparezca en más de una imagen.',
    colKind: 'Tipo',
    colHash: 'Hash del secreto',
    colImages: 'Imágenes',
    colWatchlist: 'Vigilancia',
    promote: '+ vigilancia',
    promptLabel: 'Etiqueta para esta credencial conocida como insegura:',
    promptDefault: 'credencial conocida como insegura',
    promoted: 'Añadida a la lista de vigilancia',
  },

  prevalence: {
    title: 'Prevalencia de componentes',
    sub: 'Qué versiones de componente abarcan más imágenes, y cuántos CVE emparejó grype.',
    empty: 'Todavía no hay datos de SBOM — ejecuta SBOM sobre algunas imágenes.',
    colComponent: 'Componente',
    colVersion: 'Versión',
    colImages: 'Imágenes',
    colCves: 'CVE emparejados',
  },

  families: {
    title: 'Familias de dispositivo',
    sub: 'Imágenes agrupadas por identidad (vendor:class:arch). Una familia con varias versiones es la base de la comparativa entre versiones.',
  },

  rules: {
    title: (n) => `Reglas de vigilancia (${n})`,
    colType: 'Tipo',
    colLabel: 'Etiqueta',
    colKey: 'Clave',
    remove: 'quitar',
  },
};
