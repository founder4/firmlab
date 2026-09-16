import type { Messages } from '../en';

/**
 * corpus — el corpus ENTRE IMÁGENES. Español, tipado contra el catálogo inglés, así que una clave sin traducir no
 * puede colarse.
 *
 * La pantalla dice de qué corpus habla: en este repositorio se llaman «corpus» tres cosas sin relación — esta base
 * de conocimiento, el corpus de validación (el conjunto bloqueado que mide `pnpm corpus:matrix`) y el corpus de
 * reglas YARA (`pnpm yara-corpus:sync`). Véase «The three corpora» en `ARCHITECTURE.md`.
 *
 * Todo lo que dice esta pantalla es una PISTA: señala dónde se repite una credencial, una versión de componente o
 * una identidad, nunca que algo sea vulnerable. La redacción tiene que seguir diciendo «conviene comprobar» y no
 * deslizarse hacia un veredicto. El esquema de la clave de familia (`vendor:class:arch`) se deja tal cual.
 */
export const corpus: Messages['corpus'] = {
  eyebrow: 'Espacio de trabajo',
  title: 'Corpus entre imágenes',
  desc: 'Lo que se repite en todas las imágenes de este banco — una credencial compartida, una versión de componente, una familia de dispositivo. Pistas que contrastar con los hallazgos de cada imagen, nunca veredictos. No es el corpus de validación sobre el que se mide la cobertura, ni el corpus de reglas YARA que aplica el escáner.',

  loading: 'Cargando el corpus entre imágenes…',

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

  listNote: (shown: number, total: number, rule: string) => `Mostrando ${shown} de ${total}. ${rule}`,

  prevalence: {
    title: 'Prevalencia de componentes',
    sub: 'Qué versiones de componente abarcan más imágenes, y cuántos CVE emparejó grype.',
    empty: (withSbom: number, total: number) =>
      withSbom === 0
        ? 'Todavía no hay datos de SBOM — ejecuta SBOM sobre algunas imágenes.'
        : `Ninguna versión de componente abarca aún más de una imagen (${withSbom} de ${total} imagen(es) tienen SBOM).`,
    colComponent: 'Componente',
    colVersion: 'Versión',
    colImages: 'Imágenes',
    colCves: 'CVE emparejados',
  },

  families: {
    title: 'Familias de dispositivo',
    sub: 'Las imágenes sólo comparten familia cuando consta el fabricante; un fabricante desconocido queda aislado por imagen. Una familia demostrada con varias versiones permite comparar versiones.',
  },

  rules: {
    title: (n) => `Reglas de vigilancia (${n})`,
    colType: 'Tipo',
    colLabel: 'Etiqueta',
    colKey: 'Clave',
    remove: 'quitar',
  },
};
