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

  reindex: {
    title: 'Reconciliar el corpus',
    sub: 'Reconstruye las tablas entre imágenes a partir de los resultados ya guardados de cada imagen. Aditivo e idempotente: conserva las filas existentes, no borra nada y no vuelve a ejecutar ningún proveedor.',
    run: 'Reindexar corpus',
    running: 'Reindexando…',
    totalInserted: (inserted, images) => `${inserted} fila(s) insertada(s) en ${images} imagen(es).`,
    colSource: 'Fuente',
    colInserted: 'Insertadas',
    colOffered: 'Ofrecidas',
    colWithInput: 'Imágenes con entrada',
    colWithoutInput: 'Imágenes sin entrada',
    withoutInputNote:
      'Una imagen sin entrada nunca ejecutó ese proveedor, así que no aportó nada que leer — no es un resultado que no encontró nada. Las filas ofrecidas y no insertadas ya estaban en el corpus.',
    boundedTitle: 'Entradas acotadas',
    boundedRow: (filename, kind, covered, total) =>
      `${filename} — ${kind}: ${covered} de ${total} cubiertos; sus filas del corpus heredan ese límite.`,
    unrecordedTitle: 'Límites no registrados',
    unrecordedRow: (kind, images) =>
      `${kind}: ${images} imagen(es) guardadas antes de que esta entrada registrara su cobertura — no consta que esté completa.`,
    unstampedTitle: 'Credenciales sin identidad guardada',
    unstampedRow: (filename, rows) =>
      `${filename}: ${rows} fila(s) de credenciales anteriores al sellado de identidad; no entran en la tabla de reutilización hasta volver a ejecutarse.`,
    notReconciledTitle: 'Sin reconciliar',
    notReconciledSub:
      'Tablas que este reindexado no puede restaurar por diseño. Su contenido, o que estén vacías, no es una medición.',
  },

  reclassify: {
    title: 'Volver a ejecutar el clasificador',
    sub: 'Recalcula la clase de dispositivo de cada imagen a partir de sus bytes guardados. Una imagen conserva la clase que recibió al subirse, y tanto el plan del escaneo autónomo como el aviso de cobertura se guían por ella — así que una clase anterior a una mejora del clasificador planifica e informa sobre el dispositivo equivocado. No se vuelve a ejecutar ningún proveedor ni cambia ningún hallazgo.',
    run: 'Reanalizar todas las imágenes',
    running: 'Reanalizando…',
    confirmTitle: '¿Reclasificar todas las imágenes?',
    confirmBody:
      'La identidad y el análisis estático guardados de cada imagen se sustituyen por una pasada nueva sobre sus bytes. Una clase que cambia redirige desde ahora el plan de escaneo y el aviso de cobertura de esa imagen; los hallazgos ya registrados se quedan como están. Una imagen cuya pasada falla conserva su análisis guardado.',
    confirm: 'Reanalizar',
    empty: 'No hay imágenes en este banco, así que no se reanalizó nada.',
    summary: (total, changed, unchanged, failed) =>
      `${total} imagen(es) reanalizada(s): ${changed} cambiaron de clase, ${unchanged} sin cambios, ${failed} fallaron.`,
    changedNote:
      'Una clase cambiada surte efecto en el próximo escaneo. Las etapas ya ejecutadas se planificaron con la clase anterior, así que el aviso de cobertura puede listar ahora etapas que no se han ejecutado para esa imagen; vuelve a escanearla para cubrirlas.',
    failedNote:
      'Una imagen que falló conservó su análisis guardado: la clase mostrada es la que sigue usando, no un resultado de esta pasada.',
    colImage: 'Imagen',
    colClass: 'Clase',
    colStatus: 'Estado',
    none: 'ninguna guardada',
    status: {
      changed: 'cambió',
      failed: 'falló — se conserva la clase guardada',
    },
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
    promptTitle: 'Añadir a la lista de vigilancia',
    promptBody: 'Las próximas subidas que contengan este secreto se marcarán con esta etiqueta.',
    promptLabel: 'Etiqueta',
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
    removeTitle: (label) => `¿Quitar «${label}» de la lista de vigilancia?`,
    removeBody: 'Las próximas subidas dejarán de marcarse por este secreto. Los hallazgos ya registrados se conservan.',
    removeConfirm: 'Quitar',
  },
};
