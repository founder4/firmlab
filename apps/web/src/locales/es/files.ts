import type { Messages } from '../en';

/**
 * files — Español. Tres frases explican la forma de los dos paneles y no se suavizan al traducir:
 *
 *  - `browser.nothingBody` — un árbol vacío no es nunca un firmware vacío. "No se extrajo nada", "el tallado está
 *    truncado" y "salieron 54 volúmenes y ninguno es un rootfs" se ven igual en pantalla y piden cosas opuestas.
 *  - `viewer.window` — una ventana de 64 KB de un binario de 7 MB se ve exactamente igual que un fichero entero.
 *  - `search.nonePartial` — "sin coincidencias en lo que se buscó" NO es "ausente de este firmware". El caso
 *    completo (`search.noneComplete`) es el único al que se le permite ser un negativo a secas.
 *
 * No se traducen: rutas, cadenas de modo, destinos de enlaces simbólicos, la miga `extract` (es un directorio
 * real), los ids de regla de rechazo, ni los veredictos y motivos que compuso la API.
 */
export const files: Messages['files'] = {
  browser: {
    title: 'Ficheros extraídos',
    sub: 'Abre lo que el extractor escribió en disco y lee los bytes que cita un hallazgo. Leer un fichero establece que el contenido está presente en esta extracción — no es evidencia sobre el dispositivo en marcha.',
    extractionEyebrow: (state: string) => `Extracción · ${state}`,
    refusedEyebrow: (rule: string) => `Rechazado · ${rule}`,
    nothingTitle: 'No hay nada en disco que explorar',
    nothingBody:
      'Esto no es un sistema de ficheros vacío. Lee el veredicto de arriba — dice cuál de los varios motivos posibles aplica, y qué lo cambiaría.',
    pathLabel: 'Ruta de la extracción',
    counts: (dirs: number, entries: number, links: number) =>
      `${dirs} dir · ${entries} fichero${entries === 1 ? '' : 's'} · ${links} enlace${links === 1 ? '' : 's'}`,
    symlinkEscapes: 'sale de la extracción',
  },

  state: {
    'never-run': 'nunca extraído',
    'in-progress': 'extrayendo',
    failed: 'la extracción falló',
    'no-output': 'nada en disco',
    'volumes-only': 'sólo tallado — sin rootfs',
    rootfs: 'rootfs recuperado',
  },

  viewer: {
    heading: 'Visor',
    viewLabel: 'Vista',
    text: 'Texto',
    pickTitle: 'Elige un fichero',
    pickBodyBefore:
      'Que algo sea texto o binario se decide por los bytes, no por la extensión — el error que este panel existe para evitar fue un',
    pickBodyAfter: 'que resultó contener una clave pública.',
    empty: 'Fichero vacío — 0 bytes en disco.',
    window: (from: number, to: number, size: number) => `Mostrando los bytes ${from}–${to} de ${size}.`,
    whole: (size: number) => `Fichero completo — los ${size} bytes.`,
    previous: 'Anterior',
    next: 'Siguiente',
  },

  search: {
    title: 'Buscar en la extracción',
    sub: 'Qué fichero dice esto — el CN de un certificado, un nombre de host, un símbolo, una clave NVRAM. Los binarios también se buscan; sus coincidencias llevan un desplazamiento en bytes en lugar de un número de línea.',
    termLabel: 'Término de búsqueda',
    deep: 'profunda (abrir ficheros grandes)',
    complete: 'búsqueda completa',
    partial: 'búsqueda parcial',
    noVerdict:
      'Este resultado no lleva veredicto de cobertura, así que se desconoce cuánto de la extracción llegó a cubrir.',
    noneComplete: 'Ningún fichero de esta extracción contiene ese término.',
    nonePartial:
      'Sin coincidencias en lo que se buscó — que no es lo mismo que ausente de este firmware. Mira más arriba.',
    file: 'Fichero',
    at: 'En',
    match: 'Coincidencia',
    binary: 'binario',
  },
};
