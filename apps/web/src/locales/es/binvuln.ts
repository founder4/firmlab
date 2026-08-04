import type { Messages } from '../en';

/** binvuln — español. Tipado contra el catálogo inglés. */
export const binvuln: Messages['binvuln'] = {
  title: 'Barrido de endurecimiento de binarios',
  sub: 'Cada ELF bajo el rootfs, leído en busca de llamadas inseguras contra las mitigaciones compiladas en él. Es la segunda fuente de filas del ledger y, hasta que tuvo ruta, su propio resultado no llegaba a ningún lector.',
  run: 'Ejecutar el barrido',
  rerun: 'Volver a ejecutar',
  running: 'Ejecutando…',
  leadsOnly:
    'Cada fila de aquí es una PISTA, no un fallo. El barrido es sintáctico —una llamada insegura importada y ningún canario de pila—, así que nada de lo de abajo se ejecutó ni se probó alcanzable desde una entrada. Convertir una en veredicto es alcanzabilidad simbólica o un crash reproducido, y las dos viven en otro sitio.',
  leadMark: (severity: string) => `${severity} si fuera cierto — sin establecer`,
  field: {
    scanned: 'Binarios recorridos',
    candidates: 'Candidatos hallados',
    listed: 'Listados aquí',
    relocatable: 'Reubicables, omitidos',
    neutered: 'Cortados por el extractor',
  },
  cutRule: (shown: number, candidates: number, dropped: number) =>
    `Mostrando ${shown} de ${candidates} candidatos. Los ${dropped} omitidos se cortaron por rango —exposición primero, nunca por el orden en que el recorrido llegó a ellos.`,
  exposedDropped: (n: number) =>
    `${n} de ellos están expuestos a red y aun así no cupieron, así que se nombran en vez de contarse:`,
  col: { finding: 'Candidato', kind: 'Tipo' },
  empty: {
    notRun: 'No se ha ejecutado el barrido para esta imagen, así que aquí no se ha examinado ningún binario.',
    unavailable: (reason: string) =>
      `El barrido no pudo ejecutarse${reason ? `: ${reason}` : '.'} No se examinó ningún binario, que no es lo mismo que que ningún binario sea débil.`,
    noCandidates: (scanned: number) =>
      `Se recorrieron ${scanned} binario${scanned === 1 ? '' : 's'} y ninguno cumplió la precondición del barrido. Eso acota la pregunta de ESTE barrido y nada más — una llamada insegura con canario presente, y toda clase de fallo por la que este barrido no pregunta, quedan fuera.`,
  },
};
