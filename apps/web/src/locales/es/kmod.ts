import type { Messages } from '../en';

/** kmod — español. Tipado contra el catálogo inglés. */
export const kmod: Messages['kmod'] = {
  title: 'Superficie de módulos del kernel',
  sub: 'Cada .ko bajo el rootfs: quién lo escribió, qué API del kernel enlaza y —para los módulos que puntúan— dónde una longitud leída de la red llega a un asignador. El barrido de userland excluye los objetos reubicables por construcción, así que hasta ahora los módulos de un rootfs se contaban y no los leía nadie.',
  run: 'Ejecutar el barrido',
  rerun: 'Volver a ejecutar',
  running: 'Ejecutando…',
  windowOnly:
    'Una fila de sitio de llamada informa de lo que hacen las instrucciones ANTERIORES a la llamada, y de nada más. «No aparece ninguna comparación» significa que no aparece en la ventana leída; un límite impuesto en el llamante, o más atrás de donde llega la ventana, es invisible aquí. Cada una de esas filas es una PISTA que nombra un sitio que merece abrirse, y no prueba nada sobre alcanzabilidad ni explotabilidad.',
  leadMark: (severity: string) => `${severity} si fuera cierto — sin establecer`,
  field: {
    modules: 'Módulos encontrados',
    examined: 'Desensamblados',
    sites: 'Referencias a sumidero',
    chased: 'Argumento perseguido',
    hoisted: 'Dirección aparcada, no llamada',
    unreadable: 'Tabla de símbolos ilegible',
  },
  provenance: {
    heading: 'Señal de procedencia',
    tagInUse:
      'El tag intree se usa en esta imagen, así que un módulo que no lo lleve se construyó realmente fuera del árbol del kernel y el ranking lo aprovecha.',
    tagUnused:
      'NINGÚN módulo de esta imagen lleva tag intree, así que este build no lo emite y el tag no decide nada aquí — su ausencia no es evidencia de que un módulo sea externo al árbol. El ranking recurre a la licencia declarada.',
    noLicence:
      'Ningún módulo de esta imagen declara licencia tampoco, así que no hay ninguna de las dos claves de procedencia disponible.',
  },
  hoistedNote: (n: number) =>
    `${n} referencia${n === 1 ? '' : 's'} a sumidero ${n === 1 ? 'era' : 'eran'} el lugar donde se materializa la dirección del sumidero en vez de donde se llama — el compilador la aparcó en un registro y la llama desde otro sitio, así que las instrucciones de encima no son la preparación de argumentos de esa llamada y no se leyeron como tal.`,
  modulesDropped: (n: number) =>
    `${n} módulo${n === 1 ? '' : 's'} elegible${n === 1 ? '' : 's'} puntuó dentro y no cupo en el presupuesto de desensamblado, así que se ${n === 1 ? 'nombra' : 'nombran'} en vez de contarse:`,
  sitesDropped: (n: number) =>
    `${n} referencia${n === 1 ? '' : 's'} a sumidero superó el límite de seguridad por módulo y no se examinó.`,
  col: { finding: 'Fila', kind: 'Tipo' },
  topRanked: 'Módulos mejor puntuados',
  rankCol: { module: 'Módulo', licence: 'Licencia', score: 'Puntuación', api: 'API del kernel', sites: 'Sitios' },
  empty: {
    notRun: 'El barrido no se ha ejecutado para esta imagen, así que no se ha leído ningún módulo del kernel.',
    unavailable: (reason: string) =>
      `El barrido no pudo ejecutarse${reason ? `: ${reason}` : '.'} No se leyó ningún módulo del kernel, que no es lo mismo que el kernel no llevar ninguno.`,
    noModules:
      'El rootfs no lleva ficheros .ko. Un kernel monolítico con todo compilado dentro produce exactamente este resultado, y un carve que se dejó lib/modules también — aquí no se distinguen.',
    noRows: (modules: number) =>
      `Se ${modules === 1 ? 'leyó' : 'leyeron'} ${modules} módulo${modules === 1 ? '' : 's'} y ninguno produjo fila. Eso acota solo las preguntas de este barrido — un módulo que no enlaza API de sockets, y toda clase de fallo que esta pasada no pregunta, quedan fuera.`,
    passUnavailable: (reason: string) =>
      `La pasada de sitios de llamada no se ejecutó: ${reason} El inventario de abajo sigue en pie; lo que falta es dónde una longitud en orden de red llega a un asignador, y su ausencia es un hueco, no un resultado limpio.`,
  },
};
