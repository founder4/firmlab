import type { capabilities as en } from '../en/capabilities';

/**
 * Espejo español de `en/capabilities`. La distinción que sostiene el panel es la de los tres «nada»: uno habla del
 * BANCO, otro del DESPLIEGUE, y sólo el tercero dice algo del firmware. Tres frases distintas, nunca una parafraseada
 * para los tres.
 */
export const capabilities: typeof en = {
  heading: 'Análisis especializados',
  intro:
    'Cada análisis responde a una pregunta concreta. Cada fila dice si no se ha ejecutado, si no pudo ejecutarse aquí o si se ejecutó — y sólo uno que se ejecutó dice algo sobre el firmware.',

  states: {
    notRun: {
      label: 'no ha corrido',
      body: 'Todavía no se ha preguntado, así que esto no dice nada del firmware. Ejecútalo para obtener una respuesta, aunque sea vacía.',
    },
    unavailable: {
      label: 'no pudo responder',
      body: 'La pregunta SÍ se hizo y este despliegue no pudo responderla — falta la herramienta o no estaba la entrada. Esto no es un resultado negativo, y no es lo mismo que la etapa no haber corrido nunca; el motivo del propio proveedor se imprime literal más abajo.',
    },
    ran: {
      label: 'corrió',
      body: 'Esta etapa corrió. Un resultado vacío aquí es una medición real de lo que cubrió — lee los números de cobertura de al lado antes de tomarlo por limpio.',
    },
  },

  coverage: {
    applied: (p) => `${p.applied} de ${p.denominator} ${p.unit} aplicadas`,
    appliedOnly: (p) => `${p.applied} ${p.unit} examinadas`,
    unknownDenominator:
      'este proveedor no informa de un denominador, así que qué fracción de su entrada cubre esto es desconocido',
    lost: (p) => `${p.lost} ${p.unit} nunca se aplicaron a esta imagen`,
    partial: 'PARCIAL — parte de su entrada no se examinó nunca',
  },

  findings: (n) => (n === 1 ? '1 hallazgo' : `${n} hallazgos`),
  reasonLabel: 'El proveedor dice:',
  run: 'Ejecutar',
  nextBatch: 'Ejecutar siguiente lote FwHunt',
  resumeBatch: 'Reanudar lote FwHunt',
  startCampaign: 'Iniciar campaña FwHunt reanudable',
  restartCampaign: 'Reejecutar campaña FwHunt completa',
  running: 'Ejecutando…',
  batchCoverage: (p) =>
    `Lote de módulos FwHunt ${p.current}/${p.total} · ${p.scanned}/${p.carved} módulos acumulados${
      p.incomplete ? ' · este lote está incompleto y se reanudará antes de avanzar' : ''
    }`,

  controlOffset: (n) => `la entrada controla la direccion de retorno guardada en el desplazamiento ${n}`,
  controlOffsetNone:
    'no se recupero ningun desplazamiento de control, que no es lo mismo que un desplazamiento cero — la ejecucion no establecio que la entrada alcance la direccion de retorno guardada.',

  needsBaseline:
    'El diff a nivel de función compara dos imágenes, y para ésta no se ha elegido ninguna base. Eso es una entrada que falta, no un resultado.',

  ghidra: {
    binaryLabel: 'Binario a descompilar (ruta dentro del rootfs extraído)',
    binaryRequired: 'Ruta del binario: escribe una ruta dentro del rootfs extraído, por ejemplo usr/sbin/httpd.',
    run: 'Descompilar con Ghidra',
    notInstalled:
      'Ghidra (analyzeHeadless) no está instalado en este despliegue, así que aquí no se le puede preguntar al descompilador. Es una herramienta que falta, no un resultado negativo.',
    lastBinary: 'Último descompilado:',
  },
  funcdiffBaseline: 'Último diff contra la base',
  funcdiffOpen: 'Abrir el diff de funciones en la sección Diff',
};
