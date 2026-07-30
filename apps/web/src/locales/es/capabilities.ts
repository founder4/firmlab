import type { capabilities as en } from '../en/capabilities';

/**
 * Espejo español de `en/capabilities`. La distinción que sostiene el panel es la de los tres «nada»: uno habla del
 * BANCO, otro del DESPLIEGUE, y sólo el tercero dice algo del firmware. Tres frases distintas, nunca una parafraseada
 * para los tres.
 */
export const capabilities: typeof en = {
  heading: 'Capacidades sin lector',
  intro:
    'Cada uno de estos proveedores tiene ruta, sincroniza hallazgos bajo su propia fuente y hasta ahora no tenía dónde leerse en pantalla — así que una etapa que nunca corrió era invisible en vez de aparecer como no ejecutada. Abajo se declara el estado de cada una, y los tres estados no son intercambiables a propósito.',

  states: {
    notRun: {
      label: 'no ha corrido',
      body: 'Nada ha hecho esta pregunta sobre esta imagen, así que no hay nada que mostrar. Eso es una afirmación sobre este banco, no sobre el firmware — ejecútala y la respuesta, incluso vacía, lo dirá.',
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
  running: 'Ejecutando…',

  needsBaseline:
    'El diff a nivel de función compara dos imágenes, y para ésta no se ha elegido ninguna base. Eso es una entrada que falta, no un resultado.',
};
