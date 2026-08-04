import type { Messages } from '../en';

/** kernelPosture — español. Tipado contra el catálogo inglés. */
export const kernelPosture: Messages['kernelPosture'] = {
  title: 'Postura del kernel',
  sub: 'Qué propiedades de endurecimiento tiene este kernel, leídas de una config incluida, del blob del kernel, del juego de módulos o de un sysctl del rootfs — y, para cada pregunta que no pudo cerrar, si la opción podía siquiera existir en esta versión.',
  run: 'Ejecutar postura del kernel',
  rerun: 'Volver a ejecutar',
  running: 'Ejecutando…',
  unknownValue: 'no recuperada',
  unrecorded: 'sin registrar',
  years: (n: number) => `${n} años`,
  modulesValue: (signed: number, inspected: number, total: number) =>
    `${signed} firmados de ${inspected} inspeccionados${inspected === total ? '' : ` (de ${total})`}`,
  class: {
    bad: 'débil',
    unanswered: 'sin contestar',
    good: 'correcta',
    'not-applicable': 'no aplica aquí',
  },
  census: (c: { total: number; bad: number; unanswered: number; good: number; notApplicable: number }) =>
    `${c.total} pregunta${c.total === 1 ? '' : 's'} — ${c.bad} débil${c.bad === 1 ? '' : 'es'}, ${c.good} correcta${c.good === 1 ? '' : 's'}, ${c.unanswered} sin contestar, ${c.notApplicable} sin aplicación en este kernel.`,
  legend:
    'Sin contestar y sin aplicación no son lo mismo: la primera es una pregunta que esta imagen no cerró, la segunda una que no podía existir para esta versión de kernel — una opción posterior a ella, o una que upstream ya retiró. Ninguna de las dos afirma que el endurecimiento esté desactivado.',
  field: {
    version: 'Versión',
    versionSource: 'Leída de',
    age: 'Edad de la serie',
    configPath: 'Config del kernel',
    modules: 'Módulos',
  },
  col: { state: 'Estado', question: 'Pregunta', option: 'Opción', evidence: 'Evidencia' },
  empty: {
    notRun: 'No se ha ejecutado la postura del kernel para esta imagen, así que aquí no se ha preguntado nada.',
    unavailable: (reason: string) =>
      `Las preguntas se hicieron y este despliegue no pudo contestarlas${reason ? `: ${reason}` : '.'} Eso es un hueco de este banco de trabajo, no una propiedad del firmware.`,
    notLocated: (reason: string) =>
      `No se localizó ningún kernel en esta imagen${reason ? `: ${reason}` : '.'} Eso es un hueco de cobertura, nunca una afirmación de que la imagen no tenga kernel ni de que el suyo sea sólido.`,
    searchedHeading: 'Se buscó en:',
    noQuestions: 'Se localizó un kernel y no se registró ninguna pregunta de postura contra él.',
  },
};
