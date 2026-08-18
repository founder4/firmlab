import type { Messages } from '../en';

/** exportreach — español. Tipado contra el catálogo inglés. */
export const exportreach: Messages['exportreach'] = {
  title: 'Alcanzabilidad de exportaciones',
  sub: 'Para un objeto compartido o un módulo del kernel —los objetivos que symreach rechaza, porque ninguno tiene un punto de entrada desde el que explorar—. Recupera el grafo de flujo de control y pregunta si un sumidero está en una ruta desde una función que un externo puede invocar. Una ruta en el código, no una factible: estrictamente más débil que la alcanzabilidad simbólica, y nunca un veredicto limpio cuando no encuentra nada.',
  binaryPlaceholder: 'lib/modules/…/NetUSB.ko o usr/lib/libfoo.so',
  sinksPlaceholder: 'sumideros (vacío ⇒ por clase de objetivo)',
  sinksLabel: 'Símbolos de sumidero a preguntar, separados por coma o espacio',
  budget: 'presupuesto',
  budgetLabel: 'Presupuesto por ejecución en segundos',
  ask: 'Preguntar',
  probing: 'Recuperando…',
  hint: 'A un .ko se le pregunta el vocabulario del kernel (__kmalloc, copy_from_user), a un .so el de userland (strcpy, system). Vacío usa el conjunto de la clase del objetivo; un símbolo ausente cuesta microsegundos, así que un conjunto por defecto es más barato que adivinar.',
  probeFailed: 'La sonda falló. No se concluyó nada sobre este objeto.',
  notAnswered: 'No se hizo ninguna pregunta de alcanzabilidad',
  notAnsweredHint: (binary?: string) =>
    `${binary ? `${binary}: ` : ''}esto es una capacidad ausente, no una afirmación de que el objeto no contenga ningún sumidero alcanzable.`,
  unknownArch: 'arquitectura desconocida',
  summary: (fns: number, entries: number, reachable: number, asked: number) =>
    `${fns} función(es) recuperada(s) · ${entries} punto(s) de entrada · ${reachable} de ${asked} sumidero(s) alcanzable(s)`,
  cfgSeconds: (s: number) => `grafo en ${s}s`,
  blockedHeading: 'No se pudo analizar',
  blockedBody:
    'El grafo de flujo de control volvió vacío, así que no se pudo hacer ninguna pregunta de alcanzabilidad. En este corpus eso significa que el objeto no lleva cabeceras de sección —la recuperación del CFG no encuentra nada sin ellas, con o sin un escaneo completo—. Es un límite de la herramienta, NO una afirmación de que el objeto esté libre de sumideros alcanzables, y no debe leerse como tal.',
  outcome: {
    reachable: 'alcanzable',
    not_reached: 'no alcanzado',
    absent: 'ausente',
    no_call_site: 'sin sitio de llamada',
    budget_exhausted: 'presupuesto agotado',
  },
  reachableDetail: (from: number, entries: number, holders: number) =>
    `${from} de ${entries} punto(s) de entrada alcanzan una de ${holders} función(es) portadora(s)`,
  sample: (names: string, more: number) => `p. ej. ${names}${more > 0 ? ` (+${more} más)` : ''}`,
  notReachedNote:
    'Un sumidero no alcanzado NO es un sumidero que no se pueda alcanzar: CFGFast deja las llamadas indirectas sin resolver, y tanto los objetos compartidos como los módulos del kernel se construyen sobre ellas.',
  caveat: {
    lead: 'Un sumidero alcanzable aquí es una pista, mantenida en',
    tail: '. Existe una ruta en el código, pero nada comprueba que las condiciones de las ramas a lo largo de ella puedan satisfacerse a la vez —estrictamente más débil que symreach, y nunca una prueba de explotabilidad.',
  },
  runLabel: 'Ejecuciones de alcanzabilidad de exportaciones',
  notRun:
    'No se ha ejecutado ninguna sonda de alcanzabilidad de exportaciones para esta imagen, así que aquí no se ha preguntado a ninguna biblioteca ni módulo.',
};
