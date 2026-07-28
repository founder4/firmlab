import type { Messages } from '../en';

/**
 * testbench — Español. La redacción de `outcome.means` es la afirmación, no un adorno.
 *
 * `empty` no puede leerse nunca como "ahí no hay nada": una búsqueda acotada que terminó no encontró nada *para esta
 * entrada, este presupuesto y esta pregunta*. Y `blocked` significa que la pregunta SÍ se hizo y este despliegue no
 * pudo responderla. Esa distinción es la razón de ser del banco, así que no se suaviza al traducir.
 *
 * No se traducen: rutas de objetivos, nombres de sumideros, direcciones, arquitecturas ni el techo de prueba
 * (`static_confirmed` es un identificador que viaja por la API).
 */
export const testbench: Messages['testbench'] = {
  sub: (targets: number, runs: number, examined: number) =>
    `Cada pregunta ejecutable, agrupada por aquello sobre lo que se preguntó. ${targets} objetivo${targets === 1 ? '' : 's'} · ${runs} ejecución${runs === 1 ? '' : 'es'} · ${examined} objetivo${examined === 1 ? '' : 's'} examinado${examined === 1 ? '' : 's'}.`,

  ready: {
    filesystem: 'Sistema de ficheros',
    filesystemOk: 'extraído',
    filesystemOff: 'sin extraer — no se puede ejecutar ningún objetivo',
    arch: 'Arquitectura',
    archOff: 'desconocida — la sonda dinámica no puede elegir emulador',
    ceiling: 'Techo de prueba',
    ceilingNote: '— un resultado de aquí describe el entorno aislado, nunca el dispositivo físico.',
  },

  filterLabel: 'Filtrar objetivos',
  filterPlaceholder: 'la ruta contiene…',

  noRootfsTitle: 'Todavía no hay un sistema de ficheros extraído',
  noRootfsBody:
    'Todo lo de este banco se ejecuta contra un binario del sistema de ficheros de la imagen. Ejecuta la extracción en la pestaña Extracción y los binarios que recupere aparecerán aquí como objetivos.',

  noMatchTitle: (filter: string) => `Ningún objetivo coincide con “${filter}”`,
  noMatchBody: (n: number) => `Se recuperaron ${n} binarios de esta imagen.`,

  notExamined: 'sin examinar',
  runCount: (n: number) => `${n} ejecución${n === 1 ? '' : 'es'}`,
  archUnknown: 'arquitectura desconocida',
  networkFacing: ' · expuesto a la red',
  nothingRun:
    'No se ha ejecutado nada contra este binario. Un historial vacío significa sin examinar — no es una afirmación sobre el código.',

  outcome: {
    label: {
      proven: 'probado',
      lead: 'pista',
      empty: 'no se encontró nada',
      blocked: 'bloqueado',
      failed: 'falló',
      running: 'en curso',
    },
    means: {
      proven: 'Se estableció un hecho sobre este objetivo.',
      lead: 'Merece la pena seguirlo. Todavía no se ha probado nada.',
      empty:
        'Esta ejecución no encontró nada — para esta entrada, este presupuesto y esta pregunta. No es un certificado de salud.',
      blocked: 'La pregunta se hizo y este despliegue no pudo responderla. Esto NO es un resultado negativo.',
      failed: 'El arnés se rompió. No dice nada sobre el objetivo, ni a favor ni en contra.',
      running: 'Sigue en marcha.',
    },
  },

  actions: {
    decompile: {
      title: 'Triaje',
      gives: 'Cabeceras, importaciones, símbolos y cadenas (radare2).',
      run: 'Ejecutar triaje',
    },
    symreach: {
      title: 'Alcanzabilidad',
      gives: 'Si un sumidero es alcanzable desde el punto de entrada, y en qué dirección (angr).',
      run: 'Preguntar alcanzabilidad',
      note: 'Los sumideros se leen de las propias importaciones de copia sin límite del binario. Que un sumidero no se alcance significa que la búsqueda terminó, nunca que el sumidero sea seguro.',
    },
    dynprobe: {
      title: 'Sonda dinámica',
      gives: 'Lo ejecuta bajo qemu con gdb en el sumidero: ¿se ejecuta?, ¿revienta?, ¿controla la entrada el fallo?',
      needsAddress: 'Necesita la dirección de un sumidero',
      needsAddressBefore:
        'Esta sonda se detiene en un punto de llamada exacto, así que necesita una dirección. Ejecuta antes',
      needsAddressAfter: ': cada sumidero que demuestre alcanzable aparecerá aquí como una sonda de un clic.',
      probeAt: (sink: string, address: string) => `Sondear ${sink} en ${address}`,
      noArch:
        'Bloqueado: no se conoce ninguna arquitectura para este rootfs, así que no se puede elegir un emulador de modo usuario.',
    },
  },

  running: 'Ejecutando…',

  kind: {
    dynprobe: 'Sonda dinámica',
    symreach: 'Alcanzabilidad',
    decompile: 'Triaje',
    fuzz: 'Fuzzing',
    webprobe: 'Sonda web',
    emulate: 'Emulación',
  },

  ago: {
    seconds: (n: number) => `hace ${n} s`,
    minutes: (n: number) => `hace ${n} min`,
    hours: (n: number) => `hace ${n} h`,
    days: (n: number) => `hace ${n} d`,
  },
};
