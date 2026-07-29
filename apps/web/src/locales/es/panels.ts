import type { Messages } from '../en';

/**
 * panels — Español. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse en silencio.
 *
 * Cuatro frases de estos paneles son el producto y no se suavizan al traducir:
 *
 *  - symreach — una búsqueda ACOTADA que no alcanzó un sumidero no ha demostrado nada sobre ese sumidero. «No
 *    alcanzado» no quiere decir «no explotable» ni «seguro»: el hallazgo se queda en `needs_runtime_reproduction` y
 *    una búsqueda agotada jamás es una rebaja a `false_positive`. Por eso la etiqueta del resultado es «no
 *    concluyente — búsqueda acotada» y nunca algo que suene a aprobado.
 *  - fuzz — una campaña que no encontró ninguna caída dentro de su presupuesto es un negativo honesto sobre ese
 *    harness y ese tiempo. No es un binario limpio.
 *  - webprobe — un acierto reproducido es `confirmed_in_emulation`: prueba el entorno aislado, nunca el dispositivo
 *    físico. Esa frase no se repite aquí, se toma de `proofState`, para que no existan dos redacciones distintas.
 *  - opacidad — una etapa que informa `not-built` o `skipped` no es una etapa superada: no se le llegó a preguntar
 *    nada, y el panel lo dice para que una lista corta de hallazgos no se lea como una imagen limpia.
 *
 * No se traducen nunca: los estados de prueba, los tipos de hallazgo, los tipos de trabajo y de ejecución, las
 * cadenas de origen, las severidades, los ids de trabajador y de etapa, los modos de emulación (`user-qemu`,
 * `system-qemu`…), los nombres de sumidero, los nombres de herramienta (`AFL++`, `angr`, `qemu`, `gdb`), los nombres
 * de variables de entorno y las rutas de binarios. Son identificadores que viajan por la API y acaban en SQLite. Una
 * frase construida alrededor de uno se guarda como los tramos de prosa que van antes y después, en orden de pintado,
 * y el panel vuelve a intercalar el identificador — el castellano lo coloca donde la frase lo pide.
 */
export const panels: Messages['panels'] = {
  opacidad: {
    title: 'Escaneo autónomo (opacidad)',
    sub: [
      'Planifica la cadena de trabajadores que corresponde a la clase, la ejecuta de principio a fin y compone la',
      'traza de razonamiento — una sola acción en lugar de pulsar cada proveedor a mano. Honesto por diseño: los',
      'trabajadores omitidos y los que aún no existen se muestran, nunca se ocultan.',
    ].join(' '),
    run: 'Ejecutar escaneo autónomo',
    rerun: 'Repetir el escaneo autónomo',
    running: 'Escaneando…',
    failed: 'El escaneo autónomo falló',
    narrativeLabel: 'narrativa:',
    narrativeTitle: 'Cómo se escribió la narrativa',
    replanned: 'replanificado',
    status: {
      ran: 'ran — el trabajador se ejecutó y lo que informa está debajo.',
      degraded: 'degraded — se ejecutó sin algo que necesitaba. Lee su nota antes de leer su silencio.',
      skipped: [
        'skipped — no tenía ninguna entrada sobre la que trabajar. La pregunta no llegó a hacerse, así que no es',
        'una etapa superada.',
      ].join(' '),
      'not-built': [
        'not-built — este trabajador todavía no existe. La pregunta no llegó a hacerse, así que no es una etapa',
        'superada.',
      ].join(' '),
    },
    workers: 'Trabajadores',
    findings: (n: number) => `Hallazgos (${n})`,
    noFindings: [
      'Los trabajadores que se ejecutaron no sacaron a la luz ningún hallazgo. Eso es una afirmación sobre los',
      'trabajadores de arriba — los omitidos y los que aún no existen no preguntaron nada — y nunca un certificado',
      'de limpieza para este firmware.',
    ].join(' '),
    attackPath: 'Ruta de ataque (cadena de evidencias)',
    narrative: 'Narrativa',
    honestGaps: 'Huecos honestos — lo que NO se ejecutó',
    runLabel: 'escaneo autónomo',
  },

  symreach: {
    title: 'Alcanzabilidad simbólica (angr)',
    sub: {
      lead: 'Una pregunta comprobable por sumidero:',
      question: '¿es ese punto de llamada alcanzable desde el punto de entrada con argv/stdin simbólicos?',
      provesLead: 'Un sumidero alcanzado demuestra',
      reachability: 'alcanzabilidad',
      provesTail: [
        ', no explotabilidad. Un sumidero que no se alcanza no demuestra absolutamente nada — la búsqueda está',
        'acotada, así que sigue siendo una pista.',
      ].join(' '),
    },
    outcome: {
      reached: 'alcanzable desde la entrada',
      not_reached_in_budget: 'no concluyente — búsqueda acotada',
      absent: 'símbolo ausente en este binario',
      skipped: 'sin preguntar — presupuesto de la ejecución agotado',
    },
    binaryPlaceholder: 'binario relativo al rootfs, p. ej. usr/sbin/bpalogin',
    sinksPlaceholder: 'sumideros (en blanco = derivarlos de los imports)',
    sinksLabel: 'Símbolos de sumidero por los que preguntar',
    budget: 'presupuesto',
    budgetLabel: 'Presupuesto en segundos',
    ask: 'Preguntar',
    probing: 'Sondeando…',
    probeFailed: 'la sonda falló',
    hint: {
      lead: 'Los sumideros son símbolos de función —',
      beforeAbsent: [
        '. Déjalo en blanco para preguntar por las funciones de copia sin límite que importa este binario. Un',
        'símbolo que el binario no importa vuelve como',
      ].join(' '),
      absentWord: 'ausente',
      afterAbsent: ', no como un resultado limpio.',
    },
    notAnswered: 'Sin responder',
    notAnsweredHint: (binary: string) =>
      `Esto es una capacidad ausente, no un resultado limpio — no se descartó nada sobre ${binary}.`,
    unknownArch: 'arquitectura desconocida',
    entry: 'entrada',
    reachableCount: (reached: number, total: number) => `${reached}/${total} alcanzables`,
    derivedSinks: 'sumideros derivados de los imports',
    dropped: (n: number) => `${n} sumidero(s) sin preguntar (tope por ejecución)`,
    pathFound: 'camino encontrado',
    steps: (n: number) => `${n} pasos`,
    pathTail: 'cola del camino:',
    noReason: 'no se registró ningún motivo',
    pruned: 'se podaron estados para no salirse del límite de memoria',
    errors: (n: number) => `${n} estado(s) perdidos por errores internos de angr`,
    reachedNote: [
      'Que un sumidero se alcance significa que el punto de llamada está en un camino factible desde el punto de',
      'entrada, con una entrada concreta que lo recorre. Si la copia desborda, y si eso es explotable, son preguntas',
      'distintas que esto no responde.',
    ].join(' '),
    notReached: {
      lead: [
        'No se alcanzó nada dentro del presupuesto. Eso no es prueba de inalcanzabilidad — los saltos indirectos y',
        'las llamadas al sistema sin modelar esconden de forma rutinaria caminos reales a una búsqueda acotada. Cada',
        'sumidero de arriba se queda en',
      ].join(' '),
      beforeFalsePositive: '— una búsqueda agotada nunca es una rebaja a',
      tail: '. Sube el presupuesto o somete el binario a fuzzing.',
    },
    runLabel: 'alcanzabilidad',
  },

  fuzz: {
    title: 'Fuzzing guiado por cobertura (AFL++)',
    runnable: 'ejecutable',
    optIn: 'capa opcional',
    sub: [
      'Somete a fuzzing un binario extraído dentro del entorno aislado (modo qemu). Una caída reproducida se',
      'registra como hallazgo confirmado; no encontrar nada es un resultado honesto, no un aprobado.',
    ].join(' '),
    notInstalled: {
      lead: 'AFL++ no está instalado en este despliegue — habilita la capa opcional en',
      tail: '(afl-fuzz + afl-qemu-trace). Sin él no se finge nada.',
    },
    didNotRun: 'No se ejecutó ninguna campaña contra',
    didNotRunMeaning:
      'No hay recuento de fallos para este binario — no es un recuento de cero. Debajo no se midió nada, y la frase que acompaña dice qué impidió la ejecución, que nunca es una afirmación sobre el binario.',
    noReason: 'La versión que registró esta ejecución no dejó motivo.',
    needBinary: 'Escribe la ruta de un binario del rootfs al que fuzzear (p. ej. bin/busybox).',
    harnessLabel: 'Vía de entrada',
    harnessTitle: 'Cómo llega al objetivo la entrada generada',
    run: 'Ejecutar fuzzing',
    stat: {
      binary: 'Binario',
      execs: 'Ejecuciones',
      crashes: 'Caídas',
      isolation: 'Aislamiento',
    },
    crashInputs: {
      lead: 'Entradas que provocaron una caída (primeros bytes) — se registró un hallazgo',
      tail: ':',
    },
    noCrash: [
      'Ninguna caída dentro del presupuesto de tiempo — un negativo honesto, no una garantía de seguridad. Dice que',
      'este binario sobrevivió a esta vía de entrada durante este presupuesto, y no dice nada de una ejecución más',
      'larga, de otra vía ni de otra semilla.',
    ].join(' '),
    runLabel: 'fuzzing',
  },

  webprobe: {
    title: 'Sonda web activa',
    sub: {
      lead: [
        'Dirige un servicio arrancado (chroot-service / full-system) buscando inyección de órdenes y salto de',
        'directorio. Un acierto reproducido se registra como',
      ].join(' '),
      means: ', que significa:',
      tail: 'Sólo objetivos en loopback o en red privada.',
    },
    probe: 'Sondear',
    probeFailed: 'la sonda falló',
    reachable: 'accesible',
    unreachable: 'inaccesible',
    requests: (n: number) => `${n} peticiones`,
    points: (n: number) => `${n} puntos de inyección`,
    reproduced: (n: number) => `${n} reproducidos`,
    runLabel: 'sonda web',
  },

  presets: {
    title: 'Configuraciones guardadas',
    sub: 'Guarda una configuración de emulación con nombre y vuelve a ejecutarla con un clic.',
    mode: {
      'user-qemu': 'QEMU en modo usuario',
      'chroot-qemu': 'Servicio en chroot',
      'system-qemu': 'QEMU de sistema completo',
      renode: 'Renode (arranque RTOS)',
      'uefi-chipsec': 'chipsec (comprobaciones UEFI)',
    },
    namePlaceholder: 'nombre de la configuración',
    binaryPlaceholder: 'bin/httpd (opcional)',
    save: 'Guardar configuración',
    remove: 'Eliminar esta configuración',
    started: (name: string, jobId: string) =>
      `Se inició «${name}» (trabajo ${jobId}) — mira el registro del trabajo en los paneles de arriba.`,
  },
};
