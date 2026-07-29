import type { Messages } from '../en';

/**
 * simulation — Español. Dos afirmaciones sostienen el panel y no se suavizan al traducir.
 *
 * Un peldaño que no puede ejecutarse dice POR QUÉ: `needsTools` es la insignia y `requires` la frase que nombra lo
 * que habría que instalar, porque "sin botón" se lee como "no aplica a este firmware", que es otra cosa y es falsa.
 * Y `sandboxCaveat`: que un peldaño arranque prueba que el emulador aceptó la imagen, no nada sobre la placa.
 *
 * No se traducen: los modos de emulación (`user-qemu`, `system-qemu`, `renode`, `uefi-chipsec`), las líneas de
 * comandos, los nombres de herramientas, los ids y estados de trabajo, los estados de prueba, ni el título, la
 * descripción y las notas de la receta que compone la API.
 */
export const simulation: Messages['simulation'] = {
  loading: 'Cargando el plan de emulación…',

  needsRootfs:
    'La emulación en modo usuario necesita un rootfs extraído. Ejecuta antes la extracción (requiere binwalk).',
  extractNow: 'Extraer ahora',

  runnable: 'ejecutable',
  needsTools: 'faltan herramientas',
  requires: (tools: string) => `No ejecutable en este despliegue: requiere ${tools}.`,
  sandboxCaveat:
    'La emulación prueba el entorno aislado, nunca el dispositivo físico. Que un peldaño arranque aquí demuestra que este emulador aceptó la imagen, no que la placa se comporte igual.',

  targetBinary: 'Binario objetivo',
  selectBinary: 'Elige un binario…',
  suggested: (path: string) => `sugerido: ${path}`,
  binaryPlaceholder: 'ejecuta la extracción para listar binarios',

  bootRenode: 'Arrancar bajo Renode',
  decodeScan: 'Decodificar y analizar',
  runProof: 'Ejecutar prueba',

  job: (id: string) => `Trabajo ${id}`,
  booted: 'arrancó',
  noUart: 'sin salida por UART',
  timedOut: 'agotó el tiempo (probablemente un demonio de larga duración)',

  moduleCount: (n: number) => `${n} módulo${n === 1 ? '' : 's'}`,
  noUefiVolume: 'sin volumen UEFI',
  volumeCount: (n: number) => `${n} FV`,
  secureBoot: 'Arranque seguro:',
  setupMode: (mode: string) => `modo ${mode}`,
  testKey: (key: string) => `clave de prueba: ${key}`,
  nvramVars: (n: number) => `${n} variable(s) NVRAM`,

  egressTitle: 'A dónde intentó ir',
  egressBlocked: 'salida bloqueada',
  egressOpen: 'salida abierta',
  egressOpenWarning:
    'Este arranque NO estaba aislado: el firmware podía alcanzar esto desde esta máquina. Enciende FIRMLAB_EMU_ISOLATE en Ajustes para conservar la lista y quitarle el alcance.',
  egressIsolatedNote:
    'Este arranque estaba aislado, así que no se alcanzó nada de lo de abajo. Bloquear el tráfico no oculta el intento — esto es lo que el firmware pidió.',
  egressOneBoot:
    'Un arranque es una muestra. El mismo firmware arrancado dos veces no siempre llega al mismo punto, así que esta lista es un suelo y no un total — que un destino falte aquí puede significar sólo que no se intentó en esta ejecución.',
  egressNames: 'Nombres que pidió resolver',
  egressDestinations: 'Direcciones a las que apuntó',
  egressNone: 'El guest no se dirigió a nada más allá del emulador durante esta ejecución.',
  egressScope: {
    external: 'más allá del emulador',
    emulator: 'el emulador mismo',
    local: 'su propia subred',
    multicast: 'anuncio',
  },
  egressFrames: (n: number) => `${n} trama${n === 1 ? '' : 's'}`,
  egressAskedOf: (server: string) => `preguntado a ${server}`,
  egressTruncatedNames: (n: number) =>
    `${n} pregunta(s) DNS se capturaron demasiado cortas para leer el nombre, y un nombre truncado es otro nombre.`,
};
