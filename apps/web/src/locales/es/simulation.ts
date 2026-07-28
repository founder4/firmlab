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
};
