import type { Messages } from '../en';

/** egressSection — español. Tipado contra el catálogo inglés, así una clave sin traducir no puede colarse. */
export const egressSection: Messages['egressSection'] = {
  title: 'Salida a red del firmware — a dónde se dirigió la imagen arrancada',
  sub: 'Leído de las tramas del propio invitado, así que el intento queda registrado lo dejara pasar esta ejecución o no. Un destino de aquí fue DIRECCIONADO y nunca se reporta como contactado: desde el lado que envía, un SYN a un agujero negro y un saludo completado se ven igual.',
  noRuns: 'No ha terminado ninguna emulación de esta imagen, así que no ha habido nada en su cable que observar.',
  toSimulate: 'Ir a emulación',
  runsWithoutCapture: (n: number) =>
    `${n} emulación${n === 1 ? '' : 'es'} terminada${n === 1 ? '' : 's'} y ninguna trae observación de cable. Eso NO es que este firmware no se dirija a nada: una ejecución guardada antes de que existiera la observación, o un qemu sin el objeto filter-dump, produce exactamente esto y no dice nada del invitado.`,
  runLabel: (headline: string, when: string) => `${headline} · ${when}`,
};
