import type { Messages } from '../en';

/**
 * operator — Spanish.
 *
 * Nada de aquí puede sonar a medición. Una afirmación no lleva estado de prueba, no cuenta para ninguna etapa del
 * análisis y no se borra nunca — sólo se retira, con el motivo. `assertionsSub` dice las tres cosas, y la insignia
 * NO es la del estado de prueba: reutiliza la glosa compartida `proofState.label.operator_assertion` para que el
 * registro, la tabla de hallazgos y el informe no redacten la misma fila de tres maneras.
 *
 * El histórico es histórico. `history.heading` y `history.note` existen para que una afirmación sustituida no pueda
 * leerse jamás como una segunda afirmación viva junto a la actual. Una enmienda añade; nunca sobrescribe. Suavizar
 * «ya no se afirman» a algo en presente cometería exactamente el borrado que este registro rechaza.
 *
 * Los CÓDIGOS de afirmación (`asserted_from_device`…), los de gravedad y la frase de atribución que sirve la API no
 * se traducen: los dos primeros son identificadores y la tercera se sirve justo para que la interfaz no se separe
 * del informe.
 */
export const operator: Messages['operator'] = {
  assertionsTitle: (n: number) => `Afirmaciones del operador (${n})`,
  assertionsSub:
    'Lo que sabe una persona, registrado como tal. No llevan estado de prueba, no cuentan para ninguna etapa del ' +
    'análisis y no se borran nunca — sólo se retiran, dejando dicho el motivo.',
  notAMeasurement: 'Una afirmación del operador es evidencia de que una persona afirmó algo. No es una medición.',

  claim: {
    asserted_unverified: 'Lo creo — aquí no lo ha medido nada',
    asserted_from_device: 'Lo observé en el dispositivo físico',
    asserted_from_external_evidence: 'Lo dice una fuente externa (aviso, hoja de datos)',
    disputes_finding: 'Un hallazgo decidido por el código es incorrecto',
  },

  form: {
    whoPlaceholder: 'quién lo afirma',
    whoLabel: 'Quién lo afirma',
    claimPlaceholder: 'la afirmación, en una línea',
    claimLabel: 'La afirmación',
    basisLabel: 'Con qué base',
    severityLabel: 'Gravedad afirmada',
    disputesPlaceholder: 'id del hallazgo que impugnas',
    disputesLabel: 'Id del hallazgo impugnado',
    rationalePlaceholder: 'con qué base — obligatorio, porque nadie más puede evaluar una afirmación sin ello',
    rationaleLabel: 'Base declarada',
    record: 'Registrar afirmación',
    recording: 'Registrando…',
  },

  measuredCount: (n: number) => `${n} hallazgo(s) medido(s) en esta imagen, contados aparte.`,
  noAssertions: 'No hay afirmaciones registradas. Todo lo del registro de esta imagen lo decidió el código.',

  col: {
    severity: 'Grav.',
    claim: 'Afirmación',
    provenance: 'Procedencia',
  },
  withdraw: 'Retirar',
  withdrawnBadge: 'retirada',
  withdrawnHeading: (n: number) => `Retiradas (${n})`,
  withdrawnNote: 'Se conservan a propósito. «Esto estaba mal, y aquí está por qué» es mejor registro que un hueco.',
  withdrawPrompt: '¿Por qué deja de sostenerse esta afirmación? (se registra junto a la retirada)',
  withdrawWho: '¿Quién la retira?',

  unrecordedDate: 'una fecha sin registrar',

  history: {
    noneReadable: (day: string) =>
      [
        `Enmendada el ${day}. No hay histórico legible: esta fila la enmendó una compilación que sobrescribió`,
        'a su predecesora en vez de añadirla, así que aquí sólo se sostiene la afirmación actual.',
      ].join(' '),
    hide: 'Ocultar histórico',
    show: (day: string, n: number) =>
      `Enmendada el ${day} — ver ${n} afirmación${n === 1 ? '' : 'es'} sustituida${n === 1 ? '' : 's'}`,
    heading: 'Histórico — sustituidas, ya no se afirman',
    note:
      'Una enmienda añade; nunca sobrescribe. Nada de lo de abajo se sostiene: es lo que este autor declaró antes, ' +
      'conservado para que una afirmación no pueda reformularse en silencio como otra más débil.',
    superseded: 'sustituida',
    claimNotRecorded: 'afirmación sin registrar',
    stood: (from: string, to: string) => `vigente de ${from} a ${to}`,
    contested: 'impugna',
    noBasis: 'No se registró ninguna base con esta revisión.',
  },

  notes: {
    title: (n: number) => `Notas de trabajo (${n})`,
    sub:
      'Razonamiento que no es una afirmación: una hipótesis, un hilo del que tirar después, por qué descartaste ' +
      'algo. Las notas no se cuentan nunca, no se informan nunca y nunca se pintan como hallazgos.',
    authorPlaceholder: 'autor',
    authorLabel: 'Autor de la nota',
    bodyPlaceholder: 'lo que estás pensando',
    bodyLabel: 'Cuerpo de la nota',
    save: 'Guardar nota',
    empty: 'Aún no hay notas.',
  },
};
