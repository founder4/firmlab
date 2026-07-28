import type { Messages } from '../en';

/**
 * proofState — Spanish. Los CÓDIGOS no se traducen nunca: `static_confirmed` y los demás son identificadores que
 * viajan por la API y se guardan en SQLite. Aquí sólo se traduce la etiqueta legible y su significado.
 *
 * Cuidado con `blocked_by_*`: significa que la pregunta SÍ se hizo y este despliegue no pudo responderla. No es un
 * resultado negativo, y una redacción que suene a "sin problemas" invertiría la afirmación central del banco.
 */
export const proofState: Messages['proofState'] = {
  label: {
    confirmed_full_system: 'confirmado (sistema completo)',
    confirmed_in_emulation: 'confirmado (emulado)',
    static_confirmed: 'confirmado en los bytes',
    needs_runtime_reproduction: 'falta reproducir',
    blocked_by_platform: 'bloqueado (plataforma)',
    blocked_by_security: 'bloqueado (control)',
    false_positive: 'falso positivo',
    operator_assertion: 'afirmado · no medido',
  },
  meaning: {
    confirmed_full_system: 'Reproducido bajo emulación de sistema completo.',
    confirmed_in_emulation:
      'Reproducido contra una imagen arrancada. Esto prueba el entorno aislado, nunca el dispositivo físico.',
    static_confirmed: 'La propiedad está literalmente presente en los bytes. Afirma el hecho, no que sea explotable.',
    needs_runtime_reproduction:
      'Una pista. Se observó una precondición y no se probó nada — nunca lo presentes como un fallo.',
    blocked_by_platform: 'La pregunta se hizo y este despliegue no pudo responderla. Esto NO es un resultado negativo.',
    blocked_by_security:
      'Un control — cifrado, arranque seguro — detuvo el análisis. Esto NO es un resultado negativo.',
    false_positive: 'Comprobado y descartado.',
    operator_assertion:
      'Una persona o un agente lo afirmó; FirmLab no lo midió. No lleva estado de prueba y no cuenta para ninguna etapa del análisis.',
  },
  severity: {
    critical: 'crítica',
    high: 'alta',
    medium: 'media',
    low: 'baja',
    info: 'informativa',
  },
};
