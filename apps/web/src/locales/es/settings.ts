import type { Messages } from '../en';

/** settings — Spanish. Typed against the English catalogue, so an untranslated key cannot ship silently. */
export const settings: Messages['settings'] = {
  eyebrow: 'Sistema',
  title: 'Ajustes',
  desc: 'La apariencia la decides tú aquí. El análisis, la privacidad y los límites del agente reflejan la configuración real de este despliegue.',

  tabs: {
    appearance: 'Apariencia',
    analysis: 'Análisis',
    tools: 'Herramientas',
    agent: 'IA y agente',
    privacy: 'Privacidad',
    storage: 'Almacenamiento',
    help: 'Ayuda',
  },

  appearance: {
    title: 'Apariencia',
    sub: 'Se aplica al instante y se recuerda en este dispositivo.',
    theme: 'Tema',
    themeLight: 'Claro',
    themeSystem: 'Sistema',
    themeDark: 'Oscuro',
    density: 'Densidad',
    densityComfortable: 'Cómoda',
    densityCompact: 'Compacta',
    densityHint:
      'La densidad compacta reduce el alto de las filas y los espaciados, para sesiones densas en pantallas grandes.',
  },

  language: {
    row: 'Idioma',
    hint: 'Cambia la interfaz del banco de trabajo y los informes que genera. Se aplica al instante y se recuerda en este dispositivo.',
    scope:
      'Los hallazgos conservan la redacción con la que el análisis los registró. Esas frases se almacenan junto a la imagen como evidencia, así que se muestran tal y como se escribieron en lugar de volver a traducirse.',
  },

  /**
   * El marco de los interruptores de carril. Lo que enciende cada uno y lo que sale de la máquina lo compone la
   * API en el idioma que pide esta página. `leavingNow` va en presente porque el carril YA está encendido y el
   * tráfico está ocurriendo; `ifEnabled` es condicional. Juntarlos dejaría que un carril encendido se leyera como
   * una hipótesis.
   */
  lanes: {
    title: 'Carriles',
    sub: [
      'Todo lo que puede salir de este proceso. Apagado es lo predeterminado, y el motor determinista no necesita',
      'ninguno. Un cambio surte efecto en la siguiente ejecución — sin reiniciar.',
    ].join(' '),
    loading: 'Cargando carriles…',
    leavingNow: 'Sale de esta máquina: ',
    ifEnabled: 'Si se activa: ',
    followEnvironment: 'fijado aquí · seguir al entorno',
    followEnvironmentHint: (environmentValue) =>
      `El entorno del contenedor lo tiene ${environmentValue ? 'encendido' : 'apagado'}. Vuelve a seguirlo.`,
    inertLead: 'Encendido, pero sin hacer nada — ',
    inertTail: ' está apagado, y esto sólo actúa dentro de ese carril.',
  },

  panels: {
    privacyTitle: 'Privacidad y conectividad',
    externalAgent: 'Copiloto / agente externo',
    humanApproval: 'Requiere aprobación humana',
    storageTitle: 'Almacenamiento y retención',
    localAnalysis: 'Análisis local',
    helpSub: 'Aprende a moverte por el banco, o vuelve a ver la introducción.',
  },
};
