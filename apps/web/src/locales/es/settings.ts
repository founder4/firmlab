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

  panels: {
    privacyTitle: 'Privacidad y conectividad',
    externalAgent: 'Copiloto / agente externo',
    humanApproval: 'Requiere aprobación humana',
    storageTitle: 'Almacenamiento y retención',
    localAnalysis: 'Análisis local',
    helpSub: 'Aprende a moverte por el banco, o vuelve a ver la introducción.',
  },
};
