import type { Messages } from '../en';

/** nav — Spanish. Typed against the English catalogue, so an untranslated key cannot ship silently. */
export const nav: Messages['nav'] = {
  brandSub: 'firmware · local',
  dashboard: 'Panel',
  localAnalysis: 'Análisis local',
  agents: 'Agentes',
  proxyUpdates: 'Proxy / Actualizaciones',
  corpus: 'Corpus',
  settings: 'Ajustes',
  system: 'Sistema',
  firmware: 'Firmware',
  activeImage: 'Imagen activa',
  allImages: 'Todas las imágenes',
  navigateHint: 'Navega el análisis desde la línea de pasos en la parte superior de la página.',
  localOnly: 'Sólo local. No lo expongas nunca a internet.',
  toggleNav: 'Mostrar u ocultar la navegación',
  health: {
    unreachable: 'API inaccesible',
    exposed: '⚠ expuesto a la red',
    proxied: '🔒 con autenticación',
    proxiedTitle: 'Accesible únicamente a través de un proxy inverso que autentica',
    local: '● sólo local',
    localTitle: 'Escuchando en loopback — nada sale de esta máquina',
  },
};
