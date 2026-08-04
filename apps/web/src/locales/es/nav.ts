import type { Messages } from '../en';

/** nav — Spanish. Typed against the English catalogue, so an untranslated key cannot ship silently. */
export const nav: Messages['nav'] = {
  dashboard: 'Panel',
  localAnalysis: 'Análisis local',
  agents: 'Agentes',
  proxyUpdates: 'Proxy / Actualizaciones',
  corpus: 'Corpus',
  settings: 'Ajustes',
  capabilities: 'Capacidades',
  system: 'Sistema',
  firmware: 'Firmware',
  activeImage: 'Imagen activa',
  allImages: 'Todas las imágenes',
  navigateHint:
    'Navega el análisis desde el timeline de pasos de arriba, o desde Todas las secciones en la cabecera del dossier — el timeline cubre ocho de las diecinueve.',
  posture: {
    ok: {
      label: 'Sólo local — la API escucha en loopback.',
      title: 'Escuchando en 127.0.0.1: nada fuera de esta máquina puede alcanzar el banco de trabajo.',
    },
    proxied: {
      label: 'Accesible a través de un proxy que autentica.',
      title:
        'La API no está en loopback, y este despliegue declara delante un proxy inverso de confianza que autentica (FIRMLAB_TRUSTED_PROXY).',
    },
    exposed: {
      label: 'En la red — sin autenticación de proxy declarada.',
      title:
        'La API escucha en una dirección que no es loopback y no hay proxy de confianza declarado. Cualquiera con ruta hasta este host alcanza el banco de trabajo y todo lo extraído en él.',
    },
    down: {
      label: 'Postura de red desconocida — /health no contestó.',
      title: 'La API no respondió, así que no se pudo leer la postura. Esto no afirma que sea local.',
    },
  },
  toggleNav: 'Mostrar u ocultar la navegación',
  help: 'Ayuda y visita guiada',
  helpAria: 'Ayuda y visita guiada',
  themeGroup: 'Tema',
  themeLight: 'Tema claro',
  themeSystem: 'Seguir el tema del sistema',
  themeDark: 'Tema oscuro',
  densityToggle: 'Cambiar la densidad',
  densityToComfortable: 'Densidad cómoda',
  densityToCompact: 'Densidad compacta',
  health: {
    unreachable: 'API inaccesible',
    exposed: '⚠ expuesto a la red',
    proxied: '🔒 con autenticación',
    proxiedTitle: 'Accesible únicamente a través de un proxy inverso que autentica',
    local: '● sólo local',
    localTitle: 'Escuchando en loopback — nada sale de esta máquina',
  },
};
