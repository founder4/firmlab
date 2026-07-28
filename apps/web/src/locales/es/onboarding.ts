import type { Messages } from '../en';

/**
 * onboarding — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse en
 * silencio.
 *
 * Esta es la primera prosa que lee un operador nuevo y enseña a leer todas las pantallas siguientes. El paso
 * `proof` es el que sostiene el resto: los estados de prueba se escriben tal cual — son identificadores que viajan
 * por la API y se guardan en SQLite, así que aparecen dentro de la frase exactamente como los almacena la base de
 * datos — y la frase dice lo que cada uno se niega a afirmar. Dos de esas afirmaciones se invierten si la
 * traducción las suaviza:
 *
 *   • `needs_runtime_reproduction` es una PISTA. Se observó una precondición y no se probó nada.
 *   • `blocked_by_platform` significa que la pregunta SÍ se hizo y este despliegue no pudo responderla. No es un
 *     resultado negativo, y una redacción que suene a «sin problemas» enseñaría lo contrario de la afirmación
 *     central del banco de trabajo en la primera pantalla que alguien ve.
 *
 * El vocabulario se toma del espacio `proofState` a propósito: «pista» para un lead y «limpia» para el veredicto
 * que nunca se da, para que la misma idea no tenga dos redacciones distintas en la misma sesión.
 */
export const onboarding: Messages['onboarding'] = {
  ariaLabel: 'Recorrido guiado',
  progress: (step: number, total: number) => `Paso ${step} / ${total}`,
  skip: 'Saltar',
  back: 'Atrás',
  next: 'Siguiente',
  done: 'Listo',

  welcome: {
    title: 'Bienvenido a FirmLab',
    body: [
      'Un banco de trabajo de firmware local y privado. Todo se analiza en esta máquina — no se sube nada.',
      'Esto es un recorrido de 20 segundos; puedes saltártelo cuando quieras.',
    ].join(' '),
  },
  sidebar: {
    title: 'Navega desde aquí',
    body: [
      'La barra lateral contiene tu espacio de trabajo — el panel, el corpus y lo que este despliegue puede hacer',
      '— y, con una imagen de firmware abierta, sus secciones de análisis agrupadas por propósito.',
    ].join(' '),
  },
  health: {
    title: 'Postura de seguridad, siempre a la vista',
    body: [
      'Indica si la API escucha en loopback (sólo local) o es accesible desde la red.',
      'FirmLab está pensado para quedarse en local.',
    ].join(' '),
  },
  appearance: {
    title: 'Ajústalo a tu gusto',
    body: [
      'Cambia entre tema claro, oscuro o el del sistema, y alterna la densidad cómoda o compacta para sesiones',
      'largas de análisis. Los controles completos están en Ajustes.',
    ].join(' '),
  },
  upload: {
    title: 'Empieza un análisis',
    body: [
      'Suelta una imagen de firmware (o búscala) para analizarla al instante con el motor determinista — no hace',
      'falta ninguna cadena de herramientas. Las herramientas externas añaden profundidad cuando están instaladas.',
    ].join(' '),
  },
  proof: {
    title: 'Lee primero el estado de prueba',
    body: [
      'Los hallazgos no son opiniones: cada uno lleva un estado de prueba. static_confirmed significa que la',
      'propiedad está literalmente en los bytes; needs_runtime_reproduction es una pista y nada más;',
      'blocked_by_platform significa que la pregunta se hizo y aquí no se pudo responder — nunca que la imagen esté',
      'limpia. Una lista vacía tampoco significa limpia.',
    ].join(' '),
  },
  end: {
    title: 'Ya está',
    body: [
      'Puedes reiniciar este recorrido cuando quieras desde el botón ? de la cabecera o en Ajustes → Ayuda.',
      'Buena caza.',
    ].join(' '),
  },
};
