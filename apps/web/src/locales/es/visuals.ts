import type { Messages } from '../en';

/**
 * visuals — Spanish. Tipado contra el catálogo inglés, así que una clave sin traducir no puede colarse en silencio.
 *
 * Estos cuatro dibujos pintan una medida, y una medida pintada con fuerza se lee como un veredicto. La entropía es
 * el caso que importa: por encima de 7.2 bits/byte los bytes son casi aleatorios, y la compresión, el empaquetado,
 * el cifrado, un JPEG incrustado y un blob de certificado producen exactamente eso. Por eso las advertencias de
 * `entropy.caveat` y `signal.caveat` dicen «hipótesis» y no «comprimido»: traducirlas como una afirmación
 * convertiría una pista en un veredicto. `sbom.caveat` es el mismo error del revés — un nodo gris es un componente
 * con el que no ha casado nada, que no es lo mismo que un componente seguro.
 *
 * Nada de lo que sea notación se traduce: `bits/byte`, los desplazamientos `0x…`, los tamaños en bytes, los nombres
 * y versiones de paquete, los identificadores CVE y los nombres de gravedad de grype. Llegan a estos mensajes ya
 * formateados, como cadenas, para que una traducción no pueda reescribir un número. `7.2` se escribe igual en los
 * dos idiomas por lo mismo: es el umbral con el que compara el código, no una cantidad que se localice.
 */
export const visuals: Messages['visuals'] = {
  entropy: {
    ariaLabel: 'Entropía a lo largo del desplazamiento de la imagen',
    readout: (offset: string, bits: string) => `desplazamiento ${offset} · H = ${bits} bits/byte`,
    summary: (mean: string, max: string) => `Media ${mean} · Máx ${max} · línea discontinua en 7.2 bits/byte`,
    caveat: [
      'Por encima de esa línea los bytes son casi aleatorios.',
      'La compresión, el empaquetado y el cifrado se leen igual — y también un JPEG incrustado o un blob de',
      'certificado. Las bandas sombreadas son una hipótesis que contrastar con el mapa de estructura, nunca un',
      'veredicto.',
    ].join(' '),
  },

  structure: {
    hoverPrompt: 'Pasa el cursor por un segmento para inspeccionarlo.',
    caveat: [
      'Cada banda es una coincidencia de firma en ese desplazamiento — lo que un número mágico dice que empieza',
      'ahí, no un veredicto sobre lo que son los bytes. El tramo entre dos coincidencias está sin reclamar, no',
      'vacío.',
    ].join(' '),
  },

  signal: {
    ariaLabel: 'Cinta de señal del firmware',
    title: 'Cinta de señal del firmware',
    marksPinned: (n: number) => `▲ ${n} hallazgo${n === 1 ? '' : 's'} anclado${n === 1 ? '' : 's'} a su desplazamiento`,
    caveat: [
      'La línea discontinua está en 7.2 bits/byte: por encima, los bytes son casi aleatorios, que es a lo que se',
      'parecen el empaquetado, la compresión, el cifrado — y un JPEG —, así que es una pista que contrastar con la',
      'banda de estructura de debajo.',
      'Cada marca está en el desplazamiento que registró el hallazgo; un hallazgo sin desplazamiento no aparece en',
      'la cinta.',
    ].join(' '),
  },

  sbom: {
    ariaLabel: 'Grafo de componentes del SBOM',
    title: 'Grafo de componentes del SBOM',
    pkgCount: (n: number) => `${n} paq.`,
    noKnownCves: 'sin CVE conocidos',
    legendNoCve: 'sin CVE',
    affected: (vulnerable: number, total: number) =>
      `${vulnerable} de ${total} componentes afectados · el tamaño del nodo = número de CVE`,
    caveat: [
      'Un componente con el que no ha casado nada se pinta en gris, y eso no es lo mismo que un componente seguro.',
      'La coincidencia vale lo que valgan la versión que el SBOM identificó y los datos de vulnerabilidades que',
      'este despliegue pudo consultar — la ausencia de un CVE aquí es ausencia de coincidencia, no prueba de que',
      'no exista ninguno.',
    ].join(' '),
  },
};
