import type { Messages } from '../en';

/**
 * sections — Spanish. Los IDs de sección son segmentos de RUTA y no se traducen: una URL traducida rompería cada
 * enlace guardado. Aquí sólo se traducen las etiquetas.
 */
export const sections: Messages['sections'] = {
  dossier: 'General',
  overview: 'General',
  structure: 'Estructura',
  entropy: 'Entropía',
  filesystem: 'Extracción',
  files: 'Explorador de ficheros',
  secrets: 'Secretos',
  hardware: 'Interfaces de hardware',
  bootloader: 'Gestor de arranque',
  sbom: 'SBOM y CVEs',
  compmap: 'Mapa de componentes',
  deepscans: 'Análisis profundos',
  binaries: 'Banco de pruebas',
  testbench: 'Banco de pruebas',
  findings: 'Hallazgos e informe',
  operator: 'Registro del operador',
  diff: 'Comparativa',
  egress: 'Salida a red del firmware',
  simulate: 'Recetas de emulación',
  opacidad: 'Escaneo autónomo',
  agent: 'Agente',
};

export const sectionIndex = {
  heading: 'Todas las secciones',
  intro:
    'Todas las superficies de análisis de esta imagen, y todas alcanzables desde aquí. Diez sólo se alcanzaban escribiendo una URL — incluida Ficheros, que es la superficie que permite comprobar la evidencia de un hallazgo en vez de confiarla. No se oculta nada por conjeturar qué aplica a esta clase de dispositivo: ese enrutado vive en la API y una segunda copia aquí estaría a un commit de contradecirla.',
  timelineNote: 'En el timeline de arriba',
  urlOnly: 'sólo se alcanzaba por URL',
  notRun:
    'necesita un rootfs extraído, y la extracción no ha corrido — una afirmación sobre este banco, no sobre el firmware',
  noRootfs:
    'la extracción SÍ corrió y no produjo rootfs, así que esta sección no tiene nada que leer. Es una propiedad medida de esta imagen, no una etapa que nadie arrancó.',
};
