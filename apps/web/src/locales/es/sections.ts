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
  simulate: 'Recetas de emulación',
  opacidad: 'Escaneo autónomo',
  agent: 'Agente',
};
