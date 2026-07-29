import type { Messages } from '../en';

/**
 * report — Spanish. El informe se exporta a HTML, Markdown o PDF y lo lee alguien que nunca abrirá el banco de
 * trabajo: aquí el andamiaje ES el entregable.
 *
 * Cuatro frases son la honestidad del informe, no su relleno, y no se suavizan al traducir: que cada hallazgo lleva
 * un estado de prueba explícito, que una etapa que no se ha ejecutado se declara como tal en lugar de darse por
 * limpia, que las afirmaciones del operador no cuentan ni para el total de hallazgos ni para ninguna etapa, y que
 * cero hallazgos no es lo mismo que limpio.
 *
 * Los títulos, las justificaciones, los desplazamientos, las fuentes y las severidades de los hallazgos no se
 * traducen: son el registro que escribió el análisis.
 */
export const report: Messages['report'] = {
  panelTitle: 'Informe',
  fieldTitle: 'Título',
  fieldPreparedBy: 'Preparado por',
  preparedByPlaceholder: 'analista / equipo',
  fieldClassification: 'Clasificación',
  classificationDefault: 'Confidencial',
  sectionsHeading: 'Secciones',
  moveUp: 'Subir',
  moveDown: 'Bajar',
  print: 'Imprimir / Guardar como PDF',

  defaultTitle: (filename: string) => `${filename} — Evaluación de seguridad del firmware`,
  coverPreparedBy: (who: string) => `Preparado por ${who}`,
  coverFindings: (n: number) => `${n} hallazgo${n === 1 ? '' : 's'}`,

  section: {
    summary: 'Resumen ejecutivo',
    identity: 'Identidad del firmware',
    coverage: 'Cobertura del análisis',
    findings: 'Hallazgos',
    appendix: 'Anexo — artefactos',
  },

  summary: {
    scope: (filename: string, size: string, firmwareClass: string, arch: string, endianness: string) =>
      `Este informe cubre el análisis estático del firmware ${filename} (${size}), clasificado como ${firmwareClass} sobre ${arch}/${endianness}.`,
    severityNote: (critical: number, high: number) =>
      ` — ${critical} crítico${critical === 1 ? '' : 's'}, ${high} alto${high === 1 ? '' : 's'}`,
    recorded: (n: number, severityNote: string) =>
      `Se registr${n === 1 ? 'ó' : 'aron'} ${n} hallazgo${n === 1 ? '' : 's'}${severityNote}.`,
    proofDiscipline:
      'Cada hallazgo lleva un estado de prueba explícito; una etapa que no se ha ejecutado se declara como tal en lugar de darse por limpia.',
    assertionsExcluded: (n: number) =>
      `${n} afirmación${n === 1 ? '' : 'es'} del operador ${n === 1 ? 'se lista' : 'se listan'} aparte, más abajo, y no ${n === 1 ? 'cuenta' : 'cuentan'} ni para ese total ni para ninguna etapa — FirmLab no las midió.`,
  },

  identity: {
    firmwareClass: 'Clase',
    arch: 'Arquitectura',
    filesystems: 'Sistemas de ficheros',
    bootloader: 'Gestor de arranque',
    vendorModel: 'Fabricante / modelo',
  },

  entropy: {
    mean: 'Entropía media',
    max: 'Entropía máxima',
    likelyEncrypted: 'Probablemente cifrado',
    likelyCompressed: 'Probablemente comprimido',
    highEntropyRegions: 'Regiones de entropía alta',
    bitsPerByte: (value: string) => `${value} bits/byte`,
    none: 'No hay perfil de entropía disponible.',
  },

  structure: {
    range: 'Rango',
    category: 'Categoría',
    label: 'Etiqueta',
    none: 'No se ha tallado ningún segmento estructural.',
  },

  coverage: {
    staticAnalysis: 'Análisis estático',
    extraction: 'Extracción (rootfs)',
    secrets: 'Barrido profundo de secretos',
    binaries: 'Triaje de binarios',
    emulation: 'Emulación',
  },

  findings: {
    interventionSuffix: (what: string) => `[obtenido tras modificar el firmware: ${what}]`,
    heading: (label: string, n: number) => `${label} (${n})`,
    severity: 'Severidad',
    finding: 'Hallazgo',
    offset: 'Desplazamiento',
    source: 'Fuente',
    proof: 'Estado de prueba',
    none: 'No se registró ningún hallazgo. Ojo: cero hallazgos no es lo mismo que limpio.',
  },

  assertions: {
    heading: (n: number) => `Afirmaciones del operador (${n}) — afirmadas, no medidas.`,
    provenance: 'Una persona o un agente las registró; FirmLab no las calculó.',
    excluded:
      'No llevan estado de prueba, no cuentan para ninguna etapa del análisis y quedan excluidas del recuento de hallazgos anterior.',
    claim: 'Afirmación',
    statement: 'Enunciado',
    assertedBy: 'Afirmado por',
    recorded: 'Registrado',
    agentSuffix: ' (agente)',
    unrecorded: 'sin registrar',
  },

  sbom: {
    inventory: (packages: number, vulnerabilities: number) =>
      `${packages} componentes inventariados; ${vulnerabilities} vulnerabilidades conocidas.`,
    severity: 'Severidad',
    component: 'Componente',
    fixedIn: 'Corregido en',
    none: 'No se generó SBOM (necesita extracción + syft). No se ejecutó.',
  },

  appendix: {
    size: 'Tamaño',
    imageId: 'ID de imagen',
    sizeWithBytes: (human: string, bytes: number) => `${human} (${bytes} bytes)`,
  },
};
