import type { Messages } from '../en';

/**
 * coverage — Spanish.
 *
 * Las etiquetas de estado son lo delicado de este espacio. `sin ejecutar` y `ejecutado · nada` producen la MISMA
 * lista vacía de hallazgos y son conclusiones OPUESTAS: una etapa que nunca se ejecutó no es una etapa limpia, y
 * cualquier redacción que permita leerla así invierte la afirmación central del banco. Por eso ninguna etiqueta
 * dice «sin problemas», «correcto» ni nada que suene a resultado.
 *
 * El veredicto, la justificación de clase y el motivo de cada etapa los calcula la API y se muestran tal cual: son
 * el registro de lo que este despliegue midió, no texto de interfaz.
 */
export const coverage: Messages['coverage'] = {
  eyebrow: (firmwareClass: string) => `Cobertura · ${firmwareClass}`,

  status: {
    found: 'con hallazgos',
    'ran-empty': 'ejecutado · nada',
    degraded: 'degradado',
    'no-input': 'sin entrada',
    'not-built': 'sin implementar',
    'not-run': 'sin ejecutar',
  },

  assertions: (measured: number, asserted: number) => {
    const rows =
      asserted === 1 ? 'Hay 1 fila más que es una afirmación' : `Hay ${asserted} filas más que son afirmaciones`;
    const cover = asserted === 1 ? 'no cubre' : 'no cubren';
    return [
      `Los ${measured} de arriba están medidos.`,
      `${rows} del operador: lo que declara una persona con nombre, y ${cover} ninguna etapa.`,
    ].join(' ');
  },

  hide: 'Ocultar',
  whatCanRun: (executed: number, applicable: number) =>
    `¿Qué se puede ejecutar sobre esta imagen? (${executed}/${applicable})`,
};
