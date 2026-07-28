import type { Messages } from '../en';

/** common — Spanish. Typed against the English catalogue, so an untranslated key cannot ship silently. */
export const common: Messages['common'] = {
  run: 'Ejecutar',
  cancel: 'Cancelar',
  close: 'Cerrar',
  save: 'Guardar',
  delete: 'Eliminar',
  retry: 'Reintentar',
  showAll: 'Ver todo',
  showLess: 'Ver menos',
  loading: 'Cargando…',
  copy: 'Copiar',
  copied: 'Copiado',
  download: 'Descargar',
  search: 'Buscar',
  filter: 'Filtrar',
  none: 'ninguno',
  unknown: 'desconocido',
  yes: 'sí',
  no: 'no',
  andMore: (n: number) => `+${n} más`,
};
