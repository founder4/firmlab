import type { funcdiff as en } from '../en/funcdiff';

/** Espejo español de `en/funcdiff`. Una lista vacía puede significar tres cosas distintas y cada una tiene su frase. */
export const funcdiff: typeof en = {
  textTitle: 'Comparación descompilada',
  textSub:
    'Extractos antes/después de los bloques guardados, no funciones completas ni fuente del fabricante. Los cambios pueden incluir ruido del descompilador y no prueban una corrección de seguridad.',
  textMissing: 'Este resultado antiguo no registró comparaciones descompiladas.',
  textEmpty:
    'No se guardaron comparaciones descompiladas. Solo se intenta para un conjunto limitado de funciones cambiadas; ambos lados deben descompilarse.',
  before: 'Antes (base anterior)',
  after: 'Después (imagen nueva)',
  unified: 'Diff unificado guardado',
  textTruncated: 'El proveedor omitió más bloques. Esta comparación es parcial.',
  textDisplayBound: 'Visualización limitada a 60 comparaciones y 24.000 caracteres por diff.',
  noHunks: 'No se guardaron bloques cambiados para esta comparación.',
  title: 'Diff de funciones contra una base',
  sub: 'Empareja los binarios con la misma ruta en ambos rootfs, toma la huella de cada función con radare2 e informa de qué cambió. Esta imagen es la compilación MÁS NUEVA; la elegida arriba es la base antigua. Ambas necesitan una extracción terminada.',
  run: 'Comparar funciones',
  running: 'Comparando funciones…',
  chooseBaseline: 'Imagen base: elige una en el selector de arriba antes de lanzar el diff de funciones.',
  loading: 'Cargando el último diff de funciones contra esta base…',
  none: 'Aún no se ha ejecutado ningún diff de funciones contra esta base. Eso no dice nada del firmware — ejecútalo.',

  outcome: {
    blocked:
      'El diff de funciones no pudo ejecutarse — esto no es un resultado negativo. Abajo está el motivo del proveedor.',
    identicalBytes: (n) =>
      `Idénticas: los ${n} binarios presentes en ambas compilaciones son idénticos byte a byte, así que no hay cambio de código que localizar.`,
    identicalFunctions:
      'Idénticas: cada par de binarios comparado es estructuralmente igual a nivel de función — no se ve ningún cambio de código a este nivel.',
    nothingComparable:
      'Nada comparable: ningún par de binarios emparejó funciones suficientes para juzgar un cambio. Esto NO es «idéntico» — lee abajo el motivo de cada binario.',
    notLocalized:
      'Las compilaciones difieren demasiado para localizar un cambio — es una recompilación, no un parche — así que el proveedor retiene la lista de funciones. Esto NO es «sin cambios».',
    changes: (fns, bins) =>
      `${fns} función(es) cambiada(s) en ${bins} par(es) de binarios, con un delta pequeño y localizado. Una función cambiada es un hecho del código; si alguna es una corrección de seguridad es algo que este diff no puede decir.`,
  },

  stats: { changed: 'Cambiadas', added: 'Añadidas', removed: 'Eliminadas', unmatched: 'Sin emparejar' },
  scope: (p) =>
    `${p.paired} binarios en ambas compilaciones · ${p.identical} idénticos byte a byte · ${p.analyzed} par(es) comparado(s)`,
  unmatchable: (n) =>
    n === 0
      ? 'Ninguna función quedó sin emparejar: cada una se emparejó o se informó como añadida o eliminada.'
      : `${n} función(es) no pudieron emparejarse: su huella estructural la compartían varias funciones de un lado, así que emparejarlas habría sido adivinar. Se cuentan, no se comparan — un cambio dentro de ellas no aparecería aquí.`,
  notAnalyzed: (n) =>
    `${n} par(es) de binarios distintos NO se compararon — se alcanzó el límite por ejecución, así que este diff está incompleto.`,
  walkTruncated:
    'El recorrido de un rootfs se detuvo en su presupuesto de entradas, así que los recuentos de binarios son un mínimo, no el conjunto completo.',
  reasonLabel: 'El proveedor dice:',

  binariesTitle: 'Pares de binarios comparados',
  verdict: {
    identical: 'idéntico',
    patched: 'cambio localizado',
    recompiled: 'recompilado — lista retenida',
    incomparable: 'no comparable',
  },
  colBinary: 'Binario',
  colVerdict: 'Veredicto',
  colMatched: 'Emparejadas',
  colChanged: 'Cambiadas',
  colUnmatched: 'Sin emparejar',

  changedTitle: 'Funciones cambiadas',
  changedSub:
    'Por defecto, primero el menor movimiento estructural: una corrección de seguridad suele ser un cambio pequeño, no una reescritura.',
  colFunction: 'Función',
  colInstrs: 'Δ instrucciones',
  colBlocks: 'Δ bloques',
  colCc: 'Δ complejidad',
  colSize: 'Δ tamaño (bytes)',
  sortBy: (col) => `Ordenar por ${col}`,
};
