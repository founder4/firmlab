import type { Messages } from '../en';

/** credmatch — español. Tipado contra el catálogo inglés. */
export const credmatch: Messages['credmatch'] = {
  title: 'Cotejo de credenciales',
  sub: 'Cruza los hashes de contraseña que esta imagen almacena contra las cadenas imprimibles que la misma imagen incluye —un cruce, no un descifrado—. El firmware a menudo compila el texto plano en un binario, un script de aprovisionamiento o una línea de configuración, así que el conjunto de candidatos son las propias cadenas de la imagen y un hash por candidato lo resuelve. Sólo encuentra una contraseña cuando el firmware la lleva escrita en algún sitio.',
  run: 'Ejecutar cotejo de credenciales',
  rerun: 'Reejecutar',
  running: 'Cruzando…',
  notRun:
    'No se ha ejecutado ningún cotejo de credenciales para esta imagen, así que sus hashes almacenados no se han probado contra sus propias cadenas. Esto es «no se ha ejecutado», no un resultado limpio.',
  runLabel: 'Ejecuciones de cotejo de credenciales',

  prereqHeading: 'Aún no se puede ejecutar',
  prereqHint:
    'Esto lee los hashes almacenados y las cadenas candidatas de un rootfs extraído. La frase de arriba es el propio relato de la extracción sobre por qué no hay uno disponible —un prerrequisito, no un resultado sobre el firmware.',

  runFailed: 'El cotejo de credenciales no llegó a ejecutarse.',
  runFailedHeading: 'La ejecución falló',
  runFailedHint:
    'El trabajo arrancó y no terminó. Es un fallo de este banco —una herramienta, un tiempo de espera, un disco— y NO una propiedad del firmware: no se estableció nada sobre sus credenciales. Lee el registro de la ejecución y vuelve a intentarlo.',

  blockedHeading: 'Preguntado, y no se pudo responder',
  blockedCaveat:
    'El cruce no produjo ninguna respuesta, registrado aquí para que la ausencia de hallazgos de credenciales se lea como una pregunta que nunca se llegó a hacer del todo. NO es «ninguna contraseña recuperable»: no se calculó ningún hash.',
  persistedUnavailable:
    'Este resultado almacenado es anterior a los campos que esta vista necesita para explicar su cobertura. Aquí permanece como no disponible en vez de interpretarse como un análisis vacío o limpio.',

  fact: {
    recovered: 'Recuperadas',
    targets: 'Hashes almacenados',
    tested: 'Candidatos probados',
    distinct: 'Candidatos distintos',
    dropped: 'Descartados por el tope',
    strings: 'Cadenas cosechadas',
    files: 'Ficheros leídos',
  },
  coverageHeading: 'Cobertura',
  opensslMissing:
    'openssl no está instalado en este despliegue, así que sólo se pudieron probar los hashes crypt DES tradicionales. Cualquier cuenta almacenada con md5crypt, sha-crypt, bcrypt o yescrypt se registró como bloqueada, no como un hash que resistió.',
  opensslFailure: (flag: string, reason: string) =>
    `El \`openssl passwd ${flag}\` de esta compilación no reprodujo una respuesta conocida (${reason}), así que los hashes que lo necesitan no se probaron.`,

  col: {
    account: 'Cuenta',
    scheme: 'Esquema',
    outcome: 'Resultado',
    detail: 'Qué estableció esta ejecución',
  },
  outcome: {
    recovered: 'recuperada',
    'not-recovered': 'no recuperada',
    blocked: 'no probada',
  },
  locked: 'bloqueada',
  uidRoot: 'UID 0',
  recoveredLabel: 'Contraseña',
  recoveredDetail: (tested: number) =>
    `Aplicar el hash a esta cadena con la sal almacenada junto a la cuenta reproduce el hash almacenado byte a byte (${tested} candidato${tested === 1 ? '' : 's'} probado${tested === 1 ? '' : 's'}). No es una conjetura ni proviene de un diccionario.`,
  provenance: (derivation: string, file: string, offset: number) => {
    const where = `${file} @ 0x${offset.toString(16)}`;
    switch (derivation) {
      case 'assignment-value':
        return `del valor de una línea clave=valor en ${where}`;
      case 'quoted':
        return `de una secuencia entrecomillada dentro de ${where}`;
      case 'token':
        return `de un token separado por espacios en ${where}`;
      default:
        return `de una cadena incluida en ${where}`;
    }
  },
  recoveredCeiling:
    'Lo que se confirma es una propiedad de los bytes: este texto plano corresponde a ese hash almacenado. NO es una afirmación de que la cuenta esté habilitada, de que algún servicio de login sea alcanzable, ni de que una unidad física siga ejecutando este firmware.',
  notRecoveredDetail: (tested: number) =>
    `${tested} candidato${tested === 1 ? '' : 's'} extraído${tested === 1 ? '' : 's'} de las propias cadenas de esta imagen no reprodujo este hash.`,
  emptyNotClean:
    'Un hash no recuperado es un NEGATIVO ACOTADO y nada más: el conjunto de candidatos son las cadenas que este firmware incluye, así que una contraseña que no esté escrita en ningún sitio de la imagen no puede encontrarse por esta vía. NO significa que la contraseña sea fuerte, desconocida ni ajena a una lista de valores por defecto del fabricante —no se buscó ningún espacio de claves ni se consultó ningún diccionario.',

  proof: {
    confirmed: 'el texto plano recuperado se confirma en',
    blocked: 'un esquema que este despliegue no puede calcular se mantiene en',
    negative: 'un negativo acotado se registra en',
  },
  ledgerHint:
    'Cada fila de aquí también aterriza en el registro de hallazgos bajo la fuente `credmatch`; este panel muestra la cobertura propia del cruce, no una segunda copia de ese registro.',
};
