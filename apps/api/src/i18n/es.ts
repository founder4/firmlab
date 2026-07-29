/**
 * El catálogo en español de todo lo que compone el servidor y el cliente imprime tal cual: el informe HTML, el
 * borrador de divulgación coordinada, el veredicto de cobertura, la tabla de herramientas y los carriles de red.
 *
 * Está tipado contra el catálogo inglés (`Messages`), de modo que una clave nueva allí es un error de compilación
 * aquí hasta que se traduce. No hay búsqueda en tiempo de ejecución ni respaldo al inglés: un documento a medio
 * traducir sale del edificio pareciendo terminado, y estas frases son precisamente las que no admiten eso.
 *
 * Lo que NO se traduce, nunca: los estados de prueba (`static_confirmed`, `blocked_by_platform`), los tipos de
 * hallazgo, las afirmaciones de operador (`asserted_from_device`), las cadenas de origen y las gravedades son
 * IDENTIFICADORES — viajan por la API, se guardan en SQLite, y quien busque `needs_runtime_reproduction` en el
 * borrador tiene que encontrarlo. Se imprimen literalmente en los dos idiomas; aquí sólo se traduce su glosa
 * legible. Los títulos y los fundamentos de los hallazgos tampoco se traducen: los escribió un proveedor y se
 * guardan junto a la imagen como evidencia, así que se muestran tal cual quedaron registrados.
 *
 * Cuidado con `blocked_by_*`: significa que la pregunta SÍ se hizo y este despliegue no pudo responderla. NO es un
 * resultado negativo, y una redacción que suene a «sin problemas» invertiría la afirmación central del banco. Lo
 * mismo vale para «una lista vacía de hallazgos no significa limpio», «una pista no es un veredicto», «esto prueba
 * el entorno aislado, nunca el dispositivo físico» y las frases sobre las afirmaciones de operador (no llevan
 * estado de prueba y no cuentan para ninguna etapa).
 *
 * La regla que decide qué se traduce y qué no: lo que se guarda con la imagen o con el trabajo queda CONGELADO en
 * el idioma que lo produjo; lo que se recalcula en cada lectura se traduce. Por eso `coverage`, `plan`, `tools`,
 * `captureBackends` y `flags` están aquí — describen esta ejecución del análisis y este despliegue, no el firmware
 * — mientras que el título y el fundamento de un hallazgo se muestran tal cual se registraron.
 */
import type { OperatorAssertion, OperatorClaim } from '@firmlab/core';
import { assertionDay, revisionsOf } from '../operator-findings.js';
import type { Messages, RevisionText } from './en.js';
import { escapeHtml as esc } from './escape.js';

/**
 * La frase única que repiten todas las superficies. Una sola constante en lugar de cuatro paráfrasis, porque
 * cuatro paráfrasis se separan y la más débil acaba siendo la que alguien lee.
 */
const NO_ES_UNA_MEDICION =
  'Esta fila la afirmó un autor con nombre; FirmLab no la midió. No lleva estado de prueba, no cuenta para ninguna etapa del análisis y no es evidencia de que la propiedad se cumpla.';

/** Qué autoriza a concluir cada tipo de afirmación. El código del tipo se imprime literal junto a la glosa. */
const SIGNIFICADO_AFIRMACION: Record<OperatorClaim, string> = {
  asserted_unverified:
    'Una persona declara que esto es cierto. En este banco no se midió nada que lo respalde — trátalo como testimonio y verifícalo antes de actuar sobre ello.',
  asserted_from_device:
    'Una persona informa de haberlo observado en el dispositivo FÍSICO. FirmLab no puede medir eso en absoluto (su peldaño más alto, confirmed_full_system, es emulación), así que es la observación del autor y descansa por completo en su credibilidad y su método.',
  asserted_from_external_evidence:
    'Una persona cita evidencia externa a este banco (aviso del fabricante, hoja de características, informe de terceros). FirmLab no verificó la fuente ni que sea aplicable a esta imagen.',
  disputes_finding:
    'Una persona declara que un hallazgo decidido por el código es incorrecto. Esto NO cambia el estado de prueba de ese hallazgo — ambas filas se mantienen, y quien lee decide.',
};

/**
 * La atribución de una línea. Espejo del `describeAssertion` inglés, no una envoltura suya: la frase se construye
 * entera en español, y el código de la afirmación (`a.claim`) se imprime literal dentro de ella.
 */
function describirAfirmacion(a: OperatorAssertion): string {
  const cuando = assertionDay(a.assertedAt);
  const quien = a.authorKind === 'agent' ? `${a.assertedBy} (agente)` : a.assertedBy;
  const revisiones = revisionsOf(a);
  const modificada =
    a.amendedAt !== undefined
      ? ` Modificada el ${assertionDay(a.amendedAt)}${
          revisiones.length
            ? `; ${
                revisiones.length === 1
                  ? 'se conserva 1 afirmación anterior'
                  : `se conservan ${revisiones.length} afirmaciones anteriores`
              } en el registro.`
            : '; la versión que la modificó no dejó constancia de la afirmación que sustituyó.'
        }`
      : '';
  if (a.status === 'withdrawn') {
    const porQuien = a.withdrawnBy ?? 'desconocido';
    return `RETIRADA por ${porQuien}: ${
      a.withdrawnReason ?? 'sin motivo registrado'
    } — afirmada originalmente por ${quien} el ${cuando}.${modificada}`;
  }
  return `Afirmado por ${quien} el ${cuando} (${a.claim}). ${SIGNIFICADO_AFIRMACION[a.claim]}${modificada}`;
}

export const es: Messages = {
  proofState: {
    meaning: {
      confirmed_full_system: 'Reproducido bajo emulación de sistema completo.',
      confirmed_in_emulation:
        'Reproducido contra una imagen arrancada. Esto prueba el entorno aislado, nunca el dispositivo físico.',
      static_confirmed: 'La propiedad está literalmente presente en los bytes. Afirma el hecho, no que sea explotable.',
      needs_runtime_reproduction:
        'Una pista. Se observó una precondición y no se probó nada — nunca lo presentes como un fallo.',
      blocked_by_platform:
        'La pregunta se hizo y este despliegue no pudo responderla. Esto NO es un resultado negativo.',
      blocked_by_security:
        'Un control — cifrado, arranque seguro — detuvo el análisis. Esto NO es un resultado negativo.',
      false_positive: 'Comprobado y descartado.',
      operator_assertion:
        'Una persona o un agente lo afirmó; FirmLab no lo midió. No lleva estado de prueba y no cuenta para ninguna etapa del análisis.',
    },
    unknown:
      'Un estado de prueba que esta versión no reconoce. Lo registró otra versión de FirmLab y se imprime exactamente como quedó almacenado.',
  },

  report: {
    title: (filename) => `Informe FirmLab — ${filename}`,
    generated: (when) => `generado el ${when}`,
    none: 'Ninguno.',
    identityHeading: 'Identidad',
    identityColumns: { field: 'Campo', value: 'Valor' },
    identityRows: {
      firmwareClass: 'Clase',
      arch: 'Arquitectura',
      filesystems: 'Sistemas de ficheros',
      bootloader: 'Gestor de arranque',
    },
    entropy: (p) =>
      `Entropía media ${p.mean} · ${
        p.signal === 'encrypted'
          ? 'probablemente cifrado'
          : p.signal === 'compressed'
            ? 'probablemente comprimido'
            : 'sin señal de entropía alta'
      } · ${p.signatures} firmas · ${p.segments} segmentos de estructura`,
    secretsHeading: (n) => `Secretos en crudo (${n})`,
    secretsColumns: { severity: 'Gravedad', kind: 'Tipo', offset: 'Desplazamiento', value: 'Valor' },
    sbomHeading: 'SBOM y CVE',
    sbomSummary: (p) =>
      `${p.packages} paquetes · ${p.cves} CVE (Critical ${p.critical}, High ${p.high}, Medium ${p.medium})`,
    sbomColumns: { severity: 'Gravedad', cve: 'CVE', pkg: 'Paquete', version: 'Versión', fixedIn: 'Corregido en' },
    gitleaksHeading: (n) => `Barrido profundo de secretos (${n})`,
    gitleaksColumns: { rule: 'Regla', file: 'Fichero', line: 'Línea', match: 'Coincidencia' },
    triageHeading: (binary) => `Triaje del binario — ${binary}`,
    triageSummary: (p) =>
      `${p.arch} · NX ${p.nx ? 'activo' : 'inactivo'} · canario ${p.canary ? 'activo' : 'inactivo'} · ${
        p.functions
      } funciones · ${p.imports} importaciones · ${p.strings} cadenas`,
    triageColumns: { import: 'Importación', library: 'Biblioteca' },
    footer:
      'Generado por FirmLab — banco de análisis de firmware que se ejecuta en local. Analiza únicamente firmware que estés autorizado a evaluar.',
  },

  ledger: {
    measuredHeading: (n) => `Hallazgos — medidos (${n})`,
    measuredEmpty:
      'No hay ningún hallazgo medido registrado para esta imagen. Eso es un recuento de filas del registro, no un veredicto: una etapa que nunca se ejecutó no aporta nada, y una lista vacía aquí no es evidencia de que la imagen esté limpia. Comprueba qué análisis se ejecutaron antes de leer esto como un resultado negativo.',
    measuredIntro:
      'Cada fila de abajo la decidió el código, y su estado de prueba dice qué se estableció realmente. Este recuento excluye por completo las afirmaciones de operador — se registran más abajo y no son mediciones.',
    cutRule: (p) =>
      `Se muestran ${p.shown} de ${p.total}. Las filas se ordenan por gravedad (la mayor primero, después estado de prueba y título) y se omiten las ${p.omitted} peor clasificadas — el corte sigue esa regla, nunca el orden en que se escribieron las filas. Toda fila impugnada se muestra al margen del límite.`,
    columns: { severity: 'Gravedad', proofState: 'Estado de prueba', source: 'Origen', finding: 'Hallazgo' },
    glossHeading: 'Qué afirman los estados de prueba de arriba',
    glossNote:
      'Los códigos se imprimen exactamente como quedaron registrados — son identificadores, y aquí sólo se explica su significado.',
    unrecordedAuthor: 'un autor sin registrar',
    unrecordedDate: 'una fecha sin registrar',
    agentAuthor: (who) => `${who} (agente)`,
    dispute: (p) =>
      `<div class="dispute"><strong>IMPUGNADO POR UN OPERADOR</strong> — ${esc(p.who)} afirma el ${esc(
        p.when,
      )} que este hallazgo es incorrecto: “${esc(p.title)}”.${
        p.rationale ? ` ${esc(p.rationale)}` : ''
      }<div class="muted">Registrado como afirmación de operador <code>${esc(
        p.assertionId,
      )}</code>, y listado íntegro en la sección de operador. Esto es testimonio sobre una medición, no una medición: el estado de prueba de esta fila sigue siendo <code>${esc(
        p.proofState,
      )}</code>, decidido por el código a partir de la evidencia, y la impugnación ni lo cambia, ni lo rebaja, ni elimina la fila. Ambos se mantienen; quien lee los pondera.</div></div>`,
    cited: 'Citado:',
    revision: (r: RevisionText) =>
      `<li><code>${esc(r.claim)}</code>, vigente del ${esc(r.from)} al ${esc(r.to)}${
        r.title ? ` — “${esc(r.title)}”` : ''
      }${
        r.disputesFindingId ? ` (impugnaba <code>${esc(r.disputesFindingId)}</code>)` : ''
      }<div class="muted">${esc(r.rationale)}</div></li>`,
    historyLost: (when) =>
      `<div class="history"><strong>Modificada el ${esc(
        when,
      )}.</strong> La afirmación que sustituyó no se conservó — esta fila la modificó una versión que sobrescribió a su predecesora. Lo que queda aquí es sólo la afirmación actual.</div>`,
    history: (p) =>
      `<div class="history"><strong>Modificada el ${esc(p.when)}, sustituyendo ${
        p.items.length === 1 ? '1 afirmación anterior' : `${p.items.length} afirmaciones anteriores`
      }.</strong> Una modificación añade; nunca sobrescribe. Lo que el autor declaró antes, y sobre qué base:<ol>${p.items.join(
        '',
      )}</ol></div>`,
    disputeTargetGone: (targetId) =>
      `<div class="basis">Impugna el hallazgo <code>${esc(
        targetId,
      )}</code>, que ya no está en el registro de esta imagen. Volver a ejecutar un proveedor sustituye sus filas por otras con identificadores nuevos, así que una impugnación puede sobrevivir a la fila contra la que se registró: la afirmación se conserva, y aquí no puede mostrarse a qué apuntaba.</div>`,
    disputeTarget: (p) =>
      `<div class="basis">Impugna el hallazgo <code>${esc(p.targetId)}</code> — “${esc(p.title)}” (<code>${esc(
        p.proofState,
      )}</code>, origen <code>${esc(
        p.source,
      )}</code>). Esa fila se mantiene exactamente como la decidió el código; esta afirmación queda registrada junto a ella, no por encima.</div>`,
    badgeAsserted: 'afirmado · no medido',
    badgeWithdrawn: 'retirado · no medido',
    unrecognisedClaim: 'Afirmación no reconocida — léela como una aseveración sin verificar.',
    noAuthorRecord: `Esta fila lleva la procedencia de afirmación de operador pero ningún registro de autoría. Trátala como una afirmación sin atribuir; ${NO_ES_UNA_MEDICION}`,
    assertedSeverity: (severity) => `gravedad afirmada: ${esc(severity)}`,
    statedBasis: 'Base declarada:',
    claim: 'Afirmación:',
    noAssertionStands:
      'Ninguna afirmación se mantiene en pie sobre esta imagen; las retiradas de abajo se conservan como parte del registro.',
    withdrawnHeading: (n) => `Afirmaciones retiradas (${n}) — retractadas, y conservadas`,
    withdrawnIntro:
      'Una retractación forma parte del registro, así que se muestra en lugar de borrarse: «esto estaba mal, y este es el motivo» suele ser la fila más útil que guarda un registro. Una afirmación retirada no cuenta en ningún sitio y no impugna nada.',
    operatorHeading: (n) => `Afirmaciones de operador (${n}) — afirmadas por un autor con nombre, no medidas`,
    notAMeasurement: NO_ES_UNA_MEDICION,
    operatorIntro:
      'Nada de esta sección lo produjo un análisis. Cada bloque es una afirmación registrada por el autor indicado sobre la base que declara, y se mantiene aparte de los hallazgos de arriba justamente por eso: nada de esto lleva estado de prueba, nada cuenta para ninguna etapa del análisis y nada se incluye en el recuento de mediciones. Cuando un autor impugna un hallazgo calculado, ese hallazgo queda anotado donde aparece arriba y su estado de prueba se deja exactamente como lo decidió el código.',
    describeAssertion: describirAfirmacion,
    claimMeaning: SIGNIFICADO_AFIRMACION,
  },

  disclosure: {
    title: 'Divulgación coordinada de vulnerabilidades — borrador',
    draftNotice:
      '**Esto es un BORRADOR para que lo revises y lo envíes tú.** FirmLab no contacta con nadie. Divulga de ' +
      'forma responsable: da al fabricante un plazo razonable para remediar antes de cualquier discusión ' +
      'pública, y evalúa únicamente firmware que estés autorizado a probar.',
    imageLabel: 'Imagen',
    shaLabel: 'SHA-256',
    preparedLabel: 'Preparado',
    deviceHeading: 'Dispositivo / firmware',
    vendorProduct: 'Fabricante / producto (inferido)',
    versionHints: 'Indicios de versión',
    classArch: 'Clase / arquitectura',
    filesystems: 'Sistemas de ficheros',
    contactHeading: 'Con quién contactar',
    contactNoSecurityTxt: 'no se encontró security.txt — prueba con el PSIRT del fabricante o con un CERT/CC.',
    contactNotChecked: 'no comprobado — añádelo a `FIRMLAB_RESEARCH_ALLOWLIST` para descubrir un contacto.',
    contactNone:
      'Todavía no se ha descubierto ningún contacto — ejecuta la vía de investigación (security.txt, RFC 9116) o recurre a un CERT/CC nacional como coordinador.',
    confirmedHeading: (n) => `Problemas confirmados (${n})`,
    confirmedEmpty:
      'Ningún problema confirmado. Nada de lo recogido aquí está probado en los bytes ni reproducido en el entorno aislado — no presentes pistas como confirmaciones.',
    confirmedIntro:
      'Están presentes en los bytes del firmware o se reprodujeron bajo aislamiento. El estado de prueba se indica en cada hallazgo; una reproducción emulada prueba el entorno aislado, no el dispositivo desplegado.',
    leadsHeading: (n) => `Pistas sin verificar (${n}) — alcanzabilidad no verificada`,
    leadsNotice:
      'Esto **no está confirmado**. Requiere reproducción en ejecución sobre el objetivo antes de tener sitio en ' +
      'un informe. Se listan para el triaje del propio fabricante; no las presentes como vulnerabilidades.',
    assertionsHeading: (n) => `Afirmaciones de operador (${n}) — afirmadas por una persona, no medidas aquí`,
    assertionsNotice:
      'FirmLab no midió ninguna de estas. Cada una es una afirmación del autor indicado, sobre la base que ' +
      'declara, y no lleva estado de prueba. Se incluyen porque una observación hecha sobre el dispositivo ' +
      'físico es conocimiento que este banco no puede producir por construcción — pero quien lea esto en el ' +
      'fabricante tiene que poder ver, sin preguntar, qué líneas son mediciones y cuáles testimonio.',
    withdrawnHeading: (n) => `Afirmaciones retiradas (${n}) — retractadas, y conservadas`,
    withdrawnNotice:
      'Cada una de estas se afirmó y después la retiró un autor con nombre, con el motivo registrado. Ninguna es ' +
      'ya una afirmación y ninguna impugna nada; se imprimen en lugar de borrarse para que una afirmación que ' +
      'quizá ya se comunicó no desaparezca en silencio. «Esto estaba mal, y este es el motivo» es la línea más ' +
      'útil que guarda un registro.',
    kevHeading: 'Contexto de explotación conocida (CISA KEV)',
    kevIntro:
      'CVE publicados de componentes presentes en esta imagen que figuran en la lista de vulnerabilidades explotadas conocidas de CISA. Esto eleva la prioridad; **no** confirma que el CVE sea alcanzable en esta compilación.',
    kevItem: (p) => `\`${p.cve}\` — ${p.product} (explotación conocida; alcanzabilidad no verificada)`,
    findingLabels: {
      severity: 'Gravedad',
      proofState: 'Estado de prueba',
      evidence: 'Evidencia',
      rationale: 'Fundamento',
    },
    assertionLabels: {
      severityAsserted: 'Gravedad (afirmada)',
      severityAsAsserted: 'Gravedad (según se afirmó)',
      attribution: 'Atribución',
      referenced: 'Referenciado',
      statedBasis: 'Base declarada',
    },
    dispute: (p) =>
      [
        `> **IMPUGNADO POR UN OPERADOR** — ${p.who} afirma el ${p.when} que este hallazgo es incorrecto: “${
          p.title
        }”.${p.rationale ? ` Base declarada: ${p.rationale}` : ''}`,
        '>',
        `> Esto es testimonio sobre una medición, no una medición: el estado de prueba de arriba sigue siendo \`${p.proofState}\`, decidido por el código a partir de la evidencia, y la impugnación ni lo cambia, ni lo rebaja, ni elimina el hallazgo. Ambos se mantienen — la afirmación aparece íntegra más abajo, en «Afirmaciones de operador».`,
        '',
      ].join('\n'),
    contestedGone: (targetId) =>
      `- **Impugnado:** el hallazgo \`${targetId}\`, que ya no está en el registro de esta imagen. Volver a ejecutar un análisis sustituye sus filas por otras con identificadores nuevos, así que una impugnación puede sobrevivir a la fila contra la que se registró: la afirmación se conserva, y aquí no puede mostrarse a qué apuntaba.`,
    contestedUntilWithdrawn: (p) =>
      `- **Impugnado hasta su retirada:** “${p.title}” (\`${p.proofState}\`). La objeción se ha retractado, así que ese hallazgo no lleva arriba ninguna anotación de impugnación; se mantiene como lo decidió el código, y siempre fue así.`,
    contests: (p) =>
      `- **Impugna:** “${p.title}” (\`${p.proofState}\`), anotado donde aparece arriba. Esa fila se mantiene exactamente como la decidió el código; esta afirmación queda registrada junto a ella, no por encima.`,
    amendedLost: (when) =>
      `- **Modificada el ${when}:** la afirmación que sustituyó no se conservó — esta fila la modificó una versión que sobrescribió a su predecesora. Lo que queda arriba es sólo la afirmación actual; no es necesariamente la original.`,
    amendedSuperseding: (p) =>
      `- **Modificada el ${p.when}, sustituyendo ${
        p.count === 1 ? '1 afirmación anterior' : `${p.count} afirmaciones anteriores`
      }.** Una modificación añade; nunca sobrescribe. Lo que el autor declaró antes, y sobre qué base — sustituido, y citado aquí sólo como historial:`,
    revision: (p) =>
      `  ${p.n}. \`${p.revision.claim}\`, vigente del ${p.revision.from} al ${p.revision.to}${
        p.revision.title ? ` — “${p.revision.title}”` : ''
      }${
        p.revision.disputesFindingId ? ` (impugnaba \`${p.revision.disputesFindingId}\`)` : ''
      }. Base dada en su momento: ${p.revision.rationale}`,
    emailHeading: 'Borrador de correo',
    emailSubject: (target) => `Asunto: Divulgación de seguridad — ${target}`,
    emailGreeting: 'Hola:',
    emailIntro: (p) =>
      `Escribo para comunicar ${p.count} ${p.count === 1 ? 'problema' : 'problemas'} de seguridad que encontré al ` +
      `analizar la imagen de firmware ${p.filename} (SHA-256 ${p.shaPrefix}…).`,
    emailContestedSuffix: ' — IMPUGNADO en mi lado, ver los detalles adjuntos',
    emailContestedNote: (n) =>
      `${
        n === 1
          ? 'Uno de los problemas anteriores está marcado como IMPUGNADO'
          : `${n} de los problemas anteriores están marcados como IMPUGNADOS`
      }: alguien de mi lado ha dejado constancia de que el hallazgo es incorrecto, y su objeción está en los detalles adjuntos, junto a la medición. No he eliminado ni rebajado el hallazgo — tenéis los dos, y agradecería vuestra lectura.`,
    emailClosing:
      'Los detalles técnicos completos van adjuntos. Divulgo esto de forma privada y coordinaré un calendario ' +
      'antes de cualquier discusión pública. Decidme si el contacto correcto es otro.',
    emailThanks: 'Gracias,',
    emailSignature: '[tu nombre]',
    footer:
      'Generado por FirmLab. Sólo un borrador — revísalo antes de enviarlo. Evalúa únicamente firmware que estés autorizado a probar.',
  },

  /**
   * El veredicto de cobertura. Es la frase honesta central del banco: la que impide que una lista de hallazgos
   * vacía se lea como «limpio».
   *
   * Se recalcula en cada lectura a partir de la tabla de etapas, así que habla de LA EJECUCIÓN DEL ANÁLISIS y no
   * del firmware — por eso se traduce, mientras que los títulos de los hallazgos que cuenta, no.
   *
   * Los nombres de los workers (`W3 · Credentials`, `Cross-check · Kernel command line`) llegan como datos y se
   * interpolan literalmente en los dos idiomas: son los identificadores que usan el plan, el escaneo autónomo y la
   * tabla de etapas, y quien compare el veredicto con la tabla de debajo tiene que encontrar las mismas cadenas.
   *
   * Las ramas son deliberadamente distintas: «no se ha ejecutado nada» y «se ejecutó todo y no encontró nada» son
   * conclusiones opuestas que producen la misma lista vacía, y ninguna traducción puede acercarlas.
   */
  coverage: {
    verdict: {
      unexamined: (applicable) =>
        `Todavía no se ha analizado esta imagen — ${applicable} etapa(s) aplicables están sin ejecutar. Una lista de hallazgos vacía aquí significa SIN EXAMINAR, no limpia.`,
      unknownWithFindings: (p) =>
        `No se ha ejecutado ningún escaneo autónomo, así que la cobertura de las ${p.applicable} etapa(s) aplicables es DESCONOCIDA. Los ${p.findingCount} hallazgo(s) que hay vienen de etapas ejecutadas por separado — son resultados reales, pero no son base para dar por limpio el resto.`,
      partialEmpty: (p) =>
        `${p.executed} de ${p.applicable} etapas se ejecutaron y no registraron nada; ${p.missing} nunca se ejecutaron. Cero hallazgos sólo cubre las etapas que se ejecutaron — no es un certificado de limpieza para este firmware.`,
      allRanEmpty: (applicable) =>
        `Las ${applicable} etapas aplicables se ejecutaron y no registraron nada. Eso es un negativo real para lo que este despliegue puede comprobar de forma estática — no es prueba de que el firmware sea seguro.`,
      partialWithFindings: (p) =>
        `${p.findingCount} hallazgo(s) de ${p.executed} de ${p.applicable} etapas; ${p.missing} nunca se ejecutaron, así que el panorama está incompleto.`,
      complete: (p) => `${p.findingCount} hallazgo(s) en las ${p.applicable} etapas aplicables.`,
    },
    notCovered: (p) => `Sin cubrir: ${p.workers.join(', ')}${p.more > 0 ? `, +${p.more} más` : ''}.`,
    degraded: (p) =>
      `${p.count} etapa(s) se ejecutaron DEGRADADAS y cubren menos de lo que su nombre sugiere: ${p.workers.join(
        ', ',
      )}${p.more > 0 ? `, +${p.more} más` : ''}.`,
    assertions: (n) =>
      [
        `Aparte, hay ${n} afirmación(es) de operador registradas en esta imagen — declaraciones de un autor con`,
        'nombre, no mediciones. Quedan fuera del recuento anterior y no cubren ninguna etapa.',
      ].join(' '),
    scheduledFromLead: 'planificada sobre la marcha a partir de una pista',
  },

  /**
   * La columna «por qué esta etapa» del plan por clase. Se recalcula desde `specsForClass` en cada petición y habla
   * DEL PLAN, nunca del firmware, así que se traduce — mientras el veredicto de cobertura estuvo traducido y esta
   * columna no, un lector en español leía una frase honesta en español con una columna en inglés al lado, y
   * justamente en el panel que existe para leerse con cuidado.
   *
   * Los nombres de los workers no están aquí: son identificadores y se imprimen literalmente en los dos idiomas.
   * Tampoco se traducen las rutas, los indicadores ni los nombres de biblioteca que aparecen dentro de estas
   * frases — `init=/bin/sh`, `/dev/kmem`, `/chosen bootargs`, `os.execute/io.popen` son lo que se busca en el
   * sistema de ficheros o en el registro, no palabras.
   */
  plan: {
    reason: {
      extract: 'recuperar el rootfs (extracción recursiva FIT→UBI→SquashFS cuando el contenedor lo requiere)',
      credentials: 'credenciales débiles o vacías, shells de root, material de claves',
      auxSecrets:
        'claves privadas embebidas en particiones hermanas (fuera del rootfs) que la auditoría del rootfs nunca ve',
      sbom: 'componentes → CVE conocidos (la superficie n-day)',
      componentFingerprint:
        'binarios empaquetados (pppd, openssl) → CVE que un SBOM basado sólo en manifiestos no alcanza',
      kernelPosture:
        'el kernel bajo el espacio de usuario: antigüedad de la versión, /dev/kmem, firma de módulos, KASLR/RWX (tres estados, honesto)',
      serviceEnumeration: 'demonios de red que arrancan con el sistema = superficie de ataque',
      certificates: 'postura de los certificados X.509 embebidos',
      certificatesRaw: 'postura de los certificados X.509 embebidos (lee la imagen en bruto — no necesita rootfs)',
      componentMap: 'ELF del rootfs → grafo de dependencias',
      ubootEnv: 'postura de arranque (init=/bin/sh, autoboot interrumpible, consola)',
      ubootEnvRaw: 'postura de arranque (init=/bin/sh, autoboot interrumpible, arranque por red, consola)',
      deviceTree: 'identidad de placa/SoC, mapa de flash declarado, /chosen bootargs, UART de depuración habilitada',
      bootCmdlineCrosscheck:
        'el árbol y el entorno de U-Boot declaran cada uno la suya — ¿coinciden, y qué línea pasa realmente la placa?',
      fccId: 'identificadores FCC → expedientes públicos',
      nvram:
        'almacén clave-valor en la flash de la imagen en bruto — credenciales y claves wifi que ningún barrido del rootfs alcanza',
      webTaint: 'parámetro web → uci → sumideros os.execute/io.popen (la clase del RCE como root de Tor en GL.iNet)',
      binaryVulnSweep:
        'ELF del rootfs → candidatos a desbordamiento de pila por copia sin límite y sin canario (los pwnables de DVRF)',
      updatePath: 'si la imagen va firmada, si el actualizador verifica algo, y si un downgrade está acotado',
      chipsec: 'decodificación sin conexión de los volúmenes de firmware + postura de Secure Boot / NVRAM',
      fwhunt:
        'reglas de patrón de código de FwHunt de upstream → familias conocidas de implantes y módulos vulnerables',
      rtos: 'tabla de vectores + mapa de memoria + detección de RTOS y de rutinas de decodificación',
      esp: 'tabla de particiones + almacén de claves NVS (¡claves de firma!) + postura de Flash-Enc/Secure-Boot',
      encrypted:
        'identificar cifrador/modo/IV y nombrar la vía de recuperación de la clave (veredicto honesto, nunca un vacío silencioso)',
    },
  },

  /**
   * La tabla de Capacidades: lo que desbloquea cada herramienta externa, y el marcador de versión de una
   * herramienta detectada sólo por presencia.
   *
   * Se sondea en cada petición contra los binarios que hay realmente en esta máquina, así que es texto de interfaz
   * sobre ESTE DESPLIEGUE y se traduce. Los identificadores de herramienta y los nombres de binario que aparecen al
   * lado (`binwalk`, `qemu-system-mips`, `analyzeHeadless`) son lo que se teclearía en un intérprete de comandos:
   * son identificadores, indexan este registro y se imprimen literalmente en los dos idiomas.
   *
   * Ninguna de estas frases describe el firmware. Una herramienta ausente es una RESPUESTA ausente, no un problema
   * ausente: la pregunta no llegó a hacerse.
   */
  tools: {
    unlocks: {
      binwalk: 'Extracción por firmas con reconocimiento de formato',
      unsquashfs: 'Extracción de SquashFS',
      sasquatch: 'Extracción de SquashFS de fabricante',
      jefferson: 'Extracción de JFFS2',
      lzop: 'Descompresión de payloads lzop',
      ubireader_extract_files: 'Extracción de UBIFS',
      cpio: 'Extracción de CPIO/initramfs',
      radare2: 'Triaje de binarios y desensamblado',
      analyzeHeadless: 'Decompilación sin interfaz con Ghidra',
      syft: 'Generación del SBOM',
      grype: 'Correlación de CVE (N-day)',
      gitleaks: 'Escaneo profundo de secretos',
      'qemu-mipsel-static': 'Emulación en modo usuario de MIPSel',
      'qemu-arm-static': 'Emulación en modo usuario de ARM',
      'qemu-aarch64-static': 'Emulación en modo usuario de ARM64',
      'qemu-system-mips': 'Arranque de sistema completo de MIPS big-endian',
      'qemu-system-mipsel': 'Arranque de sistema completo de MIPS',
      'qemu-system-arm': 'Arranque de sistema completo de ARM',
      'mkfs.ext2': 'Ensamblado de la imagen de disco en bruto que necesita un arranque de sistema completo',
      renode: 'Emulación de RTOS / Cortex-M',
      chipsec: 'Análisis de firmware UEFI/BIOS (decodificación sin conexión + escaneo de IOC)',
      angr: 'Alcanzabilidad simbólica (¿está un sumidero peligroso en un camino vivo?)',
      'gdb-multiarch': 'Reproducción dinámica de un candidato de seguridad de memoria (¿llega a fallar de verdad?)',
      fwhunt: 'Detección de implantes UEFI con reglas reales de patrón de código de FwHunt',
      // El motor, nunca las reglas: FirmLab no publica firmas propias, así que la frase promete un escaneo y dice
      // de quién es el corpus que ejecutaría. Que la herramienta falte es una respuesta ausente, no un problema
      // ausente — y que el corpus falte es una tercera cosa distinta, que el proveedor declara aparte.
      yara: 'Escaneo del rootfs por reglas en busca de implantes, webshells y puertas traseras conocidos, con un corpus que aportas tú',
    },
    /** Ni es una versión ni debe confundirse con una: dice que el binario está y que no se le preguntó cuál es. */
    installed: 'instalado',
  },

  /**
   * La tabla de backends de captura: qué permite ADQUIRIR cada uno cuando está disponible.
   *
   * Se sondea en cada petición contra el hardware, los privilegios y lo que el operador ha declarado, así que es
   * texto de interfaz sobre este despliegue y se traduce. Los identificadores de backend (`on-path-spoof`,
   * `network-proxy`), los transportes y las variables de entorno se imprimen literalmente.
   *
   * Aquí quedarse corto en la traducción cuesta algo fuera del navegador: dos de estas frases describen tocar la
   * red de otra persona y una describe descifrar su tráfico. Donde el inglés dice lo que se le hace a un
   * dispositivo, el español lo dice igual — esta línea se lee ANTES de armar nada.
   */
  captureBackends: {
    unlocks: {
      'network-proxy':
        'Interceptar una OTA por HTTP (o por HTTPS cuando el dispositivo no fija ni valida el certificado) y extraer el blob',
      'on-path-spoof':
        'Ponerse en el camino de un único objetivo sin tocar la configuración del router, mediante envenenamiento ARP/DNS',
      'on-path-gateway':
        'La captura más limpia: el objetivo enruta a través de FirmLab (ruta por defecto / espejo SPAN), sin suplantar nada',
      ble: 'Esnifar una OTA/DFU por BLE (Nordic DFU y similares) y reensamblar el firmware',
      zigbee: 'Capturar el clúster estándar de actualización OTA de Zigbee (0x0019)',
      'usb-serial': 'Volcado desde el propio dispositivo por UART/serie cuando no hay ninguna OTA que interceptar',
    },
  },

  /**
   * Los carriles: qué enciende cada interruptor y qué sale de esta máquina cuando está encendido.
   *
   * Se resuelven contra el entorno y las anulaciones guardadas en cada lectura, así que son texto de interfaz sobre
   * el despliegue. También son el texto donde quedarse corto en la traducción se queda corto sobre una consecuencia
   * real: la línea de salida es lo que lee un operador ANTES de accionar un interruptor que envía datos a un
   * tercero, así que cada una nombra el destino y el tipo de dato, y ninguna lo suaviza.
   *
   * Los nombres de las variables (`FIRMLAB_RESEARCH`, `FIRMLAB_CAPTURE_GATEWAY`) indexan este registro y se
   * imprimen literalmente: son variables de entorno, y quien busque una en un fichero de compose tiene que
   * encontrarla.
   */
  flags: {
    FIRMLAB_AGENT: {
      label: 'Copiloto y agente de IA',
      effect:
        'Permite ejecutar el copiloto y el esqueleto del agente. La mecánica sigue siendo determinista — el modelo sólo toma las decisiones de juicio, dentro de un gobernador que corta por pasos, tokens, dólares o tiempo de reloj.',
      egress:
        'Los prompts construidos a partir de los hallazgos y de la identidad van al proveedor de LLM configurado. Necesita una clave de API; sin clave, la capa se queda apagada aunque esto esté encendido.',
    },
    FIRMLAB_RESEARCH: {
      label: 'Inteligencia externa',
      effect:
        'Correlaciona el SBOM y los componentes identificados dentro de los binarios empaquetados contra avisos de seguridad publicados, y busca contactos de divulgación del fabricante.',
      egress:
        'Los nombres y las versiones de los componentes van a api.osv.dev y a services.nvd.nist.gov; el catálogo KEV de CISA se descarga y se cruza en local. Nunca bytes del firmware, ni secretos, ni claves. El registro de salida declara un techo antes de cada ejecución y lo concilia al terminar.',
    },
    FIRMLAB_HASH_LOOKUP: {
      label: 'Consulta en línea de hashes de contraseña',
      effect:
        'Envía a servicios públicos de búsqueda inversa los resúmenes de contraseña SIN SAL recuperados del firmware. Los hashes crypt con sal se descartan y no se envían nunca; un texto en claro recuperado se queda en local y enmascarado.',
      egress:
        'Hashes de contraseña de TU firmware llegan a un tercero. Es un paso mayor que enviar el nombre de un componente, y por eso tiene su propio interruptor — si la imagen es material de un cliente o de un encargo, trátalo como una divulgación.',
    },
    FIRMLAB_CAPTURE: {
      label: 'Carril de captura',
      effect:
        'Habilita el descubrimiento en la LAN y los backends de interceptación que se usan para obtener firmware de un dispositivo vivo. Nada toca el cable hasta que se arma una acción concreta sobre un único objetivo y con tiempo acotado.',
      egress: 'El descubrimiento barre la subred local (nmap / arp-scan / mDNS). No sale nada relativo a tu firmware.',
    },
    FIRMLAB_CAPTURE_GATEWAY: {
      label: 'Declarar posición en el camino',
      effect:
        'Tu afirmación de que FirmLab YA está en el camino del objetivo — es su ruta por defecto, o le llega un espejo de puerto. No lanza nada; es lo que hace innecesario un envenenamiento ARP, de modo que una sesión de captura se posiciona como `gateway`. Decláralo en falso y la sesión dará el objetivo por alcanzado y no capturará nada.',
      egress: 'Nada por sí solo. Cambia cómo se posiciona una sesión de captura, no lo que envía.',
    },
  },
};
