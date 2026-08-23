/** Structured, provider-aware rendering for persisted deep-analysis results. No raw JSON is exposed here: each
 * provider gets the fields an analyst can actually use, with large graphs redirected to their dedicated view. */
import type { AnalysisKind } from '../api';
import { useMessages } from '../i18n';

type RecordValue = Record<string, unknown>;

function record(value: unknown): RecordValue | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as RecordValue) : null;
}

function records(value: unknown): RecordValue[] {
  return Array.isArray(value) ? value.map(record).filter((item): item is RecordValue => item !== null) : [];
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function number(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function formatNumber(value: unknown): string {
  const n = number(value);
  return n === null ? '—' : n.toLocaleString();
}

function formatHex(value: unknown): string {
  const n = number(value);
  return n === null ? '—' : `0x${n.toString(16).padStart(8, '0')}`;
}

function safeUrl(value: unknown): string | null {
  const url = text(value);
  return url && /^https?:\/\//i.test(url) ? url : null;
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }): JSX.Element {
  return (
    <section className="deep-data-section">
      <h4>{title}</h4>
      {children}
    </section>
  );
}

function Metrics({ items }: { items: { label: string; value: React.ReactNode }[] }): JSX.Element {
  return (
    <dl className="deep-data-metrics">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function StringList({ items, empty }: { items: string[]; empty: string }): JSX.Element {
  if (items.length === 0) return <p className="deep-data-empty">{empty}</p>;
  return (
    <ul className="deep-data-list">
      {items.map((item, index) => (
        <li key={`${item}-${index}`} className="mono">
          {item}
        </li>
      ))}
    </ul>
  );
}

function Findings({ result }: { result: RecordValue }): JSX.Element | null {
  const t = useMessages().shell.deep.details;
  const findings = records(result.findings);
  if (findings.length === 0) return null;
  return (
    <DetailSection title={t.findings}>
      <div className="deep-data-cards">
        {findings.map((finding, index) => (
          <div className="deep-data-card" key={`${text(finding.kind) ?? 'finding'}-${index}`}>
            <strong>{text(finding.title) ?? text(finding.kind) ?? `#${index + 1}`}</strong>
            <div className="deep-data-tags">
              {text(finding.severity) && <span className="badge">{text(finding.severity)}</span>}
              {text(finding.proofState) && (
                <span>
                  {t.proof}: <span className="mono">{text(finding.proofState)}</span>
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </DetailSection>
  );
}

function UbootDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const vars = record(result.vars) ?? {};
  const environment = Object.entries(vars).sort(([a], [b]) => a.localeCompare(b));
  const script = record(result.bootScript);
  const variants = records(script?.variants);
  return (
    <>
      <DetailSection title={t.environment}>
        <Metrics
          items={[
            { label: t.environment, value: result.found === true ? t.yes : t.no },
            { label: t.variables, value: formatNumber(result.varCount) },
          ]}
        />
        {environment.length > 0 ? (
          <div className="deep-data-table-wrap">
            <table className="deep-data-table">
              <thead>
                <tr>
                  <th>{t.variable}</th>
                  <th>{t.value}</th>
                </tr>
              </thead>
              <tbody>
                {environment.map(([name, value]) => (
                  <tr key={name}>
                    <th className="mono">{name}</th>
                    <td className="mono deep-data-value">{String(value ?? '')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="deep-data-empty">{t.noItems}</p>
        )}
      </DetailSection>
      {script && (
        <DetailSection title={t.bootScript}>
          <Metrics items={[{ label: t.roots, value: strings(script.roots).join(' · ') || t.noItems }]} />
          {variants.length > 0 && (
            <div className="deep-data-cards">
              {variants.map((variant, index) => (
                <div className="deep-data-card" key={`${text(variant.value) ?? ''}-${index}`}>
                  <code>{text(variant.value) ?? '—'}</code>
                  <span>
                    {t.via}: <span className="mono">{strings(variant.via).join(' → ') || '—'}</span>
                  </span>
                  {variant.conditional === true && <span className="badge run-blocked">{t.conditional}</span>}
                </div>
              ))}
            </div>
          )}
        </DetailSection>
      )}
    </>
  );
}

function DeviceTreeDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const blobs = records(result.blobs);
  const rejected = records(result.rejected);
  return (
    <>
      <DetailSection title={t.searched}>
        <StringList items={strings(result.searched)} empty={t.notRecorded} />
      </DetailSection>
      {blobs.length > 0 && (
        <DetailSection title={t.trees}>
          <div className="deep-data-cards">
            {blobs.map((blob, index) => {
              const partitions = records(blob.partitions);
              const peripherals = records(blob.peripherals);
              return (
                <div className="deep-data-card" key={`${text(blob.origin) ?? 'dt'}-${index}`}>
                  <Metrics
                    items={[
                      { label: t.origin, value: <code>{text(blob.origin) ?? '—'}</code> },
                      { label: t.model, value: text(blob.model) ?? '—' },
                      { label: t.compatible, value: strings(blob.compatible).join(' · ') || '—' },
                      { label: t.bootargs, value: <code>{text(blob.bootargs) ?? '—'}</code> },
                    ]}
                  />
                  {partitions.length > 0 && (
                    <StringList
                      items={partitions.map(
                        (p) =>
                          `${text(p.label) ?? text(p.nodeName) ?? '?'} · ${formatHex(p.offset)} · ${formatNumber(p.size)} B`,
                      )}
                      empty={t.noItems}
                    />
                  )}
                  {peripherals.length > 0 && (
                    <StringList
                      items={peripherals.map(
                        (p) => `${text(p.kind) ?? '?'} · ${text(p.path) ?? '?'} · ${text(p.status) ?? '?'}`,
                      )}
                      empty={t.noItems}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </DetailSection>
      )}
      {rejected.length > 0 && (
        <DetailSection title={t.rejected}>
          <StringList
            items={rejected.map((item) => `${text(item.origin) ?? '?'} — ${text(item.reason) ?? '?'}`)}
            empty={t.noItems}
          />
        </DetailSection>
      )}
    </>
  );
}

function KernelDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const age = record(result.age);
  const modules = record(result.modules);
  const answers = records(result.answers);
  return (
    <>
      <DetailSection title={t.kernelSummary}>
        <Metrics
          items={[
            { label: t.version, value: <code>{text(result.version) ?? '—'}</code> },
            { label: t.age, value: age ? t.years(number(age.years) ?? 0) : '—' },
            {
              label: t.modules,
              value: modules
                ? `${formatNumber(modules.inspectedCount)} / ${formatNumber(modules.moduleCount)} · ${formatNumber(modules.signedCount)} ${t.signed}`
                : '—',
            },
          ]}
        />
      </DetailSection>
      <DetailSection title={t.controls}>
        {answers.length > 0 ? (
          <div className="deep-data-table-wrap">
            <table className="deep-data-table">
              <thead>
                <tr>
                  <th>{t.option}</th>
                  <th>{t.verdict}</th>
                  <th>{t.evidence}</th>
                </tr>
              </thead>
              <tbody>
                {answers.map((answer, index) => (
                  <tr key={`${text(answer.id) ?? 'answer'}-${index}`}>
                    <th>
                      <span className="mono">{text(answer.option) ?? text(answer.id) ?? '?'}</span>
                      <small>{text(answer.question)}</small>
                    </th>
                    <td>
                      <span
                        className={`badge ${answer.verdict === 'unknown' ? 'run-blocked' : answer.bad === true ? 'run-failed' : 'run-proven'}`}
                      >
                        {text(answer.verdict) ?? t.unknown}
                      </span>
                    </td>
                    <td>{text(answer.detail) ?? text(answer.reason) ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="deep-data-empty">{t.notRecorded}</p>
        )}
      </DetailSection>
    </>
  );
}

function CoverageDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const scan = record(result.scan);
  return (
    <DetailSection title={t.coverage}>
      <Metrics
        items={[
          {
            label: t.files,
            value: scan
              ? `${formatNumber(scan.filesScanned)} / ${formatNumber(scan.filesConsidered)}`
              : formatNumber(result.filesScanned),
          },
          { label: t.bytes, value: scan ? formatNumber(scan.bytesScanned) : '—' },
        ]}
      />
    </DetailSection>
  );
}

function CertificateDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const certs = records(result.certs);
  return (
    <>
      <CoverageDetails result={result} />
      <DetailSection title={t.certificates}>
        {certs.length > 0 ? (
          <div className="deep-data-cards">
            {certs.map((cert, index) => (
              <div className="deep-data-card" key={`${text(cert.subject) ?? 'cert'}-${index}`}>
                <Metrics
                  items={[
                    { label: t.subject, value: <code>{text(cert.subject) ?? '—'}</code> },
                    { label: t.issuer, value: <code>{text(cert.issuer) ?? '—'}</code> },
                    { label: t.validity, value: `${text(cert.validFrom) ?? '?'} → ${text(cert.validTo) ?? '?'}` },
                    { label: t.key, value: `${text(cert.keyType) ?? '?'} ${t.bits(number(cert.keyBits) ?? 0)}` },
                    { label: t.selfSigned, value: cert.selfSigned === true ? t.yes : t.no },
                  ]}
                />
              </div>
            ))}
          </div>
        ) : (
          <p className="deep-data-empty">{t.noItems}</p>
        )}
      </DetailSection>
    </>
  );
}

function ServiceDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const services = records(result.services);
  return (
    <DetailSection title={t.services}>
      {services.length > 0 ? (
        <div className="deep-data-table-wrap">
          <table className="deep-data-table">
            <thead>
              <tr>
                <th>{t.name}</th>
                <th>{t.binary}</th>
                <th>{t.source}</th>
                <th>{t.network}</th>
                <th>{t.autostart}</th>
                <th>{t.port}</th>
              </tr>
            </thead>
            <tbody>
              {services.map((service, index) => (
                <tr key={`${text(service.name) ?? 'service'}-${index}`}>
                  <th>{text(service.name) ?? '?'}</th>
                  <td>
                    <code>{text(service.binary) ?? '—'}</code>
                  </td>
                  <td>
                    <code>{text(service.source) ?? '—'}</code>
                  </td>
                  <td>{service.network === true ? t.yes : t.no}</td>
                  <td>{service.autostart === true ? t.yes : t.no}</td>
                  <td>{formatNumber(service.port)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="deep-data-empty">{t.noItems}</p>
      )}
    </DetailSection>
  );
}

function UpdateDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const integrity = record(result.imageIntegrity);
  const items = records(integrity?.items);
  const updaters = records(result.updaters);
  const rollback = record(result.rollback);
  return (
    <>
      <DetailSection title={t.updateCoverage}>
        <Metrics
          items={[
            { label: t.container, value: text(integrity?.container) ?? '—' },
            { label: t.files, value: formatNumber(result.filesWalked) },
            { label: t.binaries, value: formatNumber(result.elfsExamined) },
            { label: t.rollback, value: text(rollback?.state) ?? t.unknown },
          ]}
        />
      </DetailSection>
      <DetailSection title={t.integrity}>
        <StringList
          items={items.map((item) => `${text(item.kind) ?? '?'} — ${text(item.detail) ?? '?'}`)}
          empty={t.noItems}
        />
      </DetailSection>
      <DetailSection title={t.updaters}>
        {updaters.length > 0 ? (
          <div className="deep-data-cards">
            {updaters.map((updater, index) => (
              <div className="deep-data-card" key={`${text(updater.path) ?? 'updater'}-${index}`}>
                <strong>
                  <code>{text(updater.path) ?? '?'}</code>
                </strong>
                <span>{text(updater.why) ?? '—'}</span>
                <span>
                  {t.digests}: <code>{strings(updater.digestFns).join(' · ') || t.noItems}</code>
                </span>
                <span>
                  {t.signatureChecks}:{' '}
                  <code>
                    {[...strings(updater.signatureFns), ...strings(updater.verifyCommands)].join(' · ') || t.noItems}
                  </code>
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="deep-data-empty">{t.noItems}</p>
        )}
      </DetailSection>
      {rollback && (
        <DetailSection title={t.rollback}>
          <p className="deep-data-copy">{text(rollback.evidence) ?? t.notRecorded}</p>
        </DetailSection>
      )}
    </>
  );
}

function ComponentDetails({ imageId, result }: { imageId: string; result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const graph = record(result.graph);
  const edges = records(graph?.edges);
  const unresolved = strings(graph?.unresolved);
  const orphaned = strings(result.orphanBinaries);
  const shown = orphaned.slice(0, 20);
  return (
    <>
      <DetailSection title={t.componentSummary}>
        <Metrics
          items={[
            { label: t.binaries, value: `${formatNumber(result.binaryCount)} / ${formatNumber(result.elfCount)}` },
            { label: t.dependencies, value: edges.length.toLocaleString() },
            { label: t.unresolved, value: unresolved.length.toLocaleString() },
            { label: t.symlinks, value: formatNumber(result.symlinkCount) },
            { label: t.orphaned, value: orphaned.length.toLocaleString() },
          ]}
        />
        {unresolved.length > 0 && <StringList items={unresolved} empty={t.noItems} />}
        {shown.length > 0 && <StringList items={shown} empty={t.noItems} />}
        {orphaned.length > shown.length && (
          <p className="deep-data-empty">{t.countMore(shown.length, orphaned.length)}</p>
        )}
        <a className="deep-data-link" href={`#/image/${imageId}/compmap`}>
          {t.openComponentMap} →
        </a>
      </DetailSection>
    </>
  );
}

function RtosDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const vector = record(result.vectorTable);
  const memory = record(result.memoryMap);
  return (
    <DetailSection title={t.rtosSummary}>
      <Metrics
        items={[
          { label: t.cortexM, value: result.isCortexM === true ? t.yes : t.no },
          { label: t.rtosKernel, value: text(result.rtosKernel) ?? t.notRecorded },
          { label: t.initialSp, value: formatHex(vector?.initialSP) },
          { label: t.resetHandler, value: formatHex(vector?.resetHandler) },
          { label: t.flashBase, value: formatHex(memory?.flashBase) },
          { label: t.ramBase, value: formatHex(memory?.ramBase) },
        ]}
      />
    </DetailSection>
  );
}

function FccDetails({ result }: { result: RecordValue }): JSX.Element {
  const t = useMessages().shell.deep.details;
  const links = records(result.links);
  return (
    <DetailSection title={t.fccIds}>
      {links.length > 0 ? (
        <div className="deep-data-cards">
          {links.map((link, index) => {
            const filing = safeUrl(link.fccReport);
            const mirror = safeUrl(link.fccid);
            return (
              <div className="deep-data-card" key={`${text(link.id) ?? 'fcc'}-${index}`}>
                <strong className="mono">{text(link.id) ?? '?'}</strong>
                <div className="deep-data-tags">
                  {filing && (
                    <a href={filing} target="_blank" rel="noreferrer">
                      {t.filing}
                    </a>
                  )}
                  {mirror && (
                    <a href={mirror} target="_blank" rel="noreferrer">
                      {t.mirror}
                    </a>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="deep-data-empty">{t.noItems}</p>
      )}
    </DetailSection>
  );
}

export function DeepAnalysisDetails({
  imageId,
  kind,
  value,
}: { imageId: string; kind: AnalysisKind; value: unknown }): JSX.Element | null {
  const result = record(value);
  if (!result) return null;
  let provider: JSX.Element | null = null;
  switch (kind) {
    case 'uboot':
      provider = <UbootDetails result={result} />;
      break;
    case 'devicetree':
      provider = <DeviceTreeDetails result={result} />;
      break;
    case 'kernel':
      provider = <KernelDetails result={result} />;
      break;
    case 'fsaudit':
      provider = <CoverageDetails result={result} />;
      break;
    case 'certs':
      provider = <CertificateDetails result={result} />;
      break;
    case 'services':
      provider = <ServiceDetails result={result} />;
      break;
    case 'updatepath':
      provider = <UpdateDetails result={result} />;
      break;
    case 'compmap':
      provider = <ComponentDetails imageId={imageId} result={result} />;
      break;
    case 'rtos':
      provider = <RtosDetails result={result} />;
      break;
    case 'fcc':
      provider = <FccDetails result={result} />;
      break;
  }
  return (
    <div className="deep-data">
      {provider}
      <Findings result={result} />
    </div>
  );
}
