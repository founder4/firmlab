/**
 * The index that makes every analysis section reachable.
 *
 * The app had three places that navigate to a section — the step timeline's eight steps, one link to `operator`, one
 * to `dossier` — against twenty sections. Ten were reachable only by typing a URL, and the shell's own hint told the
 * reader to navigate from a timeline that cannot reach them.
 *
 * Every section is listed for every image. Which ones a device class routes to is decided once, in the API's
 * `specsForClass`, and a second copy here would be two lists of the same thing one commit from disagreeing. What the
 * rows DO say is why a section may be empty when you arrive: `sectionReadiness` separates an extraction that has not
 * run from one that ran and produced no rootfs, because sending an operator to run an extraction that already ran is
 * the cost of collapsing those two.
 */
import type { JSX } from 'react';
import { Link } from 'react-router-dom';
import { useMessages } from '../i18n';
import { needsRootfs, reachableBefore, sectionReadiness } from '../section-index';
import { ANALYSIS_STEPS } from './StepTimeline';

/** The sections linked from somewhere other than the timeline. Passed to the pure comparator, never re-derived. */
const EXPLICIT_LINKS = ['operator', 'dossier'];

export function SectionIndex({
  imageId,
  sections,
  extraction,
}: {
  imageId: string;
  /** The route segments this screen serves, in the order the page declares them. */
  sections: readonly string[];
  extraction: { ran: boolean; rootfs: boolean };
}): JSX.Element {
  const t = useMessages();
  const labels = t.sections as unknown as Record<string, string>;
  return (
    <section data-testid="section-index">
      <h2>{t.sectionIndex.heading}</h2>
      <p className="hint" style={{ maxWidth: '72ch' }}>
        {t.sectionIndex.intro}
      </p>
      <div style={{ display: 'grid', gap: 10 }}>
        {sections
          // `overview` is a dead id that `resolveSection` remaps to `dossier`; listing both would offer two links to
          // one page and imply a section that does not exist.
          .filter((s) => s !== 'overview')
          .map((s) => {
            const readiness = sectionReadiness(s, extraction);
            const wasReachable = reachableBefore(s, ANALYSIS_STEPS as unknown as string[], EXPLICIT_LINKS);
            return (
              <div key={s} data-section={s} data-readiness={readiness.kind} style={{ display: 'grid', gap: 4 }}>
                <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
                  <Link to={`/image/${imageId}/${s}`} className="mono">
                    {labels[s] ?? s}
                  </Link>
                  <span className="hint" style={{ fontSize: 11 }}>
                    {wasReachable ? t.sectionIndex.timelineNote : t.sectionIndex.urlOnly}
                  </span>
                </div>
                {needsRootfs(s) && readiness.kind !== 'ready' && (
                  <span className="hint" style={{ maxWidth: '72ch' }}>
                    {readiness.kind === 'extraction-not-run' ? t.sectionIndex.notRun : t.sectionIndex.noRootfs}
                  </span>
                )}
              </div>
            );
          })}
      </div>
    </section>
  );
}
