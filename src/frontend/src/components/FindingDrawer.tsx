import { useEffect, useState } from "react";
import { cweName, cweUrl, remediationFor } from "../lib/remediation";
import type { TriageDecision, TriageState } from "../lib/storage";
import { TRIAGE_LABEL, TRIAGE_STATES } from "../lib/storage";
import type { ValidatedFinding } from "../lib/validated";
import { EXPLOITABILITY_LABEL, PRIORITY_HINT, pathHops, shortRule } from "../lib/validated";
import type { ReachabilityVerdict } from "../types";
import { ConfidenceMeter, ExploitBadge, Icon, PriorityBadge, ReachBadge, SeverityBadge, StatusTag } from "./ui";

interface Props {
  row: ValidatedFinding;
  index: number;
  total: number;
  onPrev: () => void;
  onNext: () => void;
  onClose: () => void;
  decision?: TriageDecision;
  onTriage: (patch: { state?: TriageState; note?: string }) => void;
  previewMode: boolean;
  onOpenRoadmap: () => void;
}

export function FindingDrawer({ row, index, total, onPrev, onNext, onClose, decision, onTriage, previewMode, onOpenRoadmap }: Props) {
  const { finding: f, reachability: reach, exploitability: ex } = row;
  const remediation = remediationFor(f.cwe);
  // Esc closes, j/k (or arrows) step through the current list.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLInputElement) return;
      if (e.key === "Escape") onClose();
      if (e.key === "j") {
        e.preventDefault();
        onNext();
      }
      if (e.key === "k") {
        e.preventDefault();
        onPrev();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, onNext, onPrev]);

  const title = f.cwe[0] ? cweName(f.cwe[0]) : shortRule(f.vulnerability_type);

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Finding: ${title}`}>
        <header className="drawer-head">
          <div className="drawer-nav">
            <button type="button" className="icon-btn" onClick={onPrev} disabled={index <= 0} aria-label="Previous finding">
              <Icon name="chevronLeft" />
            </button>
            <span className="muted">
              {index + 1} / {total}
            </span>
            <button type="button" className="icon-btn" onClick={onNext} disabled={index >= total - 1} aria-label="Next finding">
              <Icon name="chevronRight" />
            </button>
            <span className="kbd-hint">
              <kbd>j</kbd>
              <kbd>k</kbd>
            </span>
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="x" />
          </button>
        </header>

        <div className="drawer-body">
          <div className="drawer-title">
            <div className="badges">
              <PriorityBadge tier={row.priority.tier} showHint />
              <SeverityBadge severity={row.severity} />
            </div>
            <h2>{title}</h2>
            <p className="mono loc">
              {f.file_path}:{f.line_start}
              {f.line_end && f.line_end !== f.line_start ? `–${f.line_end}` : ""}
            </p>
            <p className="drawer-msg">{f.message}</p>
          </div>

          {/* ---- Verdict summary ---- */}
          <div className="verdicts">
            <div className="verdict">
              <span className="verdict-label">Reachability</span>
              <ReachBadge status={reach?.status} />
              {reach && <ConfidenceMeter confidence={reach.confidence} />}
            </div>
            <div className="verdict">
              <span className="verdict-label">Exploitability</span>
              <ExploitBadge status={row.exploit} />
              {ex ? <ConfidenceMeter confidence={ex.confidence} /> : <StatusTag status="planned" onClick={onOpenRoadmap} />}
            </div>
            <div className="verdict">
              <span className="verdict-label">Priority score</span>
              <span className="verdict-score">
                {row.priority.score}
                <span className="muted">/100</span>
              </span>
              <span className="muted small">{PRIORITY_HINT[row.priority.tier]}</span>
            </div>
          </div>

          <details className="section-details">
            <summary>Why {row.priority.tier}?</summary>
            <ul className="factors">
              {row.priority.factors.map((fa) => (
                <li key={fa.label}>
                  <span>{fa.label}</span>
                  <span className={fa.points >= 0 ? "pos" : "neg"}>
                    {fa.points >= 0 ? "+" : ""}
                    {fa.points}
                  </span>
                </li>
              ))}
            </ul>
            <p className="muted small">Interim heuristic computed in the browser. Thresholds: P1 ≥ 70, P2 ≥ 50, P3 ≥ 25.</p>
          </details>

          {/* ---- Reachability evidence ---- */}
          <section className="dsection">
            <h3>
              <Icon name="route" /> Reachability evidence
            </h3>
            {reach ? (
              <>
                <p>{reach.reason}</p>
                {reach.call_path && reach.call_path.length > 0 ? (
                  <CallPath reach={reach} sinkLine={f.line_start} />
                ) : (
                  reach.containing_function && (
                    <p className="muted small">
                      Inside <code>{reach.containing_function}</code> — no caller chain leads to an entry point.
                    </p>
                  )
                )}
              </>
            ) : (
              <p className="muted">Reachability wasn't computed for this finding.</p>
            )}
          </section>

          {/* ---- Exploitability ---- */}
          <section className="dsection">
            <h3>
              <Icon name="agent" /> Exploitability
              {ex?.tier && <span className="tier-tag">Tier {ex.tier}</span>}
              {previewMode && ex && <span className="example-tag">Example data</span>}
            </h3>
            {ex ? (
              <>
                <p>
                  <strong>{EXPLOITABILITY_LABEL[row.exploit]}.</strong> {ex.reason}
                </p>
                <div className="flow">
                  <FlowStep label="Source" tone={ex.attacker_controlled ? "bad" : ex.attacker_controlled === false ? "good" : "neutral"}>
                    {ex.source?.description ?? "No attacker-controlled source identified"}
                  </FlowStep>
                  <FlowStep label="Sanitizers" tone={ex.sanitizers?.length ? "good" : "bad"}>
                    {ex.sanitizers?.length ? ex.sanitizers.map((s) => s.description).join(", ") : "None observed on the path"}
                  </FlowStep>
                  <FlowStep label="Sink" tone="neutral">
                    {ex.sink?.description ?? `${f.file_path}:${f.line_start}`}
                  </FlowStep>
                </div>
                {ex.reasoning_steps && ex.reasoning_steps.length > 0 && (
                  <details className="section-details" open>
                    <summary>Agent reasoning</summary>
                    <ol className="reasoning">
                      {ex.reasoning_steps.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ol>
                  </details>
                )}
                {ex.proof_of_concept && (
                  <>
                    <h4>Proof of concept</h4>
                    <pre className="code-plain">{ex.proof_of_concept}</pre>
                  </>
                )}
              </>
            ) : row.reachability?.status === "unreachable" ? (
              <p className="muted">Skipped — unreachable findings don't need an exploitability judgment.</p>
            ) : (
              <p className="muted">
                Not analyzed yet. The Tier A agent will answer <em>exploitable / not exploitable / can't tell</em> with its
                reasoning shown here.
              </p>
            )}
          </section>

          {/* ---- Code ---- */}
          {f.code_snippet && (
            <section className="dsection">
              <h3>
                <Icon name="code" /> Code
              </h3>
              <CodeBlock code={f.code_snippet} startLine={f.line_start} file={f.file_path} />
            </section>
          )}

          {/* ---- Remediation ---- */}
          {(remediation || ex?.suggested_fix) && (
            <section className="dsection">
              <h3>
                <Icon name="shieldCheck" /> How to fix
              </h3>
              {ex?.suggested_fix && <p>{ex.suggested_fix}</p>}
              {remediation && (
                <>
                  <p>{remediation.fix}</p>
                  {remediation.example && <pre className="code-plain">{remediation.example}</pre>}
                  {remediation.owasp && (
                    <a className="ext" href={remediation.owasp.url} target="_blank" rel="noreferrer">
                      OWASP: {remediation.owasp.label} <Icon name="external" size={12} />
                    </a>
                  )}
                </>
              )}
            </section>
          )}

          {/* ---- Triage ---- */}
          <section className="dsection">
            <h3>
              <Icon name="check" /> Triage
            </h3>
            <div className="triage-picker" role="radiogroup">
              {TRIAGE_STATES.map((s) => (
                <button
                  key={s}
                  type="button"
                  role="radio"
                  aria-checked={(decision?.state ?? "open") === s}
                  className={`triage-opt triage-${s}${(decision?.state ?? "open") === s ? " on" : ""}`}
                  onClick={() => onTriage({ state: s })}
                >
                  {TRIAGE_LABEL[s]}
                </button>
              ))}
            </div>
            <NoteField key={row.id} initial={decision?.note ?? ""} onSave={(note) => onTriage({ note })} />
            {decision?.updatedAt && <p className="muted small">Updated {new Date(decision.updatedAt).toLocaleString()} · saved in this browser</p>}
          </section>

          {/* ---- Details ---- */}
          <section className="dsection">
            <h3>Details</h3>
            <dl className="kv">
              <dt>Scanner</dt>
              <dd>{f.source_scanner}</dd>
              <dt>{f.rule_ids.length > 1 ? `Rules (${f.rule_ids.length} merged)` : "Rule"}</dt>
              <dd>
                {f.rule_ids.map((r) => (
                  <code key={r} className="block-code" title={r}>
                    {r}
                  </code>
                ))}
              </dd>
              <dt>CWE</dt>
              <dd>
                {f.cwe.length
                  ? f.cwe.map((c) => (
                      <a key={c} className="ext" href={cweUrl(c)} target="_blank" rel="noreferrer">
                        {c} <Icon name="external" size={11} />
                      </a>
                    ))
                  : "—"}
              </dd>
              {reach?.containing_function && (
                <>
                  <dt>Function</dt>
                  <dd>
                    <code>{reach.containing_function}</code>
                  </dd>
                </>
              )}
              <dt>Finding ID</dt>
              <dd>
                <code>{f.finding_id}</code>
              </dd>
            </dl>
          </section>
        </div>
      </aside>
    </>
  );
}

function FlowStep({ label, tone, children }: { label: string; tone: "good" | "bad" | "neutral"; children: React.ReactNode }) {
  return (
    <div className={`flow-step flow-${tone}`}>
      <span className="flow-label">{label}</span>
      <span className="flow-text">{children}</span>
    </div>
  );
}

function CodeBlock({ code, startLine, file }: { code: string; startLine: number; file: string }) {
  const lines = code.split("\n");
  return (
    <div className="code">
      <div className="code-head">
        <Icon name="file" size={12} /> {file}
      </div>
      <pre>
        {lines.map((l, i) => (
          <div key={i} className="code-line hl">
            <span className="ln">{startLine + i}</span>
            <span className="lc">{l || " "}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}

/** Keyed by finding id so switching findings resets the draft without an effect. */
function NoteField({ initial, onSave }: { initial: string; onSave: (note: string) => void }) {
  const [note, setNote] = useState(initial);
  return (
    <textarea
      className="textarea"
      rows={2}
      placeholder="Add a note — why it's a false positive, ticket link, owner…"
      value={note}
      onChange={(e) => setNote(e.target.value)}
      onBlur={() => note !== initial && onSave(note)}
    />
  );
}

function CallPath({ reach, sinkLine }: { reach: ReachabilityVerdict; sinkLine: number }) {
  const { entry, hops } = pathHops(reach);
  return (
    <ol className="path">
      {entry && (
        <li className="path-entry">
          <span className="path-node" />
          <span className="path-kind">{hops.length === 0 ? "Entry · contains finding" : "Entry point"}</span>
          <code>{entry}</code>
        </li>
      )}
      {hops.map((fn, i) => (
        <li key={`${fn}-${i}`}>
          <span className="path-node" />
          <span className="path-kind">{i === hops.length - 1 ? "Contains finding" : "Calls"}</span>
          <code>{fn}</code>
        </li>
      ))}
      <li className="path-sink">
        <span className="path-node" />
        <span className="path-kind">Sink</span>
        <code>line {sinkLine}</code>
      </li>
    </ol>
  );
}
