// The assistant panel.
//
// Three things make this different from a chat box bolted onto a tool:
//
//   - Every claim carries the packets behind it, and each citation is
//     checked against the capture before it is shown. A citation that does
//     not resolve is marked as unverifiable rather than rendered as a link
//     to nowhere.
//   - What it saw, what might explain it, and what the capture cannot settle
//     are three separate headings, because collapsing them is how a tool
//     like this starts inventing causes.
//   - The privacy control shows the exact text that would leave the machine,
//     not a description of it. A summary of what would be shared is a
//     promise; the string itself is a fact.
//
// Nothing here calls a language model. The answer comes from the analysis,
// on this machine, and the panel says so rather than letting anyone assume
// otherwise.

import { useEffect, useRef, useState } from 'react';
import { Explorer } from './analyse';
import type { AssistantCitation, AssistantReply, Capture, PrivacyMode } from './report';

const MODES: PrivacyMode[] = ['local', 'redacted', 'full'];

const MODE_NAME: Record<PrivacyMode, string> = {
  local: 'Stay here',
  redacted: 'Replace addresses',
  full: 'Send in full',
};

const SUGGESTIONS = [
  'What went wrong?',
  'Why is it slow?',
  'Is it the network?',
  'What about DNS?',
];

export function Assistant({
  capture,
  file,
  onClose,
  onShowPackets,
}: {
  capture: Capture | null;
  file: File | undefined;
  onClose: () => void;
  onShowPackets: (captureId: string, packet: number) => void;
}) {
  const [question, setQuestion] = useState('');
  const [mode, setMode] = useState<PrivacyMode>('local');
  const [reply, setReply] = useState<AssistantReply | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);
  const [showPack, setShowPack] = useState(false);
  const session = useRef<Explorer | null>(null);

  useEffect(() => {
    if (!file) return;
    const open = new Explorer(file);
    session.current = open;
    return () => {
      open.close();
      session.current = null;
    };
  }, [file]);

  async function ask(text: string) {
    const open = session.current;
    if (!open || !text.trim()) return;
    setAsking(true);
    setError(null);
    const result = await open.ask(text.trim(), mode);
    setAsking(false);
    if ('error' in result) {
      setError(result.error);
      setReply(null);
      return;
    }
    setReply(result);
  }

  return (
    <aside className="assistant">
      <header className="assistant-head">
        <strong>Assistant</strong>
        <button type="button" className="rail-close" onClick={onClose} aria-label="Close the assistant">
          ×
        </button>
      </header>

      {!capture || !file ? (
        <p className="muted">
          Open a capture and select it in the sidebar. The assistant answers about one capture at a time,
          because a packet number only means something inside the file it came from.
        </p>
      ) : (
        <>
          <p className="muted assistant-about">
            Asking about <strong>{capture.file}</strong>
          </p>

          {/* Three mutually exclusive options are a segmented control, and
              the app already has one for Plain/Details/Raw. Drawn as loose
              chips they looked like three filters you could combine, which
              is exactly the wrong thing to be unclear about when the
              question is how much of a capture leaves the machine. */}
          <div className="depth modes" role="radiogroup" aria-label="What may leave this machine">
            {MODES.map((option) => (
              <button
                type="button"
                key={option}
                role="radio"
                aria-checked={mode === option}
                className={`depth-item ${mode === option ? 'is-on' : ''}`}
                onClick={() => setMode(option)}
              >
                {MODE_NAME[option]}
              </button>
            ))}
          </div>
          <p className="mode-note muted">
            {mode === 'local'
              ? 'Nothing is sent anywhere. The answer is built here, from the analysis.'
              : mode === 'redacted'
                ? 'Every address, hardware address and name would be replaced with a label like host-1 before anything left.'
                : 'The real addresses and names would be sent. Only choose this when you are sure that is acceptable for this capture.'}
          </p>

          <div className="ask">
            <input
              className="search small"
              value={question}
              placeholder="Ask about this capture"
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void ask(question);
              }}
            />
            <button type="button" className="open-button primary" disabled={asking} onClick={() => void ask(question)}>
              {asking ? 'Reading…' : 'Ask'}
            </button>
          </div>

          <div className="suggestions">
            {SUGGESTIONS.map((suggestion) => (
              <button
                type="button"
                key={suggestion}
                className="chip"
                onClick={() => {
                  setQuestion(suggestion);
                  void ask(suggestion);
                }}
              >
                {suggestion}
              </button>
            ))}
          </div>

          {error && <p className="problems">{error}</p>}

          {reply && (
            <div className="reply">
              {!reply.understood && (
                <p className="reply-unsure">
                  That is not a question this assistant can answer from the analysis. What it does know about
                  the capture is below.
                </p>
              )}

              <h4>What the capture shows</h4>
              {reply.observations.length === 0 && <p className="muted">Nothing that bears on that question.</p>}
              <ul className="statements">
                {reply.observations.map((statement, i) => (
                  <li key={i}>
                    {statement.text}
                    {statement.citations.length > 0 && (
                      <span className="cites">
                        {statement.citations.map((citation, j) => (
                          <Cite
                            key={j}
                            citation={citation}
                            onOpen={() => {
                              if (citation.kind === 'finding') return;
                              onShowPackets(capture.id, Number(citation.id));
                            }}
                          />
                        ))}
                      </span>
                    )}
                  </li>
                ))}
              </ul>

              {reply.explanations.length > 0 && (
                <>
                  <h4>What might explain it</h4>
                  <ul className="statements soft">
                    {reply.explanations.map((text, i) => (
                      <li key={i}>{text}</li>
                    ))}
                  </ul>
                </>
              )}

              {reply.limits.length > 0 && (
                <>
                  <h4>What this capture cannot tell you</h4>
                  <ul className="statements soft">
                    {reply.limits.map((text, i) => (
                      <li key={i}>{text}</li>
                    ))}
                  </ul>
                </>
              )}

              <p className="assistant-source">
                Answered on this machine from the parsed capture. No language model was called - the model
                this panel is built for is not connected yet, and the grounding below is what it would be
                given.
              </p>

              <button type="button" className="linklike" onClick={() => setShowPack((v) => !v)}>
                {showPack ? 'Hide' : 'See'} exactly what would be sent
              </button>

              {showPack && (
                <>
                  {reply.redactions.length > 0 && (
                    <table className="grid redactions">
                      <thead>
                        <tr>
                          <th>In your capture</th>
                          <th>Would be sent as</th>
                        </tr>
                      </thead>
                      <tbody>
                        {reply.redactions.map((pair) => (
                          <tr key={pair.from}>
                            <td className="mono">{pair.from}</td>
                            <td className="mono">{pair.to}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  <pre className="pack">{reply.evidencePack}</pre>
                </>
              )}
            </div>
          )}
        </>
      )}
    </aside>
  );
}

function Cite({ citation, onOpen }: { citation: AssistantCitation; onOpen: () => void }) {
  if (!citation.valid) {
    // A citation that does not resolve is never shown as a link. This is the
    // check that catches a model citing a packet the capture does not hold,
    // and it would be worthless if the answer still looked clickable.
    return (
      <span className="cite is-broken" title="This points at something the capture does not contain">
        {citation.kind} {citation.id} · unverifiable
      </span>
    );
  }
  const label =
    citation.kind === 'packet'
      ? `packet ${Number(citation.id) + 1}`
      : citation.kind === 'conversation'
        ? 'conversation'
        : 'finding';
  return (
    <button type="button" className="cite" onClick={onOpen}>
      {label}
    </button>
  );
}
