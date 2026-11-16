import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  analyseFiles,
  filesFromDrop,
  filesFromInput,
  type AnalysisProgress,
  type FileProblem,
} from './analyse';
import { Assistant } from './Assistant';
import { AddressingTable, ConversationList, PacketExplorer } from './Explorer';
import { ExportPanel } from './ExportPanel';
import {
  forgetEverything,
  loadCaptures,
  retentionIsOn,
  saveCaptures,
  setRetention,
  storedSize,
} from './storage';
import {
  exampleFiles,
  CONFIDENCE_HELP,
  CONFIDENCE_LABEL,
  SEVERITY_LABEL,
  type Capture,
  type Finding,
  type Severity,
  type Confidence,
  formatBytes,
  formatDuration,
  formatTime,
} from './report';

type Depth = 'plain' | 'detail' | 'raw';

/** What the work area is showing for a single capture. */
type View = 'issues' | 'conversations' | 'addressing' | 'packets' | 'export';

const SEVERITY_ICON: Record<Severity, string> = {
  error: '✕',
  warning: '!',
  info: 'i',
};

const SEVERITY_ORDER: Record<Severity, number> = { error: 0, warning: 1, info: 2 };

interface Filter {
  captureId: string;
  severities: Severity[];
  /// The axis the whole design rests on, and for a long time the one thing
  /// the issues list could not be filtered by.
  confidences: Confidence[];
  text: string;
  /** Matches the start of a finding's kind, e.g. "dns" for dns_error. */
  kindPrefix: string;
}

const EMPTY_FILTER: Filter = {
  captureId: 'all',
  severities: [],
  confidences: [],
  text: '',
  kindPrefix: '',
};

export function App() {
  // Captures are whatever has been opened in this session. The app starts
  // empty on purpose: it is a tool for looking at your own capture, and
  // opening on someone else's sample data invites the reader to mistake it
  // for theirs.
  // Captures kept from a previous visit, if that was asked for. The reports
  // survive; the files do not, which the explorer says plainly when somebody
  // opens the packets of a restored capture.
  const [captures, setCaptures] = useState<Capture[]>(() => loadCaptures());
  const [retain, setRetain] = useState(() => retentionIsOn());
  // The files themselves, kept so the explorer can re-read one when somebody
  // opens its packets. The analysis pass closes every capture it opens, so
  // this is a handle to the file rather than its bytes.
  const [files, setFiles] = useState<Map<string, File>>(new Map());
  const [view, setView] = useState<View>('issues');
  const [flowOfPacket, setFlowOfPacket] = useState<number | null>(null);
  const [jumpTo, setJumpTo] = useState<number | null>(null);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [problems, setProblems] = useState<FileProblem[]>([]);
  const [dragging, setDragging] = useState(false);
  const abort = useRef<AbortController | null>(null);
  const filePicker = useRef<HTMLInputElement>(null);
  const folderPicker = useRef<HTMLInputElement>(null);

  const [filter, setFilter] = useState<Filter>(EMPTY_FILTER);
  const [depth, setDepth] = useState<Depth>('plain');
  const [openFinding, setOpenFinding] = useState<Finding | null>(null);
  const [assistantOpen, setAssistantOpen] = useState(false);

  // Writing on every change rather than on a timer: a browser tab can close
  // without warning, and a half-written set is worse than none.
  useEffect(() => {
    if (!retain) return;
    const failure = saveCaptures(captures);
    if (failure) {
      setRetain(false);
      setRetention(false);
      setProblems([{ file: 'keeping captures', message: failure }]);
    }
  }, [captures, retain]);

  const addFiles = useCallback(async (incoming: File[]) => {
    if (incoming.length === 0) {
      setProblems([
        {
          file: 'nothing to read',
          message:
            'None of those were capture files. AtherNet reads .pcap, .pcapng and .cap - the formats Wireshark saves.',
        },
      ]);
      return;
    }
    const controller = new AbortController();
    abort.current = controller;
    setProblems([]);
    setProgress({ index: 0, total: incoming.length, file: incoming[0].name });
    try {
      const result = await analyseFiles(incoming, setProgress, controller.signal);
      // A capture opened twice replaces the first reading rather than
      // appearing beside it as a near-identical twin.
      setCaptures((current) => {
        const byId = new Map(current.map((c) => [c.id, c]));
        for (const capture of result.captures) byId.set(capture.id, capture);
        return [...byId.values()].sort((a, b) => a.file.localeCompare(b.file));
      });
      setFiles((current) => {
        const next = new Map(current);
        for (const capture of result.captures) {
          const match = incoming.find((f) => f.name === capture.file);
          if (match) next.set(capture.id, match);
        }
        return next;
      });
      setProblems(result.problems);
      if (result.captures.length > 0) {
        setFilter(EMPTY_FILTER);
        setView('issues');
      }
    } finally {
      setProgress(null);
      abort.current = null;
    }
  }, []);

  const cancel = useCallback(() => {
    abort.current?.abort();
  }, []);

  function removeCapture(id: string) {
    setCaptures((current) => current.filter((c) => c.id !== id));
    setFiles((current) => {
      const next = new Map(current);
      next.delete(id);
      return next;
    });
    setFilter((f) => (f.captureId === id ? { ...f, captureId: 'all' } : f));
    setOpenFinding(null);
  }

  function removeEverything() {
    setCaptures([]);
    setFiles(new Map());
    forgetEverything();
    setProblems([]);
    setFilter(EMPTY_FILTER);
    setOpenFinding(null);
    setView('issues');
  }

  /** Open the explorer on the conversation a finding is about. */
  function showPacketsFor(captureId: string, packet: number) {
    setFilter((f) => ({ ...f, captureId }));
    setFlowOfPacket(packet);
    setJumpTo(packet);
    setView('packets');
    setOpenFinding(null);
  }

  async function onDrop(event: React.DragEvent) {
    event.preventDefault();
    setDragging(false);
    const dropped = await filesFromDrop(event.dataTransfer.items);
    // Safari and some older browsers have no directory entry API, so fall
    // back to the plain file list rather than appearing to do nothing.
    await addFiles(dropped.length > 0 ? dropped : filesFromInput(event.dataTransfer.files));
  }

  const visibleCaptures = useMemo(
    () => (filter.captureId === 'all' ? captures : captures.filter((c) => c.id === filter.captureId)),
    // `captures` belongs here now that it is state rather than a module
    // constant. Without it the dashboard kept rendering the previous set:
    // the rail listed a freshly opened capture while the cards said zero.
    [captures, filter.captureId],
  );

  // The one capture on screen, when exactly one is selected. The explorer is
  // per capture: "all captures" has no packet list, because packet 7 of one
  // file and packet 7 of another are not in any sequence together.
  const single = visibleCaptures.length === 1 ? visibleCaptures[0] : null;

  const rows = useMemo(() => {
    const text = filter.text.trim().toLowerCase();
    return visibleCaptures
      .flatMap((capture) => capture.findings.map((finding) => ({ capture, finding })))
      .filter(({ finding }) => filter.severities.length === 0 || filter.severities.includes(finding.severity))
      .filter(
        ({ finding }) =>
          filter.confidences.length === 0 || filter.confidences.includes(finding.confidence),
      )
      .filter(({ finding }) => !filter.kindPrefix || finding.kind.startsWith(filter.kindPrefix))
      .filter(({ finding, capture }) => {
        if (!text) return true;
        const haystack = [finding.title, finding.what, finding.kind, capture.file, ...finding.endpoints]
          .join(' ')
          .toLowerCase();
        return haystack.includes(text);
      })
      .sort((a, b) => SEVERITY_ORDER[a.finding.severity] - SEVERITY_ORDER[b.finding.severity]);
  }, [visibleCaptures, filter.severities, filter.confidences, filter.text, filter.kindPrefix]);

  const totals = useMemo(() => {
    const packets = visibleCaptures.reduce((sum, c) => sum + c.packets, 0);
    const bytes = visibleCaptures.reduce((sum, c) => sum + c.bytes, 0);
    const seconds = visibleCaptures.reduce((sum, c) => sum + c.durationSeconds, 0);
    const drops = visibleCaptures.reduce((sum, c) => sum + c.reportedDrops, 0);
    const errors = visibleCaptures.reduce(
      (sum, c) => sum + c.findings.filter((f) => f.severity === 'error').length,
      0,
    );
    return { packets, bytes, seconds, drops, errors };
  }, [visibleCaptures]);

  function toggleSeverity(severity: Severity) {
    setFilter((f) => ({
      ...f,
      severities: f.severities.includes(severity)
        ? f.severities.filter((s) => s !== severity)
        : [...f.severities, severity],
    }));
  }

  function toggleConfidence(confidence: Confidence) {
    setFilter((f) => ({
      ...f,
      confidences: f.confidences.includes(confidence)
        ? f.confidences.filter((c) => c !== confidence)
        : [...f.confidences, confidence],
    }));
  }

  return (
    <div
      className={`shell ${assistantOpen ? 'with-assistant' : ''} ${dragging ? 'is-dragging' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        // Only when the pointer has left the window, not on every child.
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={onDrop}
    >
      {/* Two pickers, because choosing a folder and choosing files are
          different gestures and a browser cannot offer both from one input. */}
      <input
        ref={filePicker}
        type="file"
        multiple
        accept=".pcap,.pcapng,.cap"
        className="hidden-input"
        onChange={(e) => {
          void addFiles(filesFromInput(e.target.files));
          e.target.value = '';
        }}
      />
      <input
        ref={folderPicker}
        type="file"
        multiple
        /* Not in the TypeScript DOM types; every Chromium browser has it. */
        {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
        className="hidden-input"
        onChange={(e) => {
          void addFiles(filesFromInput(e.target.files));
          e.target.value = '';
        }}
      />

      <aside className="rail">
        <div className="brand">
          AtherNet
          <span className="brand-sub">capture analysis</span>
        </div>

        <button
          type="button"
          className={`rail-item ${filter.captureId === 'all' ? 'is-active' : ''}`}
          onClick={() => setFilter((f) => ({ ...f, captureId: 'all' }))}
        >
          <span>All captures</span>
          <span className="rail-count">{captures.length}</span>
        </button>

        {captures.map((capture) => (
          <div className="rail-row" key={capture.id}>
            <button
              type="button"
              className={`rail-item ${filter.captureId === capture.id ? 'is-active' : ''}`}
              onClick={() => {
                setFilter((f) => ({ ...f, captureId: capture.id }));
                setFlowOfPacket(null);
                setJumpTo(null);
              }}
              title={capture.description}
              aria-label={`${capture.file}, ${capture.findings.length || 'no'} ${
                capture.findings.length === 1 ? 'finding' : 'findings'
              }`}
            >
              <span className="rail-file">{capture.file}</span>
              {capture.findings.length > 0 && <span className="rail-count">{capture.findings.length}</span>}
            </button>
            <button
              type="button"
              className="rail-close"
              onClick={() => removeCapture(capture.id)}
              aria-label={`Close ${capture.file} and remove it from this session`}
              title="Close this capture"
            >
              ×
            </button>
          </div>
        ))}

        <div className="rail-actions">
          <button type="button" className="open-button" onClick={() => filePicker.current?.click()}>
            Open capture files
          </button>
          <button type="button" className="open-button ghost" onClick={() => folderPicker.current?.click()}>
            Open a folder
          </button>
          {captures.length > 0 && (
            <button type="button" className="open-button ghost" onClick={removeEverything}>
              Close all
            </button>
          )}
        </div>

        <label className="retain">
          <input
            type="checkbox"
            checked={retain}
            onChange={(e) => {
              const on = e.target.checked;
              setRetain(on);
              setRetention(on);
              if (on) saveCaptures(captures);
            }}
          />
          <span>
            Keep these on this device
            {retain && storedSize() > 0 && (
              <span className="muted"> · {Math.round(storedSize() / 1024)} kB kept</span>
            )}
          </span>
        </label>

        <p className="rail-note">
          Drop .pcap or .pcapng files here, or a folder of them. They are read on this machine and never
          uploaded.{' '}
          {retain
            ? 'Findings are being kept in this browser until you close them or turn this off. The capture files themselves are never kept, so a capture reopened tomorrow can show its findings but not its packets.'
            : 'Closing one removes it, and closing the tab removes them all.'}
        </p>
      </aside>

      <div className="main">
        {progress && (
          <div className="progress" role="status" aria-live="polite">
            <div className="progress-text">
              Reading {progress.file} · file {progress.index} of {progress.total}
            </div>
            <div className="progress-track">
              <div
                className="progress-fill"
                style={{ width: `${(progress.index / Math.max(1, progress.total)) * 100}%` }}
              />
            </div>
            <button type="button" className="open-button ghost" onClick={cancel}>
              Stop
            </button>
          </div>
        )}

        {problems.length > 0 && (
          <ul className="problems" aria-label="Files that could not be read">
            {problems.map((problem) => (
              <li key={problem.file + problem.message}>
                <strong>{problem.file}</strong> {problem.message}
              </li>
            ))}
          </ul>
        )}

        {captures.length === 0 && !progress ? (
          <EmptyState
            keeping={retain}
            onOpenFiles={() => filePicker.current?.click()}
            onOpenFolder={() => folderPicker.current?.click()}
            onLoadExamples={() => void addFiles(exampleFiles())}
          />
        ) : (
        <>
        <header className="filterbar">
          <input
            className="search"
            type="search"
            placeholder="Filter by address, port, protocol or words in a finding"
            value={filter.text}
            onChange={(e) => setFilter((f) => ({ ...f, text: e.target.value }))}
          />
          <div className="shortcuts">
            {(['error', 'warning', 'info'] as Severity[]).map((severity) => (
              <button
                type="button"
                key={severity}
                className={`chip chip-${severity} ${filter.severities.includes(severity) ? 'is-on' : ''}`}
                onClick={() => toggleSeverity(severity)}
              >
                <span className="dot" aria-hidden="true">
                  {SEVERITY_ICON[severity]}
                </span>
                {SEVERITY_LABEL[severity]}
              </button>
            ))}
            <span className="chip-divider" aria-hidden="true" />
            {/* Severity says how much it matters; confidence says how sure
                the evidence makes us. Being able to ask for "only the things
                a packet states outright" is the whole point of keeping them
                apart, and for a long time there was no way to ask. */}
            {(['confirmed', 'suspected', 'incomplete'] as Confidence[]).map((confidence) => (
              <button
                type="button"
                key={confidence}
                className={`chip ${filter.confidences.includes(confidence) ? 'is-on' : ''}`}
                aria-pressed={filter.confidences.includes(confidence)}
                title={CONFIDENCE_HELP[confidence]}
                onClick={() => toggleConfidence(confidence)}
              >
                {CONFIDENCE_LABEL[confidence]}
              </button>
            ))}
            <span className="chip-divider" aria-hidden="true" />
            {/* A shortcut filters on the finding kind, not on the words in
                it. Searching for "dns" as text also matched a snaplen notice
                whose explanation happens to mention the DNS checks. */}
            <button
              type="button"
              className={`chip ${filter.kindPrefix === 'dns' ? 'is-on' : ''}`}
              aria-pressed={filter.kindPrefix === 'dns'}
              onClick={() =>
                setFilter((f) => ({ ...f, kindPrefix: f.kindPrefix === 'dns' ? '' : 'dns' }))
              }
            >
              DNS problems
            </button>
            <button type="button" className="chip" onClick={() => setFilter(EMPTY_FILTER)}>
              Clear
            </button>
          </div>
          <div className="depth" role="group" aria-label="Level of detail">
            {(['plain', 'detail', 'raw'] as Depth[]).map((level) => (
              <button
                type="button"
                key={level}
                className={`depth-item ${depth === level ? 'is-on' : ''}`}
                onClick={() => setDepth(level)}
              >
                {level === 'plain' ? 'Plain' : level === 'detail' ? 'Details' : 'Raw'}
              </button>
            ))}
          </div>
          <button type="button" className="assistant-toggle" onClick={() => setAssistantOpen((v) => !v)}>
            {assistantOpen ? 'Hide assistant' : 'Ask the assistant'}
          </button>
        </header>

        <main className="work">
          <section className="cards">
            <Stat label="Captures" value={visibleCaptures.length.toString()} />
            <Stat label="Packets" value={totals.packets.toLocaleString()} />
            <Stat label="Traffic" value={formatBytes(totals.bytes)} />
            <Stat label="Span" value={formatDuration(totals.seconds)} />
            <Stat label="Errors" value={totals.errors.toString()} tone={totals.errors > 0 ? 'error' : undefined} />
            <Stat
              label="Dropped by the capture tool"
              value={totals.drops.toLocaleString()}
              tone={totals.drops > 0 ? 'info' : undefined}
            />
          </section>

          {single && (
            <CaptureDetail capture={single} depth={depth} />
          )}

          {single && (
            <nav className="views" role="tablist" aria-label="What to show for this capture">
              {(['issues', 'conversations', 'addressing', 'packets', 'export'] as View[]).map((option) => (
                <button
                  type="button"
                  key={option}
                  role="tab"
                  aria-selected={view === option}
                  className={`view-tab ${view === option ? 'is-on' : ''}`}
                  onClick={() => {
                    setView(option);
                    if (option !== 'packets') setJumpTo(null);
                  }}
                >
                  {option === 'issues'
                    ? `Issues (${single.findings.length})`
                    : option === 'conversations'
                      ? `Conversations (${single.conversationCount.toLocaleString()})`
                      : option === 'addressing'
                        ? `Addressing (${single.bindings.length})`
                        : option === 'packets'
                          ? `Packets (${single.packets.toLocaleString()})`
                          : 'Export'}
                </button>
              ))}
            </nav>
          )}

          {single && view === 'conversations' && (
            <section className="issues">
              <ConversationList
                capture={single}
                onShowPackets={(firstPacket) => {
                  setFlowOfPacket(firstPacket);
                  setJumpTo(firstPacket);
                  setView('packets');
                }}
              />
            </section>
          )}

          {single && view === 'addressing' && (
            <section className="issues">
              <AddressingTable capture={single} />
            </section>
          )}

          {single && view === 'export' && (
            <section className="issues">
              <ExportPanel capture={single} file={files.get(single.id)} />
            </section>
          )}

          {single && view === 'packets' && (
            <section className="issues">
              <PacketExplorer
                capture={single}
                file={files.get(single.id)}
                flowOfPacket={flowOfPacket}
                jumpTo={jumpTo}
                onClearFlow={() => {
                  setFlowOfPacket(null);
                  setJumpTo(null);
                }}
              />
            </section>
          )}

          <section className="issues" hidden={!!single && view !== 'issues'}>
            <h2>
              Issues
              <span className="muted"> ranked by severity, then confidence</span>
            </h2>
            {rows.length === 0 && (
              <p className="empty">
                Nothing matches this filter. A capture with no findings is a real answer, not an empty screen.
              </p>
            )}
            <ul className="issue-list">
              {rows.map(({ capture, finding }) => (
                <li key={finding.id}>
                  {/* The badges inside carry icons rather than text, so the
                      button needs a name of its own: a screen reader was
                      announcing these rows as an unlabelled "button". */}
                  <button
                    type="button"
                    className="issue"
                    onClick={() => setOpenFinding(finding)}
                    aria-label={`${SEVERITY_LABEL[finding.severity]}, ${
                      CONFIDENCE_LABEL[finding.confidence]
                    }: ${finding.title}, in ${capture.file} at ${finding.at}`}
                  >
                    <SeverityBadge severity={finding.severity} />
                    <span className="issue-body">
                      <span className="issue-title">{finding.title}</span>
                      <span className="issue-meta">
                        <ConfidenceBadge confidence={finding.confidence} />
                        <span className="muted">
                          {capture.file} · {finding.at}
                          {depth !== 'plain' && ` · ${finding.kind}`}
                        </span>
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        </main>
        </>
        )}
      </div>

      {assistantOpen && (
        <Assistant
          capture={single}
          file={single ? files.get(single.id) : undefined}
          onClose={() => setAssistantOpen(false)}
          onShowPackets={showPacketsFor}
        />
      )}

      {openFinding && (
        <FindingDrawer
          finding={openFinding}
          depth={depth}
          onClose={() => setOpenFinding(null)}
          onShowPackets={() => {
            const owner = captures.find((c) => c.findings.some((f) => f.id === openFinding.id));
            if (owner) showPacketsFor(owner.id, openFinding.firstPacket ?? 0);
          }}
        />
      )}
    </div>
  );
}

/**
 * What the app shows before anything is open.
 *
 * It is the first screen most people will see, so it says what to do, what
 * the app will read, and - because these are packet captures of real traffic
 * - where the file goes. The answer is nowhere, and that is worth stating
 * plainly rather than burying in a settings page.
 */
function EmptyState({
  keeping,
  onOpenFiles,
  onOpenFolder,
  onLoadExamples,
}: {
  keeping: boolean;
  onOpenFiles: () => void;
  onOpenFolder: () => void;
  onLoadExamples: () => void;
}) {
  return (
    <main className="work empty">
      <div className="dropzone">
        <h1>Open a capture</h1>
        <p className="lead">
          Drag a <code>.pcap</code> or <code>.pcapng</code> file here - the formats Wireshark saves - or a
          whole folder of them. AtherNet reads it and tells you what went wrong, with the packets that show
          it.
        </p>
        <div className="dropzone-actions">
          <button type="button" className="open-button primary" onClick={onOpenFiles}>
            Choose capture files
          </button>
          <button type="button" className="open-button" onClick={onOpenFolder}>
            Choose a folder
          </button>
        </div>
        <p className="privacy">
          <strong>Your capture stays on this machine.</strong> It is read here in the page, by the analyser
          compiled into the app. There is no server to send it to and nothing is uploaded.{' '}
          {keeping
            ? 'You have asked for findings to be kept in this browser between visits; capture files themselves are never kept. Turn that off in the sidebar to go back to keeping nothing.'
            : 'Nothing is stored between visits - close the tab and it is gone.'}{' '}
          Nothing is sent to an AI service unless you ask a question, and the assistant will say what it is
          about to share before it does.
        </p>
        <p className="muted">
          Nothing to hand?{' '}
          <button type="button" className="linklike" onClick={onLoadExamples}>
            Load the example captures
          </button>{' '}
          - thirteen small files with faults planted in them on purpose, used to test the detectors.
        </p>
      </div>
    </main>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: Severity }) {
  return (
    <div className={`card ${tone ? `card-${tone}` : ''}`}>
      <div className="card-value">{value}</div>
      <div className="card-label">{label}</div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`sev sev-${severity}`}>
      <span className="dot" aria-hidden="true">
        {SEVERITY_ICON[severity]}
      </span>
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence: Finding['confidence'] }) {
  return (
    <span className={`conf conf-${confidence}`} title={CONFIDENCE_HELP[confidence]}>
      {CONFIDENCE_LABEL[confidence]}
    </span>
  );
}

function CaptureDetail({ capture, depth }: { capture: Capture; depth: Depth }) {
  const peak = Math.max(1, ...capture.timeline);
  return (
    <section className="capture">
      <h2>
        {capture.file}
        <span className="muted"> {capture.description}</span>
      </h2>

      <div
        className="timeline"
        role="img"
        aria-label={`Traffic over the capture, ${peak} packets at the busiest ${formatDuration(
          capture.timelineBucketMs / 1000,
        )}`}
      >
        {capture.timeline.map((value, i) => (
          <span
            key={i}
            className="bar"
            style={{ height: `${(value / peak) * 100}%` }}
            title={`${value} packets in this ${formatDuration(capture.timelineBucketMs / 1000)}`}
          />
        ))}
      </div>
      {/* The strip rebuckets itself as a capture gets longer, so it has to
          say what one bar covers rather than implying a fixed scale. */}
      <p className="timeline-scale">
        each bar covers {formatDuration(capture.timelineBucketMs / 1000)}, busiest {peak}{' '}
        {peak === 1 ? 'packet' : 'packets'}
      </p>

      <dl className="facts">
        <div>
          <dt>Started</dt>
          <dd>{formatTime(capture.startedAtUnixMs)}</dd>
        </div>
        <div>
          <dt>Link layer</dt>
          <dd>{capture.linkType}</dd>
        </div>
        <div>
          <dt>Protocols</dt>
          <dd>
            tcp {capture.protocols.tcp} · udp {capture.protocols.udp} · arp {capture.protocols.arp} · icmp{' '}
            {capture.protocols.icmp}
          </dd>
        </div>
        {depth !== 'plain' && (
          <div>
            <dt>Snaplen</dt>
            <dd>{capture.snaplen.toLocaleString()} bytes</dd>
          </div>
        )}
      </dl>

      {capture.reportedDrops > 0 && (
        <p className="banner banner-info">
          This capture reports {capture.reportedDrops.toLocaleString()} packets dropped by the capture tool.
          Anything missing from it might still have been on the wire, so no absence here is confirmed.
        </p>
      )}

    </section>
  );
}

function FindingDrawer({
  finding,
  depth,
  onClose,
  onShowPackets,
}: {
  finding: Finding;
  depth: Depth;
  onClose: () => void;
  onShowPackets: () => void;
}) {
  return (
    <div className="drawer-backdrop" onClick={onClose} role="presentation">
      <aside className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label={finding.title}>
        <header className="drawer-head">
          <SeverityBadge severity={finding.severity} />
          <ConfidenceBadge confidence={finding.confidence} />
          <button type="button" className="close" onClick={onClose} aria-label="Close">
            {'✕'}
          </button>
        </header>

        <h2>{finding.title}</h2>

        <h3>What happened</h3>
        <p>{finding.what}</p>

        {finding.endpoints.length > 0 && (
          <>
            <h3>Who was involved</h3>
            <p className="mono">{finding.endpoints.join('  ↔  ')}</p>
          </>
        )}

        <h3>When</h3>
        <p>
          {formatTime(finding.atUnixMs)}
          <span className="muted"> · {finding.at}</span>
        </p>

        <h3>The packets that show it</h3>
        <ul className="evidence">
          {finding.evidence.map((item) => (
            <li key={`${item.file}-${item.frame}`}>
              <span className="frame">
                {item.file} · frame {item.frame}
              </span>
              <span>{item.note}</span>
            </li>
          ))}
        </ul>

        <button type="button" className="open-button" onClick={onShowPackets}>
          Show these packets
        </button>

        <h3>What to check next</h3>
        <ol className="checks">
          {finding.nextChecks.map((check) => (
            <li key={check}>{check}</li>
          ))}
        </ol>

        <p className="confidence-note">
          {CONFIDENCE_LABEL[finding.confidence]}: {CONFIDENCE_HELP[finding.confidence]}
        </p>

        {finding.limits.length > 0 && (
          <>
            <h3>Why this is not confirmed</h3>
            <ul className="limits">
              {finding.limits.map((limit) => (
                <li key={limit}>{limit}</li>
              ))}
            </ul>
          </>
        )}

        {depth === 'raw' && (
          <pre className="raw">
            {JSON.stringify({ kind: finding.kind, id: finding.id, evidence: finding.evidence }, null, 2)}
          </pre>
        )}
      </aside>
    </div>
  );
}

