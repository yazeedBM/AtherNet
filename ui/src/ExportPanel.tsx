// Writing a capture out for somebody who will read it somewhere else.
//
// The whole point is a ticket, an email, or a vendor who will never see the
// capture file. So the panel shows the exact text before it goes anywhere -
// the same string that gets copied or downloaded, not a rendering of it -
// and the privacy choice sits next to the preview rather than in a settings
// page, because an export leaves the machine by definition.
//
// There are two things to export, not six formats of one thing. The summary
// is a narrative: what went wrong, what the capture cannot settle, what to
// check next. The tables are the data behind it: every finding, conversation
// and address binding, as rows. Markdown, text, PDF and Word are the
// narrative; CSV and a spreadsheet are the rows. Putting prose in a
// spreadsheet would satisfy a feature list and help nobody.

import { useEffect, useRef, useState } from 'react';
import { Explorer } from './analyse';
import { parseSummary } from './blocks';
import { csv, docx, xlsx, type Table } from './ooxml';
import { pdf } from './pdf';
import { parseTables } from './tables';
import type { Capture, PrivacyMode } from './report';

type Shape = 'summary' | 'tables';
type Format = 'markdown' | 'text' | 'pdf' | 'docx' | 'csv' | 'xlsx';

interface FormatSpec {
  id: Format;
  label: string;
  hint: string;
  extension: string;
  shape: Shape;
  /** False when the file is a rendering of the preview rather than its bytes. */
  literal: boolean;
}

const FORMATS: FormatSpec[] = [
  {
    id: 'markdown',
    label: 'Markdown',
    hint: 'For a ticket, a pull request, or anything that renders markdown.',
    extension: 'md',
    shape: 'summary',
    literal: true,
  },
  {
    id: 'text',
    label: 'Plain text',
    hint: 'For an email, a chat window, or anywhere markdown would show as symbols.',
    extension: 'txt',
    shape: 'summary',
    literal: true,
  },
  {
    id: 'pdf',
    label: 'PDF',
    hint: 'A laid-out report, for attaching to a ticket or sending on.',
    extension: 'pdf',
    shape: 'summary',
    literal: false,
  },
  {
    id: 'docx',
    label: 'Word',
    hint: 'A .docx with the headings and paragraphs of the summary.',
    extension: 'docx',
    shape: 'summary',
    literal: false,
  },
  {
    id: 'csv',
    label: 'CSV',
    hint: 'One table per download, for anything that reads comma-separated values.',
    extension: 'csv',
    shape: 'tables',
    literal: false,
  },
  {
    id: 'xlsx',
    label: 'Spreadsheet',
    hint: 'A .xlsx with one sheet per table: capture, findings, conversations, addressing.',
    extension: 'xlsx',
    shape: 'tables',
    literal: false,
  },
];

const SHAPES: { id: Shape; label: string; hint: string }[] = [
  { id: 'summary', label: 'Summary', hint: 'What went wrong, in prose' },
  { id: 'tables', label: 'Tables', hint: 'The findings and flows as rows' },
];

function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

export function ExportPanel({ capture, file }: { capture: Capture; file: File | undefined }) {
  const [shape, setShape] = useState<Shape>('summary');
  const [format, setFormat] = useState<Format>('markdown');
  const [mode, setMode] = useState<PrivacyMode>('redacted');
  const [text, setText] = useState('');
  const [tables, setTables] = useState<Table[]>([]);
  const [sheet, setSheet] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
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

  // The summary. Markdown is the source for Word and for the printed page as
  // well as being a format in its own right, so it is fetched whenever the
  // chosen format is not plain text.
  const summaryFormat = format === 'text' ? 'text' : 'markdown';
  useEffect(() => {
    let cancelled = false;
    const open = session.current;
    if (!open) return;
    setCopied(false);
    void open.exportSummary(summaryFormat, mode).then((result) => {
      if (cancelled) return;
      if (typeof result === 'string') {
        setText(result);
        setError(null);
      } else {
        setError(result.error);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [summaryFormat, mode, file]);

  // The tables, redacted in the core by the same redactor as the summary.
  useEffect(() => {
    let cancelled = false;
    const open = session.current;
    if (!open || shape !== 'tables') return;
    void open.exportSummary('tables', mode).then((result) => {
      if (cancelled) return;
      if (typeof result === 'string') {
        const parsed = parseTables(result);
        setTables(parsed);
        setSheet((n) => (n < parsed.length ? n : 0));
        setError(null);
      } else {
        setError(result.error);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [shape, mode, file]);

  if (!file) {
    return (
      <p className="muted empty-note">
        This capture was not opened from a file in this session, so it cannot be written out again.
      </p>
    );
  }

  const chosen = FORMATS.find((f) => f.id === format) ?? FORMATS[0];
  const stem = capture.file.replace(/\.[^.]+$/, '');
  const shown = tables[sheet];
  const fileName =
    format === 'csv' && shown
      ? `${stem}-${shown.name.toLowerCase()}.csv`
      : `${stem}-summary.${chosen.extension}`;

  async function copy() {
    const value = shape === 'tables' && shown ? csv(shown) : text;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      // Clipboard access can be refused, and there is nothing to be done
      // about it: the text is on screen and can be selected.
      setError('The browser would not let the app use the clipboard. Select the text below instead.');
    }
  }

  function download() {
    if (format === 'pdf') {
      save(pdf(parseSummary(text), { file: capture.file, redacted: mode === 'redacted' }), fileName);
      return;
    }
    if (format === 'docx') {
      save(docx(text), fileName);
      return;
    }
    if (format === 'xlsx') {
      save(xlsx(tables), fileName);
      return;
    }
    if (format === 'csv') {
      if (!shown) return;
      save(new Blob([csv(shown)], { type: 'text/csv;charset=utf-8' }), fileName);
      return;
    }
    save(new Blob([text], { type: 'text/plain;charset=utf-8' }), fileName);
  }

  const available = FORMATS.filter((f) => f.shape === shape);

  return (
    <div className="export">
      <div className="export-controls">
        <div className="export-group" role="radiogroup" aria-label="What to export">
          <span className="muted">Export</span>
          {SHAPES.map((option) => (
            <button
              type="button"
              key={option.id}
              role="radio"
              aria-checked={shape === option.id}
              className={`chip ${shape === option.id ? 'is-on' : ''}`}
              title={option.hint}
              onClick={() => {
                setShape(option.id);
                setFormat(option.id === 'summary' ? 'markdown' : 'xlsx');
              }}
            >
              {option.label}
            </button>
          ))}
        </div>

        <div className="export-group" role="radiogroup" aria-label="Format">
          <span className="muted">As</span>
          {available.map((option) => (
            <button
              type="button"
              key={option.id}
              role="radio"
              aria-checked={format === option.id}
              className={`chip ${format === option.id ? 'is-on' : ''}`}
              title={option.hint}
              onClick={() => setFormat(option.id)}
            >
              {option.label}
            </button>
          ))}
        </div>

        <div className="export-group" role="radiogroup" aria-label="What this export may contain">
          <span className="muted">Addresses</span>
          <button
            type="button"
            role="radio"
            aria-checked={mode === 'redacted'}
            className={`chip ${mode === 'redacted' ? 'is-on' : ''}`}
            onClick={() => setMode('redacted')}
          >
            Replaced
          </button>
          <button
            type="button"
            role="radio"
            aria-checked={mode === 'full'}
            className={`chip ${mode === 'full' ? 'is-on' : ''}`}
            onClick={() => setMode('full')}
          >
            As captured
          </button>
        </div>
      </div>

      <p className="mode-note muted">
        {mode === 'redacted'
          ? 'Addresses, hardware addresses and names are replaced with labels like host-1, and the export says so, so whoever reads it knows. The real values stay on this machine.'
          : 'The capture’s real addresses and names go into the export. A ticket is usually read by more people than you expect, and it usually outlives the problem.'}
      </p>

      {error && <p className="problems">{error}</p>}

      {/* Which sheet the preview and a CSV download are showing. A
          spreadsheet gets every table at once, so this only steers the two
          that can hold one table. */}
      {shape === 'tables' && tables.length > 0 && (
        <div className="export-group export-sheets" role="radiogroup" aria-label="Table">
          <span className="muted">Table</span>
          {tables.map((table, i) => (
            <button
              type="button"
              key={table.name}
              role="radio"
              aria-checked={sheet === i}
              className={`chip ${sheet === i ? 'is-on' : ''}`}
              onClick={() => setSheet(i)}
            >
              {table.name} <span className="view-tab-count">{table.rows.length}</span>
            </button>
          ))}
        </div>
      )}

      <div className="export-actions">
        <button type="button" className="open-button primary" onClick={() => void copy()}>
          {copied ? 'Copied' : shape === 'tables' ? 'Copy as CSV' : 'Copy'}
        </button>
        <button type="button" className="open-button" onClick={download}>
          Download {chosen.extension.toUpperCase()}
        </button>
        <span className="muted export-size">
          {shape === 'tables' && shown
            ? `${shown.rows.length.toLocaleString()} ${shown.rows.length === 1 ? 'row' : 'rows'}`
            : `${text.length.toLocaleString()} characters`}
          {' · '}
          {format === 'xlsx' ? `${stem}-summary.xlsx` : fileName}
        </span>
      </div>

      {/* The panel's oldest promise is that what you see is what gets
          written. That is still true of markdown, text and CSV, and it
          cannot be true of a PDF, a Word file or a spreadsheet - so those
          say what the preview actually is rather than letting the old
          promise quietly cover them. */}
      {!chosen.literal && (
        <p className="export-caveat muted">
          {format === 'pdf'
            ? 'The preview below is the source. The PDF is this capture set as a report — headings, findings and tables laid out for the page. It is written here, on this machine, like every other export.'
            : format === 'docx'
              ? 'The preview below is the source. The .docx holds the same words as headings and paragraphs, without the markdown punctuation.'
              : format === 'xlsx'
                ? 'The preview below is one table. The .xlsx holds all of them, one sheet each.'
                : 'The preview below is this table. Each download holds one table.'}
        </p>
      )}

      {shape === 'tables' && shown ? (
        <div className="export-table-wrap">
          <table className="grid">
            <thead>
              <tr>
                {shown.columns.map((column) => (
                  <th key={column}>{column}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.rows.slice(0, 50).map((row, i) => (
                <tr key={i}>
                  {row.map((value, j) => (
                    <td key={j}>{value}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {shown.rows.length > 50 && (
            <p className="muted export-more">
              Showing the first 50 of {shown.rows.length.toLocaleString()}. The download holds every row.
            </p>
          )}
          {shown.rows.length === 0 && (
            <p className="muted export-more">
              Nothing in this table. That is an answer about the capture, not a failure to look.
            </p>
          )}
        </div>
      ) : (
        <pre className="pack export-preview">{text}</pre>
      )}
    </div>
  );
}
