// Writing a capture out for somebody who will read it somewhere else.
//
// The whole point is a ticket, an email, or a vendor who will never see the
// capture file. So the panel shows the exact text before it goes anywhere -
// the same string that gets copied or downloaded, not a rendering of it -
// and the privacy choice sits next to the preview rather than in a settings
// page, because an export leaves the machine by definition.

import { useEffect, useRef, useState } from 'react';
import { Explorer } from './analyse';
import type { Capture, PrivacyMode } from './report';

type Format = 'markdown' | 'text';

const FORMATS: { id: Format; label: string; hint: string; extension: string }[] = [
  {
    id: 'markdown',
    label: 'Markdown',
    hint: 'For a ticket, a pull request, or anything that renders markdown.',
    extension: 'md',
  },
  {
    id: 'text',
    label: 'Plain text',
    hint: 'For an email, a chat window, or anywhere markdown would show as symbols.',
    extension: 'txt',
  },
];

export function ExportPanel({ capture, file }: { capture: Capture; file: File | undefined }) {
  const [format, setFormat] = useState<Format>('markdown');
  const [mode, setMode] = useState<PrivacyMode>('redacted');
  const [text, setText] = useState('');
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

  useEffect(() => {
    let cancelled = false;
    const open = session.current;
    if (!open) return;
    setCopied(false);
    void open.exportSummary(format, mode).then((result) => {
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
  }, [format, mode, file]);

  if (!file) {
    return (
      <p className="muted empty-note">
        This capture was not opened from a file in this session, so it cannot be written out again.
      </p>
    );
  }

  const chosen = FORMATS.find((f) => f.id === format) ?? FORMATS[0];
  const fileName = `${capture.file.replace(/\.[^.]+$/, '')}-summary.${chosen.extension}`;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      // Clipboard access can be refused, and there is nothing to be done
      // about it: the text is on screen and can be selected.
      setError('The browser would not let the app use the clipboard. Select the text below instead.');
    }
  }

  function download() {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="export">
      <div className="export-controls">
        <div className="export-group" role="radiogroup" aria-label="Format">
          <span className="muted">Format</span>
          {FORMATS.map((option) => (
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

        <div className="export-group" role="radiogroup" aria-label="What this summary may contain">
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
          ? 'Addresses, hardware addresses and names are replaced with labels like host-1, and the summary says so at the top so whoever reads it knows. The real values stay on this machine.'
          : 'The capture’s real addresses and names go into the summary. A ticket is usually read by more people than you expect, and it usually outlives the problem.'}
      </p>

      {error && <p className="problems">{error}</p>}

      <div className="export-actions">
        <button type="button" className="open-button primary" onClick={() => void copy()}>
          {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" className="open-button" onClick={download}>
          Download {chosen.extension.toUpperCase()}
        </button>
        <span className="muted export-size">
          {text.length.toLocaleString()} characters · {fileName}
        </span>
      </div>

      <pre className="pack export-preview">{text}</pre>
    </div>
  );
}
