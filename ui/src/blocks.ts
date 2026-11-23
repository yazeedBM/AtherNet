// The summary, read back as blocks.
//
// The core writes the summary as markdown. Word and PDF both need it as
// structure rather than as a string, and they need the same structure - so it
// is parsed once, here, instead of twice in two files that would quietly
// drift apart.
//
// Deliberately shallow. The only markdown this ever sees is written by
// crates/athernet-core/src/export.rs, so a general parser would be a lot of
// surface with no second caller. What it does handle is exactly what that
// file emits: three levels of heading, paragraphs, bullets, block quotes and
// pipe tables.

export type Block =
  | { kind: 'title'; text: string }
  | { kind: 'heading'; text: string }
  | { kind: 'para'; text: string }
  | { kind: 'bullet'; text: string }
  | { kind: 'quote'; text: string }
  | { kind: 'table'; header: string[]; rows: string[][] };

/**
 * Emphasis and code fences carry no meaning once the text is out of markdown,
 * and shown as literal punctuation they read as noise. The values inside a
 * code span are addresses and names, which the reader wants; the backticks
 * around them are scaffolding, which they do not.
 */
const plain = (text: string) => text.replace(/\*\*/g, '').replace(/`+/g, '').trim();

const isRule = (line: string) => /^\|[\s:|-]+\|$/.test(line);

const cells = (line: string) =>
  line
    .split('|')
    .slice(1, -1)
    .map((c) => plain(c));

export function parseSummary(markdown: string): Block[] {
  const lines = markdown.split('\n');
  const out: Block[] = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trimEnd();
    if (line === '') continue;

    if (line.startsWith('|')) {
      // A run of pipe lines is one table. The rule line under the header is
      // markdown's own scaffolding and never becomes a row.
      const rows: string[][] = [];
      let header: string[] = [];
      let first = true;
      while (i < lines.length && lines[i].trimEnd().startsWith('|')) {
        const current = lines[i].trimEnd();
        if (isRule(current)) {
          i += 1;
          continue;
        }
        if (first) {
          header = cells(current);
          first = false;
        } else {
          rows.push(cells(current));
        }
        i += 1;
      }
      i -= 1;
      // A header on its own is not a table, it is a stray line.
      if (header.length > 0) out.push({ kind: 'table', header, rows });
      continue;
    }

    if (line.startsWith('# ')) out.push({ kind: 'title', text: plain(line.slice(2)) });
    else if (line.startsWith('## ')) out.push({ kind: 'heading', text: plain(line.slice(3)) });
    else if (line.startsWith('### ')) out.push({ kind: 'heading', text: plain(line.slice(4)) });
    else if (line.startsWith('> ')) out.push({ kind: 'quote', text: plain(line.slice(2)) });
    else if (line.startsWith('- ')) out.push({ kind: 'bullet', text: plain(line.slice(2)) });
    else out.push({ kind: 'para', text: plain(line) });
  }

  return out;
}
