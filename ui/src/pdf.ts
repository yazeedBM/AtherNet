// A PDF, written here, downloaded like any other file.
//
// Printing to PDF worked and was the wrong shape: it opens a dialog, the
// browser chooses the name, and what lands on the page is the screen with its
// furniture hidden rather than a document someone designed. This writes the
// file instead, so "Download PDF" means what it says and the layout is a
// decision rather than a side effect.
//
// No dependency, and none needed. A PDF is a handful of indirect objects and
// a cross-reference table, and the fourteen standard fonts - Helvetica,
// Times, Courier and their bold and italic cuts - are in every reader, so
// nothing has to be embedded. That matters here beyond saving bytes: an
// embedded font is a file fetched from somewhere, and the one promise this
// app makes is that nothing about a capture leaves the machine.

import type { Block } from './blocks';

// --------------------------------------------------------------- the canvas

const A4 = { width: 595.28, height: 841.89 };
const MARGIN = { top: 64, bottom: 58, left: 56, right: 56 };
const COLUMN = A4.width - MARGIN.left - MARGIN.right;

/** The ink. Print colours, not the screen's - dark enough to photocopy. */
const INK = '0.07 0.09 0.12';
const BODY = '0.22 0.26 0.32';
const MUTED = '0.45 0.50 0.57';
const RULE = '0.80 0.83 0.87';
const ERROR = '0.60 0.13 0.18';
const WARN = '0.52 0.32 0.00';
const COOL = '0.10 0.31 0.54';
const BAND = '0.95 0.96 0.97';

type FontId = 'F1' | 'F2' | 'F3';
const REGULAR: FontId = 'F1';
const BOLD: FontId = 'F2';
const MONO: FontId = 'F3';

// -------------------------------------------------------------- measurement

/**
 * How wide a string is, in points.
 *
 * Measured with the browser rather than from a built-in table of font
 * metrics. Arial is metrically compatible with Helvetica by design, and
 * Courier New with Courier, so the browser's own measurement matches what the
 * reader will lay out closely enough that no line arrives at the wrong place.
 * A table of 256 widths per face, typed from memory, would be a lot of
 * numbers with no way to notice one of them being wrong.
 */
const measurer = (() => {
  let ctx: CanvasRenderingContext2D | null = null;
  try {
    ctx = document.createElement('canvas').getContext('2d');
  } catch {
    ctx = null;
  }
  return (text: string, size: number, font: FontId): number => {
    if (!ctx) {
      // No canvas: a rough average, which only costs a slightly ragged
      // right edge. Never a reason to produce no document at all.
      return text.length * size * (font === MONO ? 0.6 : 0.5);
    }
    ctx.font =
      font === MONO
        ? `${size}px "Courier New", monospace`
        : `${font === BOLD ? 'bold ' : ''}${size}px Arial, Helvetica, sans-serif`;
    return ctx.measureText(text).width;
  };
})();

// ----------------------------------------------------------------- encoding

/**
 * Latin-1 plus the printer's punctuation, which is what WinAnsiEncoding is.
 *
 * The summary is written with real typographic marks - curly quotes, an em
 * dash, a bullet - and every one of them has a code point here. A character
 * with none is replaced rather than dropped, because a missing glyph in a
 * report about someone's network reads as data loss.
 */
const WIN_ANSI: Record<string, number> = {
  '€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85,
  '†': 0x86, '‡': 0x87, 'ˆ': 0x88, '‰': 0x89, 'Š': 0x8a,
  '‹': 0x8b, 'Œ': 0x8c, 'Ž': 0x8e, '‘': 0x91, '’': 0x92,
  '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97,
  '˜': 0x98, '™': 0x99, 'š': 0x9a, '›': 0x9b, 'œ': 0x9c,
  'ž': 0x9e, 'Ÿ': 0x9f,
};

/** What to write when a character has no place in WinAnsi at all. */
const SUBSTITUTE: Record<string, string> = {
  '→': '->',
  '←': '<-',
  '≤': '<=',
  '≥': '>=',
  '×': 'x',
  '✓': 'yes',
  '·': '-',
};

/** A PDF string literal, escaped and encoded. */
function pdfString(value: string): string {
  let out = '(';
  for (const c of value) {
    const replacement = SUBSTITUTE[c];
    if (replacement) {
      out += replacement;
      continue;
    }
    const code = WIN_ANSI[c] ?? c.codePointAt(0) ?? 63;
    if (code > 0xff) {
      out += '?';
    } else if (c === '(' || c === ')' || c === '\\') {
      out += `\\${c}`;
    } else if (code < 32 || code > 126) {
      out += `\\${code.toString(8).padStart(3, '0')}`;
    } else {
      out += c;
    }
  }
  return `${out})`;
}

// ------------------------------------------------------------------ the page

interface Page {
  ops: string[];
}

class Doc {
  pages: Page[] = [];
  page: Page;
  y = 0;

  constructor() {
    this.page = { ops: [] };
    this.pages.push(this.page);
    this.y = A4.height - MARGIN.top;
  }

  /** Start a new page, or stay where we are if there is room for `needed`. */
  room(needed: number) {
    if (this.y - needed >= MARGIN.bottom) return;
    this.page = { ops: [] };
    this.pages.push(this.page);
    this.y = A4.height - MARGIN.top;
  }

  text(value: string, x: number, size: number, font: FontId, colour: string) {
    this.page.ops.push(
      `BT /${font} ${size} Tf ${colour} rg 1 0 0 1 ${x.toFixed(2)} ${this.y.toFixed(2)} Tm ${pdfString(value)} Tj ET`,
    );
  }

  rect(x: number, y: number, width: number, height: number, colour: string) {
    this.page.ops.push(
      `${colour} rg ${x.toFixed(2)} ${y.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re f`,
    );
  }

  rule(y: number, colour = RULE, thickness = 0.6) {
    this.rect(MARGIN.left, y, COLUMN, thickness, colour);
  }
}

/** Break a string into lines that fit `width`, at spaces where it can. */
function wrap(value: string, width: number, size: number, font: FontId): string[] {
  const words = value.split(/\s+/).filter(Boolean);
  if (words.length === 0) return [''];
  const lines: string[] = [];
  let line = '';
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (measurer(candidate, size, font) <= width || line === '') {
      line = candidate;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  return lines;
}

/** Cut a string to fit, with an ellipsis, for a table cell that cannot wrap. */
function clip(value: string, width: number, size: number, font: FontId): string {
  if (measurer(value, size, font) <= width) return value;
  let cut = value;
  while (cut.length > 1 && measurer(`${cut}…`, size, font) > width) {
    cut = cut.slice(0, -1);
  }
  return `${cut}…`;
}

// ------------------------------------------------------------- the type scale

const TITLE = 21;
const HEADING = 12;
const TEXT = 9.5;
const SMALL = 8;
const LEADING = 1.42;

/**
 * A severity word at the start of a finding's title, so the colour is never
 * the only thing saying it. The summary writes these as "Error - something",
 * which is the shape this looks for.
 */
function severityOf(text: string): { word: string; colour: string; rest: string } | null {
  const match = /^(Error|Warning|For information|Informational)\s*[-–—:]\s*(.*)$/i.exec(text);
  if (!match) return null;
  const word = match[1];
  const colour = /^error$/i.test(word) ? ERROR : /^warning$/i.test(word) ? WARN : COOL;
  return { word, colour, rest: match[2] };
}

function drawTable(doc: Doc, header: string[], rows: string[][]) {
  const count = header.length;
  if (count === 0) return;

  // Columns share the width in proportion to the longest thing in each, so a
  // column of ports does not get the same room as a column of sentences.
  const demand = header.map((head, i) => {
    const longest = rows.reduce(
      (n, row) => Math.max(n, measurer(row[i] ?? '', TEXT, REGULAR)),
      measurer(head, SMALL, BOLD),
    );
    return Math.max(34, longest);
  });
  const total = demand.reduce((a, b) => a + b, 0);
  const widths = demand.map((d) => (d / total) * COLUMN);

  const rowHeight = TEXT * 1.9;
  doc.room(rowHeight * 2 + 10);

  doc.y -= 6;
  doc.rect(MARGIN.left, doc.y - 4, COLUMN, rowHeight, BAND);
  doc.y -= rowHeight - TEXT - 1;
  let x = MARGIN.left + 5;
  header.forEach((head, i) => {
    doc.text(clip(head, widths[i] - 10, SMALL, BOLD), x, SMALL, BOLD, INK);
    x += widths[i];
  });
  doc.y -= 7;
  doc.rule(doc.y + 2);

  for (const row of rows) {
    doc.room(rowHeight + 4);
    doc.y -= rowHeight - 4;
    x = MARGIN.left + 5;
    row.forEach((value, i) => {
      // A number belongs in the machine's face and ranged right, so a column
      // of them can be read down rather than across.
      const numeric = /^-?[\d.,]+$/.test(value.trim()) && value.trim() !== '';
      const font = numeric || /[:.]/.test(value) ? MONO : REGULAR;
      const size = font === MONO ? TEXT - 0.8 : TEXT;
      const fitted = clip(value, widths[i] - 10, size, font);
      const at = numeric
        ? x + widths[i] - 10 - measurer(fitted, size, font)
        : x;
      doc.text(fitted, at, size, font, BODY);
      x += widths[i];
    });
    doc.y -= 4;
    doc.rule(doc.y + 1, '0.90 0.92 0.94', 0.4);
  }
  doc.y -= 10;
}

// ------------------------------------------------------------------ assembly

export function pdf(blocks: Block[], options: { file: string; redacted: boolean }): Blob {
  const doc = new Doc();

  // The masthead. A report that arrives in a ticket should say what it is and
  // what made it before it says anything about somebody's network.
  doc.y -= 2;
  doc.text('AtherNet', MARGIN.left, SMALL, BOLD, COOL);
  doc.y -= 26;
  doc.text('Capture summary', MARGIN.left, TITLE, BOLD, INK);
  doc.y -= 14;
  doc.text(
    options.redacted ? 'Addresses replaced' : options.file,
    MARGIN.left,
    SMALL + 0.5,
    MONO,
    MUTED,
  );
  doc.y -= 10;
  doc.rule(doc.y, INK, 1.1);
  doc.y -= 20;

  for (const block of blocks) {
    switch (block.kind) {
      case 'title':
        // The core's own H1 repeats the masthead, so it is not drawn twice.
        break;

      case 'heading': {
        doc.room(HEADING * 3);
        doc.y -= 12;
        doc.rule(doc.y + HEADING + 4);
        doc.y -= 2;
        for (const line of wrap(block.text, COLUMN, HEADING, BOLD)) {
          doc.text(line, MARGIN.left, HEADING, BOLD, INK);
          doc.y -= HEADING * LEADING;
        }
        doc.y -= 3;
        break;
      }

      case 'quote': {
        // The redaction note, and anything else the summary sets apart. A
        // band rather than a quotation mark: it is a statement about the
        // document, not somebody being quoted.
        const lines = wrap(block.text, COLUMN - 22, TEXT, REGULAR);
        const height = lines.length * TEXT * LEADING + 12;
        doc.room(height);
        const top = doc.y + TEXT;
        doc.rect(MARGIN.left, top - height + 6, COLUMN, height, BAND);
        doc.rect(MARGIN.left, top - height + 6, 2.5, height, COOL);
        doc.y -= 4;
        for (const line of lines) {
          doc.text(line, MARGIN.left + 12, TEXT, REGULAR, BODY);
          doc.y -= TEXT * LEADING;
        }
        doc.y -= 10;
        break;
      }

      case 'bullet': {
        const lines = wrap(block.text, COLUMN - 14, TEXT, REGULAR);
        doc.room(lines.length * TEXT * LEADING);
        lines.forEach((line, i) => {
          if (i === 0) doc.text('•', MARGIN.left + 2, TEXT, REGULAR, MUTED);
          doc.text(line, MARGIN.left + 14, TEXT, REGULAR, BODY);
          doc.y -= TEXT * LEADING;
        });
        doc.y -= 3;
        break;
      }

      case 'table':
        drawTable(doc, block.header, block.rows);
        break;

      case 'para': {
        const severity = severityOf(block.text);
        if (severity) {
          // The severity word keeps its own colour and weight, and the title
          // runs on from it, so the two are one line and not two claims.
          const width = measurer(`${severity.word}  `, TEXT, BOLD);
          const lines = wrap(severity.rest, COLUMN - width, TEXT, BOLD);
          doc.room(lines.length * TEXT * LEADING + 6);
          lines.forEach((line, i) => {
            if (i === 0) doc.text(severity.word, MARGIN.left, TEXT, BOLD, severity.colour);
            doc.text(line, MARGIN.left + (i === 0 ? width : width), TEXT, BOLD, INK);
            doc.y -= TEXT * LEADING;
          });
          doc.y -= 3;
          break;
        }
        const lines = wrap(block.text, COLUMN, TEXT, REGULAR);
        doc.room(lines.length * TEXT * LEADING);
        for (const line of lines) {
          doc.text(line, MARGIN.left, TEXT, REGULAR, BODY);
          doc.y -= TEXT * LEADING;
        }
        doc.y -= 5;
        break;
      }
    }
  }

  return serialise(doc, options.redacted);
}

// ------------------------------------------------ objects, xref and trailer

function serialise(doc: Doc, redacted: boolean): Blob {
  // The footer goes on at the end, because "page 2 of 7" cannot be written
  // until the seventh page exists.
  const total = doc.pages.length;
  doc.pages.forEach((page, i) => {
    const y = MARGIN.bottom - 22;
    const left = redacted
      ? 'AtherNet — addresses replaced'
      : 'AtherNet';
    page.ops.push(
      `BT /${REGULAR} ${SMALL - 0.5} Tf ${MUTED} rg 1 0 0 1 ${MARGIN.left} ${y} Tm ${pdfString(left)} Tj ET`,
    );
    const label = `${i + 1} of ${total}`;
    const x = A4.width - MARGIN.right - measurer(label, SMALL - 0.5, REGULAR);
    page.ops.push(
      `BT /${REGULAR} ${SMALL - 0.5} Tf ${MUTED} rg 1 0 0 1 ${x.toFixed(2)} ${y} Tm ${pdfString(label)} Tj ET`,
    );
    page.ops.push(`${RULE} rg ${MARGIN.left} ${y + 14} ${COLUMN} 0.4 re f`);
  });

  const objects: string[] = [];
  const add = (body: string) => {
    objects.push(body);
    return objects.length;
  };

  // 1 catalog, 2 pages, then three fonts, then a page and a stream each.
  const catalogId = add('');
  const pagesId = add('');
  const fontIds: Record<FontId, number> = {
    F1: add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'),
    F2: add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'),
    F3: add('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>'),
  };

  const resources = `<< /Font << /F1 ${fontIds.F1} 0 R /F2 ${fontIds.F2} 0 R /F3 ${fontIds.F3} 0 R >> >>`;
  const pageIds: number[] = [];
  for (const page of doc.pages) {
    const stream = page.ops.join('\n');
    // One byte per character, because that is how the file is written out
    // below. Every operator and every string is ASCII by the time it gets
    // here - pdfString escapes anything else to octal - so this is exact.
    const streamId = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    pageIds.push(
      add(
        `<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${A4.width} ${A4.height}] /Resources ${resources} /Contents ${streamId} 0 R >>`,
      ),
    );
  }

  objects[catalogId - 1] = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
  objects[pagesId - 1] =
    `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;

  // Byte offsets, so the cross-reference table points at real places. An
  // xref that is off by a single byte gives a file that will not open at
  // all, so these are counted the same way the bytes are written at the end
  // of this function: one byte per character, Latin-1. Measuring them as
  // UTF-8 instead would count the four high bytes in the header below as
  // eight, and every offset after it would be wrong.
  let body = '%PDF-1.4\n%âãÏÓ\n';
  const offsets: number[] = [];

  objects.forEach((object, i) => {
    offsets.push(body.length);
    body += `${i + 1} 0 obj\n${object}\nendobj\n`;
  });

  const xref = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) {
    body += `${offset.toString().padStart(10, '0')} 00000 n \n`;
  }
  body += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;

  // Latin-1 out, not UTF-8: the strings are already WinAnsi code points, and
  // encoding them as UTF-8 would turn every one above 127 into two bytes and
  // two wrong glyphs.
  const bytes = new Uint8Array(body.length);
  for (let i = 0; i < body.length; i += 1) bytes[i] = body.charCodeAt(i) & 0xff;
  return new Blob([bytes as unknown as BlobPart], { type: 'application/pdf' });
}
