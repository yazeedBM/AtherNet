// Spreadsheets and documents, written in the browser.
//
// A .xlsx and a .docx are both a ZIP holding a handful of XML files, so one
// small ZIP writer buys both formats. Everything here runs on the machine the
// capture was read on, which is the only reason these formats are available
// at all: the alternative - posting the data to a service that renders it -
// would undo the one promise the whole app is built around.
//
// The entries are STORED rather than deflated. Excel and Word both accept an
// uncompressed member, the files are a few hundred kilobytes of text at most,
// and not compressing means no dependency and no second code path to get
// wrong. If these ever need to be small, `CompressionStream('deflate-raw')`
// is the way, and only `method` and the two sizes change.

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

interface Entry {
  name: string;
  data: Uint8Array;
}

/** A ZIP file with every member stored uncompressed. */
export function zip(entries: Entry[]): Blob {
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;

  // A fixed timestamp rather than the clock. Two exports of the same capture
  // should be identical files - it makes them comparable, and the moment
  // somebody produced a report is not information the report needs to carry.
  const time = 0;
  const date = (2024 - 1980) * 512 + 1 * 32 + 1;

  for (const entry of entries) {
    const name = new TextEncoder().encode(entry.name);
    const sum = crc32(entry.data);
    const size = entry.data.length;

    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    // Bit 11 says the name is UTF-8.
    local.setUint16(6, 0x0800, true);
    local.setUint16(8, 0, true);
    local.setUint16(10, time, true);
    local.setUint16(12, date, true);
    local.setUint32(14, sum, true);
    local.setUint32(18, size, true);
    local.setUint32(22, size, true);
    local.setUint16(26, name.length, true);
    local.setUint16(28, 0, true);
    parts.push(new Uint8Array(local.buffer), name, entry.data);

    const header = new DataView(new ArrayBuffer(46));
    header.setUint32(0, 0x02014b50, true);
    header.setUint16(4, 20, true);
    header.setUint16(6, 20, true);
    header.setUint16(8, 0x0800, true);
    header.setUint16(10, 0, true);
    header.setUint16(12, time, true);
    header.setUint16(14, date, true);
    header.setUint32(16, sum, true);
    header.setUint32(20, size, true);
    header.setUint32(24, size, true);
    header.setUint16(28, name.length, true);
    header.setUint16(30, 0, true);
    header.setUint16(32, 0, true);
    header.setUint16(34, 0, true);
    header.setUint16(36, 0, true);
    header.setUint32(38, 0, true);
    header.setUint32(42, offset, true);
    central.push(new Uint8Array(header.buffer), name);

    offset += 30 + name.length + size;
  }

  const centralSize = central.reduce((n, p) => n + p.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(4, 0, true);
  end.setUint16(6, 0, true);
  end.setUint16(8, entries.length, true);
  end.setUint16(10, entries.length, true);
  end.setUint32(12, centralSize, true);
  end.setUint32(16, offset, true);
  end.setUint16(20, 0, true);

  // Every piece here is a Uint8Array over a plain ArrayBuffer. TypeScript
  // types TextEncoder's output as ArrayBufferLike, which also admits a
  // SharedArrayBuffer and so is not a BlobPart; none of these ever is one.
  const pieces = [...parts, ...central, new Uint8Array(end.buffer)] as unknown as BlobPart[];
  return new Blob(pieces, { type: 'application/octet-stream' });
}

const text = (s: string) => new TextEncoder().encode(s);

/**
 * XML-escape, and drop what XML 1.0 cannot carry at all.
 *
 * The core already replaces unprintable bytes from a capture with a full
 * stop, so this is the second line rather than the first - but a document
 * that will not open is a worse failure than a stripped character, and a
 * capture is attacker-controlled input by definition.
 */
function esc(value: string): string {
  let out = '';
  for (const c of value) {
    const code = c.codePointAt(0) ?? 0;
    if (c === '&') out += '&amp;';
    else if (c === '<') out += '&lt;';
    else if (c === '>') out += '&gt;';
    else if (c === '"') out += '&quot;';
    else if (code === 9 || code === 10 || code === 13) out += c;
    else if (code < 0x20) out += ' ';
    else out += c;
  }
  return out;
}

// --------------------------------------------------------------- the sheets

export interface Table {
  name: string;
  columns: string[];
  rows: string[][];
}

/** A1, B1 ... Z1, AA1. */
function ref(column: number, row: number): string {
  let name = '';
  let n = column;
  while (n >= 0) {
    name = String.fromCharCode(65 + (n % 26)) + name;
    n = Math.floor(n / 26) - 1;
  }
  return `${name}${row}`;
}

/** Numbers go in as numbers, so a spreadsheet can total and sort them. */
const isNumber = (value: string) => value !== '' && /^-?\d+(\.\d+)?$/.test(value);

function sheet(table: Table): string {
  const rows: string[] = [];
  const line = (index: number, cells: string[], header: boolean) => {
    const parts = cells.map((value, column) => {
      const at = ref(column, index);
      if (!header && isNumber(value)) {
        return `<c r="${at}"><v>${value}</v></c>`;
      }
      const style = header ? ' s="1"' : '';
      return `<c r="${at}"${style} t="inlineStr"><is><t xml:space="preserve">${esc(value)}</t></is></c>`;
    });
    rows.push(`<row r="${index}">${parts.join('')}</row>`);
  };

  line(1, table.columns, true);
  table.rows.forEach((row, i) => line(i + 2, row, false));

  // A width per column, from the longest value in it, so nothing opens as
  // a row of #### and nobody has to drag a dozen column edges before they
  // can read the thing.
  const widths = table.columns.map((column, i) => {
    const longest = table.rows.reduce(
      (n, row) => Math.max(n, (row[i] ?? '').length),
      column.length,
    );
    return `<col min="${i + 1}" max="${i + 1}" width="${Math.min(60, longest + 3)}" customWidth="1"/>`;
  });

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols>${widths.join(
    '',
  )}</cols><sheetData>${rows.join('')}</sheetData></worksheet>`;
}

/** Excel refuses a sheet name holding any of these, or one over 31 characters. */
const sheetName = (name: string) => name.replace(/[\\/?*[\]:]/g, '-').slice(0, 31);

export function xlsx(tables: Table[]): Blob {
  const used = tables.length > 0 ? tables : [{ name: 'Empty', columns: ['Nothing'], rows: [] }];

  const sheets = used
    .map((t, i) => `<sheet name="${esc(sheetName(t.name))}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`)
    .join('');
  const rels = used
    .map(
      (_, i) =>
        `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`,
    )
    .join('');
  const overrides = used
    .map(
      (_, i) =>
        `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`,
    )
    .join('');

  const entries: Entry[] = [
    {
      name: '[Content_Types].xml',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${overrides}</Types>`),
    },
    {
      name: '_rels/.rels',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`),
    },
    {
      name: 'xl/workbook.xml',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets}</sheets></workbook>`),
    },
    {
      name: 'xl/_rels/workbook.xml.rels',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels}<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`),
    },
    {
      // Two formats: plain, and bold for the header row. Any more and this
      // would be a theme, which a spreadsheet of someone's own data does not
      // want from the tool that produced it.
      name: 'xl/styles.xml',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="1"><fill><patternFill patternType="none"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>`),
    },
  ];

  used.forEach((table, i) => {
    entries.push({ name: `xl/worksheets/sheet${i + 1}.xml`, data: text(sheet(table)) });
  });

  return zip(entries);
}

// ------------------------------------------------------------- the document

type Para = { text: string; style: 'title' | 'heading' | 'body' | 'mono' };

/**
 * Turn the summary's markdown into paragraphs.
 *
 * Deliberately shallow: headings, list items and everything else. The summary
 * is the only thing ever passed here and it is written by this project, so a
 * full markdown parser would be code with no second caller and a lot of
 * surface to get wrong.
 */
export function paragraphs(markdown: string): Para[] {
  const out: Para[] = [];
  for (const raw of markdown.split('\n')) {
    const line = raw.trimEnd();
    if (line === '') continue;
    if (line.startsWith('# ')) {
      out.push({ text: line.slice(2), style: 'title' });
    } else if (line.startsWith('## ')) {
      out.push({ text: line.slice(3), style: 'heading' });
    } else if (line.startsWith('### ')) {
      out.push({ text: line.slice(4), style: 'heading' });
    } else if (line.startsWith('|')) {
      // A markdown table in a Word document would be a wall of pipes. The
      // rule line is dropped and the rest become plain rows; anybody who
      // wants the table as a table has the spreadsheet.
      if (/^\|[\s:|-]+\|$/.test(line)) continue;
      const cells = line.split('|').slice(1, -1).map((c) => c.trim());
      out.push({ text: cells.join('  ·  '), style: 'mono' });
    } else if (line.startsWith('> ')) {
      out.push({ text: line.slice(2), style: 'body' });
    } else if (line.startsWith('- ')) {
      out.push({ text: `•  ${line.slice(2)}`, style: 'body' });
    } else {
      out.push({ text: line, style: 'body' });
    }
    // Markdown emphasis and code fences mean nothing in a Word paragraph, so
    // they are stripped from the text rather than shown as punctuation.
    const last = out[out.length - 1];
    if (last) last.text = last.text.replace(/\*\*/g, '').replace(/`+/g, '');
  }
  return out;
}

export function docx(markdown: string): Blob {
  const body = paragraphs(markdown)
    .map((p) => {
      const size =
        p.style === 'title' ? 36 : p.style === 'heading' ? 28 : 22;
      const bold = p.style === 'title' || p.style === 'heading';
      const font = p.style === 'mono' ? 'Consolas' : 'Calibri';
      const spacing = p.style === 'heading' ? '<w:spacing w:before="240" w:after="120"/>' : '<w:spacing w:after="120"/>';
      return `<w:p><w:pPr>${spacing}<w:rPr><w:rFonts w:ascii="${font}" w:hAnsi="${font}"/><w:sz w:val="${size}"/>${bold ? '<w:b/>' : ''}</w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="${font}" w:hAnsi="${font}"/><w:sz w:val="${size}"/>${bold ? '<w:b/>' : ''}</w:rPr><w:t xml:space="preserve">${esc(p.text)}</w:t></w:r></w:p>`;
    })
    .join('');

  return zip([
    {
      name: '[Content_Types].xml',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`),
    },
    {
      name: '_rels/.rels',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`),
    },
    {
      name: 'word/document.xml',
      data: text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}</w:body></w:document>`),
    },
  ]);
}

// -------------------------------------------------------------------- CSV

/**
 * One table as CSV.
 *
 * Quoted per RFC 4180, with CRLF line endings because that is what Excel
 * expects on the platform most of these will be opened on.
 */
export function csv(table: Table): string {
  const quote = (value: string) =>
    /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
  const lines = [table.columns.map(quote).join(',')];
  for (const row of table.rows) lines.push(row.map(quote).join(','));
  return `${lines.join('\r\n')}\r\n`;
}
