// Reading the tabular export back out of the core.
//
// The core emits every table in one tab-separated document, already redacted,
// marked up with #TABLE and #COLS lines. This turns that back into rows. The
// front end never assembles these values from the JSON report, because that
// route goes around the redactor and a spreadsheet is the export most likely
// to be forwarded to somebody who should not have real addresses.

import type { Table } from './ooxml';

export function parseTables(wire: string): Table[] {
  const tables: Table[] = [];
  let current: Table | null = null;

  for (const line of wire.split('\n')) {
    if (line === '') continue;
    if (line.startsWith('#TABLE\t')) {
      current = { name: line.slice(7), columns: [], rows: [] };
      tables.push(current);
    } else if (line.startsWith('#COLS\t')) {
      if (current) current.columns = line.slice(6).split('\t');
    } else if (current) {
      const cells = line.split('\t');
      // A row that does not match its header would put values under the
      // wrong headings, which still looks like data. Pad or cut instead, so
      // what lands in a cell is at least under the right name.
      while (cells.length < current.columns.length) cells.push('');
      current.rows.push(cells.slice(0, current.columns.length));
    }
  }

  // A table with no rows is still worth a sheet: "no findings" is an answer,
  // and an absent sheet reads as the tool not having looked.
  return tables.filter((t) => t.columns.length > 0);
}
