// The conversation list and the packet explorer.
//
// Both of these exist to answer the question the dashboard cannot: "all
// right, but what actually happened?" A finding says a connection was
// refused; the explorer shows the two packets that say so, in order, with
// everything around them.
//
// The packets are not held in the page. The capture is re-opened in a worker
// when somebody looks at it, and the list asks for a hundred rows at a time.
// A capture with ten million packets would otherwise mean ten million objects
// in JavaScript before the first one appeared on screen.

import { useEffect, useMemo, useRef, useState } from 'react';
import { Explorer } from './analyse';
import { FilterBuilder } from './FilterBuilder';
import { conditionCount, describe, EMPTY_BUILDER, encode, isEmpty, type Filter } from './filter';
import {
  conversationLabel,
  formatBytes,
  formatClock,
  formatDuration,
  formatTime,
  type Capture,
  type Conversation,
  type PacketDetail,
  type PacketPage,
} from './report';

const PAGE = 100;

/**
 * A column header that sorts.
 *
 * `aria-sort` is the part that is easy to leave out and the part a screen
 * reader needs: without it the header is a button that appears to do
 * nothing.
 */
function SortHeader<K extends string>({
  label,
  column,
  sort,
  onSort,
  numeric,
}: {
  label: string;
  column: K;
  sort: { key: K; desc: boolean };
  onSort: (key: K) => void;
  numeric?: boolean;
}) {
  const active = sort.key === column;
  return (
    <th
      className={numeric ? 'num' : undefined}
      aria-sort={active ? (sort.desc ? 'descending' : 'ascending') : 'none'}
    >
      <button type="button" className="sort-header" onClick={() => onSort(column)}>
        {label}
        <span className="sort-mark" aria-hidden="true">
          {active ? (sort.desc ? '\u25be' : '\u25b4') : ''}
        </span>
      </button>
    </th>
  );
}

function useSort<K extends string>(initial: K) {
  const [sort, setSort] = useState<{ key: K; desc: boolean }>({ key: initial, desc: true });
  const onSort = (key: K) =>
    // Clicking the column already sorted reverses it; a different column
    // starts descending, which is what people expect from a size column and
    // tolerate everywhere else.
    setSort((current) => (current.key === key ? { key, desc: !current.desc } : { key, desc: true }));
  return { sort, onSort };
}

type ConversationColumn = 'conversation' | 'packets' | 'bytes' | 'duration' | 'outcome';

export function ConversationList({
  capture,
  onShowPackets,
}: {
  capture: Capture;
  onShowPackets: (firstPacket: number) => void;
}) {
  const { sort, onSort } = useSort<ConversationColumn>('bytes');
  const [text, setText] = useState('');

  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const matching = capture.conversations.filter(
      (c) => !needle || conversationLabel(c).toLowerCase().includes(needle) || c.outcome.includes(needle),
    );
    const sorted = [...matching].sort((a, b) => {
      switch (sort.key) {
        case 'packets':
          return a.packets - b.packets;
        case 'bytes':
          return a.bytes - b.bytes;
        case 'duration':
          return a.durationSeconds - b.durationSeconds;
        case 'outcome':
          return a.outcome.localeCompare(b.outcome);
        default:
          return conversationLabel(a).localeCompare(conversationLabel(b));
      }
    });
    return sort.desc ? sorted.reverse() : sorted;
  }, [capture.conversations, sort, text]);

  if (capture.conversations.length === 0) {
    return (
      <p className="muted empty-note">
        No conversations in this capture. Everything in it is below the IP layer - ARP, or a link-layer
        protocol this app does not take apart.
      </p>
    );
  }

  return (
    <>
      <div className="table-bar">
        <input
          className="search small"
          type="search"
          value={text}
          placeholder="Filter conversations by address, port or outcome"
          onChange={(e) => setText(e.target.value)}
        />
        <span className="muted">
          {rows.length.toLocaleString()} of {capture.conversationCount.toLocaleString()}
          {capture.conversationCount > capture.conversations.length &&
            ` - the first ${capture.conversations.length} by size are listed`}
        </span>
      </div>
      <table className="grid">
        <thead>
          <tr>
            <SortHeader label="Conversation" column="conversation" sort={sort} onSort={onSort} />
            <SortHeader label="Packets" column="packets" sort={sort} onSort={onSort} numeric />
            <SortHeader label="Bytes" column="bytes" sort={sort} onSort={onSort} numeric />
            <SortHeader label="Duration" column="duration" sort={sort} onSort={onSort} numeric />
            <SortHeader label="How it ended" column="outcome" sort={sort} onSort={onSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((c: Conversation) => (
            <tr key={c.firstPacket}>
              <td className="mono">{conversationLabel(c)}</td>
              <td className="num">{c.packets.toLocaleString()}</td>
              <td className="num">{formatBytes(c.bytes)}</td>
              <td className="num">{formatDuration(c.durationSeconds)}</td>
              <td>
                {c.outcome}
                {c.outcome !== 'completed' && <span className="muted"> · {c.confidence}</span>}
              </td>
              <td>
                <button type="button" className="linklike" onClick={() => onShowPackets(c.firstPacket)}>
                  Packets
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && (
        <p className="muted empty-note">
          No conversation matches that. Clear the box to see them all.
        </p>
      )}
    </>
  );
}

type AddressColumn = 'address' | 'mac' | 'evidence' | 'firstSeen' | 'observations';

/**
 * What the capture proves about which hardware address holds which address.
 *
 * The role column is the part that matters. For anything off the local
 * segment the hardware address on the packet belongs to the router, not to
 * the host, so a table that lists the two the same way is quietly wrong -
 * and it is wrong in the direction that sends somebody looking for a device
 * that was never there.
 */
export function AddressingTable({ capture }: { capture: Capture }) {
  const { sort, onSort } = useSort<AddressColumn>('address');
  const [text, setText] = useState('');

  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const matching = capture.bindings.filter(
      (b) =>
        !needle ||
        b.address.toLowerCase().includes(needle) ||
        b.mac.toLowerCase().includes(needle) ||
        b.evidence.toLowerCase().includes(needle),
    );
    const sorted = [...matching].sort((a, b) => {
      switch (sort.key) {
        case 'mac':
          return a.mac.localeCompare(b.mac);
        case 'evidence':
          return a.evidence.localeCompare(b.evidence);
        case 'firstSeen':
          return a.firstSeenUnixMs - b.firstSeenUnixMs;
        case 'observations':
          return a.observations - b.observations;
        default:
          return a.address.localeCompare(b.address, undefined, { numeric: true });
      }
    });
    return sort.desc && sort.key !== 'address' ? sorted.reverse() : sorted;
  }, [capture.bindings, sort, text]);

  if (capture.bindings.length === 0 && capture.nextHops.length === 0) {
    return (
      <p className="muted empty-note">
        Nothing in this capture proves which hardware address holds which network address. That takes ARP,
        and there is none here - which is normal for a capture taken away from the local segment.
      </p>
    );
  }

  return (
    <>
      {capture.bindings.length > 0 && (
        <>
          <div className="table-bar">
            <input
              className="search small"
              type="search"
              aria-label="Filter addresses"
              value={text}
              placeholder="Filter by address, hardware address or evidence"
              onChange={(e) => setText(e.target.value)}
            />
            <span className="muted">
              {rows.length.toLocaleString()} of {capture.bindings.length.toLocaleString()}
            </span>
          </div>
          <p className="muted empty-note">
            Every row is something the capture shows outright. An address not listed here was never claimed
            in front of this capture point, which is not the same as it not existing.
          </p>
          <table className="grid">
            <thead>
              <tr>
                <SortHeader label="Address" column="address" sort={sort} onSort={onSort} />
                <SortHeader label="Hardware address" column="mac" sort={sort} onSort={onSort} />
                <SortHeader label="What proves it" column="evidence" sort={sort} onSort={onSort} />
                <SortHeader label="First seen" column="firstSeen" sort={sort} onSort={onSort} />
                <th>Last seen</th>
                <SortHeader label="Times" column="observations" sort={sort} onSort={onSort} numeric />
                <th>That hardware address looks like</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((binding) => (
                <tr key={`${binding.address}-${binding.mac}`}>
                  <td className="mono">{binding.address}</td>
                  <td className="mono">{binding.mac}</td>
                  <td>
                    {binding.evidence} <span className="muted">· {binding.strength}</span>
                  </td>
                  <td className="mono">{formatClock(binding.firstSeenUnixMs)}</td>
                  <td className="mono">{formatClock(binding.lastSeenUnixMs)}</td>
                  <td className="num">{binding.observations}</td>
                  <td>
                    {binding.role}
                    {binding.addressesBehindMac > 1 && (
                      <span className="muted"> · carried {binding.addressesBehindMac} addresses</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && (
            <p className="muted empty-note">No address matches that. Clear the box to see them all.</p>
          )}
        </>
      )}

      {capture.nextHops.length > 0 && (
        <>
          <h3 className="addressing-head">Ways out of this network</h3>
          <p className="muted empty-note">
            These hardware addresses carried traffic for several different network addresses, which is what a
            router looks like from where this capture was taken. Traffic to anything beyond them shows their
            hardware address, not the far end's.
          </p>
          <table className="grid">
            <thead>
              <tr>
                <th>Hardware address</th>
                <th className="num">Addresses behind it</th>
                <th className="num">Packets</th>
              </tr>
            </thead>
            <tbody>
              {capture.nextHops.map((hop) => (
                <tr key={hop.mac}>
                  <td className="mono">{hop.mac}</td>
                  <td className="num">
                    {hop.addresses}
                    {hop.capped && <span className="muted"> or more</span>}
                  </td>
                  <td className="num">{hop.packets.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <p className="muted empty-note">
        Times are from the capture's own clock, which started {formatTime(capture.startedAtUnixMs)}.
      </p>
    </>
  );
}

export function PacketExplorer({
  capture,
  file,
  flowOfPacket,
  jumpTo,
  onClearFlow,
}: {
  capture: Capture;
  file: File | undefined;
  /** Show only this packet's conversation, or null for all of them. */
  flowOfPacket: number | null;
  /** Select this packet as soon as the list is up. */
  jumpTo: number | null;
  onClearFlow: () => void;
}) {
  const explorer = useRef<Explorer | null>(null);
  const [page, setPage] = useState<PacketPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [start, setStart] = useState(0);
  const [text, setText] = useState('');
  const [selected, setSelected] = useState<PacketDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<Filter>(EMPTY_BUILDER);
  const [builderOpen, setBuilderOpen] = useState(false);

  // The core reads the filter as text, and rebuilding that string is cheap,
  // but it is also the effect's dependency - so it is memoised to stop every
  // unrelated render from re-running the query.
  const encoded = useMemo(() => encode(filter), [filter]);

  // One capture open at a time. Closing it releases the file and everything
  // built from it, which is the whole reason the analysis pass does not keep
  // captures open in the first place.
  useEffect(() => {
    if (!file) return;
    const session = new Explorer(file);
    explorer.current = session;
    return () => {
      session.close();
      explorer.current = null;
    };
  }, [file]);

  // Starting at a packet means starting on the page that holds it.
  useEffect(() => {
    if (jumpTo === null) return;
    setStart(Math.floor(jumpTo / PAGE) * PAGE);
  }, [jumpTo]);

  useEffect(() => {
    let cancelled = false;
    const session = explorer.current;
    if (!session) return;
    setLoading(true);
    void session.packets({ start, count: PAGE, flowOfPacket, text, filter: encoded }).then((result) => {
      if (cancelled) return;
      setLoading(false);
      if ('error' in result) {
        setError(result.error);
        setPage(null);
      } else {
        setError(null);
        setPage(result);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [start, text, flowOfPacket, file, encoded]);

  // Open the packet a finding pointed at, once its page has arrived.
  useEffect(() => {
    if (jumpTo === null || !page) return;
    if (!page.rows.some((row) => row.index === jumpTo)) return;
    void openPacket(jumpTo);
    // openPacket is stable for the life of this component.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jumpTo, page]);

  async function openPacket(index: number) {
    const session = explorer.current;
    if (!session) return;
    const result = await session.packet(index);
    if ('error' in result) {
      setError(result.error);
      return;
    }
    setSelected(result);
  }

  if (!file) {
    return (
      <p className="muted empty-note">
        The packets for this capture are not available. The file is re-read when you open its packets, and
        this capture was not opened from a file in this session.
      </p>
    );
  }

  const shown = page?.rows ?? [];
  const matching = page?.matching ?? 0;

  return (
    <div className="explorer">
      <div className="explorer-bar">
        <input
          className="search small"
          type="search"
          aria-label="Filter packets"
          value={text}
          placeholder="Filter packets by address, port or protocol"
          onChange={(e) => {
            setStart(0);
            setText(e.target.value);
          }}
        />
        {flowOfPacket !== null && (
          <button type="button" className="chip is-on" onClick={onClearFlow}>
            One conversation only · show all
          </button>
        )}
        <button
          type="button"
          className={`chip ${!isEmpty(filter) ? 'is-on' : ''}`}
          aria-expanded={builderOpen}
          onClick={() => setBuilderOpen((open) => !open)}
        >
          Filter{!isEmpty(filter) && ` · ${conditionCount(filter)}`}
        </button>
        <span className="muted explorer-count">
          {matching.toLocaleString()} {matching === 1 ? 'packet' : 'packets'}
          {page && page.matching !== page.indexed && ` of ${page.indexed.toLocaleString()}`}
        </span>
      </div>

      {builderOpen && (
        <FilterBuilder
          filter={filter}
          onChange={(next) => {
            // A new filter means a different set of packets, so the page
            // number from the old one means nothing.
            setStart(0);
            setFilter(next);
          }}
        />
      )}

      {!builderOpen && !isEmpty(filter) && (
        <p className="muted empty-note">
          <strong>Showing:</strong> {describe(filter)}{' '}
          <button type="button" className="linklike" onClick={() => setBuilderOpen(true)}>
            change
          </button>
        </p>
      )}

      {capture.packetIndexCapped && (
        <p className="explorer-cap">
          This capture holds {capture.packets.toLocaleString()} packets and the explorer indexes the first{' '}
          {capture.indexedPackets.toLocaleString()}. Every finding was still drawn from the whole file - it
          is the packet list that stops here, not the analysis.
        </p>
      )}

      {error && <p className="problems">{error}</p>}

      <div className="explorer-body">
        <div className="packet-list">
          <table className="grid packets">
            <thead>
              <tr>
                <th className="num">#</th>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th className="num">Length</th>
                <th>What it says</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((row) => (
                <tr
                  key={row.index}
                  className={selected?.index === row.index ? 'is-selected' : ''}
                  onClick={() => void openPacket(row.index)}
                >
                  <td className="num mono">{row.index + 1}</td>
                  <td className="mono">{formatClock(row.tsUnixMs)}</td>
                  <td className="mono">{row.source || '-'}</td>
                  <td className="mono">{row.destination || '-'}</td>
                  <td>{row.protocol}</td>
                  <td className="num mono">
                    {row.length}
                    {row.truncated && (
                      <span className="muted" title="Cut short by the capture's snaplen">
                        {' '}
                        *
                      </span>
                    )}
                  </td>
                  <td className="summary">{row.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {shown.length === 0 && !loading && (
            <p className="muted empty-note">
              No packet matches that filter. The whole capture is still there -{' '}
              {isEmpty(filter) ? 'clear the search box' : 'loosen or clear the filter'} to see it.
            </p>
          )}

          {matching > PAGE && (
            <div className="pager">
              <button
                type="button"
                className="open-button ghost"
                disabled={start === 0}
                onClick={() => setStart(Math.max(0, start - PAGE))}
              >
                Earlier
              </button>
              <span className="muted">
                {(start + 1).toLocaleString()} to {Math.min(start + PAGE, matching).toLocaleString()}
              </span>
              <button
                type="button"
                className="open-button ghost"
                disabled={start + PAGE >= matching}
                onClick={() => setStart(start + PAGE)}
              >
                Later
              </button>
            </div>
          )}
        </div>

        {selected && <PacketDetailPanel detail={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}

function PacketDetailPanel({ detail, onClose }: { detail: PacketDetail; onClose: () => void }) {
  return (
    <aside className="packet-detail">
      <header>
        <h3>Packet {detail.index + 1}</h3>
        <button type="button" className="rail-close" onClick={onClose} aria-label="Close this packet">
          ×
        </button>
      </header>
      <p className="muted">{detail.summary}</p>

      {detail.truncated && (
        <p className="explorer-cap">
          Only {detail.capturedLength} of this packet's {detail.wireLength} bytes were captured. What is
          below is everything the file holds; the rest was never written.
        </p>
      )}

      {detail.layers.map((layer) => (
        <section key={layer.name} className="layer">
          <h4>{layer.name}</h4>
          <dl>
            {layer.fields.map((field) => (
              <div key={field.name}>
                <dt>{field.name}</dt>
                <dd className="mono">{field.value}</dd>
              </div>
            ))}
          </dl>
        </section>
      ))}

      <section className="layer">
        <h4>Bytes</h4>
        <HexDump hex={detail.bytes} />
      </section>
    </aside>
  );
}

function HexDump({ hex }: { hex: string }) {
  const lines = useMemo(() => {
    const bytes: number[] = [];
    for (let i = 0; i + 1 < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
    const out: { offset: string; hex: string; text: string }[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      out.push({
        offset: i.toString(16).padStart(4, '0'),
        hex: chunk.map((b) => b.toString(16).padStart(2, '0')).join(' '),
        // Printable ASCII only. A capture's own bytes are data, and letting
        // them through as anything else is how a hex view becomes a hazard.
        text: chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join(''),
      });
    }
    return out;
  }, [hex]);

  if (lines.length === 0) return <p className="muted">No bytes were captured for this packet.</p>;

  return (
    <pre className="hex">
      {lines.map((line) => (
        <div key={line.offset}>
          <span className="hex-offset">{line.offset}</span>
          <span className="hex-bytes">{line.hex}</span>
          <span className="hex-text">{line.text}</span>
        </div>
      ))}
    </pre>
  );
}
