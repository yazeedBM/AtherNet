// The map.
//
// Every edge here is a conversation the capture actually holds, and every
// node is an address that appeared in one. Nothing is inferred about the
// shape of the network: this is not a topology diagram, and it does not
// claim to show the switches and routers between these hosts. It shows who
// spoke to whom, which is a different and more honest picture - a capture
// taken at one point on the network cannot see the rest of it.
//
// What makes it worth having over the conversation table is that a problem
// has a shape. Twenty hosts all failing to reach one server looks like one
// thing; one host failing to reach twenty looks like another, and the table
// shows both as a list of rows.
//
// There is no graph library here. The layout is a small force simulation
// run to a fixed number of steps from a seeded start, so the same capture
// always draws the same way - a map that rearranged itself on every visit
// would be useless for comparing two readings of the same network.

import { useEffect, useMemo, useRef, useState } from 'react';
import { conversationLabel, formatBytes, type Capture, type Conversation } from './report';

/** Past this many, the picture stops being readable before it stops being drawable. */
const MAX_NODES = 120;

const WIDTH = 1000;
const HEIGHT = 680;

type Tone = 'normal' | 'warning' | 'error';

interface Node {
  id: string;
  mac?: string;
  role?: string;
  bytes: number;
  packets: number;
  degree: number;
  tone: Tone;
  x: number;
  y: number;
}

interface Edge {
  a: string;
  b: string;
  bytes: number;
  packets: number;
  tone: Tone;
  outcomes: string[];
  /** The conversation to open when this edge is clicked. */
  firstPacket: number;
  conversations: Conversation[];
}

const worse = (a: Tone, b: Tone): Tone =>
  a === 'error' || b === 'error' ? 'error' : a === 'warning' || b === 'warning' ? 'warning' : 'normal';

/** What a conversation's ending says about the line that represents it. */
function toneOf(outcome: string): Tone {
  if (outcome === 'completed') return 'normal';
  if (outcome === 'connection refused') return 'error';
  return 'warning';
}

/**
 * A seeded generator, so the same capture lays out the same way every time.
 * Comparing this morning's capture with this afternoon's is the whole point
 * of a picture, and it cannot be done if the picture moves.
 */
function seeded(seed: number) {
  let state = seed || 1;
  return () => {
    state = (state * 1664525 + 1013904223) % 4294967296;
    return state / 4294967296;
  };
}

function buildGraph(capture: Capture): { nodes: Node[]; edges: Edge[]; hidden: number } {
  const macOf = new Map(capture.bindings.map((b) => [b.address, b]));

  // Conversations are per port pair; the map is per host pair, because
  // fifty connections between two machines are one relationship.
  const edges = new Map<string, Edge>();
  for (const c of capture.conversations) {
    const [a, b] = [c.a, c.b].sort();
    const key = `${a}|${b}`;
    const existing = edges.get(key);
    const tone = toneOf(c.outcome);
    if (existing) {
      existing.bytes += c.bytes;
      existing.packets += c.packets;
      existing.tone = worse(existing.tone, tone);
      existing.conversations.push(c);
      if (!existing.outcomes.includes(c.outcome)) existing.outcomes.push(c.outcome);
    } else {
      edges.set(key, {
        a,
        b,
        bytes: c.bytes,
        packets: c.packets,
        tone,
        outcomes: [c.outcome],
        firstPacket: c.firstPacket,
        conversations: [c],
      });
    }
  }

  const nodes = new Map<string, Node>();
  const touch = (id: string) => {
    let node = nodes.get(id);
    if (!node) {
      const binding = macOf.get(id);
      node = {
        id,
        mac: binding?.mac,
        role: binding?.role,
        bytes: 0,
        packets: 0,
        degree: 0,
        tone: 'normal',
        x: 0,
        y: 0,
      };
      nodes.set(id, node);
    }
    return node;
  };

  for (const edge of edges.values()) {
    for (const id of [edge.a, edge.b]) {
      const node = touch(id);
      node.bytes += edge.bytes;
      node.packets += edge.packets;
      node.degree += 1;
      node.tone = worse(node.tone, edge.tone);
    }
  }

  // A finding about an address outranks anything its conversations say.
  for (const finding of capture.findings) {
    if (finding.severity === 'info') continue;
    const tone: Tone = finding.severity === 'error' ? 'error' : 'warning';
    for (const endpoint of finding.endpoints) {
      const address = endpoint.split(':')[0];
      const node = nodes.get(address);
      if (node) node.tone = worse(node.tone, tone);
    }
  }

  // Busiest first, then cut. The ones left out are counted, not hidden.
  const kept = [...nodes.values()].sort((x, y) => y.bytes - x.bytes).slice(0, MAX_NODES);
  const keptIds = new Set(kept.map((n) => n.id));
  const keptEdges = [...edges.values()].filter((e) => keptIds.has(e.a) && keptIds.has(e.b));

  return { nodes: kept, edges: keptEdges, hidden: nodes.size - kept.length };
}

/**
 * Repulsion between every pair, attraction along every edge, and a pull
 * towards the middle. Two hundred steps is enough for a hundred nodes and
 * finishes faster than a frame.
 */
function layout(nodes: Node[], edges: Edge[]) {
  const random = seeded(nodes.length * 7919 + edges.length);
  const index = new Map(nodes.map((n, i) => [n.id, i]));

  // Start on a circle rather than at random: a ring untangles into a graph
  // far more reliably than a cloud does.
  nodes.forEach((node, i) => {
    const angle = (i / Math.max(1, nodes.length)) * Math.PI * 2;
    const jitter = random() * 30 - 15;
    node.x = WIDTH / 2 + Math.cos(angle) * (260 + jitter);
    node.y = HEIGHT / 2 + Math.sin(angle) * (220 + jitter);
  });

  const steps = 220;
  for (let step = 0; step < steps; step += 1) {
    const cooling = 1 - step / steps;

    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = i + 1; j < nodes.length; j += 1) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let distance = Math.hypot(dx, dy);
        if (distance < 0.01) {
          dx = random() - 0.5;
          dy = random() - 0.5;
          distance = 0.01;
        }
        const push = (9000 / (distance * distance)) * cooling;
        const ux = (dx / distance) * push;
        const uy = (dy / distance) * push;
        a.x += ux;
        a.y += uy;
        b.x -= ux;
        b.y -= uy;
      }
    }

    for (const edge of edges) {
      const a = nodes[index.get(edge.a)!];
      const b = nodes[index.get(edge.b)!];
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const distance = Math.max(1, Math.hypot(dx, dy));
      const pull = ((distance - 150) * 0.012) * cooling;
      const ux = (dx / distance) * pull;
      const uy = (dy / distance) * pull;
      a.x += ux;
      a.y += uy;
      b.x -= ux;
      b.y -= uy;
    }

    for (const node of nodes) {
      node.x += (WIDTH / 2 - node.x) * 0.004 * cooling;
      node.y += (HEIGHT / 2 - node.y) * 0.004 * cooling;
      node.x = Math.min(WIDTH - 40, Math.max(40, node.x));
      node.y = Math.min(HEIGHT - 40, Math.max(40, node.y));
    }
  }
}

export function NetworkMap({
  capture,
  onShowPackets,
}: {
  capture: Capture;
  onShowPackets: (firstPacket: number) => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const dragging = useRef<{ x: number; y: number } | null>(null);

  const graph = useMemo(() => {
    const built = buildGraph(capture);
    layout(built.nodes, built.edges);
    return built;
  }, [capture]);

  // The map used to open at 1:1 on a 1000x680 canvas whatever it had to
  // draw, so four addresses - which is most captures - sat in a knot in
  // the middle of an empty rectangle, and "Fit" put them back exactly
  // where they already were. Fit now means what it says: the view is the
  // box the addresses actually occupy, with room to breathe.
  const home = useMemo(() => {
    if (graph.nodes.length === 0) return { x: 0, y: 0, scale: 1 };
    const xs = graph.nodes.map((n) => n.x);
    const ys = graph.nodes.map((n) => n.y);
    // Enough margin for the biggest node plus the label hanging under it.
    const pad = 70;
    const left = Math.min(...xs) - pad;
    const top = Math.min(...ys) - pad;
    const width = Math.max(Math.max(...xs) + pad - left, 220);
    const height = Math.max(Math.max(...ys) + pad - top, 160);
    // One scale for both axes, so nothing is stretched.
    const scale = Math.min(WIDTH / width, HEIGHT / height, 3);
    return {
      x: left - (WIDTH / scale - width) / 2,
      y: top - (HEIGHT / scale - height) / 2,
      scale,
    };
  }, [graph]);

  const [view, setView] = useState(home);

  // A different capture is a different graph, so it gets its own fit.
  useEffect(() => setView(home), [home]);

  // A capture the map cannot say anything about says so, rather than
  // drawing an empty box.
  useEffect(() => setSelected(null), [capture.id]);

  if (graph.nodes.length === 0) {
    return (
      <p className="muted empty-note">
        Nothing in this capture is a conversation between two addresses, so there is no map to draw. That is
        normal for a file holding only ARP, or only one direction of traffic below the IP layer.
      </p>
    );
  }

  const neighbours = new Set<string>();
  if (selected) {
    neighbours.add(selected);
    for (const edge of graph.edges) {
      if (edge.a === selected) neighbours.add(edge.b);
      if (edge.b === selected) neighbours.add(edge.a);
    }
  }

  const position = new Map(graph.nodes.map((n) => [n.id, n]));
  const biggest = Math.max(...graph.nodes.map((n) => n.bytes), 1);
  const radius = (node: Node) => 7 + Math.sqrt(node.bytes / biggest) * 15;

  const chosen = selected ? position.get(selected) : null;
  const chosenEdges = selected
    ? graph.edges.filter((e) => e.a === selected || e.b === selected)
    : [];

  const viewBox = `${view.x} ${view.y} ${WIDTH / view.scale} ${HEIGHT / view.scale}`;

  return (
    <div className="map">
      <div className="map-bar">
        <span className="muted">
          {graph.nodes.length} {graph.nodes.length === 1 ? 'address' : 'addresses'},{' '}
          {graph.edges.length} {graph.edges.length === 1 ? 'pair' : 'pairs'} talking
          {graph.hidden > 0 && ` - ${graph.hidden} quieter ${graph.hidden === 1 ? 'address is' : 'addresses are'} left out`}
        </span>
        <span className="map-legend">
          <span className="key key-error" /> something failed
          <span className="key key-warning" /> something unanswered
          <span className="key key-normal" /> completed
        </span>
        <span className="map-zoom">
          <button type="button" className="open-button ghost" onClick={() => setView(home)}>
            Fit
          </button>
        </span>
      </div>

      <div className="map-body">
        <svg
          viewBox={viewBox}
          className="map-svg"
          role="img"
          aria-label={`A map of ${graph.nodes.length} addresses and the conversations between them`}
          onMouseDown={(e) => {
            dragging.current = { x: e.clientX, y: e.clientY };
          }}
          onMouseMove={(e) => {
            if (!dragging.current) return;
            const dx = (e.clientX - dragging.current.x) / view.scale;
            const dy = (e.clientY - dragging.current.y) / view.scale;
            dragging.current = { x: e.clientX, y: e.clientY };
            setView((v) => ({ ...v, x: v.x - dx, y: v.y - dy }));
          }}
          onMouseUp={() => {
            dragging.current = null;
          }}
          onMouseLeave={() => {
            dragging.current = null;
          }}
          onWheel={(e) => {
            const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
            setView((v) => ({ ...v, scale: Math.min(4, Math.max(0.4, v.scale * factor)) }));
          }}
        >
          {graph.edges.map((edge) => {
            const a = position.get(edge.a)!;
            const b = position.get(edge.b)!;
            const dim = selected !== null && edge.a !== selected && edge.b !== selected;
            // A gentle curve, so two lines between the same region of the
            // picture do not lie on top of each other.
            const mx = (a.x + b.x) / 2 + (b.y - a.y) * 0.08;
            const my = (a.y + b.y) / 2 - (b.x - a.x) * 0.08;
            return (
              <path
                key={`${edge.a}|${edge.b}`}
                className={`edge edge-${edge.tone} ${dim ? 'is-dim' : ''}`}
                d={`M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}`}
                strokeWidth={1 + Math.sqrt(edge.packets) * 0.12}
                onClick={() => onShowPackets(edge.firstPacket)}
              >
                <title>
                  {`${edge.a} and ${edge.b}: ${edge.packets} packets, ${formatBytes(edge.bytes)}, ${edge.outcomes.join(', ')}`}
                </title>
              </path>
            );
          })}

          {graph.nodes.map((node) => {
            const dim = selected !== null && !neighbours.has(node.id);
            return (
              <g
                key={node.id}
                className={`node node-${node.tone} ${dim ? 'is-dim' : ''} ${selected === node.id ? 'is-chosen' : ''}`}
                transform={`translate(${node.x} ${node.y})`}
                onClick={() => setSelected(selected === node.id ? null : node.id)}
              >
                <circle r={radius(node)} />
                {/* An address nobody can read is not a label. These were
                    fixed at 8 user units, which came out around six and a
                    half pixels on screen; sized against the current zoom
                    they stay legible however far in or out you are. */}
                <text
                  y={radius(node) + 15 / view.scale}
                  textAnchor="middle"
                  fontSize={(selected === node.id ? 13 : 12) / view.scale}
                >
                  {node.mac ? `${node.mac} | ${node.id}` : node.id}
                </text>
                <title>
                  {`${node.id}${node.mac ? ` at ${node.mac}` : ''} - ${node.degree} ${node.degree === 1 ? 'pair' : 'pairs'}, ${formatBytes(node.bytes)}`}
                </title>
              </g>
            );
          })}
        </svg>

        {chosen && (
          <aside className="map-detail">
            <header>
              <h3>{chosen.id}</h3>
              <button
                type="button"
                className="rail-close"
                onClick={() => setSelected(null)}
                aria-label="Clear the selection"
              >
                ×
              </button>
            </header>
            {chosen.mac && (
              <p className="muted">
                at {chosen.mac}
                {chosen.role ? ` - ${chosen.role}` : ''}
              </p>
            )}
            <p className="muted">
              {formatBytes(chosen.bytes)} across {chosen.packets.toLocaleString()} packets, with{' '}
              {chosen.degree} {chosen.degree === 1 ? 'other address' : 'other addresses'}.
            </p>

            <h4>Who it spoke to</h4>
            <ul className="map-list">
              {chosenEdges
                .sort((x, y) => y.bytes - x.bytes)
                .map((edge) => {
                  const other = edge.a === chosen.id ? edge.b : edge.a;
                  return (
                    <li key={`${edge.a}|${edge.b}`}>
                      <span className={`dot dot-${edge.tone}`} aria-hidden="true" />
                      <span className="mono">{other}</span>
                      <span className="muted">
                        {edge.packets.toLocaleString()} packets · {edge.outcomes.join(', ')}
                      </span>
                      {edge.conversations.slice(0, 4).map((c) => (
                        <button
                          type="button"
                          key={c.firstPacket}
                          className="linklike"
                          onClick={() => onShowPackets(c.firstPacket)}
                        >
                          {conversationLabel(c)}
                        </button>
                      ))}
                    </li>
                  );
                })}
            </ul>
          </aside>
        )}
      </div>

      <p className="muted empty-note">
        This is who spoke to whom, not the shape of the network. A capture taken at one point cannot see the
        switches and routers between these addresses, so none are drawn. Drag to move, scroll to zoom, click
        an address to follow it, click a line to open its packets.
      </p>
    </div>
  );
}
