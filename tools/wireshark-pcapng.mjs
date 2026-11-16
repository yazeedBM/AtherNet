// Writes a pcapng the way dumpcap and Wireshark write one.
//
// The other fixtures use the minimum structure the format allows, which is
// the right way to test the reader's core. It is not what arrives when
// somebody saves a capture out of Wireshark and opens it here. A real file
// carries option blocks on nearly everything, and at least one block type
// this app has no interest in but still has to step over cleanly:
//
//   SHB  with shb_hardware, shb_os, shb_userappl
//   IDB  with if_name, if_description, if_tsresol, if_os
//   NRB  a name resolution block - unknown to us, and must be skipped
//   EPB  each with an epb_flags option after the packet data
//   ISB  with start and end times, packets received and packets dropped
//
// Reading one of those is the difference between a tool that works on the
// files its author generated and a tool that works on the file a user has.

import { writeFileSync } from 'node:fs';

function option(code, value) {
  const pad = (4 - (value.length % 4)) % 4;
  const b = Buffer.alloc(4 + value.length + pad);
  b.writeUInt16LE(code, 0);
  b.writeUInt16LE(value.length, 2);
  value.copy(b, 4);
  return b;
}

const text = (code, s) => option(code, Buffer.from(s, 'utf8'));
const endOfOptions = () => option(0, Buffer.alloc(0));

function block(type, body) {
  const pad = (4 - (body.length % 4)) % 4;
  const total = 12 + body.length + pad;
  const b = Buffer.alloc(total);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(total, 4);
  body.copy(b, 8);
  b.writeUInt32LE(total, total - 4);
  return b;
}

function u64le(value) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(value), 0);
  return b;
}

function timestampPair(micros) {
  const b = Buffer.alloc(8);
  b.writeUInt32LE(Number(micros >> 32n), 0);
  b.writeUInt32LE(Number(micros & 0xffffffffn), 4);
  return b;
}

export function writeWiresharkPcapng(path, packets, { snaplen = 262144, drops = 0, baseMicros } = {}) {
  const parts = [];

  const shb = Buffer.alloc(16);
  shb.writeUInt32LE(0x1a2b3c4d, 0);
  shb.writeUInt16LE(1, 4);
  shb.writeUInt16LE(0, 6);
  shb.writeBigInt64LE(-1n, 8);
  parts.push(
    block(
      0x0a0d0d0a,
      Buffer.concat([
        shb,
        text(2, 'Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz (with SSE4.2)'),
        text(3, '64-bit Windows 11, build 26200'),
        text(4, 'Dumpcap (Wireshark) 4.2.0 (v4.2.0-0-g54eedfc63953)'),
        endOfOptions(),
      ]),
    ),
  );

  const idb = Buffer.alloc(8);
  idb.writeUInt16LE(1, 0); // Ethernet
  idb.writeUInt32LE(snaplen, 4);
  parts.push(
    block(
      0x00000001,
      Buffer.concat([
        idb,
        text(2, '\\Device\\NPF_{8B2C1F4A-6D3E-4A71-9C55-2E0B7D41AA3F}'),
        text(3, 'Intel(R) Wi-Fi 6 AX201 160MHz'),
        option(9, Buffer.from([6])), // if_tsresol: microseconds
        text(12, '64-bit Windows 11, build 26200'),
        endOfOptions(),
      ]),
    ),
  );

  // A name resolution block. Nothing here reads it; everything here has to
  // walk past it without losing its place in the file.
  parts.push(
    block(
      0x00000004,
      Buffer.concat([
        option(1, Buffer.concat([Buffer.from([10, 4, 30, 15]), Buffer.from('fileserver.corp.internal\0', 'ascii')])),
        option(0, Buffer.alloc(0)), // nrb_record_end
        endOfOptions(),
      ]),
    ),
  );

  for (const { micros, bytes } of packets) {
    const captured = bytes.subarray(0, snaplen);
    const ts = baseMicros + BigInt(micros);
    const body = Buffer.alloc(20 + captured.length + ((4 - (captured.length % 4)) % 4));
    body.writeUInt32LE(0, 0);
    body.writeUInt32LE(Number(ts >> 32n), 4);
    body.writeUInt32LE(Number(ts & 0xffffffffn), 8);
    body.writeUInt32LE(captured.length, 12);
    body.writeUInt32LE(bytes.length, 16);
    captured.copy(body, 20);
    const flags = Buffer.alloc(4);
    flags.writeUInt32LE(0x00000001, 0); // inbound
    parts.push(block(0x00000006, Buffer.concat([body, option(2, flags), endOfOptions()])));
  }

  const last = baseMicros + BigInt(packets.at(-1)?.micros ?? 0);
  const isb = Buffer.alloc(12);
  isb.writeUInt32LE(0, 0);
  isb.writeUInt32LE(Number(last >> 32n), 4);
  isb.writeUInt32LE(Number(last & 0xffffffffn), 8);
  parts.push(
    block(
      0x00000005,
      Buffer.concat([
        isb,
        option(2, timestampPair(baseMicros)), // isb_starttime
        option(3, timestampPair(last)), // isb_endtime
        option(4, u64le(packets.length)), // isb_ifrecv
        option(5, u64le(drops)), // isb_ifdrop
        endOfOptions(),
      ]),
    ),
  );

  writeFileSync(path, Buffer.concat(parts));
}
