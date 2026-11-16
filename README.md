# AtherNet

A capture-file analysis app that explains what went wrong on the network, for
people who are not going to read a packet list. Open a `.pcap` or `.pcapng`
file - one, several, or a folder - and get findings with the evidence behind
them.

The design proposal this is built from: <https://claude.ai/artifact/3HY34xHwFc4gfFXXKcMcRd>

Two rules run through the whole codebase:

- **Severity and confidence are separate.** Colour carries severity (error,
  warning, informational); a badge carries confidence (confirmed, suspected,
  incomplete evidence). A retransmission is never a confirmed failure.
- **"Did not happen" is not "not captured."** Snaplen truncation, dropped
  packets, one-sided flows and encryption each downgrade what the app is
  willing to claim, and each says so on screen.

## Layout

    crates/athernet-core/    Capture readers, decoders, flows, detectors. No dependencies.
    crates/athernet-wasm/    The same core, compiled for the browser.
    crates/athernet-app/     Tauri desktop shell; commands over the core.
    ui/                      React + TypeScript front end (Vite).
    tools/make-fixtures.mjs  Builds the labelled test corpus.
    tools/check-corpus.mjs   Checks the detectors against it. The phase 2 gate.
    tools/build-wasm.mjs     Compiles the core for the browser and installs it in ui/.
    tools/make-examples.mjs  Bundles the small fixtures as the app's example captures.
    fixtures/                Generated captures + manifest.json of expected findings.

## Running it

```bash
rustup target add wasm32-unknown-unknown   # once
node tools/build-wasm.mjs                  # compiles the core for the browser
node tools/make-examples.mjs               # bundles the example captures
npm --prefix ui install
npm --prefix ui run dev                    # http://localhost:1420
```

The app opens empty, waiting for a capture. Drop a `.pcap` or `.pcapng` file
on the window, or a folder of them, or use the two buttons in the sidebar. The
file is read and analysed in the page.

**The capture never leaves the machine**, and not as a promise: there is no
server in this project, and the WebAssembly module has no imports - no
network, no file system, no clock. There is nowhere for it to send anything.
Nothing is stored between visits either; closing a capture removes it and
closing the tab removes them all. Captures are customer traffic, and the only
privacy guarantee worth much is the one that is structurally impossible to
break.

If you have no capture to hand, the empty screen offers the example corpus:
thirteen small files with faults planted in them on purpose, which is what the
detectors are tested against. They are the fixture *files*, fed through the
file picker, the worker and the core exactly as a capture you drop in is -
not a pre-computed report. An example that takes a different path from the
real thing is an example that can quietly stop being true.

### Why the browser runs the analysis

The desktop app reads files from disk through Tauri, which on Windows needs
the MSVC toolchain and the Visual Studio C++ build tools - a multi-gigabyte
install nobody here has done yet. Compiling the core to WebAssembly needs one
`rustup target add`, and runs the identical reader, detectors and report
function. So the browser build is what you can actually use today.

It is also the right architecture for a web build rather than a stopgap. The
one real difference from the desktop app is memory: the browser holds the
whole file, where the desktop app streams it, so wasm32's practical ceiling of
around 2 GB is the ceiling for a single capture here.

## The analysis core

```bash
cargo test --workspace --exclude athernet-app   # 56 tests + a doc test
cargo build --release -p athernet-core --bin athernet-bench
./target/release/athernet-bench fixtures/       # findings, and the throughput gate
./target/release/athernet-bench --assistant fixtures/   # the assistant gates
node tools/check-corpus.mjs                     # every gate, pass or fail
```

`athernet-bench` serves both gates. It prints what the detectors found in each
file, in plain language, with the evidence and the limits; and it reports
packets per minute per core against the million-a-minute figure the
architecture rests on.

**Measured, 16 November 2026**, on one core of a Windows 11 laptop, GNU
toolchain, release build, files already in the page cache:

    bulk-transfer.pcap   66-107 M packets/minute, six consecutive runs
    the whole corpus     72-91 M packets/minute, six consecutive runs

The spread is the machine, not the code. This is a laptop with other things
running on it, and a single quiet reading earlier in the same session put the
corpus at 99-102 M. Quoting the best number would have been easy and wrong;
the range is what the thing actually does.

Throughput has come down twice, and both drops are worth stating rather than
hiding. The packet index took it from 180-186 M to 148-152 M: a row per
packet is what an explorer costs. Profiling hardware addresses cost roughly
another tenth, because that meant a set lookup per packet on top - first
measured around 90 M, recovered by remembering the last address seen behind
each hardware address, since almost every packet repeats the pair before it.

The gate is a million packets a minute. The worst reading here is seventy
times that, and reading has never been where the time goes.

Read those as an upper bound, for two reasons. That file is one conversation,
so the flow table stays in cache and every branch predicts perfectly; a real
capture with hundreds of thousands of flows will be slower. And the page cache
is doing the reading - an earlier run over files freshly written to disk
measured about 52 M packets a minute, and a genuinely cold read from storage
has not been measured here at all, because there is no simple way to empty the
cache on this machine.

The useful conclusion is narrower than any of those numbers, and still worth
having: **the parser is not where the time goes.** Reading is two orders of
magnitude clear of the gate under every condition measured, so the
architecture does not have to defend it, and the next thing worth measuring is
the dashboard's aggregates rather than the reader.

### Toolchain note

Set up with the **GNU** toolchain (`stable-x86_64-pc-windows-gnu`), which is
self-contained and needs no Visual Studio. The core, the bench and the wasm
build all work with it.

The Tauri desktop app has **not** been built, for the reason above. It holds
no analysis and no report shaping of its own: it opens files, runs the core
and hands back the JSON the core produced. The desktop app, the browser build
and the headless tool all come out of one function, `capture_json` in
`crates/athernet-core/src/report.rs`.

```bash
rustup toolchain install stable-x86_64-pc-windows-msvc   # after the C++ build tools
cargo install tauri-cli
```

## The packet explorer

Every capture gets three views: the issues, its conversations, and its
packets. A finding has a **Show these packets** button that opens the
explorer filtered to the conversation the finding is about, with the packet
itself selected - which is the whole point of keeping evidence as packet
numbers rather than prose.

The packet list reads the way a packet list should: number, time, source,
destination, protocol, length, and a line saying what the packet is. That
line is not generated twice. The DNS, DHCP, TLS and ICMP detectors have
already parsed the payload to do their own job, so each hands back the
summary as it goes.

Opening a packet shows it layer by layer - frame, Ethernet, IP, transport,
and what the application-layer dissector made of it - and then the bytes in
hex. The hex view renders printable ASCII and a full stop for everything
else, for the same reason the rest of the app does: a capture's contents are
data.

### Addressing

Who holds which address, with what proves it, and when.

Every row is something the capture states outright - ARP, and only ARP, with
the kind of ARP named. An address not in the table was never claimed in front
of the capture point, which is not the same as it not existing, and the screen
says so.

The column that matters most is the last one. For anything off the local
segment the hardware address on the packet belongs to the **router**, not to
the host, so a table that lists the two the same way is quietly wrong in the
direction that sends someone hunting for a device that was never there. A
hardware address that carried traffic for several different network addresses
is listed as a way out of the network rather than a device on it, and the
count is shown so the reader can judge the call themselves.

The addressing detector also learned to tell two claims apart by **when**
they happened. Two hardware addresses answering for one address within ten
seconds is a clash: a confirmed error, because both devices believed it at
once. The same two claims forty-five seconds apart is an address changing
hands - a renewed lease or a swapped device - and is reported as information,
not a fault.

That distinction was a false positive sitting in the code for most of this
project's life. `summary.rs` carried a comment saying the difference was for
the detector to judge; the detector then did not judge it, and reported every
address with two claims as a duplicate. On a real network with DHCP that
fires constantly. `fixtures/address-reassigned.pcap` is the file that now
holds it down.

### The filter

The explorer has the visual AND/OR builder the proposal asks for. Conditions
inside a group combine one way, groups combine the other, which gives
`(A or B) and C` without ever showing a bracket to someone who did not ask for
one. Two levels rather than a free tree is a deliberate limit: it covers what
people actually write, and a freely nested boolean tree is - for an audience
that has never used a packet tool - unusable.

You can match on either address, the source or the destination (exactly, by
text, or **inside a CIDR range**), either port or one end of it, protocol, TCP
flag, length, how far into the capture a packet is, whether the snaplen cut it
short, and what the summary line says. Any condition can be negated.

Underneath it the filter is written back as a sentence - *"address (either
end) is not inside 192.168.1.0/24"* - because a builder made only of
dropdowns leaves people unsure what they have built, and that line is what
they read to check. It is also what makes a saved filter recognisable a week
later.

Six shortcuts cover the common questions (connection attempts, resets, name
lookups, encrypted setup, large packets, cut short), and a filter can be
named and kept. Saved filters live in `localStorage` in that browser only:
there is no account and no server to put them on, and a filter is a question
about your own network.

The matching runs in the core, over the whole index, not over the page on
screen - a filter that quietly searched only what was already loaded would be
worse than no filter. Address conditions are resolved once per distinct
address rather than once per packet, and the summary line, which is the only
part that costs real work, is built only when a condition actually asks about
it.

The wire format is tab-separated lines rather than JSON, because JSON would
mean writing a JSON *parser* in a crate that intends to keep no
dependencies: thirty lines against two hundred. A filter that cannot be read
narrows nothing, rather than hiding everything and looking like an empty
capture.

### What it costs

This is the one structure in the core that grows with the capture. Everywhere
else the reader counts and discards, which is what lets it run at the rate it
does.

A row is 48 bytes and holds no strings. Addresses are interned, because a
capture of a few thousand hosts repeats the same handful of addresses
millions of times; so are the summary lines, because a DNS name repeats just
as hard. The packet's own bytes are never copied - a row keeps the offset into
the original file, and the bytes are read from there only when somebody opens
that packet.

Indexing stops at a million packets, about 48 MB. A larger capture is still
**analysed in full** - every finding is still found - but the explorer shows
the first million and says so on screen. An unbounded index is how a tool like
this runs a machine out of memory on the one capture that mattered.

The browser keeps one capture open at a time. The analysis pass closes each
file as soon as its report is out, and the explorer re-reads the file when you
look at its packets, so opening a folder of captures does not leave every
one of them resident.

The desktop app does not have the explorer yet: its command set still returns
only the report. The session API the browser uses - open, report, packets,
packet, close - is what it needs, and it cannot be written honestly until
there is a toolchain here that compiles it.

## The assistant

The proposal asks for an assistant that answers from the parsed capture,
links to the packets behind each claim, separates what it saw from what might
explain it, says when it does not know, and treats captured content as data
rather than instructions. Every one of those is a property of the code
*around* a model rather than of the model, which is why all of it lives in
`crates/athernet-core/src/assistant.rs` and is tested without one.

**No language model is connected.** Nothing in this project reaches the
network, and the wasm module has no imports to reach it with. What answers
today is a deterministic responder that recognises a handful of question
shapes - what went wrong, why is it slow, what about this address, what about
DNS - and answers them straight from the analysis with real citations. It
says so on screen rather than letting anyone assume otherwise, and it says
plainly when a question is not one it can answer. An assistant that produces
a confident paragraph for every input is worse than one that answers five
questions and admits the sixth.

What is built and tested around that gap is the part a model would need:

- **The evidence pack** is the whole context, and it is exactly the string
  the privacy preview shows. Showing a *description* of what would be shared
  is a promise; showing the string itself is a fact somebody can check.
- **Citations are validated.** Every `[finding:ID]`, `[packet:N]` and
  `[conversation:N]` is resolved against the analysis before it is rendered.
  One that does not resolve is shown as unverifiable, never as a link - a
  model citing a packet the capture does not hold is not giving a weaker
  answer, it is giving a false one.
- **Captured text cannot become structure.** Everything from the wire is
  already stripped to printable ASCII by `appl`; the pack additionally
  escapes `&`, `<` and `>` in every captured value, so a host name of
  `</observed>` cannot close the tag around it.
- **Three privacy modes**, defaulting to redacted. Addresses, hardware
  addresses and names are replaced with stable labels - `host-1`, `device-2`
  - so the shape of the problem survives and whose network it is does not.
  The question is redacted too: somebody asking "what is wrong with
  10.4.12.88" did not mean to send that address.

### The gates

`./target/release/athernet-bench --assistant fixtures/` is phase 5's gate,
and it checks three things over every capture. It builds the pack, strips
every tag the app writes, and fails if a single angle bracket is left - if
one is, something from the wire is being read as markup. It validates the
answer's own citations the way a model's would be. And in redacted mode it
goes looking for an address, rather than trusting the redactor to have been
called.

That last check found two real leaks the moment it ran. Findings are rendered
before conversations, so at the time a finding was written the redactor had
not yet been shown a single address and `sweep` had nothing to replace. And a
DHCP refusal names the address a device *asked for*, which never appears as
an endpoint anywhere, so no amount of seeding could have known it. Redaction
is now two passes - what the capture taught it, plus anything else shaped
like an address - and the gate is the only reason either was found.

`fixtures/prompt-injection.pcap` exists to attack this. Its DNS name, its TLS
server name and its DHCP server message are all written to be read as
instructions by whatever summarises the capture. The findings it produces are
ordinary; what it tests is that none of its text ever becomes anything but
text. It is still *shown* - it is evidence, and hiding it would be its own
kind of dishonesty - but it cannot be structure.

## Export

Every capture can be written out as markdown, for a ticket or a pull request,
or as plain text for an email. The panel shows the exact string that will be
copied or downloaded - not a rendering of it - with the privacy choice beside
the preview rather than in a settings page, because an export leaves the
machine by definition.

Three things it does that are easy to get wrong:

**The limits come before the findings.** Somebody skimming a ticket should
meet what the capture cannot settle before they meet a list that looks like
certainty. Confidence travels with each finding, and so do the reasons it is
not higher.

**It offers the same redaction the assistant does**, out of the same
`Redactor`, and a redacted export says so in its first paragraph - otherwise
the reader takes `host-1` for a name somebody chose.

**Captured text ends up inside somebody else's document.** A host name of
`[click here](http://example.invalid)` is a working link once it is in a
ticket, and a name containing a pipe quietly breaks the table around it.
Every value that came off the wire is wrapped in a code fence long enough to
contain it - CommonMark lets a span be delimited by any run of backticks, so
nothing has to be altered to be made safe, only fenced properly. A code span
cannot be a link, a heading or a table row.

The gate checks that by name: for every finding in every fixture, the export
must contain that title *inside a fence*, rather than the code being trusted
to have applied one. It also builds a redacted export and goes looking for an
address in it, which is how it found that the "what to check next" lines name
addresses - a redacted export that redacted the finding and not its advice
would have leaked on the last line.

## The labelled corpus

`fixtures/manifest.json` lists all sixteen generated captures with the
findings each one should produce - type, severity, confidence, and a note on
why. `node tools/check-corpus.mjs` compares the two and exits non-zero on any
mismatch, so this is a gate rather than a document.

It also parses the JSON report and checks the fields the front end depends on
are there. The report is written by hand in Rust, without serde, so nothing in
the compiler checks its shape - and a key emitted with no value still balances
its braces, which is exactly the bug that got through once and broke every
capture in the UI at the same time.

It compares all three parts of a finding, not only its type. A confirmed error
reported as a suspicion fails, and so does a suspicion reported as confirmed:
severity and confidence are separate axes, and getting either wrong is the
specific way a tool like this loses a user's trust.

Two captures are deliberately clean. A detector that reports anything at all
on `clean-browse.pcap` or `bulk-transfer.pcap` is wrong, and the gate says so.
One of them is a trap on purpose: `clean-browse.pcap` sends 517 bytes of
`0x16`, which begins exactly like a TLS handshake record. The TLS detector
checks the version bytes too, and ignores it.

`wireshark-style.pcapng` is there for a different reason. The other pcapng
fixtures use the minimum structure the format allows, which is the right way
to test the reader's core and the wrong way to find out what happens when
somebody saves a capture out of Wireshark. That one carries option blocks on
every block, an interface name and timestamp resolution, per-packet flags, and
a name resolution block the app has no use for and must step over without
losing its place.

### What the detectors cover

| Finding | Confidence | Comes from |
| --- | --- | --- |
| `connection_refused` | confirmed | a reset answering a connection attempt |
| `blocked_by_device` | confirmed | ICMP administratively prohibited, matched back to the flow it quotes |
| `port_unreachable`, `host_unreachable`, `mtu_too_large`, `ttl_exceeded` | confirmed | the other ICMP error types, same correlation |
| `dns_error` | confirmed | a non-zero DNS response code |
| `dhcp_nak`, `dhcp_declined` | confirmed | the server refusing an address, or the client rejecting one |
| `tls_alert` | confirmed | a fatal TLS alert |
| `duplicate_address` | confirmed | two MAC addresses answering ARP for one IP |
| `connection_unanswered` | suspected | a connection attempt with no answer of any kind |
| `dns_unanswered`, `dhcp_no_offer`, `dhcp_no_ack`, `tls_no_server_hello` | suspected | a request with no response in the file |
| `reset_mid_session` | suspected | a reset after the connection was established |
| `one_sided`, `capture_incomplete` | incomplete evidence | the capture itself cannot settle it |

The confirmed column is the point of the whole exercise. Every one of those is
a packet in which a device states the problem itself, so nothing missing from
the capture weakens it. Everything in the suspected column rests on a packet
that is *absent*, and each of those findings carries the reasons absence
proves less than it looks: what the file can and cannot say about dropped
packets, and the possibility that the response exists but does not pass the
point the capture was taken at.

Two behaviours are worth knowing about, because both are places where the
obvious implementation reports one event twice:

- An ICMP error that quotes a connection attempt **replaces** the "no answer"
  finding for that connection rather than joining it. The capture does not
  show a silence; it shows a device saying no.
- A fatal TLS alert **replaces** the mid-session reset that usually follows
  it. One event, one finding.

Anything the app copies out of a capture as text - a DNS name, a TLS server
name, a DHCP server's message - goes through one function in
`crates/athernet-core/src/appl.rs` that strips it to printable ASCII and caps
its length. Captured content is data. A test plants control bytes and an
escape sequence in a DNS name and checks they do not survive.

## Build order

1. **Parser spike** - throughput and format coverage. Gate: a million packets a
   minute per core.
2. **Analysis core, headless** - passes, database, detectors, the bench tool.
   Gate: the labelled corpus, with no false positives on the clean files.
3. **Shell, dashboard, issues, finding drawer.** Gate: someone who has never
   used Wireshark names the problem in a test capture unaided.
4. **Conversations, endpoints, packet explorer, filters.**
5. **Assistant, privacy modes, export.** Gate: citation validation rejects
   fabricated ids, and a prompt-injection corpus changes no answer.

Step 5 has its grounding, its citation validation, its three privacy modes,
its export and both of its gates. What it has not got is a model: nothing
here reaches the network, and the assistant answers from the analysis on this
machine. The honest summary is that the hard half is done and the easy half
is missing - wiring a model in is a few hundred lines against an interface
that already exists, and everything that makes such a model safe to trust
with somebody's capture is written and under test.

Every feature the brief named is now built, which makes the remaining gap a
different kind. Nobody who has never used Wireshark has sat in front of this,
and the gate for step 3 says they should be able to name the problem in a
test capture unaided. Until somebody does that, the claim that this is easier
to understand than a packet list is an intention rather than a result.

Steps 1 and 2 are **done and passed**: the throughput gate by measurement, the
corpus gate by `node tools/check-corpus.mjs`, which matches all sixteen
captures with no false positives on the clean two.

Step 3 works end to end for a capture you open yourself. The dashboard, the
issues list and the finding drawer render real analysis, including the
evidence, the limits behind a confidence badge, and a traffic strip that
rebuckets itself as a capture gets longer and says what one bar covers.

Step 4 has its conversation list, its packet explorer, its addressing screen
and the filter builder with saved filters and shortcuts. What it has not got
is sorting and searching inside the conversation and addressing tables, and
the filter applies to packets only, not to the issues list, which still has
its three chips and a text box.

Its gate - someone who has never used Wireshark names the problem in a test
capture unaided - has not been attempted. Nobody has sat in front of this, and
reading the screen is no substitute for watching someone use it.

What the analysis still does not have, and would want before anyone leaned on
it:

- **A database.** Findings and the packet index are built in memory and
  thrown away. Nothing survives a reload, and the explorer re-reads a capture
  each time you open its packets rather than keeping the index between
  visits.
- **Retransmission and window analysis**, which needs sequence-number
  tracking per direction rather than per-packet flags. It is also where false
  positives are easiest to create, so it wants its own fixtures first:
  checksum offload and a mirrored port both manufacture duplicates that were
  never on the wire.
- **DNS over TCP**, and DNS over TLS or HTTPS, which this cannot see at all.
- **Fixtures taken from real captures.** Every file in the corpus was written
  by hand, which is why the expected result is known exactly - and also why it
  cannot catch whatever real traffic does that nobody thought to write down.
  `wireshark-style.pcapng` narrows that gap on the file format; it does
  nothing about the traffic inside.
