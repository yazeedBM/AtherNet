// Where captures come from.
//
// Three routes, one analysis. The desktop app reads files from disk through
// Tauri; the browser runs the same core compiled to WebAssembly; and the
// example captures are the project's own fixture files, fed through the
// identical path rather than shipped as a pre-computed report. All of it
// comes out of one place, `crates/athernet-core/src/report.rs`.
//
// Nothing here uploads anything. There is no server in this project, and the
// wasm module has no network imports, so a capture physically cannot leave
// the machine it is opened on. That is worth more than a privacy policy.

import type { AssistantReply, Capture, PacketDetail, PacketPage } from './report';
import type { WorkerRequest, WorkerResponse } from './analyse.worker';

/** Wireshark writes .pcapng by default; .pcap and .cap are the older ones. */
export const CAPTURE_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

export function looksLikeACapture(name: string): boolean {
  const lower = name.toLowerCase();
  return CAPTURE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export interface AnalysisProgress {
  /** 1-based, for "file 3 of 12". */
  index: number;
  total: number;
  file: string;
}

export interface FileProblem {
  file: string;
  message: string;
}

export interface AnalysisResult {
  captures: Capture[];
  problems: FileProblem[];
  cancelled: boolean;
}

/** What the core returns for a file it could not read at all. */
interface ErrorReport {
  file: string;
  error: string;
}

/**
 * Omit over a union has to be distributed by hand, or TypeScript narrows it
 * to the keys every member shares - which here is only `id`, the one key
 * being removed.
 */
type WithoutId<T> = T extends { id: number } ? Omit<T, 'id'> : never;

function newWorker(): Worker {
  return new Worker(new URL('./analyse.worker.ts', import.meta.url), { type: 'module' });
}

/**
 * A worker with request ids on top, so several questions can be in flight and
 * each answer finds its own caller.
 */
class Channel {
  private worker: Worker | null = newWorker();
  private seq = 0;
  private waiting = new Map<number, { resolve: (r: WorkerResponse) => void }>();

  constructor() {
    this.worker!.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const pending = this.waiting.get(event.data.id);
      this.waiting.delete(event.data.id);
      pending?.resolve(event.data);
    };
  }

  send(request: WithoutId<WorkerRequest>, transfer: Transferable[] = []): Promise<WorkerResponse> {
    if (!this.worker) {
      return Promise.resolve({ id: -1, ok: false, message: 'this capture was closed' });
    }
    const id = ++this.seq;
    return new Promise((resolve) => {
      this.waiting.set(id, { resolve });
      this.worker!.postMessage({ ...request, id } as WorkerRequest, transfer);
    });
  }

  stop() {
    this.worker?.terminate();
    this.worker = null;
    // Anything still waiting will never be answered, so answer it here rather
    // than leaving a promise hanging for the lifetime of the page.
    for (const [id, pending] of this.waiting) {
      pending.resolve({ id, ok: false, message: 'this capture was closed' });
    }
    this.waiting.clear();
  }
}

/**
 * Analyse capture files in the browser, one at a time, off the main thread.
 *
 * `onProgress` fires before each file. The returned object always lists what
 * it managed to read and what it could not, so one unreadable file in a
 * folder of twenty does not throw away the other nineteen.
 *
 * Each file is closed as soon as its report is out, so analysing a folder
 * does not end with every capture's bytes resident at once. The explorer
 * re-opens a capture when somebody actually looks at its packets.
 */
export async function analyseFiles(
  files: File[],
  onProgress: (progress: AnalysisProgress) => void,
  signal?: AbortSignal,
): Promise<AnalysisResult> {
  const captures: Capture[] = [];
  const problems: FileProblem[] = [];
  if (files.length === 0) return { captures, problems, cancelled: false };

  const channel = new Channel();
  // Stopping terminates the worker outright. That is safe because every
  // report produced so far is already here on the main thread.
  const onAbort = () => channel.stop();
  signal?.addEventListener('abort', onAbort);

  try {
    for (const [i, file] of files.entries()) {
      if (signal?.aborted) return { captures, problems, cancelled: true };
      onProgress({ index: i + 1, total: files.length, file: file.name });

      let bytes: ArrayBuffer;
      try {
        bytes = await file.arrayBuffer();
      } catch (e) {
        problems.push({ file: file.name, message: `could not be read: ${(e as Error).message}` });
        continue;
      }
      if (signal?.aborted) return { captures, problems, cancelled: true };

      // Handing the buffer over rather than copying it matters once a capture
      // is a few hundred megabytes.
      const reply = await channel.send({ type: 'open', name: file.name, bytes }, [bytes]);
      if (!reply.ok) {
        if (!signal?.aborted) problems.push({ file: file.name, message: reply.message });
        continue;
      }
      if (reply.handle) void channel.send({ type: 'close', handle: reply.handle });

      let parsed: Capture | ErrorReport;
      try {
        parsed = JSON.parse(reply.json ?? '') as Capture | ErrorReport;
      } catch {
        problems.push({ file: file.name, message: 'the analysis core returned something unreadable' });
        continue;
      }
      if ('error' in parsed) {
        problems.push({ file: file.name, message: parsed.error });
        continue;
      }
      captures.push(parsed);
    }
  } finally {
    signal?.removeEventListener('abort', onAbort);
    channel.stop();
  }

  return { captures, problems, cancelled: signal?.aborted ?? false };
}

/**
 * One capture, held open so its packets can be paged through.
 *
 * The analysis pass closes every capture it opens, so this re-reads the file
 * rather than keeping every byte of every capture resident for the whole
 * session. Only one of these is alive at a time.
 */
export class Explorer {
  private channel = new Channel();
  private handle: number | null = null;
  private opening: Promise<string | null> | null = null;

  constructor(private readonly file: File) {}

  /** Returns an error message, or null when the capture is open. */
  private ensure(): Promise<string | null> {
    if (this.opening) return this.opening;
    this.opening = (async () => {
      const bytes = await this.file.arrayBuffer();
      const reply = await this.channel.send(
        { type: 'open', name: this.file.name, bytes },
        [bytes],
      );
      if (!reply.ok) return reply.message;
      this.handle = reply.handle ?? null;
      return this.handle === null ? 'this capture could not be opened' : null;
    })();
    return this.opening;
  }

  async packets(query: {
    start: number;
    count: number;
    flowOfPacket: number | null;
    text: string;
    filter: string;
  }): Promise<PacketPage | { error: string }> {
    const failure = await this.ensure();
    if (failure) return { error: failure };
    const reply = await this.channel.send({ type: 'packets', handle: this.handle!, ...query });
    if (!reply.ok) return { error: reply.message };
    return JSON.parse(reply.json ?? '') as PacketPage;
  }

  async packet(index: number): Promise<PacketDetail | { error: string }> {
    const failure = await this.ensure();
    if (failure) return { error: failure };
    const reply = await this.channel.send({ type: 'packet', handle: this.handle!, index });
    if (!reply.ok) return { error: reply.message };
    return JSON.parse(reply.json ?? '') as PacketDetail | { error: string };
  }

  async ask(question: string, mode: string): Promise<AssistantReply | { error: string }> {
    const failure = await this.ensure();
    if (failure) return { error: failure };
    const reply = await this.channel.send({ type: 'ask', handle: this.handle!, question, mode });
    if (!reply.ok) return { error: reply.message };
    return JSON.parse(reply.json ?? '') as AssistantReply;
  }

  /** The capture written out for somebody who will read it elsewhere. */
  async exportSummary(format: string, mode: string): Promise<string | { error: string }> {
    const failure = await this.ensure();
    if (failure) return { error: failure };
    const reply = await this.channel.send({ type: 'export', handle: this.handle!, format, mode });
    if (!reply.ok) return { error: reply.message };
    return reply.json ?? '';
  }

  close() {
    this.channel.stop();
    this.handle = null;
  }
}

/**
 * Pull capture files out of a drop, including folders dropped whole.
 *
 * A folder arrives as a directory entry rather than a file, so it has to be
 * walked. Files that are not captures are left out here rather than reported:
 * dropping a folder that happens to contain a README should not produce an
 * error about the README.
 */
export async function filesFromDrop(items: DataTransferItemList): Promise<File[]> {
  const entries: FileSystemEntry[] = [];
  for (const item of Array.from(items)) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) entries.push(entry);
  }
  if (entries.length === 0) return [];

  const out: File[] = [];
  const walk = async (entry: FileSystemEntry): Promise<void> => {
    if (entry.isFile) {
      const file = await new Promise<File | null>((resolve) =>
        (entry as FileSystemFileEntry).file(resolve, () => resolve(null)),
      );
      if (file && looksLikeACapture(file.name)) out.push(file);
      return;
    }
    if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader();
      // readEntries returns at most 100 at a time, so it has to be drained.
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((resolve) =>
          reader.readEntries(resolve, () => resolve([])),
        );
        if (batch.length === 0) break;
        for (const child of batch) await walk(child);
      }
    }
  };

  for (const entry of entries) await walk(entry);
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

/** Captures chosen through a file or folder picker. */
export function filesFromInput(list: FileList | null): File[] {
  if (!list) return [];
  return Array.from(list)
    .filter((file) => looksLikeACapture(file.name))
    .sort((a, b) => a.name.localeCompare(b.name));
}
