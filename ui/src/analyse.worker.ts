// Runs the analysis core, compiled to WebAssembly, off the main thread.
//
// Two reasons it is a worker rather than a plain call. A capture of any size
// takes long enough that doing it on the main thread would freeze the window,
// and the design proposal asks for progress and a cancel button rather than a
// frozen one. And cancelling is then real: the main thread terminates the
// worker, which stops the work rather than letting it run on unwatched.
//
// A capture is a session. The file stays in the module, analysed once, and
// the page asks for what it needs - the report, a page of the packet list,
// one packet in full. Handing the whole packet list across as JSON would mean
// megabytes of string for a capture nobody has scrolled yet.
//
// The module has no imports - no network, no file system, no clock. A capture
// handed to it cannot leave the machine, because there is nowhere to send it.

export type WorkerRequest =
  | { id: number; type: 'open'; name: string; bytes: ArrayBuffer }
  | {
      id: number;
      type: 'packets';
      handle: number;
      start: number;
      count: number;
      flowOfPacket: number | null;
      text: string;
      /** The built filter, in the line format the core reads. */
      filter: string;
    }
  | { id: number; type: 'packet'; handle: number; index: number }
  | { id: number; type: 'ask'; handle: number; question: string; mode: string }
  | {
      id: number;
      type: 'export';
      handle: number;
      format: string;
      mode: string;
      /** The capture-wide filter in the core's wire format, or ''. */
      filter: string;
      /** How to describe that filter to whoever reads the export. */
      said: string;
    }
  | { id: number; type: 'close'; handle: number };

export type WorkerResponse =
  | { id: number; ok: true; handle?: number; json?: string }
  | { id: number; ok: false; message: string };

interface CoreExports {
  memory: WebAssembly.Memory;
  athernet_alloc: (len: number) => number;
  athernet_free: (ptr: number, len: number) => void;
  athernet_open: (namePtr: number, nameLen: number, dataPtr: number, dataLen: number) => number;
  athernet_close: (handle: number) => void;
  athernet_report: (handle: number) => number;
  athernet_packets: (
    handle: number,
    start: number,
    count: number,
    flowOfPacketPlusOne: number,
    textPtr: number,
    textLen: number,
    filterPtr: number,
    filterLen: number,
  ) => number;
  athernet_packet: (handle: number, index: number) => number;
  athernet_export: (
    handle: number,
    formatPtr: number,
    formatLen: number,
    modePtr: number,
    modeLen: number,
    filterPtr: number,
    filterLen: number,
    saidPtr: number,
    saidLen: number,
  ) => number;
  athernet_ask: (
    handle: number,
    questionPtr: number,
    questionLen: number,
    modePtr: number,
    modeLen: number,
  ) => number;
}

let core: CoreExports | null = null;
let wasmUrl = new URL('./athernet.wasm', import.meta.url).href;

async function start(): Promise<CoreExports> {
  const response = await fetch(wasmUrl);
  if (!response.ok) {
    throw new Error(`could not load the analysis core (${response.status})`);
  }
  // instantiateStreaming needs the server to send application/wasm, which not
  // every static host does, so fall back rather than failing over a header.
  let instance: WebAssembly.Instance;
  try {
    ({ instance } = await WebAssembly.instantiateStreaming(response.clone(), {}));
  } catch {
    ({ instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {}));
  }
  return instance.exports as unknown as CoreExports;
}

/** Copy a string into the module and return its pointer and length. */
function writeString(exports: CoreExports, text: string): [number, number] {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length === 0) return [0, 0];
  const ptr = exports.athernet_alloc(bytes.length);
  // Every allocation can grow the module's memory, and growing it replaces
  // the ArrayBuffer behind it. So each view is built after the allocation it
  // writes into, never reused across one.
  new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

/** Read and free a length-prefixed result buffer. */
function readResult(exports: CoreExports, ptr: number): string {
  if (!ptr) throw new Error('the analysis core ran out of memory');
  const length = new DataView(exports.memory.buffer).getUint32(ptr, true);
  const text = new TextDecoder().decode(new Uint8Array(exports.memory.buffer, ptr + 4, length));
  exports.athernet_free(ptr, 4 + length);
  return text;
}

function open(exports: CoreExports, name: string, bytes: Uint8Array): number {
  const [namePtr, nameLen] = writeString(exports, name);
  const dataPtr = exports.athernet_alloc(bytes.length);
  if (!dataPtr && bytes.length > 0) {
    exports.athernet_free(namePtr, nameLen);
    throw new Error('there was not enough memory in the browser to hold this file');
  }
  new Uint8Array(exports.memory.buffer, dataPtr, bytes.length).set(bytes);

  // athernet_open takes ownership of the data buffer, so it is deliberately
  // not freed here. Closing the session releases it.
  const handle = exports.athernet_open(namePtr, nameLen, dataPtr, bytes.length);
  exports.athernet_free(namePtr, nameLen);
  if (!handle) throw new Error('the analysis core could not open this file');
  return handle;
}

const post = (message: WorkerResponse) => self.postMessage(message);

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  try {
    if (!core) core = await start();

    switch (request.type) {
      case 'open': {
        const handle = open(core, request.name, new Uint8Array(request.bytes));
        post({ id: request.id, ok: true, handle, json: readResult(core, core.athernet_report(handle)) });
        break;
      }
      case 'packets': {
        const [textPtr, textLen] = writeString(core, request.text);
        const [filterPtr, filterLen] = writeString(core, request.filter);
        const ptr = core.athernet_packets(
          request.handle,
          request.start,
          request.count,
          request.flowOfPacket === null ? 0 : request.flowOfPacket + 1,
          textPtr,
          textLen,
          filterPtr,
          filterLen,
        );
        const json = readResult(core, ptr);
        core.athernet_free(textPtr, textLen);
        core.athernet_free(filterPtr, filterLen);
        post({ id: request.id, ok: true, json });
        break;
      }
      case 'packet': {
        post({
          id: request.id,
          ok: true,
          json: readResult(core, core.athernet_packet(request.handle, request.index)),
        });
        break;
      }
      case 'ask': {
        const [qPtr, qLen] = writeString(core, request.question);
        const [mPtr, mLen] = writeString(core, request.mode);
        const json = readResult(core, core.athernet_ask(request.handle, qPtr, qLen, mPtr, mLen));
        core.athernet_free(qPtr, qLen);
        core.athernet_free(mPtr, mLen);
        post({ id: request.id, ok: true, json });
        break;
      }
      case 'export': {
        const [fPtr, fLen] = writeString(core, request.format);
        const [mPtr, mLen] = writeString(core, request.mode);
        const [qPtr, qLen] = writeString(core, request.filter ?? '');
        const [sPtr, sLen] = writeString(core, request.said ?? '');
        const json = readResult(
          core,
          core.athernet_export(request.handle, fPtr, fLen, mPtr, mLen, qPtr, qLen, sPtr, sLen),
        );
        core.athernet_free(fPtr, fLen);
        core.athernet_free(mPtr, mLen);
        core.athernet_free(qPtr, qLen);
        core.athernet_free(sPtr, sLen);
        post({ id: request.id, ok: true, json });
        break;
      }
      case 'close': {
        core.athernet_close(request.handle);
        post({ id: request.id, ok: true });
        break;
      }
    }
  } catch (e) {
    // A trap inside the module leaves it unusable, so the next request starts
    // from a fresh instance rather than inheriting a poisoned one. Any open
    // sessions die with it, which the caller treats as the capture closing.
    core = null;
    post({ id: request.id, ok: false, message: (e as Error).message });
  }
};
