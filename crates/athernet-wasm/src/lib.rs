//! The analysis core, compiled for the browser.
//!
//! The desktop app reads capture files from disk through Tauri. That needs
//! the MSVC toolchain on Windows, which is a multi-gigabyte install, and
//! until someone does it there is no way to open a file you chose - only the
//! fixtures baked into the bundle. Compiling the core to WebAssembly removes
//! that wait: the same reader, the same detectors and the same report
//! functions run in the page.
//!
//! It is also the honest architecture for the web build, not a stopgap. The
//! capture never leaves the machine, because there is nowhere for it to go:
//! the module has no imports, no network and no file system. A capture is
//! customer traffic, and the strongest privacy guarantee is the one that is
//! structurally impossible to break rather than promised in a policy.
//!
//! The interface is deliberately raw - a handful of `extern "C"` functions
//! over byte buffers - so the core keeps its no-dependency rule.
//!
//! **A capture is a session.** The file stays here, analysed once, and the
//! page asks for what it needs: the report, a page of the packet list, one
//! packet in full. The alternative - handing the whole packet list across as
//! JSON - would mean megabytes of string for a capture nobody has scrolled
//! yet, and re-reading the file for every page after that.
//!
//! **The one real difference from the desktop build**: the browser holds the
//! whole file in memory, where the desktop app streams it. wasm32 tops out
//! near 2 GB in practice, so very large captures belong in the desktop app.

use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::HashMap;

use athernet_core::assistant::PrivacyMode;
use athernet_core::export::{export, export_tables, ExportFormat};
use athernet_core::{
    assistant_json, capture_json, decode, packet_detail_json, packets_json, Analysis, CaptureFile,
    CaptureLimits, PacketQuery,
};

struct Session {
    file: Vec<u8>,
    analysis: Analysis,
    /// Built once when the file is opened, because every screen wants it.
    report: String,
    /// Kept so the assistant can ground an answer without re-reading.
    name: String,
    limits: CaptureLimits,
}

thread_local! {
    static SESSIONS: RefCell<HashMap<u32, Session>> = RefCell::new(HashMap::new());
    static NEXT_HANDLE: RefCell<u32> = const { RefCell::new(1) };
}

// ------------------------------------------------------------------ memory

/// Reserve a buffer for the caller to write into.
///
/// # Safety
/// The caller must pass the same `len` back to `athernet_free`, unless the
/// buffer was handed to `athernet_open`, which takes ownership of it.
#[no_mangle]
pub extern "C" fn athernet_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    match Layout::from_size_align(len, 1) {
        Ok(layout) => unsafe { alloc(layout) },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Release a buffer from `athernet_alloc` or from a function that returns a
/// result buffer.
///
/// # Safety
/// `ptr` must have come from this module with exactly this `len`.
#[no_mangle]
pub unsafe extern "C" fn athernet_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(len, 1) {
        dealloc(ptr, layout);
    }
}

/// Copy a string into a freshly allocated, length-prefixed buffer: a
/// little-endian `u32` length, then that many bytes of UTF-8. The caller
/// frees it with `athernet_free(ptr, 4 + length)`.
fn handback(text: String) -> *mut u8 {
    let bytes = text.into_bytes();
    let total = 4 + bytes.len();
    let Ok(layout) = Layout::from_size_align(total, 1) else {
        return std::ptr::null_mut();
    };
    unsafe {
        let out = alloc(layout);
        if out.is_null() {
            return out;
        }
        let header = (bytes.len() as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(header.as_ptr(), out, 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(4), bytes.len());
        out
    }
}

/// # Safety
/// `ptr` must be valid for `len` bytes, or null with `len` 0.
unsafe fn borrow_str(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
}

// ----------------------------------------------------------------- sessions

/// Open a capture file and analyse it. Returns a handle, or 0 if no session
/// could be created at all.
///
/// A file that turns out not to be a capture still gets a handle: ask it for
/// its report and the report says, in plain language, what went wrong. One
/// path for both outcomes is easier to get right than two.
///
/// # Safety
/// `data_ptr` must come from `athernet_alloc` with exactly `data_len` bytes.
/// **This function takes ownership of it**; the caller must not free it, and
/// must not use it afterwards. `athernet_close` releases it.
#[no_mangle]
pub unsafe extern "C" fn athernet_open(
    name_ptr: *const u8,
    name_len: usize,
    data_ptr: *mut u8,
    data_len: usize,
) -> u32 {
    let name = {
        let name = borrow_str(name_ptr, name_len);
        if name.is_empty() {
            "capture".to_string()
        } else {
            name
        }
    };
    // Taking the buffer rather than copying it matters: a copy would double
    // the memory a large capture needs at the worst possible moment.
    let file = if data_ptr.is_null() || data_len == 0 {
        Vec::new()
    } else {
        Vec::from_raw_parts(data_ptr, data_len, data_len)
    };

    let (analysis, report, limits) = analyse(&name, &file);
    let handle = NEXT_HANDLE.with(|n| {
        let mut n = n.borrow_mut();
        let handle = *n;
        *n = n.wrapping_add(1).max(1);
        handle
    });
    SESSIONS.with(|s| {
        s.borrow_mut().insert(
            handle,
            Session {
                file,
                analysis,
                report,
                name,
                limits,
            },
        )
    });
    handle
}

/// Release a capture and everything built from it.
#[no_mangle]
pub extern "C" fn athernet_close(handle: u32) {
    SESSIONS.with(|s| s.borrow_mut().remove(&handle));
}

/// The capture report: counters, conversations, findings, bindings.
#[no_mangle]
pub extern "C" fn athernet_report(handle: u32) -> *mut u8 {
    SESSIONS.with(|s| match s.borrow().get(&handle) {
        Some(session) => handback(session.report.clone()),
        None => handback(missing(handle)),
    })
}

/// One page of the packet list.
///
/// `flow_of_packet_plus_one` is 0 for no conversation filter, or a packet
/// index plus one to show only that packet's conversation. Plus one so that
/// packet zero - which is a real packet, and often the interesting one - is
/// not the same value as "no filter".
///
/// `filter_ptr` carries the built filter in the wire format
/// `athernet_core::filter` documents, or nothing for no filter.
///
/// # Safety
/// Each pointer must be valid for its length, or null with a length of 0.
#[no_mangle]
pub unsafe extern "C" fn athernet_packets(
    handle: u32,
    start: usize,
    count: usize,
    flow_of_packet_plus_one: usize,
    text_ptr: *const u8,
    text_len: usize,
    filter_ptr: *const u8,
    filter_len: usize,
) -> *mut u8 {
    let text = borrow_str(text_ptr, text_len);
    let filter = borrow_str(filter_ptr, filter_len);
    SESSIONS.with(|s| match s.borrow().get(&handle) {
        Some(session) => handback(packets_json(
            &session.analysis,
            PacketQuery {
                start,
                count,
                flow_of_packet: flow_of_packet_plus_one.checked_sub(1),
                text: &text,
                filter: &filter,
            },
        )),
        None => handback(missing(handle)),
    })
}

/// One packet, decoded layer by layer, with its bytes.
#[no_mangle]
pub extern "C" fn athernet_packet(handle: u32, index: usize) -> *mut u8 {
    SESSIONS.with(|s| match s.borrow().get(&handle) {
        Some(session) => handback(packet_detail_json(
            &session.analysis,
            &session.file,
            index,
        )),
        None => handback(missing(handle)),
    })
}

/// Ask a question about this capture.
///
/// Returns the answer, the evidence behind it, and the exact text that would
/// leave the machine in the chosen privacy mode. Nothing here reaches the
/// network - the module has no imports to reach it with - so what comes back
/// is produced on this machine from the analysis.
///
/// # Safety
/// Each pointer must be valid for its length, or null with a length of 0.
#[no_mangle]
pub unsafe extern "C" fn athernet_ask(
    handle: u32,
    question_ptr: *const u8,
    question_len: usize,
    mode_ptr: *const u8,
    mode_len: usize,
) -> *mut u8 {
    let question = borrow_str(question_ptr, question_len);
    let mode = PrivacyMode::parse(&borrow_str(mode_ptr, mode_len));
    SESSIONS.with(|s| match s.borrow().get(&handle) {
        Some(session) => handback(assistant_json(
            &session.analysis,
            session.limits,
            &session.name,
            &question,
            mode,
        )),
        None => handback(missing(handle)),
    })
}

/// Write this capture out for somebody who will read it somewhere else.
///
/// Returns the summary itself, not JSON: the caller copies it, downloads it,
/// or pastes it into a ticket.
///
/// # Safety
/// Each pointer must be valid for its length, or null with a length of 0.
#[no_mangle]
pub unsafe extern "C" fn athernet_export(
    handle: u32,
    format_ptr: *const u8,
    format_len: usize,
    mode_ptr: *const u8,
    mode_len: usize,
) -> *mut u8 {
    let requested = borrow_str(format_ptr, format_len);
    let mode = PrivacyMode::parse(&borrow_str(mode_ptr, mode_len));
    SESSIONS.with(|s| match s.borrow().get(&handle) {
        Some(session) => {
            let mut redactor = athernet_core::Redactor::new(mode);
            // "tables" is a different shape of the same capture rather than a
            // different format of the summary, so it does not belong in
            // ExportFormat - but it comes down the same call, because what the
            // caller needs is identical: a handle, a privacy mode, and text
            // back that has already been through the redactor.
            if requested == "tables" {
                return handback(export_tables(
                    &session.analysis,
                    session.limits,
                    &session.name,
                    &mut redactor,
                ));
            }
            handback(export(
                &session.analysis,
                session.limits,
                &session.name,
                ExportFormat::parse(&requested),
                &mut redactor,
            ))
        }
        None => handback(missing(handle)),
    })
}

// ----------------------------------------------------------------- analysis

/// The same pass the desktop app and the headless tool make, over bytes in
/// memory rather than a file on disk.
fn analyse(name: &str, bytes: &[u8]) -> (Analysis, String, CaptureLimits) {
    let mut analysis = Analysis::new();
    let mut capture = match CaptureFile::open(bytes) {
        Ok(capture) => capture,
        // The reader's errors are already written for a person to read, so
        // they go straight through rather than being replaced with a code.
        Err(e) => {
            return (
                analysis,
                error_json(name, &e.to_string()),
                CaptureLimits::default(),
            )
        }
    };

    let mut read_error = None;
    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                let decoded = decode(packet.link_type, packet.data);
                analysis.observe(&packet, &decoded);
            }
            Ok(None) => break,
            // A file that stops partway through still has everything before
            // the break worth showing, so this reports what it read rather
            // than throwing the capture away.
            Err(e) => {
                read_error = Some(e.to_string());
                break;
            }
        }
    }

    let limits = CaptureLimits {
        reported_drops: capture.reported_drops(),
        snaplen: capture.snaplen(),
    };
    let mut report = capture_json(name, name, &analysis, limits);
    if let Some(message) = read_error {
        report.pop(); // the closing brace
        report.push_str(",\"readError\":");
        push_json_string(&mut report, &message);
        report.push('}');
    }
    (analysis, report, limits)
}

fn missing(handle: u32) -> String {
    format!("{{\"error\":\"capture {handle} is not open any more\"}}")
}

fn error_json(name: &str, message: &str) -> String {
    let mut out = String::from("{\"file\":");
    push_json_string(&mut out, name);
    out.push_str(",\"error\":");
    push_json_string(&mut out, message);
    out.push('}');
    out
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_not_a_capture_comes_back_as_readable_json() {
        let (_, report, _) = analyse("notes.txt", b"this is not a capture file");
        assert!(report.contains("\"file\":\"notes.txt\""));
        assert!(report.contains("\"error\":"));
        // The message is the reader's own plain-language one, not a code.
        assert!(!report.contains("UnknownFormat"), "got {report}");
    }

    #[test]
    fn an_empty_file_does_not_panic() {
        let (_, report, _) = analyse("empty.pcap", b"");
        assert!(report.contains("\"error\":"));
    }

    #[test]
    fn escapes_a_name_with_a_quotation_mark_in_it() {
        let mut out = String::new();
        push_json_string(&mut out, "od\"d\nname");
        assert_eq!(out, "\"od\\\"d\\nname\"");
    }

    #[test]
    fn asking_about_a_closed_capture_is_an_error_not_a_crash() {
        let json = athernet_report(4242);
        assert!(!json.is_null());
        unsafe {
            let len = std::ptr::read_unaligned(json as *const u32) as usize;
            let text =
                String::from_utf8_lossy(std::slice::from_raw_parts(json.add(4), len)).into_owned();
            assert!(text.contains("is not open any more"), "got {text}");
            athernet_free(json, 4 + len);
        }
    }
}
