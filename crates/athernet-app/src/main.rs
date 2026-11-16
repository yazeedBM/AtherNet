// The desktop shell. Everything heavy happens in athernet-core; this file
// only carries results across to the web view.
//
// There is deliberately no analysis here and no report shaping either. Every
// command hands back a string the core produced, so the desktop app, the
// browser build and the headless tool cannot disagree about what a capture
// shows. The command set mirrors the WebAssembly one in athernet-wasm,
// function for function, for the same reason.
//
// One thing it does differently, and it is the point of having a desktop
// build at all: a session keeps the capture's **path**, not its bytes. The
// browser has to hold the whole file to show one packet; this seeks to the
// offset the packet index kept and reads only that packet. A two gigabyte
// capture costs two gigabytes of reading in the browser and a few hundred
// bytes here.
//
// NOT YET COMPILED: Tauri on Windows needs the MSVC toolchain and the Visual
// Studio C++ build tools, which are not installed on the machine this was
// written on. Treat it as a first draft to build against. Everything it
// calls is covered by the core's tests; the wiring between is not.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use athernet_core::assistant::PrivacyMode;
use athernet_core::export::{export, ExportFormat};
use athernet_core::{
    assistant_json, capture_json, decode, packet_detail_from, packets_json, Analysis, CaptureFile,
    CaptureLimits, PacketQuery, Redactor,
};

/// One capture, analysed, with the path it came from.
struct Session {
    path: PathBuf,
    name: String,
    analysis: Analysis,
    limits: CaptureLimits,
    /// Built once when the file is opened, because every screen wants it.
    report: String,
}

#[derive(Default)]
struct Sessions {
    open: Mutex<HashMap<u32, Session>>,
    next: Mutex<u32>,
}

impl Sessions {
    fn insert(&self, session: Session) -> u32 {
        let handle = {
            let mut next = self.next.lock().expect("sessions");
            *next = next.wrapping_add(1).max(1);
            *next
        };
        self.open.lock().expect("sessions").insert(handle, session);
        handle
    }

    /// Run something against an open capture.
    fn with<T>(&self, handle: u32, f: impl FnOnce(&Session) -> T) -> Result<T, String> {
        let open = self.open.lock().map_err(|_| "the session list is unusable".to_string())?;
        match open.get(&handle) {
            Some(session) => Ok(f(session)),
            None => Err(format!("capture {handle} is not open any more")),
        }
    }
}

// ------------------------------------------------------------------ opening

/// Read one capture file and build everything that comes from it.
fn analyse_file(path: PathBuf) -> Result<Session, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capture")
        .to_string();

    let file = File::open(&path).map_err(|e| format!("{name}: {e}"))?;
    let mut capture = CaptureFile::open(file).map_err(|e| format!("{name}: {e}"))?;
    let mut analysis = Analysis::new();
    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                let decoded = decode(packet.link_type, packet.data);
                analysis.observe(&packet, &decoded);
            }
            Ok(None) => break,
            // A file that stops partway through still has everything before
            // the break worth showing, so what was read is kept.
            Err(e) => return Err(format!("{name}: {e}")),
        }
    }

    let limits = CaptureLimits {
        reported_drops: capture.reported_drops(),
        snaplen: capture.snaplen(),
    };
    let report = capture_json(&name, &path.display().to_string(), &analysis, limits);

    Ok(Session {
        path,
        name,
        analysis,
        limits,
        report,
    })
}

/// Analyse one capture and keep it open. Returns its handle and its report.
#[tauri::command]
fn open_capture(path: String, sessions: tauri::State<'_, Sessions>) -> Result<String, String> {
    let session = analyse_file(PathBuf::from(path))?;
    let report = session.report.clone();
    let handle = sessions.insert(session);
    // The web view wants both, and one string is one round trip.
    Ok(format!("{{\"handle\":{handle},\"report\":{report}}}"))
}

/// Analyse every capture in the given files and folders, without keeping any
/// of them open. This is what the first screen uses.
#[tauri::command]
fn analyse_paths(paths: Vec<String>) -> Result<String, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for path in paths {
        collect(Path::new(&path), &mut files).map_err(|e| e.to_string())?;
    }
    files.sort();

    let mut out = String::from("[");
    for (i, path) in files.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // The session is dropped at the end of each turn of this loop: the
        // first screen wants reports, not twenty captures held open.
        out.push_str(&analyse_file(path)?.report);
    }
    out.push(']');
    Ok(out)
}

#[tauri::command]
fn close_capture(handle: u32, sessions: tauri::State<'_, Sessions>) {
    if let Ok(mut open) = sessions.open.lock() {
        open.remove(&handle);
    }
}

// ----------------------------------------------------------------- reading

#[tauri::command]
fn capture_report(handle: u32, sessions: tauri::State<'_, Sessions>) -> Result<String, String> {
    sessions.with(handle, |session| session.report.clone())
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
fn capture_packets(
    handle: u32,
    start: usize,
    count: usize,
    flow_of_packet: Option<usize>,
    text: String,
    filter: String,
    sessions: tauri::State<'_, Sessions>,
) -> Result<String, String> {
    sessions.with(handle, |session| {
        packets_json(
            &session.analysis,
            PacketQuery {
                start,
                count,
                flow_of_packet,
                text: &text,
                filter: &filter,
            },
        )
    })
}

/// One packet, read from the file rather than from memory.
#[tauri::command]
fn capture_packet(
    handle: u32,
    index: usize,
    sessions: tauri::State<'_, Sessions>,
) -> Result<String, String> {
    let located = sessions.with(handle, |session| {
        session
            .analysis
            .packets
            .row(index)
            .map(|row| (session.path.clone(), row.offset, row.captured_len as usize))
    })?;
    let Some((path, offset, length)) = located else {
        return Err(format!("packet {index} is not in this capture"));
    };

    let mut file = File::open(&path).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut bytes = vec![0u8; length];
    // A short read means the file changed under us, which is worth saying
    // rather than showing a packet padded with zeroes.
    file.read_exact(&mut bytes)
        .map_err(|_| "that packet is no longer where the index says it is - has the file changed?".to_string())?;

    sessions.with(handle, |session| {
        packet_detail_from(&session.analysis, index, &bytes)
    })
}

// -------------------------------------------------------- assistant, export

#[tauri::command]
fn ask(
    handle: u32,
    question: String,
    mode: String,
    sessions: tauri::State<'_, Sessions>,
) -> Result<String, String> {
    let mode = PrivacyMode::parse(&mode);
    sessions.with(handle, |session| {
        assistant_json(
            &session.analysis,
            session.limits,
            &session.name,
            &question,
            mode,
        )
    })
}

#[tauri::command]
fn export_summary(
    handle: u32,
    format: String,
    mode: String,
    sessions: tauri::State<'_, Sessions>,
) -> Result<String, String> {
    let format = ExportFormat::parse(&format);
    let mode = PrivacyMode::parse(&mode);
    sessions.with(handle, |session| {
        let mut redactor = Redactor::new(mode);
        export(
            &session.analysis,
            session.limits,
            &session.name,
            format,
            &mut redactor,
        )
    })
}

// ------------------------------------------------------------------ helpers

fn collect(path: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            collect(&entry?.path(), out)?;
        }
        return Ok(());
    }
    let is_capture = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            e.eq_ignore_ascii_case("pcap")
                || e.eq_ignore_ascii_case("pcapng")
                || e.eq_ignore_ascii_case("cap")
        })
        .unwrap_or(false);
    if is_capture {
        out.push(path.to_path_buf());
    }
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(Sessions::default())
        .invoke_handler(tauri::generate_handler![
            analyse_paths,
            open_capture,
            close_capture,
            capture_report,
            capture_packets,
            capture_packet,
            ask,
            export_summary
        ])
        .run(tauri::generate_context!())
        .expect("AtherNet could not start");
}
