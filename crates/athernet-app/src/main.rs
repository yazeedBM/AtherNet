// The desktop shell. Everything heavy happens in athernet-core; this file
// only carries results across to the web view.
//
// There is deliberately no analysis here, and now no report shaping either.
// The command hands back the JSON the core produced, so the desktop app, the
// headless tool and the fixture report the dev server renders all come out of
// one function in crates/athernet-core/src/report.rs. An earlier draft built
// the JSON here with serde, which meant two mappings that could drift apart
// and only one of them under test.
//
// NOT YET COMPILED: Tauri on Windows needs the MSVC toolchain and the Visual
// Studio C++ build tools, which are not installed here. Treat this file as a
// first draft to build against. The core crate is the part that matters and
// it has tests.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::path::{Path, PathBuf};

use athernet_core::{capture_json, decode, Analysis, CaptureFile, CaptureLimits};

/// Analyse every capture file in the given files and folders.
///
/// Returns a JSON array as a string, which the web view parses. Returning the
/// text rather than a typed value costs one extra parse and buys the single
/// mapping described above; the alternative was a second set of structs here
/// that nothing tests.
#[tauri::command]
fn analyse_paths(paths: Vec<String>) -> Result<String, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for path in paths {
        collect(Path::new(&path), &mut files).map_err(|e| e.to_string())?;
    }
    files.sort();

    let mut out = String::from("[");
    for (i, path) in files.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&analyse_one(path)?);
    }
    out.push(']');
    Ok(out)
}

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
        .map(|e| e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("pcapng"))
        .unwrap_or(false);
    if is_capture {
        out.push(path.to_path_buf());
    }
    Ok(())
}

fn analyse_one(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capture");
    let file = File::open(path).map_err(|e| format!("{name}: {e}"))?;
    let mut capture = CaptureFile::open(file).map_err(|e| format!("{name}: {e}"))?;
    let mut analysis = Analysis::new();
    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                let decoded = decode(packet.link_type, packet.data);
                analysis.observe(&packet, &decoded);
            }
            Ok(None) => break,
            Err(e) => return Err(format!("{name}: {e}")),
        }
    }
    let limits = CaptureLimits {
        reported_drops: capture.reported_drops(),
        snaplen: capture.snaplen(),
    };
    Ok(capture_json(
        name,
        &path.display().to_string(),
        &analysis,
        limits,
    ))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![analyse_paths])
        .run(tauri::generate_context!())
        .expect("AtherNet could not start");
}
