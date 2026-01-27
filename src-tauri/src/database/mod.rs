mod helpers;
mod structs;

use std::{collections::HashMap, sync::Mutex};
use tauri::{State, command};

use structs::{
    CompressionAlgorithm, DatabaseFile, EncryptionAlgorithm, EntryDto, Header, HeaderFields,
    InternalContent, KDFParams, KeyDerivationFunction, SaveMethod,
};

/// Application state holding a single open database in memory.
pub struct AppState {
    current_db: Mutex<Option<DatabaseFile>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            current_db: Mutex::new(None),
        }
    }
}
// Clippy screaming at me
impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns whether a database is currently open in memory.
#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn is_db_open(state: State<AppState>) -> Result<bool, String> {
    let guard = state
        .current_db
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    Ok(guard.is_some())
}

/// Closes the currently open database (if any).
#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn close_db(state: State<AppState>) -> Result<(), String> {
    let mut guard = state
        .current_db
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    *guard = None;
    Ok(())
}

/// Loads a database from disk and keeps it open in memory.
///
/// Note: The frontend should NOT expect the database file contents to be returned.
/// Instead, subsequent commands should operate against the in-memory database.
#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn load_db(
    state: State<AppState>,
    path: String,
    master_password: String,
) -> Result<(), String> {
    let db = DatabaseFile::deserialise(&path, master_password.as_bytes())
        .map_err(|e| format!("failed to load db: {e}"))?;

    let mut guard = state
        .current_db
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    *guard = Some(db);
    Ok(())
}

/// Saves the currently open database to disk using the provided master password.
///
/// - `atomic = true` writes to a temporary file and then renames it into place.
/// - `atomic = false` writes directly to the destination file path.
#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn save_db(
    state: State<AppState>,
    path: String,
    master_password: String,
    atomic: bool,
) -> Result<(), String> {
    let mut guard = state
        .current_db
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    let db = guard
        .as_mut()
        .ok_or_else(|| "no database open".to_string())?;
    let method = if atomic {
        SaveMethod::Atomic
    } else {
        SaveMethod::Direct
    };

    db.save(&path, method, master_password.as_bytes())
        .map_err(|e| format!("failed to save db: {e}"))?;
    Ok(())
}

/// Lists entries from the open database.
#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn list_entries(state: State<AppState>) -> Result<Vec<EntryDto>, String> {
    let guard = state
        .current_db
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    let db = guard
        .as_ref()
        .ok_or_else(|| "no database open".to_string())?;
    Ok(db.list_entries_dto())
}

/// Adds an entry to the in-memory database.
#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn add_entry(
    state: State<AppState>,
    icon: String,
    fields: HashMap<String, String>,
    url: String,
    expiry_unix: Option<i64>,
    expiry_offset_secs: Option<i32>,
) -> Result<(), String> {
    let mut guard = state
        .current_db
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    let db = guard
        .as_mut()
        .ok_or_else(|| "no database open".to_string())?;
    let fields = fields
        .into_iter()
        .map(|(k, v)| (k, v.into_bytes()))
        .collect();
    db.add_entry_plain(&icon, fields, &url, expiry_unix, expiry_offset_secs)
        .map_err(|e| format!("failed to add entry: {e}"))?;

    Ok(())
}

/// Creates a new database and loads it into memory.
#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn new_db(
    state: State<AppState>,
    encryption: Option<u8>,
    compression: Option<u8>,
    kdf_variant: Option<u8>,
    kdf_iterations: u32,
    kdf_memory_kb: u32,
    kdf_threads: u32,
) -> Result<(), String> {
    let kdf_variant_enum = match kdf_variant {
        Some(i) => Some(KeyDerivationFunction::try_from_u8(i).map_err(|e| e.to_string())?),
        None => None,
    };
    let params = KDFParams::new(kdf_variant_enum, kdf_iterations, kdf_memory_kb, kdf_threads);

    let encryption_enum = match encryption {
        Some(i) => Some(EncryptionAlgorithm::try_from_u8(i).map_err(|e| e.to_string())?),
        None => None,
    };
    let compression_enum = match compression {
        Some(i) => Some(CompressionAlgorithm::try_from_u8(i).map_err(|e| e.to_string())?),
        None => None,
    };

    let fields = HeaderFields::new(encryption_enum, compression_enum, params);
    let header = Header::new(fields);
    let internal = InternalContent::new();

    let db = DatabaseFile::new(header, internal);

    let mut guard = state
        .current_db
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    *guard = Some(db);

    Ok(())
}
