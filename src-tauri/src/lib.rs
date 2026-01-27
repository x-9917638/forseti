pub mod database;
pub mod generator;

use database::*;
use generator::generate_password;
use std::error;
use tauri::App;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(debug_assertions)]
    export_types();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(database::AppState::new())
        .invoke_handler(tauri::generate_handler![
            is_db_open,
            close_db,
            load_db,
            save_db,
            list_entries,
            add_entry,
            new_db,
            generate_password
        ])
        .setup(app_setup)
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Setup function for configuration of Tauri from Rust.
fn app_setup(app: &mut App) -> Result<(), Box<dyn error::Error>> {
    app.remove_menu()?;
    Ok(())
}

#[cfg(debug_assertions)]
fn export_types() {
    use specta_typescript::Typescript;
    use tauri_specta::{Builder, collect_commands};

    let builder = Builder::<tauri::Wry>::new().commands(collect_commands![
        is_db_open,
        close_db,
        load_db,
        save_db,
        list_entries,
        add_entry,
        new_db,
        generate_password
    ]);
    builder
        .export(
            Typescript::new().bigint(specta_typescript::BigIntExportBehavior::Number),
            "../src/lib/bindings.ts",
        )
        .expect("Failed to export typescript bindings");
    let _ = std::process::Command::new("npx")
        .arg("ts-node")
        .arg("../convert-to-object-params.ts")
        .output();
}
