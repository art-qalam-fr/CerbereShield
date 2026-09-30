/// Ouvre une URL dans le navigateur système (liens externes, exports).
/// La webview ne gère pas target="_blank" / window.open vers l'extérieur.
#[tauri::command]
fn open_url(url: String) {
  #[cfg(target_os = "windows")]
  {
    let _ = std::process::Command::new("cmd")
      .args(["/c", "start", "", &url])
      .spawn();
  }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![open_url])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
