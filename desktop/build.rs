fn main() {
    // Déclarer les commandes de l'app les fait refuser sauf si une capability les accorde :
    // seule la fenêtre de configuration a droit à set_server (capabilities/setup.json)
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["set_server"])),
    )
    .expect("tauri build step failed");
}
