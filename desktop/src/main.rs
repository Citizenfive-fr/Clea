//! App de bureau Cléa : ouvre un Cléa auto-hébergé dans sa propre fenêtre.
//!
//! - Premier lancement : une page locale demande l'adresse du serveur (https:// seulement,
//!   ou http:// sur localhost pour tester). Elle est enregistrée dans le dossier de
//!   configuration de l'app.
//! - La fenêtre Cléa n'affiche que ce site : toute autre adresse s'ouvre dans le
//!   navigateur habituel. Le site distant n'a aucun accès à l'app (aucune capability),
//!   seule la page locale de configuration peut appeler `set_server`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{path::PathBuf, sync::Mutex, time::Duration};

use serde::{Deserialize, Serialize};
use tauri::{
    webview::{DownloadEvent, NewWindowResponse},
    AppHandle, Manager, Url, WebviewUrl, WebviewWindowBuilder,
};
use tauri_plugin_opener::OpenerExt;

const SETTINGS_FILE: &str = "serveur.json";
const SETUP: &str = "setup";
const MAIN: &str = "main";
/// Lien qui ouvre la fenêtre « Changer de serveur ». Les pages (page d'accueil de Cléa dans
/// l'app, page d'erreur) l'utilisent comme un simple lien : l'app l'intercepte, le site
/// n'obtient aucun accès.
const CHANGE_SERVER_LINK: &str = "clea-app:changer-serveur";
/// Permet au serveur Cléa de n'afficher le lien « Changer de serveur » que dans l'app.
const USER_AGENT: &str = "Mozilla/5.0 AppleWebKit/605.1.15 (KHTML, like Gecko) CleaDesktop";

/// Serveur affiché dans la fenêtre principale : lu à chaque navigation, changé par `set_server`.
#[derive(Default)]
struct CurrentServer(Mutex<Option<Url>>);

impl CurrentServer {
    fn get(&self) -> Option<Url> {
        self.0.lock().ok()?.clone()
    }

    fn set(&self, server: Url) {
        if let Ok(mut current) = self.0.lock() {
            *current = Some(server);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Settings {
    server: String,
}

/// Vérifie l'adresse saisie et n'en garde que l'origine (`https://hôte:port`).
fn parse_server(input: &str) -> Result<Url, String> {
    let url = Url::parse(input.trim())
        .map_err(|_| "Adresse invalide. Exemple : https://clea.monentreprise.fr".to_string())?;
    let host = url
        .host_str()
        .ok_or("Adresse invalide : il manque le nom du serveur.")?;
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        "http" => {
            return Err(
                "L'adresse doit commencer par https:// pour que la connexion soit \
                        chiffrée (http:// n'est accepté que pour localhost, pour tester)."
                    .into(),
            )
        }
        _ => return Err("L'adresse doit commencer par https://".into()),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("L'adresse ne doit pas contenir d'identifiant ni de mot de passe.".into());
    }
    Url::parse(&url.origin().ascii_serialization()).map_err(|_| "Adresse invalide.".to_string())
}

/// Vérifie qu'un Cléa répond à cette adresse (`/api/health`) avant de l'enregistrer.
fn check_server(server: &Url) -> Result<(), String> {
    use ureq::{config::AutoHeaderValue, tls::RootCerts, tls::TlsConfig, Error};

    let health = server
        .join("api/health")
        .map_err(|_| "Adresse invalide.".to_string())?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        // Rien sur l'app n'est envoyé au serveur
        .user_agent(AutoHeaderValue::None)
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .into();
    let not_clea = || "Ce serveur ne répond pas comme un Cléa. Vérifie l'adresse.".to_string();

    let mut response = agent.get(health.as_str()).call().map_err(|e| match e {
        Error::HostNotFound => "Serveur introuvable. Vérifie l'adresse.".to_string(),
        Error::ConnectionFailed | Error::Io(_) => {
            "Le serveur ne répond pas. Vérifie l'adresse et ta connexion.".into()
        }
        Error::Timeout(_) => "Le serveur met trop de temps à répondre. Réessaie.".into(),
        Error::Tls(_) | Error::Rustls(_) => {
            "La connexion sécurisée a échoué : le certificat du serveur n'est pas valide.".into()
        }
        _ => not_clea(),
    })?;
    let body = response
        .body_mut()
        .with_config()
        .limit(4096)
        .read_to_string()
        .map_err(|_| not_clea())?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|_| not_clea())?;
    if json["status"] != "ok" {
        return Err(not_clea());
    }
    Ok(())
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join(SETTINGS_FILE))
        .map_err(|e| format!("Dossier de configuration introuvable : {e}"))
}

fn load_server(app: &AppHandle) -> Option<Url> {
    let content = std::fs::read_to_string(settings_path(app).ok()?).ok()?;
    let settings: Settings = serde_json::from_str(&content).ok()?;
    parse_server(&settings.server).ok()
}

fn save_server(app: &AppHandle, server: &Url) -> Result<(), String> {
    let path = settings_path(app)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let settings = Settings {
        server: server.to_string(),
    };
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("Enregistrement impossible : {e}"))
}

/// Ouvre une adresse dans le navigateur habituel (adresses web seulement).
fn open_outside(app: &AppHandle, url: &Url) {
    if matches!(url.scheme(), "https" | "http" | "mailto") {
        if let Err(e) = app.opener().open_url(url.as_str(), None::<&str>) {
            eprintln!("Ouverture dans le navigateur impossible : {e}");
        }
    }
}

/// Fenêtre « Enregistrer sous » du système. Renvoie false si on annule (téléchargement
/// arrêté). `destination` arrive sous la forme Téléchargements/<nom proposé>.
#[cfg(target_os = "linux")]
fn ask_destination(webview: &tauri::Webview, destination: &mut PathBuf) -> bool {
    use gtk::prelude::*;
    let parent = webview.window().gtk_window().ok();
    let dialog = gtk::FileChooserNative::new(
        Some("Enregistrer le fichier"),
        parent.as_ref(),
        gtk::FileChooserAction::Save,
        Some("Enregistrer"),
        Some("Annuler"),
    );
    dialog.set_do_overwrite_confirmation(true);
    if let Some(dir) = destination.parent() {
        dialog.set_current_folder(dir);
    }
    if let Some(name) = destination.file_name() {
        dialog.set_current_name(name.to_string_lossy().as_ref());
    }
    let accepted = dialog.run() == gtk::ResponseType::Accept;
    match dialog.filename() {
        Some(path) if accepted => {
            *destination = path;
            true
        }
        _ => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn ask_destination(_webview: &tauri::Webview, _destination: &mut PathBuf) -> bool {
    true
}

/// Paliers de zoom, comme dans les navigateurs.
const ZOOM_LEVELS: [f64; 12] = [
    0.5, 0.67, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0,
];

/// Niveau de zoom suivant : `step` vaut 1 pour agrandir, -1 pour réduire, 0 pour 100 %.
fn next_zoom(current: f64, step: i8) -> f64 {
    match step {
        1 => ZOOM_LEVELS
            .into_iter()
            .find(|z| *z > current + 0.001)
            .unwrap_or(3.0),
        -1 => ZOOM_LEVELS
            .into_iter()
            .rev()
            .find(|z| *z < current - 0.001)
            .unwrap_or(0.5),
        _ => 1.0,
    }
}

/// Raccourcis gérés par l'app, avant que la page reçoive les touches (rien n'y est injecté) :
/// - F5 ou Ctrl+R recharge la page ;
/// - Ctrl+Maj+S ouvre la fenêtre « Changer de serveur » ;
/// - zoom avec Ctrl + / Ctrl - / Ctrl 0 (le zoom de Tauri sous Linux demande un script
///   dans la page avec accès à l'app, ce que le site distant ne doit pas avoir) ;
/// - collage ignoré quand le presse-papiers est vide : WebKitGTK 2.54 plante dans ce cas.
#[cfg(target_os = "linux")]
fn keyboard_shortcuts(window: &tauri::WebviewWindow) {
    use gtk::{gdk, gdk::keys::constants as key, glib, prelude::*};
    use std::cell::Cell;

    let Ok(gtk_window) = window.gtk_window() else {
        return;
    };
    let window = window.clone();
    let zoom = Cell::new(1.0);
    gtk_window.connect_key_press_event(move |_, event| {
        let state = event.state();
        let ctrl = state.contains(gdk::ModifierType::CONTROL_MASK);
        let keyval = event.keyval();

        let step = match keyval {
            _ if !ctrl => None,
            k if k == key::plus || k == key::equal || k == key::KP_Add => Some(1),
            k if k == key::minus || k == key::KP_Subtract => Some(-1),
            k if k == key::_0 || k == key::KP_0 || k == key::agrave => Some(0),
            _ => None,
        };
        let shift = state.contains(gdk::ModifierType::SHIFT_MASK);
        if keyval == key::F5 || (ctrl && (keyval == key::r || keyval == key::R)) {
            let _ = window.reload();
            return glib::Propagation::Stop;
        }
        if ctrl && shift && (keyval == key::S || keyval == key::s) {
            let _ = open_setup(window.app_handle());
            return glib::Propagation::Stop;
        }

        if let Some(step) = step {
            let level = next_zoom(zoom.get(), step);
            if window.set_zoom(level).is_ok() {
                zoom.set(level);
            }
            return glib::Propagation::Stop;
        }

        let paste =
            (ctrl && (keyval == key::v || keyval == key::V)) || (shift && keyval == key::Insert);
        if paste {
            let clipboard = gtk::Clipboard::get(&gdk::SELECTION_CLIPBOARD);
            if clipboard
                .wait_for_targets()
                .is_none_or(|targets| targets.is_empty())
            {
                return glib::Propagation::Stop;
            }
        }
        glib::Propagation::Proceed
    });
}

#[cfg(not(target_os = "linux"))]
fn keyboard_shortcuts(_window: &tauri::WebviewWindow) {}

/// Page en français affichée dans la fenêtre principale quand le serveur ne répond pas, à la
/// place de l'erreur brute de WebKit. Seulement des liens : « Réessayer » recharge
/// l'adresse, l'autre est CHANGE_SERVER_LINK.
fn error_page(failing_url: &str, server: &str) -> String {
    fn escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }
    include_str!("../ui/erreur.html")
        .replace("{{STYLE}}", include_str!("../ui/style.css"))
        .replace("{{SERVER}}", &escape(server))
        .replace("{{URL}}", &escape(failing_url))
}

#[cfg(target_os = "linux")]
fn show_error_page_on_failure(window: &tauri::WebviewWindow) {
    let app = window.app_handle().clone();
    let _ = window.with_webview(move |platform| {
        use webkit2gtk::{NetworkError, PolicyError, WebViewExt};
        platform
            .inner()
            .connect_load_failed(move |webview, _event, failing_url, error| {
                // Chargements arrêtés, téléchargements et liens envoyés au navigateur : pas des erreurs
                if error.matches(NetworkError::Cancelled) || error.kind::<PolicyError>().is_some() {
                    return false;
                }
                let server = app
                    .state::<CurrentServer>()
                    .get()
                    .map(|s| s.origin().ascii_serialization())
                    .unwrap_or_default();
                webview.load_alternate_html(&error_page(failing_url, &server), failing_url, None);
                true
            });
    });
}

#[cfg(not(target_os = "linux"))]
fn show_error_page_on_failure(_window: &tauri::WebviewWindow) {}

/// Petite fenêtre affichée pendant un téléchargement (barre animée), puis « terminé » ou
/// l'erreur. Tauri ne signale que le début et la fin d'un téléchargement, pas sa progression.
#[cfg(target_os = "linux")]
mod download_progress {
    use gtk::{glib, prelude::*};
    use std::{cell::RefCell, collections::HashMap, path::Path, time::Duration};

    struct Pending {
        dialog: gtk::MessageDialog,
        bar: gtk::ProgressBar,
        pulse: Option<glib::SourceId>,
        path: String,
    }

    thread_local! {
        // Les widgets GTK vivent sur le fil principal, où arrivent les événements de téléchargement
        static PENDING: RefCell<HashMap<String, Pending>> = RefCell::default();
    }

    pub fn started(webview: &tauri::Webview, url: &str, destination: &Path) {
        let parent = webview.window().gtk_window().ok();
        let name = destination
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dialog = gtk::MessageDialog::new(
            parent.as_ref(),
            gtk::DialogFlags::DESTROY_WITH_PARENT,
            gtk::MessageType::Info,
            gtk::ButtonsType::Close,
            &format!("Téléchargement de {name}…"),
        );
        dialog.set_title("Téléchargement");
        let bar = gtk::ProgressBar::new();
        if let Ok(area) = dialog.message_area().downcast::<gtk::Box>() {
            area.pack_start(&bar, false, false, 6);
        }
        let key = url.to_string();
        dialog.connect_response(move |dialog, _| {
            if let Some(pulse) = PENDING
                .with(|m| m.borrow_mut().remove(&key))
                .and_then(|p| p.pulse)
            {
                pulse.remove();
            }
            dialog.close();
        });
        dialog.show_all();
        let pulse = glib::timeout_add_local(Duration::from_millis(120), {
            let bar = bar.clone();
            move || {
                bar.pulse();
                glib::ControlFlow::Continue
            }
        });
        let pending = Pending {
            dialog,
            bar,
            pulse: Some(pulse),
            path: destination.display().to_string(),
        };
        PENDING.with(|m| m.borrow_mut().insert(url.to_string(), pending));
    }

    pub fn finished(url: &str, success: bool) {
        // L'entrée reste jusqu'à ce que la personne ferme la fenêtre
        PENDING.with(|m| {
            let mut map = m.borrow_mut();
            let Some(p) = map.get_mut(url) else { return };
            if let Some(pulse) = p.pulse.take() {
                pulse.remove();
            }
            p.bar.set_fraction(if success { 1.0 } else { 0.0 });
            if success {
                p.dialog.set_text(Some("Téléchargement terminé"));
                p.dialog
                    .set_secondary_text(Some(&format!("Fichier enregistré ici :\n{}", p.path)));
            } else {
                p.dialog.set_message_type(gtk::MessageType::Error);
                p.dialog.set_text(Some("Le téléchargement a échoué"));
                p.dialog.set_secondary_text(Some("Réessaie."));
            }
        });
    }
}

#[cfg(not(target_os = "linux"))]
mod download_progress {
    pub fn started(_webview: &tauri::Webview, _url: &str, _destination: &std::path::Path) {}
    pub fn finished(_url: &str, _success: bool) {}
}

fn open_setup(app: &AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(SETUP) {
        return window.set_focus().map_err(|e| e.to_string());
    }
    WebviewWindowBuilder::new(app, SETUP, WebviewUrl::App("index.html".into()))
        .title("Cléa : connexion à ton serveur")
        .inner_size(560.0, 560.0)
        .min_inner_size(360.0, 480.0)
        .build()
        .map(|window| keyboard_shortcuts(&window))
        .map_err(|e| e.to_string())
}

/// Affiche `server` dans la fenêtre principale : le charge dans la fenêtre si elle existe,
/// la crée sinon. À appeler sur le fil principal.
fn open_main(app: &AppHandle, server: &Url) -> Result<(), String> {
    let start = server
        .join("app")
        .map_err(|_| "Adresse invalide.".to_string())?;
    app.state::<CurrentServer>().set(server.clone());
    if let Some(window) = app.get_webview_window(MAIN) {
        window.navigate(start).map_err(|e| e.to_string())?;
        return window.set_focus().map_err(|e| e.to_string());
    }
    let (nav_app, popup_app) = (app.clone(), app.clone());

    WebviewWindowBuilder::new(app, MAIN, WebviewUrl::External(start))
        .title("Cléa")
        .user_agent(USER_AGENT)
        // Windows : raccourcis de zoom natifs de WebView2 (Linux : voir keyboard_shortcuts)
        .zoom_hotkeys_enabled(cfg!(windows))
        .inner_size(1280.0, 860.0)
        .min_inner_size(420.0, 500.0)
        // Seulement le site Cléa dans cette fenêtre, tout le reste dans le navigateur
        .on_navigation(move |url| {
            if url.as_str() == CHANGE_SERVER_LINK {
                let _ = open_setup(&nav_app);
                return false;
            }
            let current = nav_app.state::<CurrentServer>().get();
            if current.is_some_and(|server| server.origin() == url.origin()) {
                return true;
            }
            open_outside(&nav_app, url);
            false
        })
        // Les liens qui ouvrent une nouvelle fenêtre (sources des Actualités, wiki...) vont au navigateur
        .on_new_window(move |url, _features| {
            open_outside(&popup_app, &url);
            NewWindowResponse::Deny
        })
        // Téléchargements (sauvegardes) : la personne choisit où les enregistrer
        .on_download(|webview, event| match event {
            DownloadEvent::Requested { url, destination } => {
                let accepted = ask_destination(&webview, destination);
                if accepted {
                    download_progress::started(&webview, url.as_str(), destination);
                }
                accepted
            }
            DownloadEvent::Finished { url, success, .. } => {
                download_progress::finished(url.as_str(), success);
                true
            }
            _ => true,
        })
        .build()
        .map(|window| {
            keyboard_shortcuts(&window);
            show_error_page_on_failure(&window);
        })
        .map_err(|e| e.to_string())
}

/// Appelée seulement par la page de configuration (voir capabilities/setup.json).
/// Asynchrone pour que la vérification réseau ne fige pas la fenêtre.
#[tauri::command]
async fn set_server(app: AppHandle, url: String) -> Result<(), String> {
    let server = parse_server(&url)?;
    let checked = server.clone();
    tauri::async_runtime::spawn_blocking(move || check_server(&checked))
        .await
        .map_err(|e| e.to_string())??;
    save_server(&app, &server)?;
    // Les fenêtres se gèrent sur le fil principal (cette commande tourne sur un autre)
    let handle = app.clone();
    app.run_on_main_thread(move || {
        if let Err(e) = open_main(&handle, &server) {
            eprintln!("Ouverture de Cléa impossible : {e}");
        }
        if let Some(window) = handle.get_webview_window(SETUP) {
            let _ = window.close();
        }
    })
    .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        // Aucun script injecté dans les pages : le site distant n'a de toute façon aucun accès
        // à l'app, les liens partent au navigateur via on_navigation / on_new_window
        .plugin(
            tauri_plugin_opener::Builder::new()
                .open_js_links_on_click(false)
                .build(),
        )
        .manage(CurrentServer::default())
        .invoke_handler(tauri::generate_handler![set_server])
        .setup(|app| {
            let handle = app.handle().clone();
            match load_server(&handle) {
                Some(server) => open_main(&handle, &server)?,
                None => open_setup(&handle)?,
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Cléa n'a pas pu démarrer");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_address_is_checked_and_reduced_to_its_origin() {
        assert_eq!(
            parse_server(" https://clea.example.fr/app?x=1 ")
                .unwrap()
                .as_str(),
            "https://clea.example.fr/"
        );
        assert_eq!(
            parse_server("https://clea.example.fr:8443")
                .unwrap()
                .as_str(),
            "https://clea.example.fr:8443/"
        );
        assert!(parse_server("http://localhost:8080").is_ok());
        assert!(parse_server("http://clea.example.fr").is_err());
        assert!(parse_server("https://user:pass@clea.example.fr").is_err());
        assert!(parse_server("file:///etc/passwd").is_err());
        assert!(parse_server("javascript:alert(1)").is_err());
        assert!(parse_server("clea.example.fr").is_err());
    }

    #[test]
    fn error_page_escapes_the_address() {
        let page = error_page(
            "https://clea.example.fr/app?a=\"><script>",
            "https://clea.example.fr",
        );
        assert!(page.contains(r#"href="https://clea.example.fr/app?a=&quot;&gt;&lt;script&gt;""#));
        assert!(!page.contains("<script>"));
        assert!(page.contains(CHANGE_SERVER_LINK));
    }

    #[test]
    fn zoom_goes_step_by_step_and_stays_in_range() {
        assert_eq!(next_zoom(1.0, 1), 1.1);
        assert_eq!(next_zoom(1.0, -1), 0.9);
        assert_eq!(next_zoom(3.0, 1), 3.0);
        assert_eq!(next_zoom(0.5, -1), 0.5);
        assert_eq!(next_zoom(2.5, 0), 1.0);
    }

    /// Serveur local qui répond une fois avec `body` ; renvoie son adresse.
    fn fake_server(status: &str, body: &'static str) -> Url {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0; 1024]);
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        });
        parse_server(&format!("http://127.0.0.1:{}", addr.port())).unwrap()
    }

    #[test]
    fn only_a_clea_server_is_accepted() {
        assert!(check_server(&fake_server(
            "200 OK",
            r#"{"status":"ok","version":"0.2.0"}"#
        ))
        .is_ok());
        assert!(check_server(&fake_server("200 OK", "<html>autre site</html>")).is_err());
        assert!(check_server(&fake_server("404 Not Found", "")).is_err());
        assert!(check_server(&fake_server("302 Found", "")).is_err());
        // Rien n'écoute sur ce port
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let url = parse_server(&format!("http://127.0.0.1:{}", closed.port())).unwrap();
        assert!(check_server(&url).is_err());
    }
}
