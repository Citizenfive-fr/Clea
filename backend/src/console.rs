//! `clea console`: the host commands in a menu, each one explained, with confirmation before
//! anything risky. Same code as the command line (commands.rs), nothing more.
//!
//! Colors and the big title only in a real terminal, and never with NO_COLOR: a screen
//! reader would otherwise read the drawing character by character. The menu never relies
//! on color alone (states are also written in words).

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use sqlx::PgPool;

use crate::{backup, cli, commands, config::Config};

type Rgb = (u8, u8, u8);

// Colors of tokens.css, converted from OKLCH to sRGB
const CYAN: Rgb = (24, 177, 205); // --brand-cyan
const TEAL: Rgb = (78, 190, 125); // --brand-teal
const VIOLET: Rgb = (123, 101, 209); // --brand-pink
const SOFT: Rgb = (149, 160, 166); // --soft-fg
const DANGER: Rgb = (254, 185, 189); // --danger-fg
const SUCCESS: Rgb = (164, 222, 183); // --success-fg

/// "ANSI Shadow" style, drawn by hand, with the accent on the É.
const BANNER: [&str; 7] = [
    "                   ▄▄▀▀       ",
    " ██████╗██╗     ███████╗ █████╗ ",
    "██╔════╝██║     ██╔════╝██╔══██╗",
    "██║     ██║     █████╗  ███████║",
    "██║     ██║     ██╔══╝  ██╔══██║",
    "╚██████╗███████╗███████╗██║  ██║",
    " ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝",
];
const TAGLINE: &str = "Conformité · Liberté · Équité · Accessibilité";
const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Style {
    color: bool,
}

impl Style {
    fn detect() -> Self {
        Self {
            color: io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    fn paint(&self, (r, g, b): Rgb, text: &str) -> String {
        if self.color {
            format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        if self.color {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// Aurora gradient, cyan -> teal -> violet, for `t` from 0 to 1.
fn gradient(t: f32) -> Rgb {
    let stops = [CYAN, TEAL, VIOLET];
    let t = t.clamp(0.0, 1.0) * (stops.len() - 1) as f32;
    let i = (t as usize).min(stops.len() - 2);
    let u = t - i as f32;
    let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * u).round() as u8;
    let (a, b) = (stops[i], stops[i + 1]);
    (mix(a.0, b.0), mix(a.1, b.1), mix(a.2, b.2))
}

fn print_banner(style: &Style) {
    println!();
    if !style.color {
        println!("Cléa {VERSION} · console d'administration\n");
        return;
    }
    let width = BANNER.iter().map(|l| l.chars().count()).max().unwrap_or(1);
    let total = width.max(TAGLINE.chars().count());
    let left = " ".repeat(2 + (total - width) / 2);
    for line in BANNER {
        let mut out = left.clone();
        for (x, ch) in line.chars().enumerate() {
            if ch == ' ' {
                out.push(ch);
            } else {
                out.push_str(
                    &style.paint(gradient(x as f32 / (width - 1) as f32), &ch.to_string()),
                );
            }
        }
        println!("{}", out.trim_end());
    }
    let pad = " ".repeat(2 + (total - TAGLINE.chars().count()) / 2);
    println!("{pad}{}", style.paint(SOFT, TAGLINE));
    println!(
        "\n  {}  {}",
        style.bold("Console d'administration"),
        style.paint(SOFT, &format!("version {VERSION}"))
    );
}

#[derive(Debug, PartialEq)]
enum Choice {
    Backup,
    Verify,
    Restore,
    RotateKey,
    Recover,
    NewRecoveryKey,
    UpdateCheck,
    Help,
    Quit,
}

fn parse_choice(input: &str) -> Option<Choice> {
    match input.trim().to_lowercase().as_str() {
        "1" => Some(Choice::Backup),
        "2" => Some(Choice::Verify),
        "3" => Some(Choice::Restore),
        "4" => Some(Choice::RotateKey),
        "5" => Some(Choice::Recover),
        "6" => Some(Choice::NewRecoveryKey),
        "7" => Some(Choice::UpdateCheck),
        "a" | "aide" | "h" | "help" => Some(Choice::Help),
        "q" | "quitter" | "quit" | "exit" => Some(Choice::Quit),
        _ => None,
    }
}

fn print_menu(style: &Style, running: Option<bool>, config: &Config) {
    let server = match running {
        Some(true) => style.paint(TEAL, "● en marche"),
        Some(false) => style.paint(SOFT, "○ arrêtée"),
        None => style.paint(DANGER, "état inconnu"),
    };
    let backups = match &config.backup_dir {
        Some(dir) => style.paint(TEAL, &format!("● {}", dir.display())),
        None => style.paint(SOFT, "○ non configurées (BACKUP_DIR)"),
    };
    println!();
    println!(
        "  {}  Cléa {server}   Sauvegardes {backups}",
        style.paint(SOFT, "État")
    );

    // Actions that need Cléa stopped are marked in words, not only in color
    let stopped_only = running == Some(true);
    let item = |key: &str, label: &str, needs_stop: bool| {
        let key = style.paint(CYAN, key);
        if needs_stop && stopped_only {
            println!(
                "    {key}  {}  {}",
                style.paint(SOFT, label),
                style.paint(SOFT, "(arrête Cléa d'abord)")
            );
        } else {
            println!("    {key}  {label}");
        }
    };
    println!("\n  {}", style.bold("Sauvegardes"));
    item("1", "Faire une sauvegarde maintenant", false);
    item("2", "Vérifier les empreintes des sauvegardes", false);
    item("3", "Restaurer une sauvegarde", true);
    println!("\n  {}", style.bold("Clés"));
    item("4", "Changer la clé maîtresse", true);
    item(
        "5",
        "Clé maîtresse perdue : récupérer avec la clé de secours",
        true,
    );
    item("6", "Créer une nouvelle clé de secours", false);
    println!("\n  {}", style.bold("Cléa"));
    item("7", "Vérifier les mises à jour", false);
    println!();
    item("a", "Aide : toutes les commandes", false);
    item("q", "Quitter", false);
}

/// Reads one line. None at the end of the input (Ctrl+D): the console stops.
fn prompt(style: &Style, question: &str) -> Option<String> {
    print!("\n  {} ", style.paint(CYAN, &format!("{question} :")));
    io::stdout().flush().ok();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

fn explain(style: &Style, title: &str, text: &str) {
    println!("\n  {}", style.bold(title));
    for line in text.lines() {
        println!("  {}", line.trim());
    }
}

fn error(style: &Style, text: &str) {
    for line in text.lines() {
        println!("  {}", style.paint(DANGER, line));
    }
}

fn success(style: &Style, text: &str) {
    println!("  {}", style.paint(SUCCESS, text));
}

/// Asks to type `word` before a risky action. Anything else cancels.
fn confirm(style: &Style, word: &str) -> bool {
    let ok = prompt(
        style,
        &format!("Pour confirmer, tape {word} (ou Entrée pour annuler)"),
    )
    .is_some_and(|answer| answer == word);
    if !ok {
        println!("  Annulé, rien n'a été modifié.");
    }
    ok
}

/// Whether an answer looks like a key typed instead of a file path.
fn looks_like_a_key(input: &str) -> bool {
    let upper = input.trim().to_uppercase();
    upper.starts_with("CLEA-")
        || (upper.len() >= 64 && upper.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Asks for the path of a file holding a key. Keys are never typed here: they would stay
/// on screen and in the terminal scrollback.
fn ask_key_file(style: &Style, what: &str) -> Option<String> {
    let path = prompt(style, &format!("Chemin du fichier qui contient {what}"))?;
    if path.is_empty() {
        println!("  Annulé.");
        return None;
    }
    if looks_like_a_key(&path) {
        error(
            style,
            "Indique le chemin d'un fichier, pas la clé elle-même : elle resterait affichée \
             à l'écran.",
        );
        return None;
    }
    if path == "-" || !Path::new(&path).is_file() {
        error(style, &format!("Fichier introuvable : {path}"));
        return None;
    }
    Some(path)
}

/// Refuses the actions that need Cléa stopped while it is running.
fn needs_stopped(style: &Style, running: Option<bool>) -> bool {
    if running == Some(true) {
        error(
            style,
            "Cléa tourne encore. Arrête-la d'abord (docker compose stop app), puis relance \
             la console avec : docker compose run --rm -it app console",
        );
        return false;
    }
    true
}

fn report(style: &Style, result: Result<(), String>) {
    if let Err(e) = result {
        error(style, &e);
    }
}

/// Lists the backups of BACKUP_DIR, newest first, numbered from 1.
fn show_backups(style: &Style, dir: &Path) -> Vec<PathBuf> {
    let backups = match backup::list(dir) {
        Ok(b) => b,
        Err(e) => {
            error(style, &e);
            return Vec::new();
        }
    };
    if backups.is_empty() {
        println!("  Aucune sauvegarde dans {}.", dir.display());
        return Vec::new();
    }
    let mut paths = Vec::new();
    for (i, b) in backups.iter().rev().enumerate() {
        let state = match b.fingerprint {
            backup::Fingerprint::Valid => style.paint(SUCCESS, "empreinte bonne"),
            backup::Fingerprint::Missing => style.paint(DANGER, "empreinte absente"),
            backup::Fingerprint::Mismatch => style.paint(DANGER, "MODIFIÉE"),
        };
        println!(
            "    {}  {}  {:>8} Ko  {state}",
            style.paint(CYAN, &format!("{:>2}", i + 1)),
            b.at.format("%d/%m/%Y %H:%M UTC"),
            b.size.div_ceil(1024)
        );
        paths.push(dir.join(&b.file));
    }
    paths
}

async fn restore(style: &Style, db: &PgPool, config: &Config, running: Option<bool>) {
    explain(
        style,
        "Restaurer une sauvegarde",
        "Remplace toute la base par celle de la sauvegarde. La base doit être neuve (sans setup).
         Ce qui a été fait après la sauvegarde est perdu, et tout le monde devra se reconnecter.
         Il faut la clé de sauvegarde du propriétaire, dans un fichier, et la même clé maîtresse.",
    );
    if !needs_stopped(style, running) {
        return;
    }
    let listed = match &config.backup_dir {
        Some(dir) => show_backups(style, dir),
        None => Vec::new(),
    };
    let Some(answer) = prompt(
        style,
        "Numéro de la sauvegarde, ou chemin d'un fichier .backup",
    ) else {
        return;
    };
    let file = match answer.parse::<usize>() {
        Ok(n) if (1..=listed.len()).contains(&n) => listed[n - 1].clone(),
        _ if answer.is_empty() => {
            println!("  Annulé.");
            return;
        }
        _ => PathBuf::from(answer),
    };
    if !file.is_file() {
        error(style, &format!("Fichier introuvable : {}", file.display()));
        return;
    }
    let Some(key_file) = ask_key_file(style, "la clé de sauvegarde") else {
        return;
    };
    if confirm(style, "RESTAURER") {
        report(style, commands::restore(db, config, &file, &key_file).await);
    }
}

async fn rotate_key(style: &Style, db: &PgPool, config: &Config, running: Option<bool>) {
    explain(
        style,
        "Changer la clé maîtresse",
        "Enferme les clés des organisations avec une nouvelle clé maîtresse.
         Prépare-la d'abord dans un fichier : openssl rand -hex 64 > nouvelle-cle.txt
         Ensuite, mets-la dans APP_SECRET_KEY ou APP_KEY_FILE avant de relancer Cléa.",
    );
    if !needs_stopped(style, running) {
        return;
    }
    let Some(file) = ask_key_file(style, "la nouvelle clé maîtresse") else {
        return;
    };
    if confirm(style, "oui") {
        report(style, commands::rotate_key(db, config, &file).await);
    }
}

async fn recover(style: &Style, db: &PgPool, config: &Config, running: Option<bool>) {
    explain(
        style,
        "Clé maîtresse perdue : récupérer",
        "Rouvre la clé de l'organisation avec la clé de secours, puis l'enferme avec la clé
         maîtresse actuelle (APP_SECRET_KEY ou APP_KEY_FILE, la nouvelle).
         Une nouvelle clé de secours est créée et affichée une seule fois : l'ancienne ne
         marchera plus.",
    );
    if !needs_stopped(style, running) {
        return;
    }
    let Some(file) = ask_key_file(style, "la clé de secours") else {
        return;
    };
    if confirm(style, "oui") {
        report(style, commands::recover(db, config, &file).await);
    }
}

async fn new_recovery_key(style: &Style, db: &PgPool, config: &Config) {
    explain(
        style,
        "Créer une nouvelle clé de secours",
        "Pour une clé de secours perdue ou jamais rangée. La nouvelle clé est affichée une
         seule fois, et l'ancienne ne marchera plus. Le propriétaire sera prévenu dans Cléa.",
    );
    if confirm(style, "oui") {
        report(style, commands::new_recovery_key(db, config).await);
    }
}

pub async fn run(db: &PgPool, config: &Config) {
    let style = Style::detect();
    print_banner(&style);
    loop {
        let running = commands::server_running(db).await.ok();
        print_menu(&style, running, config);
        let Some(answer) = prompt(&style, "Ton choix") else {
            break;
        };
        match parse_choice(&answer) {
            Some(Choice::Quit) => break,
            Some(Choice::Backup) => {
                explain(
                    &style,
                    "Faire une sauvegarde maintenant",
                    "Copie chiffrée de toute la base, avec son empreinte, dans le dossier des
                     sauvegardes. Possible pendant que Cléa tourne.",
                );
                match commands::backup(db, config).await {
                    Ok(()) => success(&style, "C'est fait."),
                    Err(e) => error(&style, &e),
                }
            }
            Some(Choice::Verify) => {
                explain(
                    &style,
                    "Vérifier les empreintes des sauvegardes",
                    "Recalcule l'empreinte de chaque sauvegarde et la compare à son fichier
                     .sha256. Ne demande aucune clé.",
                );
                if let Some(dir) = &config.backup_dir {
                    show_backups(&style, dir);
                }
                match commands::backup_verify(config) {
                    Ok(()) => success(&style, "Tout est en ordre."),
                    Err(e) => error(&style, &e),
                }
            }
            Some(Choice::Restore) => restore(&style, db, config, running).await,
            Some(Choice::RotateKey) => rotate_key(&style, db, config, running).await,
            Some(Choice::Recover) => recover(&style, db, config, running).await,
            Some(Choice::NewRecoveryKey) => new_recovery_key(&style, db, config).await,
            Some(Choice::UpdateCheck) => {
                explain(
                    &style,
                    "Vérifier les mises à jour",
                    "Demande à la forge du projet (git.citizenfive.fr) la dernière version stable.
                     Seulement maintenant, à ta demande : rien n'est installé ni envoyé d'autre.",
                );
                if let Err(e) = commands::update_check().await {
                    error(&style, &e);
                }
            }
            Some(Choice::Help) => println!("\n{}", cli::USAGE),
            None => {
                error(&style, "Choix inconnu : tape un numéro du menu, a ou q.");
                continue;
            }
        }
        if prompt(&style, "Entrée pour revenir au menu").is_none() {
            break;
        }
    }
    println!("\n  À bientôt.\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_lines_have_the_same_width() {
        let widths: Vec<usize> = BANNER[1..].iter().map(|l| l.chars().count()).collect();
        assert!(widths.iter().all(|w| *w == widths[0]));
        assert!(BANNER[0].chars().count() <= widths[0]);
    }

    #[test]
    fn gradient_goes_from_cyan_to_violet() {
        assert_eq!(gradient(0.0), CYAN);
        assert_eq!(gradient(0.5), TEAL);
        assert_eq!(gradient(1.0), VIOLET);
    }

    #[test]
    fn menu_choices() {
        assert_eq!(parse_choice(" 1 "), Some(Choice::Backup));
        assert_eq!(parse_choice("Q"), Some(Choice::Quit));
        assert_eq!(parse_choice("aide"), Some(Choice::Help));
        assert_eq!(parse_choice("7"), Some(Choice::UpdateCheck));
        assert_eq!(parse_choice("8"), None);
        assert_eq!(parse_choice(""), None);
    }

    #[test]
    fn a_pasted_key_is_not_taken_for_a_path() {
        assert!(looks_like_a_key("CLEA-BACKUP-KEY-306d-57d1"));
        assert!(looks_like_a_key("clea-recovery-key-0909"));
        assert!(looks_like_a_key(&"ab".repeat(64)));
        assert!(!looks_like_a_key("/root/cle-sauvegarde.txt"));
        assert!(!looks_like_a_key("secours.txt"));
    }

    #[test]
    fn no_color_means_plain_text() {
        let style = Style { color: false };
        assert_eq!(style.paint(CYAN, "x"), "x");
        assert_eq!(style.bold("x"), "x");
    }
}
