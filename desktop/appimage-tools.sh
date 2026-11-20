#!/bin/sh
# Outils de l'AppImage aux versions figées listées dans appimage-tools.txt.
#   ./appimage-tools.sh fetch <dossier>   les télécharge dans <dossier> (cache de Tauri :
#                                         $XDG_CACHE_HOME/tauri), chacun vérifié par son SHA-256
#   ./appimage-tools.sh check <dossier>   après `cargo tauri build` : échoue si Tauri a téléchargé
#                                         un outil absent de la liste (nouvelle version de Tauri)
#   ./appimage-tools.sh tauri <version>   vérifie que la liste contient le linuxdeploy et l'AppRun
#                                         attendus par cette version de tauri-cli (lu dans son code
#                                         publié sur crates.io, sans l'installer)
#   ./appimage-tools.sh update            recalcule les SHA-256 après avoir changé une adresse,
#                                         puis relire la différence avant de commiter
set -eu
cd "$(dirname "$0")"
LIST=appimage-tools.txt

tools() {
    grep -v '^#' "$LIST" | grep .
}

case "${1:-}" in
fetch)
    dir=${2:?dossier manquant}
    mkdir -p "$dir"
    tools | while read -r sum name url; do
        curl -fsSL --proto '=https' -o "$dir/$name.part" "$url"
        if ! echo "$sum  $dir/$name.part" | sha256sum -c --quiet -; then
            rm -f "$dir/$name.part"
            echo "Empreinte différente pour $name : fichier refusé" >&2
            exit 1
        fi
        mv "$dir/$name.part" "$dir/$name"
        chmod +x "$dir/$name"
    done
    ;;
check)
    dir=${2:?dossier manquant}
    # Scripts de greffons que Tauri écrit à partir de ses propres sources
    allowed=$( (tools | awk '{print $2}'; echo linuxdeploy-plugin-gtk.sh; echo linuxdeploy-plugin-gstreamer.sh) )
    for file in "$dir"/*; do
        if ! echo "$allowed" | grep -qxF "$(basename "$file")"; then
            echo "Tauri a téléchargé un outil qui n'est pas dans $LIST : $(basename "$file")" >&2
            exit 1
        fi
    done
    ;;
tauri)
    version=${2:?version de tauri-cli manquante}
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    crate() {
        curl -fsSL --proto '=https' "https://static.crates.io/crates/$1/$1-$2.crate" | tar -xz -C "$tmp"
    }
    # tauri-cli fabrique l'AppImage avec tauri-bundler : sa version est dans le Cargo.lock publié
    crate tauri-cli "$version"
    bundler=$(grep -A1 '^name = "tauri-bundler"$' "$tmp/tauri-cli-$version/Cargo.lock" \
        | sed -n 's/^version = "\(.*\)"$/\1/p')
    crate tauri-bundler "$bundler"
    src="$tmp/tauri-bundler-$bundler/src/bundle/linux/appimage/linuxdeploy.rs"
    if [ ! -f "$src" ]; then
        echo "tauri-bundler $bundler n'a plus linuxdeploy.rs au même endroit : à vérifier à la main" >&2
        exit 1
    fi
    commit=$(sed -n 's/.*LINUXDEPLOY_COMMIT_HASH: &str = "\([0-9a-f]*\)".*/\1/p' "$src")
    apprun=$(sed -n 's|.*/releases/download/\(apprun-[^/]*\)/AppRun-.*|\1|p' "$src")
    if [ -z "$commit" ] || [ -z "$apprun" ]; then
        echo "Impossible de lire les outils attendus par tauri-bundler $bundler : à vérifier à la main" >&2
        exit 1
    fi
    if ! tools | grep -q " linuxdeploy-$commit-x86_64.AppImage " \
        || ! tools | grep -q "/releases/download/$apprun/AppRun-x86_64$"; then
        echo "tauri-cli $version attend linuxdeploy $commit et AppRun $apprun : mettre à jour $LIST" >&2
        exit 1
    fi
    echo "tauri-cli $version (tauri-bundler $bundler) : linuxdeploy $commit et AppRun $apprun, conformes à la liste"
    ;;
update)
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    {
        grep '^#' "$LIST"
        tools | while read -r _ name url; do
            curl -fsSL --proto '=https' -o "$tmp/tool" "$url"
            printf '%s  %s  %s\n' "$(sha256sum "$tmp/tool" | cut -d' ' -f1)" "$name" "$url"
        done
    } > "$tmp/list"
    cp "$tmp/list" "$LIST"
    git diff -- "$LIST"
    ;;
*)
    echo "Usage : $0 fetch <dossier> | check <dossier> | tauri <version> | update" >&2
    exit 1
    ;;
esac
