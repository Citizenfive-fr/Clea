#!/bin/sh
# Outils de l'AppImage aux versions figées listées dans appimage-tools.txt.
#   ./appimage-tools.sh fetch <dossier>   les télécharge dans <dossier> (cache de Tauri :
#                                         $XDG_CACHE_HOME/tauri), chacun vérifié par son SHA-256
#   ./appimage-tools.sh check <dossier>   après `cargo tauri build` : échoue si Tauri a téléchargé
#                                         un outil absent de la liste (nouvelle version de Tauri)
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
    echo "Usage : $0 fetch <dossier> | check <dossier> | update" >&2
    exit 1
    ;;
esac
