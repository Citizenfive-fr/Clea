# Cléa, application de bureau

Une petite application qui ouvre ton instance Cléa dans sa propre fenêtre. Cléa reste
installée sur un serveur : l'application ne fait que s'y connecter.

- Au premier lancement, elle demande l'adresse de ton Cléa (`https://…`) et vérifie
  qu'un Cléa y répond avant de l'enregistrer.
- Ensuite, elle ouvre directement le tableau de bord.
- Seul ton Cléa s'ouvre dans la fenêtre : les autres liens s'ouvrent dans ton navigateur.
- Pour un téléchargement (sauvegardes), elle te demande où enregistrer le fichier.
- Zoom : Ctrl et +, Ctrl et -, Ctrl et 0 pour revenir à 100 %. F5 ou Ctrl+R recharge la page.
- Pour changer de serveur : bouton **Changer de serveur** sur la page d'accueil de Cléa
  (le logo en haut de la barre latérale y mène), ou Ctrl+Maj+S.
- Si le serveur ne répond pas, une page le dit, avec **Réessayer** et **Changer de serveur**.

L'adresse est enregistrée dans le dossier de configuration de ton système
(sous Linux : `~/.config/fr.citizenfive.clea/serveur.json`).

## Connexions

L'application se connecte seulement à ton Cléa. Quand tu valides une adresse, elle
appelle `/api/health` sur ce serveur pour vérifier que c'est bien un Cléa, sans rien
envoyer sur elle-même (pas de nom ni de version). Les liens externes sont ouverts par
ton navigateur, pas par l'application.

## Installer et vérifier

Chaque release de Cléa propose l'app en deux formats :

- `clea_<version>_amd64.deb` pour Debian, Ubuntu et Mint. À préférer quand c'est possible :
  il utilise le WebKitGTK du système, mis à jour avec le reste.
- `clea_<version>_amd64.AppImage` pour les autres distributions. Elle contient sa propre
  copie de WebKitGTK, qui ne se met à jour qu'avec une nouvelle AppImage : prends toujours
  la dernière.

Pour vérifier un paquet, télécharge aussi `SHA256SUMS` et `SHA256SUMS.sigstore.json`, et
le fichier `cosign.pub` du dépôt, puis :

```bash
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

La première commande prouve que la liste des empreintes vient bien du projet, la seconde
que ton fichier correspond à la liste.

## Compiler (Linux)

Il faut WebKitGTK 4.1, la version pour GTK 3 (`net-libs/webkit-gtk:4.1` sur Gentoo,
`libwebkit2gtk-4.1-dev` sur Debian et Ubuntu). La version pour GTK 4
(`webkit-gtk:6`, `webkitgtk-6.0`) ne convient pas.

```bash
cd desktop
cargo run              # lance l'application en mode développement
cargo test             # tests
```

Pour fabriquer l'AppImage et le paquet .deb, il faut aussi l'outil de Tauri :

```bash
cargo install tauri-cli --version "^2" --locked
cargo tauri build
```
