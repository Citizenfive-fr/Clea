# Cléa

**Conformité, Liberté, Équité, Accessibilité**

> La conformité RGPD sans prestataire ni abonnement. Open-source, self-hosted, privacy by design.

> ⚠️ Projet en cours de développement actif, pas encore prêt pour la production.

---

## Présentation

Cléa est un outil **open-source** et **auto-hébergé** d'aide à la conformité RGPD (Règlement Général sur la Protection des Données) pour les entreprises.

L'objectif : rendre la conformité accessible, compréhensible et souveraine, sans abonnement, sans prestataire tiers, sans télémétrie. Vos données restent sur votre infrastructure, point.

L'outil guide les entreprises étape par étape : comprendre le règlement, documenter leurs traitements, gérer les droits des personnes concernées, et maintenir leur conformité dans le temps.

---

## Contexte

Le RGPD est en application depuis 2018. Pourtant, une large majorité des entreprises reste en situation de non-conformité, non par mauvaise volonté, mais parce que les ressources disponibles sont soit trop complexes, soit trop coûteuses, soit des SaaS fermés dont on ne sait pas grand-chose de ce qu'ils font des informations qu'on leur confie. Pour un outil censé aider à protéger des données personnelles, c'est pour le moins paradoxal.

Ce constat, je ne l'ai pas seulement lu dans des rapports. Plusieurs de mes expériences m'ont montré de l'intérieur à quel point les outils de conformité disponibles pèchent en termes d'accessibilité, pour les personnes sans formation juridique, mais aussi pour des structures qui n'ont ni le budget ni le temps d'implémenter des solutions pensées pour de grands groupes.

Cléa est une réponse à ce paradoxe.

---

## Qui je suis

Je suis juriste en droit du numérique, spécialisé en protection des données. À côté de ça, j'aime profondément le monde du logiciel libre depuis longtemps, et je cherchais depuis un moment une façon d'y participer activement plutôt que d'en être seulement utilisateur.

Cléa est la concrétisation de ces deux univers : mes connaissances juridiques au service d'un outil libre, construit dans le respect des valeurs qui font la force de l'open source.

---

## Ce que fait Cléa

Cléa s'articule autour de deux axes complémentaires.

**Comprendre le RGPD**

Avant de se conformer, encore faut-il comprendre. Cette partie couvre les grands principes du règlement, les concepts clés, les droits des personnes et les obligations des entreprises, présentés de façon accessible et sans jargon inutile. L'objectif est de donner à chacun les bases pour savoir de quoi on parle et pourquoi ça compte.

**Outil d'accompagnement à la conformité**

Une fois les bases posées, Cléa accompagne les entreprises dans leur mise en conformité de A à Z. L'outil prend en charge l'ensemble du parcours, des premières étapes jusqu'au suivi dans le temps.

---

## Installation

La méthode recommandée est Docker. L'image est publiée sur le registre GitHub (`ghcr.io/citizenfivefr/clea`).

**1. Créer un fichier `.env`**

```env
POSTGRES_PASSWORD=un_mot_de_passe_solide
APP_SECRET_KEY=colle_ici_le_resultat_de_la_commande_ci_dessous
```

Génère la clé avec `openssl rand -hex 64` (32 caractères minimum, sinon Cléa ne démarre pas). Elle chiffre les secrets 2FA en base. Garde-en une copie **séparée** des sauvegardes de la base (gestionnaire de mots de passe par exemple). Si elle est perdue ou modifiée, les secrets 2FA deviennent illisibles et chaque 2FA doit être réinitialisé.

**2. Créer un fichier `docker-compose.yml`**

```yaml
services:
  db:
    image: postgres:alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: clea
      POSTGRES_USER: clea
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U clea"]
      interval: 5s
      timeout: 5s
      retries: 5

  app:
    image: ghcr.io/citizenfivefr/clea:latest
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      DATABASE_URL: postgres://clea:${POSTGRES_PASSWORD}@db:5432/clea
      APP_SECRET_KEY: ${APP_SECRET_KEY}
      SECURE_COOKIES: "true"
      TRUST_PROXY: "true"
      SESSION_DURATION_HOURS: "24"
      INVITATION_DURATION_HOURS: "72"

volumes:
  postgres_data:
```

**3. Lancer**

```bash
docker compose up -d
```

L'application est accessible sur `http://localhost:8080`. Au premier lancement, rendez-vous sur `/setup` pour créer le compte administrateur.

**Reverse proxy (recommandé)**

Il est fortement conseillé de placer Cléa derrière un reverse proxy avec HTTPS. Deux options courantes :

- **Caddy** : configuration minimale, HTTPS automatique via Let's Encrypt
- **Nginx** : plus classique, configuration manuelle du certificat TLS

L'option `SECURE_COOKIES: "true"` est déjà activée dans la configuration ci-dessus et requiert HTTPS en production.

---

## Stack technique

| Couche          | Technologie                        |
|-----------------|------------------------------------|
| Backend         | Rust + Axum                        |
| Frontend        | HTML + CSS + JS                    |
| Base de données | PostgreSQL + SQLx                  |
| Auth            | Sessions cookie                    |
| Déploiement     | Self-hosted                        |

Le choix de Rust n'est pas anodin. C'est un langage pensé pour la sécurité et la fiabilité, deux qualités particulièrement pertinentes pour un outil qui touche à des données personnelles et qui se veut digne de confiance. C'est aussi le langage que je maîtrise le mieux, ce qui me permet de développer avec assurance et de comprendre précisément ce que je livre.

---

## À propos de l'IA

Par souci de transparence : l'IA est utilisée sur ce projet, au strict minimum.

Le travail juridique qui sous-tend Cléa est **100 % humain**. La compréhension du RGPD, la structuration des contenus, les choix de conception liés à la conformité sont le fruit de mes recherches, de mes lectures et de ma formation.

Je travaille seul sur ce projet pour le moment. Dans ce contexte, l'IA sert avant tout à gagner du temps sur certaines tâches techniques répétitives ou de vérification, ce qui me permet de me concentrer sur ce qui compte vraiment : le fond juridique, les choix de conception et la qualité du résultat. Si le projet accueille un jour des contributeur.rices, ce recours à l'IA aura encore moins de raison d'être, puisque c'est l'humain qui prend naturellement cette place.

Je fais attention à ne pas déléguer davantage, pas seulement le raisonnement juridique, mais aussi le reste du travail technique au sens large. Faire les choses moi-même me permet d'apprendre, de comprendre, de consolider mes connaissances et d'entretenir le projet dans la durée. Et parce que l'IA a un coût environnemental réel, la limiter au strict nécessaire est aussi une question de cohérence pour un projet comme Cléa.

---

## Licence

[AGPL-3.0](LICENSE) : parce que la liberté du logiciel, ça se défend.
