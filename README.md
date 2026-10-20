# DeskPilot

Serveur API, console web et serveur de rendez-vous open source pour **RustDesk**, compatible avec le client RustDesk officiel. DeskPilot reprend les fonctions de RustDesk Server Pro : comptes, carnets d'adresses partagés, appareils, stratégies, journaux, SSO, et, grâce à son fork de `hbbs`, contrôle d'accès, blocage d'appareils et changement d'ID.

- Console et API : ASP.NET Core 10 + Blazor Server, PostgreSQL, EF Core
- Rendez-vous : fork de [rustdesk-server](https://github.com/rustdesk/rustdesk-server) (`hbbs/`), relié à DeskPilot
- Interface en français, thème clair et sombre, utilisable sur mobile
- Licence AGPL-3.0

## Fonctionnalités

| Domaine | Ce que fait DeskPilot |
|---|---|
| Comptes | Connexion depuis le client et la console, comptes locaux, rôles admin / utilisateur, désactivation, révocation des sessions client |
| Double authentification | TOTP (Aegis, FreeOTP, Google/Microsoft Authenticator), demandée aussi par le client RustDesk |
| SSO | OpenID Connect (Keycloak, Authentik, Entra ID, Google…) avec PKCE, LDAP / Active Directory avec groupe d'administrateurs |
| Carnets d'adresses | Carnet personnel par utilisateur, carnets partagés avec droits lecture / écriture / contrôle total par utilisateur ou par groupe, étiquettes colorées, mots de passe partagés, ancienne API (`/api/ab`) |
| Appareils | Inventaire (OS, CPU, RAM, version, session), présence en ligne, propriétaire, groupe d'appareils, note, coupure de session à distance |
| Groupes | Groupes d'utilisateurs et groupes d'appareils, visibilité croisée dans l'onglet « Groupes » du client |
| Stratégies | Options de configuration imposées aux clients (transfert de fichiers, presse-papiers, mode d'acceptation, liste blanche…), héritage appareil → propriétaire → groupe, retrait propre des options |
| Journaux | Connexions (avec note de fin de session), transferts de fichiers, alarmes de sécurité, actions de la console, export CSV |
| Enregistrements | Réception des enregistrements de session téléversés par les clients |
| Déploiement | `rustdesk --assign` et `rustdesk --deploy` avec jetons d'API, options `preset-*` des clients personnalisés, déploiement obligatoire |
| Contrôle d'accès (hbbs) | Ouvert, compte obligatoire, ou compte + groupes : chaque demande de connexion est autorisée ou refusée par DeskPilot, le motif s'affiche dans le client |
| Permissions par session (hbbs) | Permissions retirées par groupe d'utilisateurs (fichiers, presse-papiers, clavier, terminal…), imposées au poste contrôlé |
| Appareils (hbbs) | Blocage, libération d'ID à la suppression, présence en temps réel, changement d'ID depuis le client avec historique |
| Relais (hbbs) | Serveur relais choisi par groupe d'appareils |
| Traçabilité (hbbs) | Journal des autorisations et compte DeskPilot affiché sur chaque connexion |

### Le fork de hbbs

Le client RustDesk ne parle à l'API HTTP que pour la gestion ; les connexions passent par `hbbs`. Le dossier `hbbs/` contient un fork minimal de `rustdesk-server` (détails et patch dans [`hbbs/DESKPILOT.md`](hbbs/DESKPILOT.md)) qui :

- réalise l'**échange de clés** attendu par les clients connectés à un compte. Sans lui, avec le `hbbs` libre et une clé configurée, un client connecté à son compte échoue avec « Failed to secure tcp: deadline has elapsed » ;
- interroge DeskPilot à chaque demande de connexion (`/api/hbbs/connect`) et applique sa décision ;
- récupère toutes les 10 s la politique (appareils bloqués, déploiement, ID à libérer) et remonte les appareils en ligne (`/api/hbbs/sync`) ;
- gère le changement d'ID demandé par le client (`/api/hbbs/change-id`).

Sans `DESKPILOT_URL`, ce `hbbs` se comporte exactement comme l'amont. DeskPilot fonctionne aussi avec le `hbbs` libre, sans les fonctions marquées « hbbs » ci-dessus.

### Ce qui n'est pas couvert

- Client web : sa partie JavaScript n'est pas publiée par RustDesk.
- Générateur de client personnalisé et codes de vérification par e-mail : pas encore implémentés.
- Les connexions directes par IP et sur le réseau local ne passent pas par `hbbs` et échappent au contrôle d'accès (comme avec Pro).
- WebRTC : le fork ne relaie pas encore les offres WebRTC des clients récents, qui se rabattent sur leurs autres transports.

## Démarrage rapide (Docker)

```bash
git clone https://github.com/<vous>/deskpilot.git && cd deskpilot
cp .env.example .env        # renseigner POSTGRES_PASSWORD et HBBS_SECRET (openssl rand -hex 32)
docker compose up -d
docker compose logs deskpilot | grep "admin account"   # mot de passe admin généré
```

La console est sur `http://<serveur>:21114`. Le fichier `docker-compose.yml` construit et démarre aussi le fork de `hbbs` et `hbbr` (premier build : quelques minutes) ; la clé publique à donner aux clients est dans `data/rustdesk/id_ed25519.pub`. Paramètres › Accès et hbbs indique si `hbbs` est bien relié.

Ports à ouvrir : `21114/tcp` (console + API), `21115-21117/tcp`, `21116/udp`, `21118-21119/tcp` (hbbs/hbbr).

## Configurer le client RustDesk

Paramètres › Réseau › Serveur d'ID/relais :

| Champ | Valeur |
|---|---|
| Serveur d'ID | `<serveur>` |
| Serveur relais | `<serveur>` |
| Serveur API | `http://<serveur>:21114` (ou `https://rustdesk.exemple.fr` derrière un reverse proxy) |
| Clé | contenu de `id_ed25519.pub` |

Si le champ « Serveur API » est vide, le client utilise `http://<serveur d'ID>:21114`, ce qui correspond au port par défaut de DeskPilot.

Une fois le serveur API renseigné, l'appareil apparaît dans la console sous 15 secondes. Le bouton « Se connecter » de l'onglet Carnet d'adresses du client utilise les comptes DeskPilot (et les boutons SSO configurés).

### HTTPS

Placez DeskPilot derrière un reverse proxy (Caddy, Traefik, nginx) avec un certificat valide et renseignez `PUBLIC_URL`. Les en-têtes `X-Forwarded-*` sont pris en compte. Le client refuse les certificats auto-signés.

```caddyfile
rustdesk.exemple.fr {
    reverse_proxy 127.0.0.1:21114
}
```

La console Blazor utilise des WebSockets : le proxy doit les laisser passer (c'est le cas par défaut avec Caddy et Traefik ; avec nginx, ajouter les en-têtes `Upgrade` / `Connection`).

## Déploiement en masse

Créez un jeton dans Paramètres › Jetons d'API, puis sur chaque poste (droits administrateur) :

```bash
# Rattacher le poste à un utilisateur, un groupe, une stratégie, un carnet partagé
rustdesk --assign --token dp_xxxxx --user_name jdupont --device_group_name Comptabilité \
         --strategy_name "Postes compta" --address_book_name Serveurs --address_book_tag prod

# Pré-enregistrer un poste (utile avec l'option « N'accepter que les appareils pré-enregistrés »)
rustdesk --deploy --token dp_xxxxx
```

Les clients personnalisés peuvent aussi embarquer les options `preset-user-name`, `preset-strategy-name`, `preset-device-group-name`, `preset-address-book-name`, `preset-address-book-tag`, `preset-address-book-alias`, `preset-address-book-password`, `preset-address-book-note`, `preset-note`, `preset-device-name` et `preset-device-username`. Elles ne remplissent que les champs vides : une affectation faite dans la console n'est jamais écrasée.

## SSO

**OIDC** : Paramètres › OIDC › Ajouter un fournisseur. Déclarez chez le fournisseur l'URL de redirection affichée (`<PUBLIC_URL>/oidc/callback`). Un compte existant est lié automatiquement si le fournisseur renvoie la même adresse e-mail **vérifiée** ; sinon un compte est créé (si l'inscription automatique est activée).

**LDAP** : Paramètres › LDAP. Recherche puis liaison avec le compte de l'utilisateur. Pour Active Directory : filtre `(&(objectClass=user)(sAMAccountName={0}))`, attribut identifiant `sAMAccountName`. Si un DN de groupe administrateur est renseigné, le rôle admin suit l'appartenance `memberOf` à chaque connexion.

## Configuration

Variables d'environnement (en plus de `.env`) :

| Variable | Rôle |
|---|---|
| `ConnectionStrings__Default` | Chaîne de connexion PostgreSQL |
| `DeskPilot__AdminUsername` / `DeskPilot__AdminPassword` | Compte créé au premier démarrage si la base est vide |
| `DeskPilot__DataPath` | Clés de protection des cookies et enregistrements (`/data` dans le conteneur) |
| `DeskPilot__RecordsPath` | Dossier des enregistrements (défaut : `<DataPath>/records`) |
| `DeskPilot__general__public_url` | URL publique (sinon modifiable dans la console) |
| `DeskPilot__HbbsSecret` | Secret partagé avec `hbbs` (`DESKPILOT_SECRET`). Sans lui, l'API `/api/hbbs` est désactivée |

Côté `hbbs` : `DESKPILOT_URL`, `DESKPILOT_SECRET`, `DESKPILOT_FAIL_MODE` (`open` par défaut : si DeskPilot ne répond pas, les connexions passent ; `closed` : elles sont refusées). Voir [`hbbs/DESKPILOT.md`](hbbs/DESKPILOT.md).

Le schéma de base est créé et migré automatiquement au démarrage.

## Sécurité

- Le protocole RustDesk n'authentifie pas les envois des appareils (`/api/heartbeat`, `/api/sysinfo`, `/api/audit/*`) : c'est aussi le cas de RustDesk Pro. N'exposez le port 21114 qu'aux réseaux de vos clients, ou activez le déploiement obligatoire.
- Le contrôle d'accès s'ajoute au mot de passe de l'appareil, il ne le remplace pas.
- `/api/hbbs/*` n'est accessible qu'avec le secret partagé ; dans Docker, `hbbs` joint DeskPilot par le réseau interne.
- Mots de passe hachés (PBKDF2, ASP.NET Identity), jetons stockés hachés (SHA-256), verrouillage après 10 échecs, PKCE pour OIDC.
- Les doublons d'audit renvoyés par le client sont ignorés (nonce).

## Développement

```bash
# PostgreSQL local, puis :
cd src/DeskPilot
DeskPilot__AdminPassword='Admin123!' dotnet run --urls http://127.0.0.1:21114

# Test de bout en bout de l'API, avec les mêmes appels que le client RustDesk
python3 tests/smoke_test.py http://127.0.0.1:21114 admin 'Admin123!'

# Fork hbbs : test unitaire de l'échange de clés, puis test de bout en bout hbbs ↔ DeskPilot
# avec un client de test bâti sur le code réseau du client RustDesk actuel (tests/hbbs-compat)
(cd hbbs && cargo test --lib deskpilot && cargo build --bin hbbs)
(cd tests/hbbs-compat && cargo build)
DeskPilot__HbbsSecret=s3cret …                     # DeskPilot
DESKPILOT_URL=http://127.0.0.1:21114 DESKPILOT_SECRET=s3cret hbbs/target/debug/hbbs
python3 tests/hbbs_integration.py --compat tests/hbbs-compat/target/debug/hbbs-compat \
  --key "$(cat id_ed25519.pub)" --password 'Admin123!' --psql 'psql -d deskpilot'

# Nouvelle migration après modification des entités
dotnet ef migrations add <Nom> -o Data/Migrations
```

Structure :

```
src/DeskPilot/
  Api/            endpoints appelés par le client RustDesk (/api/...) et par la console
  Services/       authentification, LDAP, OIDC, droits d'accès, appareils et stratégies
  Data/           entités EF Core et migrations
  Components/     console Blazor (pages, mise en page, composants)
hbbs/             fork de rustdesk-server (module src/deskpilot.rs, patch, Dockerfile)
tests/            test de bout en bout de l'API, test d'intégration hbbs, client de test (hbbs-compat)
```

### Compatibilité de l'API

Les routes et formats suivent le code du client ([rustdesk/rustdesk](https://github.com/rustdesk/rustdesk) : `src/hbbs_http`, `src/server/connection.rs`, `flutter/lib/models`) :

`/api/login`, `/api/logout`, `/api/currentUser`, `/api/login-options`, `/api/oidc/auth`, `/api/oidc/auth-query`, `/api/heartbeat`, `/api/sysinfo`, `/api/sysinfo_ver`, `/api/users`, `/api/peers`, `/api/device-group/accessible`, `/api/ab` (ancienne API), `/api/ab/settings`, `/api/ab/personal`, `/api/ab/shared/profiles`, `/api/ab/peers`, `/api/ab/tags/{guid}`, `/api/ab/peer/add|update/{guid}`, `/api/ab/peer/{guid}`, `/api/ab/tag/add|rename|update/{guid}`, `/api/ab/tag/{guid}`, `/api/audit/conn|file|alarm`, `/api/record`, `/api/devices/cli`, `/api/devices/deploy`, `/api/switch-grant`.

Côté rendez-vous, le fork suit `rendezvous.proto` du client : `KeyExchange` (v0 et v1 signée), `PunchHoleRequest.token`, `PunchHoleResponse.other_failure`, `RelayResponse.refuse_reason`, `ControlPermissions`, `ControlledContext`, `RegisterPk.old_id`, `RegisterPkResponse.NOT_DEPLOYED`.

RustDesk est une marque de ses auteurs ; DeskPilot est un projet indépendant, non affilié.

## Licence

[AGPL-3.0](LICENSE)
