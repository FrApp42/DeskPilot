# hbbs — fork DeskPilot

Fork de [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) (AGPL-3.0)
qui relie hbbs à la console DeskPilot.

- Base amont : `873230e35a8805de7fd057e7eb763c46f7a174ef` (hbb_common `69cea8dafee147848ae88702029f4bf7df7224c3`)
- Modifications : `deskpilot.patch` (diff complet par rapport à l'amont)

Sans `DESKPILOT_URL`, le comportement est strictement celui de l'amont.

## Ce qui est ajouté

| Fonction | Où |
|---|---|
| Échange de clés avec les clients (v0 et v1 signée) : nécessaire pour que les clients connectés à un compte puissent joindre un appareil et transmettre leur jeton | `deskpilot::kx_*`, `handle_secure_listener` |
| Contrôle d'accès à chaque demande de connexion (punch hole et relais) | `deskpilot::check_connect` |
| Restrictions de permissions par session et référence d'audit transmises au poste contrôlé | `ControlPermissions`, `ControlledContext` |
| Relais choisi par DeskPilot (par groupe d'appareils) | `Decision.relay` |
| Blocage d'appareil et déploiement obligatoire (`NOT_DEPLOYED`) | `deskpilot::refuse_register` |
| Changement d'ID demandé par le client (`RegisterPk.old_id`) | `deskpilot::change_id` |
| Présence remontée à DeskPilot et libération d'ID | `deskpilot::spawn_sync` |

Le protocole `rendezvous.proto` reçoit seulement les champs `KeyExchange.version`,
`KeyExchange.signed_params` et le message `KxParams`, identiques à ceux du hbb_common du client.

## Configuration

| Variable | Rôle |
|---|---|
| `DESKPILOT_URL` | URL de DeskPilot vue depuis hbbs, ex. `http://deskpilot:21114` |
| `DESKPILOT_SECRET` | Secret partagé, identique à `DeskPilot__HbbsSecret` côté DeskPilot |
| `DESKPILOT_FAIL_MODE` | `open` (défaut) : si DeskPilot ne répond pas, les connexions sont acceptées. `closed` : elles sont refusées |

## Mettre à jour depuis l'amont

```bash
git clone https://github.com/rustdesk/rustdesk-server.git && cd rustdesk-server
git submodule update --init
git apply ../deskpilot.patch      # résoudre les conflits éventuels dans rendezvous_server.rs
```

Les ajouts sont regroupés dans `src/deskpilot.rs` ; les fichiers amont ne reçoivent que des
appels d'une ou deux lignes, plus `handle_secure_listener` et quelques méthodes de `PeerMap`
et `Database`.
