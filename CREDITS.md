# Remerciements & crédits

Cerbere Security Shield n'existerait pas sans le travail — souvent bénévole,
rarement remercié — des équipes et plateformes ci-dessous. Ce document les
remercie publiquement et précise la nature exacte de leur usage dans le
projet, dans un souci de transparence et de respect de leurs licences
respectives.

---

## Listes de filtrage (blocage DNS, pubs, trackers, parental)

Ces listes communautaires sont téléchargées par l'application et appliquées
localement. Aucune donnée utilisateur n'est envoyée à leurs mainteneurs.

| Liste | Mainteneur | Usage | Licence |
|---|---|---|---|
| **EasyList / EasyPrivacy** | [easylist.to](https://easylist.to) | Blocage publicité & trackers | [CC BY-SA 3.0](licenses/CC-BY-SA-3.0.txt) |
| **AdGuard DNS Filter** | [AdGuard](https://github.com/AdguardTeam/AdGuardSDNSFilter) | Filtrage DNS | [GPL-3.0](licenses/GPL-3.0.txt) |
| **OISD** | [oisd.nl](https://oisd.nl/) | Filtrage DNS complet | Voir site du projet |
| **HaGeZi DNS Blocklists** | [hagezi](https://github.com/hagezi/dns-blocklists) | Filtrage DNS multi-niveaux | Voir licence du dépôt |
| **anudeepND Whitelist** | [anudeepND](https://github.com/anudeepND/whitelist) | Liste blanche (faux positifs) | Voir licence du dépôt |

## Renseignement sur les menaces (appels API automatisés)

| Service | Usage | Conditions |
|---|---|---|
| **MalwareBazaar** ([abuse.ch](https://abuse.ch)) | Vérification de signatures de fichiers par hash | API gratuite, sans clé, à but non lucratif |
| **URLhaus** ([abuse.ch](https://urlhaus.abuse.ch)) | Réputation de domaines/URLs malveillants | API gratuite, sans clé, à but non lucratif |
| **RDAP** ([rdap.org](https://rdap.org)) | Enregistrement et informations WHOIS de domaines | Service public IETF/IETF-trust |
| **Cloudflare DNS** (`cloudflare-dns.com`) | Résolution DoH de secours pour révéler la vraie IP d'un domaine bloqué | Resolver public 1.1.1.1 |

Un immense merci à **abuse.ch** (Spamhaus/ibsa) dont les bases MalwareBazaar
et URLhaus, maintenues bénévolement, sont des piliers de la sécurité
grand public.

## Services consultés par simple hyperlien

Ces plateformes ne reçoivent **aucun appel automatisé** de Cerbere : ce sont
uniquement des liens « 1 clic » ouverts dans le navigateur de l'utilisateur,
qui relève alors de leurs conditions d'utilisation habituelles.

- **[VirusTotal](https://www.virustotal.com)** — analyse multi-moteurs
  (Google Chronicle)
- **[urlscan.io](https://urlscan.io)** — analyse et captures de sites
- **[Cisco Talos Intelligence](https://talosintelligence.com)** — réputation IP/domaine
- **[Google Safe Browsing — Transparency Report](https://transparencyreport.google.com/safe-browsing/search)** — statut d'un site
- **[Whois.com](https://www.whois.com)** — fiche WHOIS d'un domaine
- **[ProcessLibrary](https://www.processlibrary.com)** — fiches descriptives de processus
- **[SpeedGuide](https://www.speedguide.net)** — base de données des ports TCP/UDP
- **[SANS Internet Storm Center](https://isc.sans.edu)** — réputation d'un port (attaque en cours)
- **[GRC ShieldsUP!](https://www.grc.com/shieldsup)** — documentation historique des ports (Steve Gibson)

## Technologies open source

Python · FastAPI · React · Tauri · Rust · PyInstaller · Inno Setup ·
WinDivert/pydivert · SQLite — et tout l'écosystème qui les entoure.

---

## Note légale

L'usage des API ci-dessus respecte leurs conditions publiées à la date de
rédaction : les services automatisés (abuse.ch, RDAP, Cloudflare DoH) sont
interrogés de façon mesurée et uniquement pour les fonctions décrites ; les
autres plateformes ne sont liées que par hyperlien, sans scraping ni
interrogation automatisée. Les listes de filtrage sont utilisées
conformément à leurs licences (attribution EasyList via ce fichier, textes
de licence dans [`licenses/`](licenses/)).

Si vous êtes mainteneur de l'un de ces services et souhaitez que Cerbere
modifie ou cesse un usage, ouvrez un ticket sur
[GitHub Issues](https://github.com/art-qalam-fr/CerbereShield/issues) — la
correction sera faite rapidement et de bonne foi.
