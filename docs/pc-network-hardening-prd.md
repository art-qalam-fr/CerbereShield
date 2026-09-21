---
description: PRD - Outil de surveillance et durcissement sécurité PC / réseau 
---

# PRD - Outil de surveillance et durcissement de la sécurité (PC, réseau, box)

## 1. Contexte et objectifs

L’utilisateur souhaite disposer d’un outil permettant :

- de **détecter** les services exposés (ports ouverts, écoute sur 0.0.0.0, etc.) ;
- de **surveiller** les connexions suspectes (scans, pings malveillants, tentatives d’accès non légitimes) ;
- de **aider au durcissement** de la configuration sécurité du PC, du réseau local et éventuellement de la box/routeur ;
- sans lien direct avec le code métier MCP / Gateway WebUI.

Objectif principal : **réduire la surface d’attaque** et **rendre visibles** les signaux faibles (scans, tentatives d’intrusion) côté poste de travail et réseau domestique.

## 2. Périmètre (scope)

### 2.1 Inclus

- **PC local (Windows)** :
  - détection des ports en écoute (TCP/UDP) et des processus associés ;
  - identification des services écoutant sur `0.0.0.0` vs `127.0.0.1` ;
  - collecte simple de journaux pertinents (logs d’applications, éventuellement logs Windows) ;
  - génération d’un **rapport lisible** indiquant les points faibles potentiels.

- **Applications locales de développement** (ex : Uvicorn, FastAPI, serveurs de test) :
  - vérification qu’elles n’exposent pas inutilement un port sur toutes les interfaces ;
  - recommandations de configuration (ex : forcer `host=127.0.0.1`).

- **Diagnostic réseau basique** :
  - liste des connexions entrantes récentes ;
  - repérage d’IP potentiellement suspectes (nombre élevé de tentatives, pays d’origine, etc. – indicatif seulement) ;
  - export de ces informations dans un fichier de log ou un rapport HTML/Markdown.

### 2.2 Exclus (hors scope)

- Configuration automatique de la **box/routeur** (UPnP, redirections de ports, firewall du FAI) : seulement des recommandations textuelles.
- Mise en place d’un **IDS/IPS complet** (type fail2ban avancé, Snort, etc.).
- Gestion d’antivirus / antimalware : l’outil ne remplace pas les solutions professionnelles existantes.

## 3. Utilisateurs cibles

- **Utilisateur principal** : le propriétaire du PC (développeur, administrateur de sa propre machine).
- Public technique mais non expert en sécurité : besoin d’un outil qui **explique clairement** les risques et les actions possibles.

## 4. Exigences fonctionnelles

### 4.1 Découverte des ports et services

1. **Lister les ports en écoute** sur la machine locale (TCP/UDP), avec :
   - numéro de port,
   - protocole (TCP/UDP),
   - adresse d’écoute (`127.0.0.1`, `0.0.0.0`, IP locale spécifique),
   - processus / binaire associé (si disponible).
2. **Marquer** clairement :
   - les services écoutant sur `0.0.0.0` (potentiellement accessibles depuis l’extérieur) ;
   - les ports dans une **liste blanche** définie par l’utilisateur (ex : 8080 local seulement) ;
   - les ports inattendus par rapport à cette liste blanche.

### 4.2 Analyse de risques simple

1. Fournir une **analyse synthétique** :
   - nombre de ports exposés sur 0.0.0.0 ;
   - liste des ports critiques (ex : 22, 80, 443, 3306, etc.) si présents ;
   - recommandations génériques ("forcer l’écoute sur 127.0.0.1", "fermer le port dans le firewall", etc.).

2. Détecter les **connexions entrantes répétées** depuis une même IP sur une courte période (signe de scan), dans la mesure du possible à partir des commandes système/logs accessibles sans droits élevés.

### 4.3 Rapport et alertes

1. Générer un **rapport lisible** (Markdown ou HTML simple) contenant :
   - résumé de l’état de la machine ;
   - tableau des ports ouverts ;
   - liste des points de vigilance ;
   - suggestions d’actions concrètes.

2. Optionnel :
   - proposer un mode "batch" pour pouvoir être lancé régulièrement (via tâche planifiée) et archiver les rapports.

### 4.4 Intégration avec le workflow de développement

1. Fournir un **script CLI** (ex. `python security_audit.py`) :
   - exécutable depuis la venv du projet ou en global ;
   - ne dépendant pas du code Gateway WebUI ;
   - capable d’analyser en priorité les ports fréquemment utilisés en dev (8080, 4050, 3000, etc.).

2. Prévoir une **configuration simple** (fichier YAML/JSON ou `.env`) pour :
   - définir les ports "attendus" ;
   - exclure certains processus connus ;
   - régler le niveau de verbosité.

## 5. Exigences non fonctionnelles

- **Sécurité** :
  - par défaut, le script fonctionne en **lecture seule** (pas de modification automatique de firewall, de registre, etc.) ;
  - toute action potentiellement intrusive (fermeture de port, modification firewall) doit être explicitement confirmée et, idéalement, placée dans une phase ultérieure.

- **Portabilité** :
  - cible principale : **Windows 10/11** ;
  - éventuellement support de base pour Linux à terme (non prioritaire).

- **Simplicité** :
  - ne pas exiger d’outils complexes (Snort, Suricata, etc.) ;
  - s’appuyer sur des commandes natives (`netstat`, `Get-NetTCPConnection`, etc.) ou des bibliothèques Python standard/psutil.

## 6. Architecture et approche technique envisagée

- **Langage** : Python (cohérence avec l’environnement actuel).
- **Sources d’information** possibles :
  - commandes système (`netstat`, `Get-NetTCPConnection`, `Get-Process`, etc.) ;
  - bibliothèque `psutil` (si disponible) pour détecter ports/processus ;
  - logs applicatifs simples (ex : fichiers de log uvicorn, FastAPI) si l’utilisateur les pointe explicitement.

- **Structure proposée** :
  - `security_audit/`
    - `collector.py` : collecte des infos (ports, processus, connexions) ;
    - `analyzer.py` : règles simples d’analyse de risque ;
    - `reporter.py` : génération de sortie Markdown/HTML ;
    - `config.example.yml` : exemple de configuration ;
    - `security_audit.py` : point d’entrée CLI.

## 7. Phasage (MVP puis améliorations)

### Phase 1 – MVP

- Script CLI unique `security_audit.py` capable de :
  - lister les ports en écoute + processus ;
  - distinguer `127.0.0.1` / `0.0.0.0` ;
  - générer un rapport texte/Markdown avec points de vigilance ;
  - fonctionner en lecture seule.

### Phase 2 – Analyse enrichie

- Détection des motifs de scan basiques (multiples tentatives sur plusieurs ports depuis une même IP).
- Ajout de règles de risque plus fines.
- Export HTML plus lisible.

### Phase 3 – Intégration et automatisation

- Intégration avec tâches planifiées Windows.
- Notifications (par exemple simple log coloré dans le terminal, ou e‑mail/Discord webhook si la configuration est fournie).

## 8. Critères de succès

- L’utilisateur peut, en un seul script, **voir rapidement** :
  - quels ports sont accessibles,
  - quelles applis les utilisent,
  - où sont les points faibles probables.

- Le script ne modifie rien tout seul, mais **donne des recommandations claires**.
- Le PRD et la structure proposée permettent ensuite d’implémenter progressivement les fonctionnalités, indépendamment du projet Gateway WebUI existant.
