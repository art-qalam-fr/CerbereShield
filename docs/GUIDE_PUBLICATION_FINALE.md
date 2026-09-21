# Guide final — Publication du repo public + signature SignPath

Document de travail unique : toutes les étapes restantes, dans l'ordre.

## Étape 1 — Créer l'identité publique (~10 min)

1. Créer un **nouveau compte GitHub** (ou une **organisation gratuite** —
   recommandé, ex. `CerbereShield`).
2. Créer le repo : `CerbereShield`, **public**, sans README initial.

## Étape 2 — Générer l'export propre (~2 min)

```bat
packaging\export_public.bat D:\CerbereShield
```

Produit une copie sanitizée : historique vierge (1 commit "public release"),
sans `.agent/`, `.env`, `backup/`, `dist/`, `PRD_Amélioration/`, caches, etc.
(~8 Mo, ~100 fichiers : code, tests, docs, wiki, packaging).

## Étape 3 — Pousser le repo public (~2 min)

```bat
cd D:\CerbereShield
git remote add origin https://github.com/<compte>/CerbereShield.git
git push -u origin main
```

## Étape 4 — Clé abuse.ch pour les utilisateurs

L'app fonctionne sans clé (fail-open). Pour activer la réputation SHA-256
et URLhaus, chaque utilisateur crée son compte gratuit sur https://abuse.ch
puis :

```powershell
setx MALWAREBAZAAR_API_KEY "sa-cle"
```

Déjà fait sur la machine de dev (clé validée sur les 2 API).

## Étape 5 — Signature SignPath (voir GUIDE_SIGNATURE_SIGNPATH.md)

1. https://signpath.org/apply.html → formulaire de candidature direct
   (pas de compte à créer avant — l'accès SignPath.io vient APRÈS approbation).
2. Formulaire pré-rempli dans `docs/GUIDE_SIGNATURE_SIGNPATH.md`
   (repo : `github.com/art-qalam-fr/CerbereShield`).
3. Après approbation : secrets `SIGNPATH_API_TOKEN` +
   `SIGNPATH_ORGANIZATION_ID` dans le repo public → activer le workflow
   `.github/workflows/release-sign.yml` (squelette fourni dans le guide).

## Étape 6 — Build & release signés

- Build local : `packaging\build.bat` → `dist\installer\CerbereShield_Setup.exe`
- Release publique signée : via GitHub Actions (étape 5) → joindre le Setup
  signé à une GitHub Release.

## Checklist finale

- [ ] Repo public poussé, MIT, README avec banderole
- [ ] SmartScreen : avertissement normal tant que non signé
- [ ] SignPath approuvé → secrets posés → workflow testé
- [ ] Release publique avec `CerbereShield_Setup.exe` signé
