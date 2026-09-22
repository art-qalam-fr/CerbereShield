# Guide — Signature du code avec SignPath (procédure réelle, validée)

> **Statut : pipeline de signature FONCTIONNEL** — vérifié de bout en bout le
> 2026-09-21 (run GitHub Actions vert, `CerbereShield.exe` et
> `CerbereShield_Setup.exe` signés avec le certificat de test).

Ce document décrit la procédure **telle qu'elle a réellement fonctionné** —
l'interface SignPath actuelle (v1.219) diffère de la documentation officielle
sur plusieurs points. Les pièges rencontrés sont notés au fil des étapes.

---

## État actuel (où on en est)

| Élément | Valeur / Statut |
|---|---|
| Organisation SignPath | `art-qalam-fr` — ID `4c68f7ab-9667-433f-9f08-34f2ef420477` |
| Projet | slug `cerbere-security-shield` |
| Signing policy | slug `Test_signing` (attention : underscore, T majuscule) |
| Certificat | `Cerbere Test Cert` — X.509 auto-signé, valable 1 an |
| Secrets GitHub | `SIGNPATH_API_TOKEN` + `SIGNPATH_ORGANIZATION_ID` ✅ posés |
| Workflow | `.github/workflows/release-sign.yml` — **API REST directe**, vert ✅ |
| Artefact signé | dans le run : **Artifacts → `signed-package`** |

## Usage courant (une fois tout configuré — c'est juste ça)

**Actions → Release signée → Run workflow** → ~7 min → télécharger
l'artefact `signed-package` → les exe signés sont dedans.

Pour publier : relancer avec `publish_release` coché → crée une GitHub
Release avec les exe signés en pièces jointes.

> ⚠️ **Releases immuables** (activées sur le repo) : une release publiée
> `burn` son tag **définitivement** — même si on la supprime, le tag ne peut
> plus être réutilisé. Le workflow crée donc la release en **draft**, uploade
> les assets, puis publie (`gh release edit --draft=false`). Si la
> publication échoue, incrémenter le tag (`v0.9.2-beta`, `v0.9.3-beta`…)
> plutôt que de réessayer le même.

---

## Procédure complète (pour refaire de zéro)

### 1. Compte et projet SignPath

1. Créer un compte sur `app.signpath.io` (email + mot de passe — **pas** de
   login GitHub).
2. **Projects → Create** :
   - Name : `Cerbere Security Shield`
   - ⚠️ Le **slug** est auto-généré — noter la valeur exacte affichée après
     création (chez nous : `cerbere-security-shield`). C'est elle qu'il faut
     dans le workflow, pas le nom.
   - Repository URL : `https://github.com/art-qalam-fr/CerbereShield`
   - Artifact configuration : **Portable Executable files (.exe, .dll)**
   - Cocher **« Sign multiple files »** → structure `zip-file → pe-file`
   - « Create and add signing policy »

### 2. Certificat de test

1. **Certificates** (menu gauche) → **Create a self-signed X.509 certificate**
   - Name `Cerbere Test Cert`, slug `cerbere-test-cert`
   - Key store : Software — Key algorithm : RSA 4096 — Validité : 1 an
     (recommandé, les signatures timestampées restent valides après)
   - Champs X.509 cosmétiques (CN=`Cerbere Security Shield`, O=`art-qalam-fr`…)
2. Télécharger le `.cer` (format Windows, clé publique uniquement).
3. Pour un test local : double-clic → Installer → **Utilisateur actuel** →
   « Placer dans le magasin suivant » → **Autorités de certification racines
   de confiance**. Ne rend la signature valide QUE sur cette machine —
   SmartScreen reste affiché chez les autres utilisateurs.

### 3. Signing policy

**Projects → Cerbere Security Shield → Signing policies → Add** :

| Champ | Valeur |
|---|---|
| Name | `Test signing` |
| Slug | `Test_signing` — relever la valeur EXACTE créée (underscore !) |
| Purpose | `Any` |
| Certificate | `Cerbere Test Cert` (créé à l'étape 2 — sinon la liste est vide) |
| Submitters | soi-même |
| Use approval process / trusted build system / origin policy | ⬜ tout décoché |

### 4. API token

⚠️ **Piège UI** : pas de menu « API tokens » dans l'organisation. Le token est
au niveau **utilisateur** :

1. Cliquer son **nom/avatar en haut à droite** → **My profile**
2. Section **API Token** → **Generate token**
3. **Copier immédiatement** — affiché une seule fois

### 5. Secrets GitHub

Repo `art-qalam-fr/CerbereShield` → **Settings → Secrets and variables →
Actions → Repository secrets** (PAS environment, PAS organization) :

- `SIGNPATH_API_TOKEN` = le token
- `SIGNPATH_ORGANIZATION_ID` = `4c68f7ab-9667-433f-9f08-34f2ef420477`

💡 Méthode infaillible (zéro faute de frappe) :

```powershell
"LE_TOKEN" | gh secret set SIGNPATH_API_TOKEN -R art-qalam-fr/CerbereShield
```

### 6. Artifact configuration — ⚠️ LE piège final

Le template par défaut contient `<include path="sample.exe" />` — SignPath
cherche littéralement `sample.exe` → erreur *« Expected path to match exactly
1 item, but found 0 »*. Éditer la config (Projects → projet → artifact
configuration → Edit) :

```xml
<?xml version="1.0" encoding="utf-8" ?>
<artifact-configuration xmlns="http://signpath.io/artifact-configuration/v1">
  <zip-file>
    <pe-file-set>
      <include path="*.exe" min-matches="1" max-matches="unbounded" />
      <include path="*.dll" min-matches="0" max-matches="unbounded" />
      <for-each>
        <authenticode-sign />
      </for-each>
    </pe-file-set>
  </zip-file>
</artifact-configuration>
```

### 7. Workflow — pourquoi l'API REST et pas l'action officielle

L'action `signpath/github-action-submit-signing-request` passe par le
**connecteur GitHub**, qui exige un « Trusted Build System GitHub.com » déclaré
dans l'organisation — or la nouvelle UI n'expose plus le bouton
« Add predefined » (la doc officielle est obsolète) → erreur
*« Trusted build system is not allowed to log into the organization »*.

Le workflow utilise donc l'**API REST directement** (documentée,
`SubmitWithArtifact`), qui suffit pour une policy de test sans vérification
d'origine :

```
POST   /API/v1/{org}/SigningRequests/SubmitWithArtifact   (multipart, le zip)
GET    /API/v1/{org}/SigningRequests/{id}/Status          (polling)
GET    /API/v1/{org}/SigningRequests/{id}/SignedArtifact  (zip signé)
```

Voir `.github/workflows/release-sign.yml`. Tester le token à la main :

```powershell
Invoke-WebRequest "https://app.signpath.io/API/v1/<ORG_ID>/SigningRequests" `
  -Headers @{Authorization="Bearer <TOKEN>"}   # 200 = token OK
```

### Erreurs rencontrées et leur signification

| Erreur | Cause réelle |
|---|---|
| `Input required and not supplied: api-token` | secret absent ou mal nommé |
| `Could not authorize against SignPath API` | token invalide dans le secret |
| `No matching entity was found` | mauvais slug projet/policy |
| `Trusted build system is not allowed...` | connecteur GitHub non autorisé → passer en REST |
| `Expected path to match exactly 1 item, but found 0` | `sample.exe` resté dans l'artifact config |
| `Status: UnknownError` dans `Get-AuthenticodeSignature` | normal : cert auto-signé non installé en racine sur cette machine |

---

## Étapes restantes

### Court terme
- [ ] **Candidature SignPath Foundation** : https://signpath.org/apply.html
      (formulaire direct, valeurs ci-dessous). Délai : quelques jours.
- [ ] Distribuer le build signé-test au collaborateur via l'artefact
      `signed-package` d'un run vert (SmartScreen affichera l'avertissement
      chez lui — normal en auto-signé).

### Après approbation Foundation (certificat de confiance → SmartScreen propre)
- [ ] Créer la policy `release-signing` avec le certificat Foundation
- [ ] La Foundation exige la **vérification d'origine** → il faudra alors le
      connecteur GitHub (trusted build system) — le point sera à régler avec
      leur support si l'UI ne l'expose toujours pas
- [ ] Lancer le workflow avec `signing_policy=release-signing` et
      `publish_release` coché → Release publique avec l'installeur signé
- [ ] Ajouter le lien Releases dans le README public

### Formulaire Foundation — valeurs prêtes à copier

| Champ | Valeur |
|---|---|
| Project name | `Cerbere Security Shield` |
| Repository URL | `https://github.com/art-qalam-fr/CerbereShield` |
| License | `MIT` |
| Download / Release URL | `https://github.com/art-qalam-fr/CerbereShield/releases` |
| Description | `Free Windows security suite: real-time network port monitoring, DNS-based ad/tracker/parental blocking (EasyList, AdGuard, OISD, HaGeZi), firewall hardening, intrusion detection, systray client. 100% local, no telemetry.` |

## Alternative payante (si SignPath Foundation tarde)

Azure Trusted Signing (~10 $/mois) : confiance SmartScreen immédiate,
fonctionne aussi avec un repo privé.
