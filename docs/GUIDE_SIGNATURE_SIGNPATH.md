# Guide — Signature du code avec SignPath (gratuit, open source)

Objectif : faire signer `CerbereShield.exe` et `CerbereShield_Setup.exe` par le
certificat de confiance de la SignPath Foundation → SmartScreen propre,
éditeur identifié, zéro coût.

## Prérequis (à faire par le propriétaire — ~10 min)

1. **Repo public obligatoire** — ✅ fait : `https://github.com/art-qalam-fr/CerbereShield` (licence MIT, fichier `LICENSE` à la racine).
2. **Candidature** : https://signpath.org/apply.html — formulaire direct,
   **pas besoin de compte SignPath au préalable** (l'accès à l'organisation
   SignPath est accordé APRÈS approbation).
3. Champ « Download / Release URL » : `https://github.com/art-qalam-fr/CerbereShield/releases`

## Formulaire — valeurs prêtes à copier

| Champ | Valeur |
|---|---|
| Project name | `Cerbere Security Shield` |
| Description | `Windows security suite: network port monitoring, DNS ad/tracker/parental blocking, firewall hardening plans, systray client.` |
| Repository URL | `https://github.com/art-qalam-fr/CerbereShield` |
| Website | `https://github.com/art-qalam-fr/CerbereShield` |
| License | `MIT` |
| Privacy policy URL | lien vers `PRIVACY.md` du repo public |
| Development model | `Open source, releases via GitHub Actions` |

## Après approbation (délai : quelques jours)

SignPath fournit : **Organization ID**, **API token**, **signing policy**
(`release-signing`). À mettre dans les secrets du repo public :

- `SIGNPATH_API_TOKEN`
- `SIGNPATH_ORGANIZATION_ID`

## Intégration CI (workflow prêt)

Le signataire standard est l'action `signpath/github-action-submit-signing-request`
qui signe un artefact produit par le workflow (l'exe est donc **buildé en CI**
puis signé — c'est ce qui donne la provenance vérifiable qu'exige SignPath) :

```yaml
# .github/workflows/release-sign.yml — squelette à activer après approbation
name: Release signée
on:
  workflow_dispatch:
jobs:
  build-sign:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.13" }
      - run: pip install -r requirements.txt pyinstaller
      - run: packaging\build.bat            # produit dist\CerbereShield\
      - uses: actions/upload-artifact@v4    # artefact à signer
        with:
          name: CerbereShield-unsigned
          path: dist/CerbereShield/CerbereShield.exe
      - uses: signpath/github-action-submit-signing-request@v1
        with:
          api-token: ${{ secrets.SIGNPATH_API_TOKEN }}
          organization-id: ${{ secrets.SIGNPATH_ORGANIZATION_ID }}
          project-slug: cerbere-shield
          signing-policy-slug: release-signing
          github-artifact-id: <id de l'artefact uploadé>
          output-artifact-directory: signed
```

## Alternative si repo privé conservé

Azure Trusted Signing (~10 $/mois, confiance SmartScreen immédiate,
fonctionne avec un repo privé).
