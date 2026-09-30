# `curated/` — Listes de domaines maintenues par le projet

Ce dossier contient les listes de domaines **curées manuellement** pour le
module `parental_control` (contrairement aux listes téléchargées dans
`state/filter_lists/`, celles-ci sont versionnées dans le dépôt et ne
dépendent d'aucune source ni licence externe).

- `payment_domains.txt` — domaines de paiement en ligne (PSP, 3-D Secure,
  banques, BNPL, cartes prépayées) bloqués par le « contrôle domestique ».
- `doh_bypass.txt` — hostnames de résolveurs DNS-over-HTTPS (DoH) publics,
  bloqués pour limiter le contournement du filtrage DNS par un navigateur.
- `vpn_domains.txt` — domaines de fournisseurs VPN grand public et outils de
  contournement (téléchargement/inscription ; ne bloque pas un tunnel déjà
  établi).

## Contribuer

1. Un domaine par ligne, minuscules, sans `https://` ni chemin ; `#` = commentaire.
2. Vérifier le domaine sur la documentation officielle du service avant ajout.
3. Le blocage est par suffixe : un domaine bloque tous ses sous-domaines —
   n'ajouter un sous-domaine que si le domaine parent ne doit pas l'être.
4. Garder les sections thématiques ordonnées et commenter les cas particuliers.
