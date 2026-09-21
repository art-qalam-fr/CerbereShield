# Tester Cerbere Security Shield (beta)

Merci de tester Cerbere ! Voici tout ce qu'il te faut, étape par étape.
Durée totale : ~5 minutes.

## 1. Télécharger l'installateur

👉 **https://github.com/art-qalam-fr/CerbereShield/releases**

Sur cette page, dans la release `v0.9.0-beta`, télécharge le fichier
**`CerbereShield_Setup.exe`** (section « Assets »).

> Pas besoin de compte GitHub — le lien fonctionne pour tout le monde.

## 2. L'alerte SmartScreen (c'est normal — version beta)

Windows va afficher **« Windows a protégé votre PC »** car le certificat de
signature est encore un certificat de test (le certificat officiel est en
cours d'obtention auprès de la SignPath Foundation).

Pour continuer :

1. Clique **« Informations complémentaires »**
2. Clique **« Exécuter quand même »**

C'est un faux positif lié à l'absence de réputation du certificat — le
fichier est bien signé par le projet.

> Optionnel : si tu veux voir la signature « valide », installe le certificat
> de test `Cerbere_Test_Cert.cer` (fourni séparément) dans
> *Utilisateur actuel → Autorités de certification racines de confiance*.

## 3. Installer et lancer

1. Lance `CerbereShield_Setup.exe` → l'installation se fait normalement
2. À la fin, Cerbere se lance ; le tableau de bord s'ouvre dans le navigateur
   sur **http://localhost:4050**
3. Certaines fonctions (pare-feu, durcissement) demanderont les droits
   administrateur — accepte l'élévation UAC quand elle apparaît

## 4. Quoi tester

- **Dashboard** : monitoring des ports en temps réel
- **Bloqueur DNS** : activation du filtrage pubs/trackers (EasyList, AdGuard,
  OISD, HaGeZi)
- **Contrôle parental / domestique**
- **Détection d'intrusion**
- **Paramètres → Langue** : FR / EN / DE / ES
- **Onglet Aide** : documentation intégrée

## 5. Config système requise

- Windows 10 ou 11 (64 bits)
- Connexion internet pour les listes de blocage et l'enrichissement
- (Optionnel) clé API abuse.ch gratuite pour la réputation des processus —
  l'app fonctionne sans, cette fonction est simplement désactivée

## 6. Remonter tes retours

Envoie directement à Michel :

- Ce qui fonctionne / ne fonctionne pas
- Captures d'écran si bug visuel
- Le log de crash si l'app plante : `%TEMP%\security_shield_crash.log`

Ou ouvre un ticket : https://github.com/art-qalam-fr/CerbereShield/issues
