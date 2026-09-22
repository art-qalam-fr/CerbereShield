# Tester Cerbere Security Shield (beta)

Merci de tester Cerbere ! Voici tout ce qu'il te faut, étape par étape.
Durée totale : ~5 minutes.

## 1. Télécharger l'installateur

👉 **https://github.com/art-qalam-fr/CerbereShield/releases**

Sur cette page, dans la release la plus récente, télécharge le fichier
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

> 🛑 **Blocage total sans bouton « Exécuter quand même » ?** Sur Windows 11,
> **Smart App Control** peut bloquer complètement l'installation (message du
> type « application bloquée / suspecte » sans option de contournement).
> Pour l'autoriser :
>
> 1. Menu Démarrer → **Sécurité Windows**
> 2. **Contrôle des applications et du navigateur**
> 3. **Paramètres de Smart App Control** → **Désactivé**
> 4. Relance le setup → l'écran bleu « Exécuter quand même » apparaît
>
> *Attention : Smart App Control ne se réactive pas sans réinitialiser
> Windows. Ce blocage disparaîtra avec le certificat officiel (en cours
> d'obtention auprès de la SignPath Foundation).*

> Optionnel : si tu veux voir la signature « valide », installe le certificat
> de test `Cerbere_Test_Cert.cer` (fourni séparément) dans
> *Utilisateur actuel → Autorités de certification racines de confiance*.

## 3. Installer et lancer

> ⚠️ **Si tu as déjà installé une version beta précédente** (ex. celle qui
> demandait le mot de passe Windows) : la réinstallation seule **ne suffit
> pas** — l'ancienne configuration survit. Avant de réinstaller :
>
> 1. Désinstalle CerbereShield (Paramètres Windows → Applications →
>    CerbereShield → Désinstaller)
> 2. Supprime le dossier de données : colle `%LOCALAPPDATA%\CerbereShield`
>    dans la barre d'adresse de l'explorateur et supprime le dossier entier
>    (ça efface l'ancienne config qui demandait le mot de passe Windows)
> 3. Puis installe la nouvelle version normalement
>
> *Première installation ? Ignore ce bloc, tu peux continuer direct.*

1. Lance `CerbereShield_Setup.exe` → l'installation se fait normalement
2. À la fin, Cerbere se lance ; le tableau de bord s'ouvre dans le navigateur
   sur **http://localhost:4050**
3. **Premier lancement** : l'écran te demande de **créer un mot de passe
   dédié à l'application** (min. 4 caractères). C'est lui qui déverrouillera
   l'app ensuite — retiens-le (aucun lien avec ton mot de passe Windows,
   compatible Windows Hello).
4. Certaines fonctions (pare-feu, durcissement) demanderont les droits
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
