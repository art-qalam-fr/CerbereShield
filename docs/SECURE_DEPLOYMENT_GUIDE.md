# 🚨 PROCÉDURE DE HARDENING SÉCURISÉ - ÉVITER LES INTERRUPTIONS DE SERVICE

## ⚠️ PRÉREQUIS CRITIQUES

### 1. **SAUVEGARDE SYSTÈME**

```powershell
# Créer un point de restauration (nécessite droits admin)
Checkpoint-Computer -Description "Avant hardening sécurité" -RestorePointType "MODIFY_SETTINGS"
```

### 2. **VÉRIFICATION DES SERVICES ACTIFS**

```powershell
# Exécuter le script de vérification
.\check_services.ps1

# Vérifier le rapport généré
Get-Content service_check_*.txt | Select-Object -Last 30
```

## 🔄 PROCÉDURE ÉTAPE PAR ÉTAPE

### PHASE 1: Préparation (0 risque)

```powershell
# 1. Vérifier les services actifs
.\check_services.ps1

# 2. Test du hardening en mode simulation
.\security_hardening.ps1 -DryRun

# 3. Vérifier les logs de simulation
Get-Content port_hardening_*_dryrun.log | Select-Object -Last 20
```

### PHASE 2: Hardening Progressif (Risque Contrôlé)

#### Option A: Hardening Manuel avec Validation

```powershell
# Exécuter le hardening réel
.\security_hardening.ps1

# Vérifier immédiatement que les services fonctionnent
# Tester les MCP et autres services critiques
```

#### Option B: Hardening avec Rollback Automatique

```powershell
# Créer un job avec timeout
$job = Start-Job -ScriptBlock {
    .\security_hardening.ps1
    Start-Sleep 30  # Attendre 30 secondes
    # Tests automatiques des services critiques
}

# Attendre le job avec timeout
Wait-Job $job -Timeout 300  # 5 minutes max

# Si timeout ou erreur, rollback
if ($job.State -ne "Completed") {
    Stop-Job $job
    Write-Host "❌ Hardening interrompu - rollback nécessaire"
    # Restaurer les règles firewall supprimées
}
```

### PHASE 3: Validation Post-Hardening

#### Tests de Connectivité

```powershell
# Tester les ports critiques
Test-NetConnection -ComputerName localhost -Port 3000  # MCP agent
Test-NetConnection -ComputerName localhost -Port 5000  # MCP simple
Test-NetConnection -ComputerName localhost -Port 80    # HTTP si nécessaire
Test-NetConnection -ComputerName localhost -Port 443   # HTTPS si nécessaire

# Tester les services Windows
Get-Service | Where-Object { $_.Status -ne 'Running' } | Format-Table Name, DisplayName, Status
```

#### Vérification du Rapport Final

```powershell
# Lire le rapport d'audit après hardening
Get-Content security_audit_report.md

# Vérifier l'amélioration du score
# Score devrait passer de 100/100 à ≤30/100
```

## 🛡️ MESURES DE PROTECTION CONTRE LES INTERRUPTIONS

### 1. **Liste Blanche des Services Critiques**

Les ports suivants sont automatiquement préservés :

- **3000**: MCP agent-mcp-gateway
- **5000**: MCP simple-gateway
- **4050**: FastAPI/Uvicorn (Cerbere Security Shield Dashboard)
- **8080**: Services web locaux
- **80/443**: HTTP/HTTPS (si autorisés)

### 2. **Stratégie de Blocage Intelligent**

- **Ports autorisés** → Changement de liaison vers `127.0.0.1` (pas de blocage)
- **Ports critiques inattendus** → Blocage firewall (PostgreSQL 5432)
- **Ports inconnus** → Blocage firewall (RPC 135, SMB 445, etc.)

### 3. **Rollback d'Urgence**

Si un service critique est bloqué :

```powershell
# Supprimer la règle firewall bloquante
Remove-NetFirewallRule -DisplayName "Block_Port_*"

# Redémarrer les services affectés
Restart-Service -Name "nom_du_service"

# Reconfigurer les liaisons si nécessaire
netsh http add iplisten ipaddress=0.0.0.0
```

## 🔍 DIAGNOSTIC DES PROBLÈMES

### Service MCP ne fonctionne plus ?

```powershell
# Vérifier si le port est bloqué
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Block*" }

# Tester la connectivité
Test-NetConnection -ComputerName localhost -Port 3000

# Vérifier les logs de hardening
Get-Content port_hardening_*.log | Select-String "3000"
```

### Port critique bloqué par erreur ?

1. Vérifier le log pour voir pourquoi il a été bloqué
2. Ajouter le port à `$AllowedPorts` dans `security_hardening.ps1`
3. Re-exécuter le script ou supprimer manuellement la règle firewall

## 📊 INDICATEURS DE SUCCÈS

Après hardening réussi, vous devriez observer :

- ✅ Score de risque ≤ 30/100
- ✅ ≤ 2 ports exposés (vs 14 initialement)
- ✅ Services MCP opérationnels
- ✅ Services Windows fonctionnels
- ✅ Accès RDP et navigation préservés

## 🆘 PROCÉDURE D'URGENCE

Si le système devient inaccessible :

1. **Redémarrage en Mode Sans Échec** (F8 au boot)
2. **Connexion avec compte administrateur local**
3. **Suppression des règles firewall** :

   ```cmd
   netsh advfirewall firewall delete rule name="Block_Port_*"
   ```

4. **Restauration système** si nécessaire

---

⚠️ **IMPORTANT** : Cette procédure est conçue pour minimiser les risques, mais aucun hardening n'est 100% sans risque. Testez toujours en dry-run d'abord !
