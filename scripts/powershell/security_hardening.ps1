# Script de durcissement automatique des ports Windows
# À exécuter avec des droits administrateur

param(
    [switch]$DryRun,
    [string]$LogFile,
    [string]$Plan,
    [string]$Action
)

# Chemin de log par défaut : ..\\..\\logs\\hardening\\port_hardening_YYYYMMDD_HHMMSS.log
if (-not $LogFile) {
    try {
        $projectRoot = Join-Path -Path $PSScriptRoot -ChildPath "..\\.."
        $logsDir     = Join-Path -Path $projectRoot -ChildPath "logs\\hardening"
        if (-not (Test-Path -Path $logsDir)) {
            New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
        }
        $LogFile = Join-Path -Path $logsDir -ChildPath ("port_hardening_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    } catch {
        # En dernier recours, retomber sur un fichier dans le répertoire courant
        $LogFile = "port_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }
}

# Action courante du plan ("harden" / "release"), partagée entre fonctions
$script:PlanAction = $null

# Si aucun plan n'est explicitement fourni, essayer automatiquement de trouver
# le dernier plan généré par le Web Port Dashboard.
if (-not $Plan) {
    try {
        # 1) Chemin relatif au script (exécution depuis n'importe où)
        $candidateFromScript = Join-Path -Path $PSScriptRoot -ChildPath "..\..\web_port_dashboard\hardening_plan.json"

        # 2) Chemin relatif au répertoire courant (exécution depuis la racine du projet)
        $candidateFromCwd = Join-Path -Path (Get-Location) -ChildPath "web_port_dashboard\hardening_plan.json"

        # 3) Installation packagée (exe PyInstaller) : données dans %LOCALAPPDATA%
        $candidatePackaged = Join-Path -Path $env:LOCALAPPDATA -ChildPath "CerbereShield\hardening_plan.json"

        if (Test-Path -Path $candidateFromScript) {
            $Plan = $candidateFromScript
        } elseif (Test-Path -Path $candidateFromCwd) {
            $Plan = $candidateFromCwd
        } elseif (Test-Path -Path $candidatePackaged) {
            $Plan = $candidatePackaged
        }
    } catch {
        # En cas d'erreur, on laisse $Plan vide et le script retombera en mode auto
    }
}

function Unblock-PortWithFirewall {
    param([int]$Port, [string]$Protocol = "TCP")

    if ($DryRun) {
        Write-Log "DRY RUN: Supprimerait la règle firewall pour le port $Port ($Protocol)" "WARNING"
        return $true
    }

    try {
        $ruleName = "Block_Port_${Port}_${Protocol}"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

        if (-not $existingRule) {
            Write-Log "Aucune règle firewall à supprimer pour le port $Port ($Protocol)" "INFO"
            return $true
        }

        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
        Write-Log "Règle firewall supprimée pour le port $Port ($Protocol)" "INFO"
        return $true
    }
    catch {
        Write-Log "Erreur lors de la suppression de la règle firewall pour le port $Port : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Auto-élévation : si le script n'est pas lancé en tant qu'administrateur,
# il se relance lui-même avec RunAs (UAC) en conservant les paramètres.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relance du script en mode administrateur..." -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"

    $argsList = @()
    if ($DryRun) { $argsList += "-DryRun" }
    if ($LogFile) { $argsList += "-LogFile `"$LogFile`"" }
    if ($Plan)   { $argsList += "-Plan `"$Plan`"" }
    if ($Action) { $argsList += "-Action `"$Action`"" }

    $scriptPath = $MyInvocation.MyCommand.Path
    $psi.Arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" " + ($argsList -join ' ')
    $psi.Verb = "runas"

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Host "Élévation annulée ou échouée : $($_.Exception.Message)" -ForegroundColor Red
    }

    exit
}

# Configuration des ports autorisés (à adapter selon vos besoins)
$AllowedPorts = @(
    80,     # HTTP (nginx / redirections éventuelles)
    443,    # HTTPS (nginx / accès n8n)
    3000,   # MCP agent-mcp-gateway
    5000,   # MCP simple-gateway (si utilisé)
    4050,   # FastAPI/Uvicorn Web Port Dashboard
    8080,   # Autres services web locaux
    5678,   # n8n (API / UI)
    5679,   # n8n Task Broker
    5433    # PostgreSQL n8n (local sur 127.0.0.1)
    # Ajoutez d'autres ports autorisés ici
)

$CriticalPorts = @(
    22,     # SSH (si utilisé)
    80,     # HTTP
    443,    # HTTPS
    3389,   # RDP
    3306,   # MySQL
    5432    # PostgreSQL
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    if ($LogFile) {
        try {
            $logDir = Split-Path -Path $LogFile -Parent
            if ($logDir -and -not (Test-Path -Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            $retry = 0
            while ($retry -lt 3) {
                try {
                    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction Stop
                    break
                } catch {
                    $retry++
                    Start-Sleep -Milliseconds 100
                }
            }
        } catch {
            Write-Host "[LOG-ERROR] Impossible d'écrire dans le fichier de log '$LogFile' : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}


function Update-ProtectionState {
    param([bool]$Enabled)

    # En mode DryRun, on ne change pas réellement l'état côté API
    if ($DryRun) {
        Write-Log "DRY RUN: mettrait à jour l'état de protection via API (Enabled=$Enabled)" "INFO"
        return
    }

    try {
        $body = @{ enabled = $Enabled } | ConvertTo-Json -Depth 3
        $url  = "http://127.0.0.1:4050/api/protection/state"

        Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -ErrorAction Stop | Out-Null
        Write-Log "État de protection mis à jour via API (Enabled=$Enabled)" "INFO"
    }
    catch {
        Write-Log "Impossible de mettre à jour l'état de protection via API: $($_.Exception.Message)" "WARNING"
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PlanPorts {
    param([string]$PlanPath)

    if (-not $PlanPath) { return $null }

    if (-not (Test-Path -Path $PlanPath)) {
        Write-Log "Fichier de plan introuvable: $PlanPath - le script utilisera la détection auto." "WARNING"
        return $null
    }

    try {
        $json = Get-Content -Path $PlanPath -Raw -ErrorAction Stop | ConvertFrom-Json
        if (-not $json.ports) {
            Write-Log "Plan vide ou sans section 'ports' - le script utilisera la détection auto." "WARNING"
            return $null
        }

        $ports = @()

        # Action globale du plan : "harden" (par défaut) ou "release" (libération)
        $script:PlanAction = "harden"
        if ($Action) {
            $script:PlanAction = $Action.ToLower()
            Write-Log "Action forcée via paramètre: $script:PlanAction" "INFO"
        } elseif ($json.action) {
            $script:PlanAction = $json.action.ToString().ToLower()
        }
        foreach ($p in $json.ports) {
            if ($p.port -and $p.protocol) {
                $ports += [PSCustomObject]@{
                    Port     = [int]$p.port
                    Protocol = ($p.protocol.Trim().ToUpper())
                    Risk     = ($p.risk)
                }
            }
        }

        if ($ports.Count -eq 0) {
            Write-Log "Aucun port valide dans le plan - utilisation de la détection auto." "WARNING"
            return $null
        }

        Write-Log "Plan chargé: $($ports.Count) port(s) sélectionné(s) depuis $PlanPath (action: $script:PlanAction)" "INFO"
        return $ports
    } catch {
        Write-Log "Erreur lors du chargement du plan $PlanPath : $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-ExposedPorts {
    Write-Log "Scanning des ports exposés..."
    $netstat = netstat -ano | Select-String "LISTENING"

    $exposedPorts = @()
    foreach ($line in $netstat) {
        $parts = $line -split '\s+'
        if ($parts.Length -ge 5) {
            $localAddress = $parts[1]
            $state = $parts[3]
            $processId = $parts[4]

            if ($localAddress -match '(.+):(\d+)') {
                $ip = $matches[1]
                $port = [int]$matches[2]

                # Vérifier si exposé sur toutes les interfaces
                if ($ip -eq "0.0.0.0" -or $ip -eq "*" -or $ip -eq "::") {
                    $exposedPorts += @{
                        Port = $port
                        IP = $ip
                        PID = $processId
                        State = $state
                    }
                }
            }
        }
    }
    return $exposedPorts
}

function Block-PortWithFirewall {
    param([int]$Port, [string]$Protocol = "TCP", [string]$ProcessName = "Unknown")

    if ($DryRun) {
        Write-Log "DRY RUN: Bloquerait le port $Port ($Protocol) - $ProcessName" "WARNING"
        return $true
    }

    try {
        # Créer une règle firewall pour bloquer le port entrant
        $ruleName = "Block_Port_${Port}_${Protocol}"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Write-Log "Règle firewall existe déjà pour le port $Port"
            return $true
        }

        New-NetFirewallRule -DisplayName $ruleName `
                          -Direction Inbound `
                          -LocalPort $Port `
                          -Protocol $Protocol `
                          -Action Block `
                          -Profile Any

        Write-Log "Port $Port ($Protocol) bloqué avec succès via firewall"
        return $true
    }
    catch {
        Write-Log "Erreur lors du blocage du port $Port : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-ServiceBinding {
    param([int]$Port, [string]$NewIP = "127.0.0.1")

    if ($DryRun) {
        Write-Log "DRY RUN: Changerait la liaison du port $Port vers $NewIP" "WARNING"
        return $true
    }

    try {
        # Pour les services HTTP (ports 80/443), utiliser netsh
        if ($Port -eq 80 -or $Port -eq 443) {
            Write-Log "Exécution: netsh http delete iplisten ipaddress=0.0.0.0"
            $result = netsh.exe http delete iplisten ipaddress=0.0.0.0 2>&1
            Write-Log "Résultat: $result"

            Write-Log "Exécution: netsh http add iplisten ipaddress=$NewIP"
            $result = netsh.exe http add iplisten ipaddress=$NewIP 2>&1
            Write-Log "Résultat: $result"
        }

        # Pour PostgreSQL (port 5432), modifier postgresql.conf et pg_hba.conf
        elseif ($Port -eq 5432) {
            Write-Log "Port PostgreSQL détecté - modification manuelle requise dans postgresql.conf"
            Write-Log "Recommandation: listen_addresses = 'localhost'"
        }

        Write-Log "Tentative de modification de liaison pour le port $Port"
        return $true
    }
    catch {
        Write-Log "Erreur lors du changement de liaison du port $Port : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Protect-System {
    Write-Log "=== DÉBUT DU DURCISSEMENT AUTOMATIQUE ==="

    if (-not (Test-Administrator)) {
        Write-Log "Ce script doit être exécuté en tant qu'administrateur!" "ERROR"
        exit 1
    }

    $planPorts = Get-PlanPorts -PlanPath $Plan
    $isPlanMode = $false
    if ($planPorts) {
        Write-Log "Utilisation du plan fourni pour le durcissement/libération (sans rescan netstat)." "INFO"
        $exposedPorts = $planPorts
        $isPlanMode = $true
        Write-Log "Ports dans le plan: $($exposedPorts.Count)" "INFO"
    } else {
        $exposedPorts = Get-ExposedPorts
        Write-Log "Ports exposés trouvés: $($exposedPorts.Count)"
    }

    $blockedCount = 0
    $bindingChangedCount = 0
    $releasedCount = 0

    foreach ($portInfo in $exposedPorts) {
        $port = $portInfo.Port
        $processName = "Unknown" # On pourrait améliorer avec Get-Process
        $risk = $portInfo.PSObject.Properties["Risk"].Value
        $protocol = $portInfo.PSObject.Properties["Protocol"].Value
        if (-not $protocol) { $protocol = "TCP" }

        Write-Log "Traitement du port $port (PID: $($portInfo.PID))"

        # --- Mode plan: le plan PRIME sur la config autorisée/critique ---
        if ($isPlanMode -and $risk) {
            $riskLower = $risk.ToString().ToLower()

            if ($script:PlanAction -eq "release") {
                # Plan de libération : on enlève les règles Block_Port_*
                Write-Log "Plan (release): port $port -> suppression de la règle firewall si présente" "INFO"
                $success = Unblock-PortWithFirewall -Port $port -Protocol $protocol
                if ($success) { $releasedCount++ }
                continue
            }

            if ($script:PlanAction -eq "harden" -and ($riskLower -eq "critical" -or $riskLower -eq "unexpected")) {
                Write-Log "Plan: port $port marqué '$riskLower' -> blocage via firewall" "WARNING"
                $success = Block-PortWithFirewall -Port $port -Protocol $protocol -ProcessName $processName
                if ($success) { $blockedCount++ }
                continue
            }
        }

        # --- Mode auto ou ports non marqués dans le plan: comportement historique ---
        # Si le port est dans la liste des autorisés, seulement changer la liaison
        if ($port -in $AllowedPorts) {
            Write-Log "Port $port autorisé - changement de liaison vers localhost"
            $success = Set-ServiceBinding -Port $port
            if ($success) { $bindingChangedCount++ }
        }
        # Si le port est critique et inattendu, le bloquer
        elseif ($port -in $CriticalPorts) {
            Write-Log "Port critique $port exposé - blocage immédiat" "WARNING"
            $success = Block-PortWithFirewall -Port $port -ProcessName $processName
            if ($success) { $blockedCount++ }
        }
        # Pour les autres ports exposés, les bloquer
        else {
            Write-Log "Port inattendu $port - blocage" "WARNING"
            $success = Block-PortWithFirewall -Port $port -ProcessName $processName
            if ($success) { $blockedCount++ }
        }
    }

    Write-Log "=== RÉSULTATS DU DURCISSEMENT ==="
    Write-Log "Ports bloqués: $blockedCount"
    Write-Log "Ports libérés (règles supprimées): $releasedCount"
    Write-Log "Liaisons changées: $bindingChangedCount"
    Write-Log "Log sauvegardé dans: $LogFile"

    # Mise à jour de l'état global de protection côté API
    # - Si on a un plan explicite avec action "harden" / "release", on s'y fie.
    # - Sinon, en mode auto, si on a effectivement bloqué des ports ou changé des liaisons,
    #   on considère la protection comme active.
    $targetEnabled = $null

    if ($isPlanMode -and $script:PlanAction) {
        if ($script:PlanAction -eq "release") {
            $targetEnabled = $false
        }
        elseif ($script:PlanAction -eq "harden") {
            $targetEnabled = $true
        }
    }
    elseif (-not $isPlanMode) {
        if ($blockedCount -gt 0 -or $bindingChangedCount -gt 0) {
            $targetEnabled = $true
        }
    }

    if ($null -ne $targetEnabled) {
        Update-ProtectionState -Enabled:$targetEnabled
    }
}

# Exécution principale
if ($DryRun) {
    Write-Log "=== MODE DRY RUN - AUCUNE MODIFICATION RÉELLE ===" "WARNING"
}

Protect-System

Write-Log "=== FIN DU SCRIPT ==="
