# Script de surveillance continue des ports
# À exécuter en arrière-plan avec des droits administrateur

param(
    [int]$IntervalMinutes = 60,  # Intervalle de vérification en minutes
    [string]$LogFile = "port_monitoring_$(Get-Date -Format 'yyyyMMdd').log",
    [switch]$AutoHarden,
    [string]$EmailTo = "",  # Adresse email pour les alertes
    [string]$SMTPServer = "smtp.gmail.com",
    [int]$SMTPPort = 587
)

# Auto-élévation : si le script n'est pas lancé en tant qu'administrateur,
# il se relance lui-même avec RunAs (UAC) en conservant les paramètres.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relance du script en mode administrateur..." -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"

    $argsList = @()
    $argsList += "-IntervalMinutes $IntervalMinutes"
    if ($LogFile)    { $argsList += "-LogFile `"$LogFile`"" }
    if ($AutoHarden) { $argsList += "-AutoHarden" }
    if ($EmailTo)    { $argsList += "-EmailTo `"$EmailTo`"" }
    if ($SMTPServer) { $argsList += "-SMTPServer `"$SMTPServer`"" }
    if ($SMTPPort)   { $argsList += "-SMTPPort $SMTPPort" }

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

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $LogEntry
    }
}

function Send-AlertEmail {
    param([string]$Subject, [string]$Body)

    if (-not $EmailTo) {
        Write-Log "Aucune adresse email configurée pour les alertes"
        return
    }

    try {
        $emailParams = @{
            To = $EmailTo
            From = "security-monitor@localhost"
            Subject = $Subject
            Body = $Body
            SMTPServer = $SMTPServer
            Port = $SMTPPort
            UseSSL = $true
        }

        Send-MailMessage @emailParams
        Write-Log "Alerte email envoyée à $EmailTo"
    }
    catch {
        Write-Log "Erreur envoi email: $($_.Exception.Message)" "ERROR"
    }
}

function Get-CurrentRiskScore {
    # Simule l'exécution de l'audit de sécurité
    $auditPath = "$PSScriptRoot\..\..\security_audit\security_audit.py"

    if (-not (Test-Path $auditPath)) {
        Write-Log "Script d'audit non trouvé: $auditPath" "ERROR"
        return 100  # Score élevé par défaut en cas d'erreur
    }

    try {
        & python $auditPath 2>&1 | Out-Null
        Write-Log "Audit exécuté"

        # Lire le rapport généré
        $reportPath = "$PSScriptRoot\..\..\security_audit_report.md"
        if (Test-Path $reportPath) {
            $content = Get-Content $reportPath -Raw

            # Extraire le score de risque
            if ($content -match "Score: (\d+)/100") {
                return [int]$matches[1]
            }
        }

        return 50  # Score moyen si parsing échoue
    }
    catch {
        Write-Log "Erreur lors de l'audit: $($_.Exception.Message)" "ERROR"
        return 100
    }
}

function Invoke-AutoHarden {
    $hardeningScript = "$PSScriptRoot\security_hardening.ps1"

    if (-not (Test-Path $hardeningScript)) {
        Write-Log "Script de hardening non trouvé: $hardeningScript" "ERROR"
        return $false
    }

    try {
        Write-Log "Exécution du hardening automatique..."
        $result = & powershell.exe -ExecutionPolicy Bypass -File $hardeningScript 2>&1

        Write-Log "Hardening terminé"
        Write-Log "Résultat: $result"

        return $true
    }
    catch {
        Write-Log "Erreur lors du hardening: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-PortMonitoring {
    Write-Log "=== DÉMARRAGE DE LA SURVEILLANCE CONTINUE ==="
    Write-Log "Intervalle: $IntervalMinutes minutes"
    Write-Log "Hardening automatique: $AutoHarden"
    Write-Log "Email d'alerte: $EmailTo"
    Write-Log "Log: $LogFile"

    $lastRiskScore = 0

    while ($true) {
        $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Log "=== VÉRIFICATION À $currentTime ==="

        $riskScore = Get-CurrentRiskScore
        Write-Log "Score de risque actuel: $riskScore/100"

        # Vérifier si le risque a augmenté significativement
        if ($riskScore -gt $lastRiskScore + 20) {
            Write-Log "ALERTE: Augmentation significative du risque de sécurité!" "WARNING"

            $subject = "🚨 Alerte Sécurité - Risque Élevé Détecté"
            $body = @"
Un audit de sécurité automatique a détecté une augmentation du niveau de risque.

Score actuel: $riskScore/100
Score précédent: $lastRiskScore/100

Vérifiez immédiatement le rapport de sécurité:
$PSScriptRoot\..\..\security_audit_report.md

Temps: $currentTime
"@

            Send-AlertEmail -Subject $subject -Body $body

            # Hardening automatique si activé
            if ($AutoHarden) {
                Write-Log "Déclenchement du hardening automatique..."
                $success = Invoke-AutoHarden

                if ($success) {
                    Write-Log "Hardening automatique réussi"

                    # Vérifier à nouveau après hardening
                    Start-Sleep -Seconds 10
                    $newRiskScore = Get-CurrentRiskScore
                    Write-Log "Nouveau score après hardening: $newRiskScore/100"

                    $followUpBody = @"
Hardening automatique exécuté.
Nouveau score de risque: $newRiskScore/100
Rapport mis à jour disponible.
"@

                    Send-AlertEmail -Subject "✅ Hardening Automatique Réussi" -Body $followUpBody
                }
                else {
                    Send-AlertEmail -Subject "❌ Échec du Hardening Automatique" -Body "Le hardening automatique a échoué. Intervention manuelle requise."
                }
            }
        }

        $lastRiskScore = $riskScore

        Write-Log "Prochaine vérification dans $IntervalMinutes minutes..."
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
}

# Gestion des interruptions propre
$global:MonitoringRunning = $true

$handler = {
    Write-Log "Interruption détectée - arrêt propre..."
    $global:MonitoringRunning = $false
}

Register-ObjectEvent -InputObject ([Console]::ReadKey()) -EventName "KeyPressed" -Action $handler | Out-Null

try {
    Start-PortMonitoring
}
catch {
    Write-Log "Erreur fatale: $($_.Exception.Message)" "ERROR"
}
finally {
    Write-Log "=== ARRÊT DE LA SURVEILLANCE ==="
}
