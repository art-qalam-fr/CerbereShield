param(
    [string]$LogFile
)

# Script de vérification des règles de durcissement des ports
# - Liste les règles firewall Block_Port_*
# - Tente une connexion locale sur chaque port bloqué
# - Génère un rapport dans les logs (succès/échec du blocage)

# Auto-élévation : si le script n'est pas lancé en tant qu'administrateur,
# il se relance lui-même avec RunAs (UAC) en conservant les paramètres.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relance du script en mode administrateur..." -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"

    $argsList = @()
    if ($LogFile) { $argsList += "-LogFile `"$LogFile`"" }

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
        try {
            $logDir = Split-Path -Path $LogFile -Parent
            if ($logDir -and -not (Test-Path -Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            Add-Content -Path $LogFile -Value $LogEntry
        } catch {
            Write-Host "[LOG-ERROR] Impossible d'écrire dans le fichier de log '$LogFile' : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Chemin de log par défaut : ..\\..\\logs\\hardening\\port_hardening_verify_YYYYMMDD_HHMMSS.log
if (-not $LogFile) {
    try {
        $projectRoot = Join-Path -Path $PSScriptRoot -ChildPath "..\\.."
        $logsDir     = Join-Path -Path $projectRoot -ChildPath "logs\\hardening"
        if (-not (Test-Path -Path $logsDir)) {
            New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
        }
        $LogFile = Join-Path -Path $logsDir -ChildPath ("port_hardening_verify_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    } catch {
        $LogFile = "port_hardening_verify_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }
}

Write-Log "=== DÉBUT DE LA VÉRIFICATION DU DURCISSEMENT DES PORTS ==="

if (-not (Test-Administrator)) {
    Write-Log "Ce script doit être exécuté en tant qu'administrateur!" "ERROR"
    exit 1
}

# Déterminer une adresse IPv4 locale non-loopback pour simuler un accès réseau
try {
    $localIp = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias '*' `
        | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } `
        | Sort-Object -Property SkipAsSource, AddressState -Descending `
        | Select-Object -First 1
} catch {
    $localIp = $null
}

if (-not $localIp) {
    Write-Log "Impossible de déterminer une adresse IPv4 locale non-loopback. Le test utilisera 127.0.0.1, ce qui NE reflète pas le trafic réseau réel." "WARNING"
    $testComputerName = '127.0.0.1'
} else {
    Write-Log "Adresse IPv4 locale utilisée pour les tests: $($localIp.IPAddress)" "INFO"
    $testComputerName = $localIp.IPAddress
}

try {
    $rules = Get-NetFirewallRule -DisplayName 'Block_Port_*' -ErrorAction SilentlyContinue |
             Get-NetFirewallPortFilter |
             Select-Object LocalPort, Protocol
} catch {
    Write-Log "Erreur lors de la récupération des règles Block_Port_* : $($_.Exception.Message)" "ERROR"
    exit 1
}

if (-not $rules -or $rules.Count -eq 0) {
    Write-Log "Aucune règle Block_Port_* trouvée. Rien à vérifier." "WARNING"
    Write-Log "=== FIN DE LA VÉRIFICATION (AUCUNE RÈGLE) ==="
    exit 0
}

Write-Log "Règles Block_Port_* détectées : $($rules.Count)" "INFO"

$okCount = 0
$failCount = 0

foreach ($rule in $rules) {
    $port = [int]$rule.LocalPort
    $proto = ($rule.Protocol.ToString()).ToUpper()

    Write-Log "Vérification du port $port ($proto) sur $testComputerName..."

    # On ne sait tester de façon fiable qu'en TCP avec Test-NetConnection
    if ($proto -ne 'TCP') {
        Write-Log "Protocole $proto non testé (vérification automatique uniquement pour TCP)." "WARNING"
        continue
    }

    try {
        $result = Test-NetConnection -ComputerName $testComputerName -Port $port -WarningAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            Write-Log "ECHEC: le port $port (TCP) semble TOUJOURS accessible malgré la règle Block_Port_*" "ERROR"
            $failCount++
        } else {
            Write-Log "OK: le port $port (TCP) est effectivement bloqué (connexion échouée)." "INFO"
            $okCount++
        }
    } catch {
        Write-Log "Erreur lors du test de connexion sur le port $port (TCP) : $($_.Exception.Message)" "ERROR"
        $failCount++
    }
}

Write-Log "=== RÉSULTATS DE LA VÉRIFICATION ==="
Write-Log "Ports TCP vérifiés OK: $okCount"
Write-Log "Ports TCP en ECHEC: $failCount"
Write-Log "Log de vérification sauvegardé dans: $LogFile"
Write-Log "=== FIN DU SCRIPT DE VÉRIFICATION ==="
