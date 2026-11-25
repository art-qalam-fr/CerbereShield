# Script de vérification des services actifs avant hardening
# À exécuter avant le hardening pour éviter les interruptions

param(
    [string]$OutputFile = "service_check_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# Auto-élévation : si le script n'est pas lancé en tant qu'administrateur,
# il se relance lui-même avec RunAs (UAC) en conservant les paramètres.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relance du script en mode administrateur..." -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"

    $argsList = @()
    if ($OutputFile) { $argsList += "-OutputFile `"$OutputFile`"" }

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

function Write-Report {
    param([string]$Message)
    Write-Host $Message
    Add-Content -Path $OutputFile -Value $Message
}

function Get-ActiveServices {
    Write-Report "=== VERIFICATION DES SERVICES ACTIFS ==="
    Write-Report "Date: $(Get-Date)"
    Write-Report ""

    # Services Windows critiques
    Write-Report "=== SERVICES WINDOWS ==="
    try {
        $services = Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.Name -notlike "*sysmon*" -and $_.Name -notlike "*spp*" } | Select-Object -First 10
        foreach ($service in $services) {
            Write-Report "$($service.Name): $($service.DisplayName) - $($service.Status)"
        }
    } catch {
        Write-Report "Erreur lors de la récupération des services: $($_.Exception.Message)"
    }
    Write-Report ""

    # Processus écoutant sur des ports
    Write-Report "=== PROCESSUS ECOUTANT SUR LES PORTS ==="
    try {
        $netstatOutput = netstat -ano 2>$null
        $listeningLines = $netstatOutput | Select-String "LISTENING"

        if ($listeningLines.Count -eq 0) {
            Write-Report "Aucun port en ecoute detecte ou erreur netstat"
        } else {
            foreach ($line in $listeningLines) {
                $parts = $line -split '\s+'
                if ($parts.Length -ge 5) {
                    $localAddress = $parts[1]
                    $processId = $parts[4]

                    if ($localAddress -match '(.+):(\d+)') {
                        $port = $matches[2]
                        try {
                            $process = Get-Process -Id ([int]$processId) -ErrorAction SilentlyContinue
                            $processName = if ($process) { $process.Name } else { "Unknown" }
                            Write-Report "Port $port (PID: $processId): $processName"
                        } catch {
                            Write-Report "Port $port (PID: $processId): Processus introuvable"
                        }
                    }
                }
            }
        }
    } catch {
        Write-Report "Erreur lors de l'execution de netstat: $($_.Exception.Message)"
    }
    Write-Report ""

    # Verification des ports MCP potentiels
    Write-Report "=== VERIFICATION PORTS MCP ==="
    $mcpPorts = @(3000, 5000, 4050, 8080, 9000)
    foreach ($port in $mcpPorts) {
        try {
            $connection = Test-NetConnection -ComputerName localhost -Port $port -WarningAction SilentlyContinue
            if ($connection.TcpTestSucceeded) {
                Write-Report "OK Port $port : ACTIF (potentiellement MCP ou service web)"
            } else {
                Write-Report "XX Port $port : INACTIF"
            }
        } catch {
            Write-Report "? Port $port : Erreur de test - $($_.Exception.Message)"
        }
    }
    Write-Report ""

    # Recommandations
    Write-Report "=== RECOMMANDATIONS ==="
    Write-Report "Avant d'executer le hardening, verifiez que :"
    Write-Report "1. Tous vos services critiques sont listes ci-dessus"
    Write-Report "2. Les ports MCP (3000, 5000, 4050, 8080) sont actifs si utilises"
    Write-Report "3. Aucun service essentiel n'est arrete"
    Write-Report ""
    Write-Report "Si un service manque, il pourrait etre bloque par le hardening."
    Write-Report "Ajoutez ses ports a la variable AllowedPorts dans security_hardening.ps1"
    Write-Report ""

    Write-Report "=== FIN DU RAPPORT ==="
}

# Execution
Get-ActiveServices
Write-Report "Rapport sauvegarde dans: $OutputFile"
