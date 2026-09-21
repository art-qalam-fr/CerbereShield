using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WebPortSystray;

public class TrayApplication : ApplicationContext
{
    private readonly NotifyIcon _notifyIcon;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly System.Windows.Forms.Timer _alertTimer;
    private readonly HttpClient _httpClient;
    private readonly HashSet<string> _seenAlertKeys = new();
    private readonly Dictionary<string, DateTime> _messageCooldown = new();
    private static readonly TimeSpan MessageCooldown = TimeSpan.FromMinutes(10);
    private bool _alertsInitialized;

    private readonly Icon _iconOnlineEnabled;
    private readonly Icon _iconOnlineDisabled;
    private readonly Icon _iconOffline;

    private const string ApiStateUrl = "http://localhost:4050/api/protection/state";
    private const string ApiAlertsUrl = "http://localhost:4050/api/alerts";
    private const string ApiFilterStatusUrl = "http://localhost:4050/api/filter/status";
    private const string ApiFilterStartUrl = "http://localhost:4050/api/filter/start";
    private const string ApiFilterStopUrl = "http://localhost:4050/api/filter/stop";
    private const string DashboardUrl = "http://localhost:4050/";

    public TrayApplication()
    {
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(3)
        };

        // Chargement de l'icône depuis cerbere.ico à côté de l'exe avec fallback SystemIcons.Shield si absent
        Icon appIcon;
        try
        {
            string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cerbere.ico");
            if (!System.IO.File.Exists(iconPath))
            {
                iconPath = AppDomain.CurrentDomain.BaseDirectory + "cerbere.ico";
            }
            appIcon = System.IO.File.Exists(iconPath) ? new Icon(iconPath) : SystemIcons.Shield;
        }
        catch
        {
            appIcon = SystemIcons.Shield;
        }

        _iconOnlineEnabled = appIcon;
        _iconOnlineDisabled = appIcon;
        _iconOffline = appIcon;

        _notifyIcon = new NotifyIcon
        {
            Icon = _iconOffline,
            Visible = true,
            Text = "Web Port Protection - état inconnu"
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add("Ouvrir le Cerbere Security Shield", null, (_, _) => OpenDashboard());
        menu.Items.Add("Activer la protection", null, async (_, _) => await SetProtectionAsync(true));
        menu.Items.Add("Désactiver la protection", null, async (_, _) => await SetProtectionAsync(false));
        menu.Items.Add("Filtrage trackers : on/off", null, async (_, _) => await ToggleTrackerFilterAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Appliquer plan durcissement", null, (_, _) => RunScript("appliquer_plan_durcissement_ports.bat"));
        menu.Items.Add("Appliquer plan libération", null, (_, _) => RunScript("appliquer_plan_liberation_ports.bat"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Quitter l'application", null, (_, _) => ExitApplication());

        _notifyIcon.ContextMenuStrip = menu;

        _timer = new System.Windows.Forms.Timer
        {
            Interval = 10000
        };
        _timer.Tick += async (_, _) => await RefreshStateAsync();
        _timer.Start();

        _alertTimer = new System.Windows.Forms.Timer
        {
            Interval = 15000
        };
        _alertTimer.Tick += async (_, _) => await CheckAlertsAsync();
        _alertTimer.Start();

        // Premier rafraîchissement immédiat
        _ = RefreshStateAsync();
        _ = CheckAlertsAsync();
    }

    private void OpenDashboard()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = DashboardUrl,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _notifyIcon.BalloonTipTitle = "Cerbere Security Shield";
            _notifyIcon.BalloonTipText = "Impossible d'ouvrir le navigateur : " + ex.Message;
            _notifyIcon.ShowBalloonTip(3000);
        }
    }

    private async Task SetProtectionAsync(bool enabled)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new { enabled });
            using var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
            using var response = await _httpClient.PostAsync(ApiStateUrl, content);
            response.EnsureSuccessStatusCode();
            await RefreshStateAsync();
        }
        catch (Exception ex)
        {
            _notifyIcon.Icon = _iconOffline;
            _notifyIcon.Text = "Web Port Protection - serveur indisponible";
            _notifyIcon.BalloonTipTitle = "Web Port Protection";
            _notifyIcon.BalloonTipText = "Erreur lors de la mise à jour de l'état : " + ex.Message;
            _notifyIcon.ShowBalloonTip(3000);
        }
    }

    private async Task ToggleTrackerFilterAsync()
    {
        try
        {
            using var response = await _httpClient.GetAsync(ApiFilterStatusUrl);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(json);
            bool isRunningOrEnabled = false;
            if (doc.RootElement.TryGetProperty("running", out var runningProp) && runningProp.GetBoolean())
            {
                isRunningOrEnabled = true;
            }
            else if (doc.RootElement.TryGetProperty("enabled", out var enabledProp) && enabledProp.GetBoolean())
            {
                isRunningOrEnabled = true;
            }

            if (isRunningOrEnabled)
            {
                using var stopRes = await _httpClient.PostAsync(ApiFilterStopUrl, null);
                stopRes.EnsureSuccessStatusCode();
                _notifyIcon.BalloonTipTitle = "Filtrage trackers";
                _notifyIcon.BalloonTipText = "Filtrage trackers désactivé";
                _notifyIcon.ShowBalloonTip(3000);
            }
            else
            {
                using var startRes = await _httpClient.PostAsync(ApiFilterStartUrl, null);
                startRes.EnsureSuccessStatusCode();
                _notifyIcon.BalloonTipTitle = "Filtrage trackers";
                _notifyIcon.BalloonTipText = "Filtrage trackers activé";
                _notifyIcon.ShowBalloonTip(3000);
            }
        }
        catch (Exception ex)
        {
            _notifyIcon.BalloonTipTitle = "Filtrage trackers";
            _notifyIcon.BalloonTipText = "Erreur filtrage trackers : " + ex.Message;
            _notifyIcon.ShowBalloonTip(3000);
        }
    }

    private async Task RefreshStateAsync()
    {
        try
        {
            using var response = await _httpClient.GetAsync(ApiStateUrl);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(json);
            bool enabled = doc.RootElement.TryGetProperty("enabled", out var enabledProp) && enabledProp.GetBoolean();

            if (enabled)
            {
                _notifyIcon.Icon = _iconOnlineEnabled;
                _notifyIcon.Text = "Web Port Protection - ACTIVÉE";
            }
            else
            {
                _notifyIcon.Icon = _iconOnlineDisabled;
                _notifyIcon.Text = "Web Port Protection - DÉSACTIVÉE";
            }
        }
        catch
        {
            _notifyIcon.Icon = _iconOffline;
            _notifyIcon.Text = "Web Port Protection - serveur indisponible";
        }
    }

    private async Task CheckAlertsAsync()
    {
        try
        {
            using var response = await _httpClient.GetAsync(ApiAlertsUrl);
            if (!response.IsSuccessStatusCode)
            {
                return;
            }

            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            var items = new List<JsonElement>();
            foreach (var elem in doc.RootElement.EnumerateArray())
            {
                items.Add(elem.Clone());
            }

            // Inverser pour traiter les alertes de la plus ancienne à la plus récente
            items.Reverse();

            // Au premier poll réussi : seeding initial sans afficher de balloon tips
            if (!_alertsInitialized)
            {
                foreach (var alert in items)
                {
                    string key = GetAlertKey(alert);
                    if (!string.IsNullOrWhiteSpace(key))
                    {
                        _seenAlertKeys.Add(key);
                    }
                }
                _alertsInitialized = true;
                return;
            }

            int balloonsShown = 0;
            const int maxBalloonsPerPoll = 3;

            foreach (var alert in items)
            {
                string key = GetAlertKey(alert);
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }

                if (_seenAlertKeys.Add(key))
                {
                    // Cooldown par message : le backend déduplique déjà, mais
                    // une alerte ré-émise (nouveau timestamp = nouvelle clé)
                    // ne doit pas re-afficher de balloon si le même message a
                    // été montré il y a moins de 10 minutes.
                    string message = alert.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? "" : "";
                    if (!string.IsNullOrWhiteSpace(message)
                        && _messageCooldown.TryGetValue(message, out var lastShown)
                        && (DateTime.UtcNow - lastShown) < MessageCooldown)
                    {
                        continue;
                    }

                    if (balloonsShown < maxBalloonsPerPoll)
                    {
                        string severity = alert.TryGetProperty("severity", out var sevProp) ? sevProp.GetString() ?? "" : "";
                        int riskScore = alert.TryGetProperty("risk_score", out var scoreProp) && scoreProp.TryGetInt32(out var s) ? s : 0;

                        bool isCritical = severity.Equals("critical", StringComparison.OrdinalIgnoreCase) || riskScore >= 80;
                        ToolTipIcon tipIcon = isCritical ? ToolTipIcon.Error : ToolTipIcon.Warning;

                        string tipText = !string.IsNullOrWhiteSpace(message) ? message : "Alerte de sécurité détectée.";
                        _notifyIcon.ShowBalloonTip(4000, "Security Sheeld - Alerte", tipText, tipIcon);
                        balloonsShown++;
                        if (!string.IsNullOrWhiteSpace(message))
                        {
                            _messageCooldown[message] = DateTime.UtcNow;
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignorer silencieusement si l'API est down
        }
    }

    private static string GetAlertKey(JsonElement alert)
    {
        string id = alert.TryGetProperty("id", out var idProp) ? idProp.GetRawText() : "";
        string timestamp = alert.TryGetProperty("timestamp", out var tsProp) ? tsProp.GetString() ?? "" : "";
        string message = alert.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? "" : "";

        return !string.IsNullOrEmpty(id) ? id : $"{timestamp}_{message}";
    }

    private static string? PromptForPin(string prompt)
    {
        using var form = new Form
        {
            Text = "PIN parental requis",
            Width = 420,
            Height = 190,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterScreen,
            MaximizeBox = false,
            MinimizeBox = false,
            TopMost = true,
        };
        var label = new Label { Left = 12, Top = 12, Width = 380, Height = 56, Text = prompt };
        var input = new TextBox { Left = 12, Top = 70, Width = 380, UseSystemPasswordChar = true };
        var ok = new Button { Text = "Valider", Left = 232, Width = 75, Top = 104, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Annuler", Left = 317, Width = 75, Top = 104, DialogResult = DialogResult.Cancel };
        form.Controls.AddRange(new Control[] { label, input, ok, cancel });
        form.AcceptButton = ok;
        form.CancelButton = cancel;
        return form.ShowDialog() == DialogResult.OK ? input.Text : null;
    }

    private async void ExitApplication()
    {
        var confirm = MessageBox.Show(
            "Quitter Cerbere Security Shield ?\n\nLa surveillance des ports, la détection d'intrusion et le filtrage DNS seront arrêtés.",
            "Cerbere Security Shield",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (confirm != DialogResult.Yes)
        {
            return;
        }

        _timer.Stop();
        _timer.Dispose();
        _alertTimer.Stop();
        _alertTimer.Dispose();

        // Demander l'arrêt complet du backend (surveillance + filtrage DNS).
        // Si le contrôle parental/domestique est actif, le backend exige le PIN
        // parental (403) : on le demande, sinon seule l'icône se ferme.
        try
        {
            var response = await _httpClient.PostAsync("http://localhost:4050/api/shutdown", null);
            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                string? pin = PromptForPin(
                    "Protection active.\n\nEntrez le PIN parental pour arrêter complètement l'application.\n(Annuler ferme uniquement cette icône — la protection continue en arrière-plan.)");
                if (pin == null)
                {
                    // Quitter « en surface » : le backend continue de filtrer.
                    _notifyIcon.Visible = false;
                    _notifyIcon.Dispose();
                    _httpClient.Dispose();
                    Application.Exit();
                    return;
                }

                var content = new StringContent(
                    JsonSerializer.Serialize(new { pin }),
                    System.Text.Encoding.UTF8, "application/json");
                response = await _httpClient.PostAsync("http://localhost:4050/api/shutdown", content);
                if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    MessageBox.Show(
                        "PIN incorrect ou verrouillé. L'application reste active.",
                        "Cerbere Security Shield",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    // Relancer les timers : l'icône reste en place.
                    _timer.Start();
                    _alertTimer.Start();
                    return;
                }
            }
        }
        catch
        {
            // Backend déjà arrêté ou injoignable — on quitte quand même
        }

        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _httpClient.Dispose();
        Application.Exit();
    }

    private void RunScript(string scriptName)
    {
        try
        {
            string scriptPath = GetFullPath(scriptName);
            if (!System.IO.File.Exists(scriptPath))
            {
                throw new Exception($"Fichier introuvable : {scriptPath}");
            }

            bool isElevated = new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

            if (isElevated)
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c \"" + scriptPath + "\" -hidden -q",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process? p = Process.Start(psi);
                if (p != null)
                {
                    p.EnableRaisingEvents = true;
                    p.Exited += (s, e) =>
                    {
                        _notifyIcon.BalloonTipTitle = "Security Sheeld";
                        _notifyIcon.BalloonTipText = (p.ExitCode == 0)
                            ? (scriptName.Contains("liberation") ? "Liberation des ports effectuee." : "Plan de durcissement applique.")
                            : ("Echec du script (code " + p.ExitCode + ")");
                        _notifyIcon.ShowBalloonTip(5000);
                    };
                }
            }
            else
            {
                // Lancer le .bat en tant qu'administrateur (UAC)
                // Le .bat se chargera de se cacher.
                var psi = new ProcessStartInfo
                {
                    FileName = scriptPath,
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(psi);
            }
        }
        catch (Exception ex)
        {
            _notifyIcon.BalloonTipTitle = "Web Port Protection";
            _notifyIcon.BalloonTipText = "Erreur script : " + ex.Message;
            _notifyIcon.ShowBalloonTip(3000);
        }
    }

    private string GetFullPath(string scriptName)
    {
        string currentDir = AppDomain.CurrentDomain.BaseDirectory;
        // Retourner à la racine du projet depuis systray_client/bin/Release/net6.0-windows/win-x64/publish/
        string rootDir = System.IO.Path.GetFullPath(System.IO.Path.Combine(currentDir, "..", "..", "..", "..", "..", ".."));

        // Les scripts utilitaires vivent dans le dossier scripts/ à la racine du projet
        string scriptPath = System.IO.Path.Combine(rootDir, "scripts", scriptName);

        if (!System.IO.File.Exists(scriptPath))
        {
            // Compatibilité : ancien emplacement à la racine du projet
            scriptPath = System.IO.Path.Combine(rootDir, scriptName);
        }

        if (!System.IO.File.Exists(scriptPath))
        {
            // Fallback si on est lancé autrement
            scriptPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "scripts", scriptName);
        }

        return scriptPath;
    }
}
