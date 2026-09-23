using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Net.Http;
using System.Runtime.InteropServices;
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

    // Éléments de menu mis à jour selon l'état courant
    private readonly ToolStripMenuItem _statusItem;
    private readonly ToolStripMenuItem _enableItem;
    private readonly ToolStripMenuItem _disableItem;

    // AUMID explicite : permet à Windows 10/11 d'attribuer les notifications
    // toast à l'application (sinon elles peuvent être avalées/masquées).
    [DllImport("shell32.dll", SetLastError = true)]
    private static extern void SetCurrentProcessExplicitAppUserModelID(
        [MarshalAs(UnmanagedType.LPWStr)] string appID);

    private const string ApiStateUrl = "http://localhost:4050/api/protection/state";
    private const string ApiAlertsUrl = "http://localhost:4050/api/alerts";
    private const string ApiFilterStatusUrl = "http://localhost:4050/api/filter/status";
    private const string ApiFilterStartUrl = "http://localhost:4050/api/filter/start";
    private const string ApiFilterStopUrl = "http://localhost:4050/api/filter/stop";
    private const string DashboardUrl = "http://localhost:4050/";

    public TrayApplication()
    {
        try { SetCurrentProcessExplicitAppUserModelID("Cerbere.SecurityShield"); } catch { }

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

        // Badge coloré en bas à droite : vert = protégé, rouge = arrêté, gris = hors-ligne
        _iconOnlineEnabled = CreateBadgeIcon(appIcon, Color.FromArgb(34, 197, 94));
        _iconOnlineDisabled = CreateBadgeIcon(appIcon, Color.FromArgb(239, 68, 68));
        _iconOffline = CreateBadgeIcon(appIcon, Color.FromArgb(107, 114, 128));

        _notifyIcon = new NotifyIcon
        {
            Icon = _iconOffline,
            Visible = true,
            Text = "Cerbere Security Shield - état inconnu"
        };

        var menu = new ContextMenuStrip();
        _statusItem = new ToolStripMenuItem("⚫ Cerbere : état inconnu")
        {
            Enabled = false,
            Font = new Font(menu.Font, FontStyle.Bold)
        };
        menu.Items.Add(_statusItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Ouvrir le Cerbere Security Shield", null, (_, _) => OpenDashboard());
        _enableItem = (ToolStripMenuItem)menu.Items.Add("🟢 Activer la protection", null, async (_, _) => await SetProtectionAsync(true));
        _disableItem = (ToolStripMenuItem)menu.Items.Add("🔴 Désactiver la protection", null, async (_, _) => await SetProtectionAsync(false));
        menu.Items.Add("Filtrage trackers : on/off", null, async (_, _) => await ToggleTrackerFilterAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Appliquer plan durcissement", null, (_, _) => RunHardeningScript("harden"));
        menu.Items.Add("Appliquer plan libération", null, (_, _) => RunHardeningScript("release"));
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

    /// <summary>Dessine l'icône de l'app avec un point coloré en bas à droite
    /// (vert = protection active, rouge = inactive, gris = backend injoignable).</summary>
    private static Icon CreateBadgeIcon(Icon baseIcon, Color badgeColor)
    {
        var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.Transparent);
            g.DrawIcon(baseIcon, new Rectangle(0, 0, 32, 32));
            using (var brush = new SolidBrush(badgeColor))
                g.FillEllipse(brush, 18, 18, 13, 13);
            using (var pen = new Pen(Color.White, 1.6f))
                g.DrawEllipse(pen, 18, 18, 13, 13);
        }
        // GetHicon alloue un handle non libéré — acceptable pour 3 icônes
        // persistantes vivant aussi longtemps que le processus.
        IntPtr h = bmp.GetHicon();
        bmp.Dispose();
        return Icon.FromHandle(h);
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
                _notifyIcon.Text = "Cerbere Security Shield - protection ACTIVÉE";
                _statusItem.Text = "🟢 Protection activée — vous êtes protégé";
                _enableItem.Enabled = false;
                _disableItem.Enabled = true;
            }
            else
            {
                _notifyIcon.Icon = _iconOnlineDisabled;
                _notifyIcon.Text = "Cerbere Security Shield - protection DÉSACTIVÉE";
                _statusItem.Text = "🔴 Protection désactivée — vous n'êtes pas protégé";
                _enableItem.Enabled = true;
                _disableItem.Enabled = false;
            }
        }
        catch
        {
            _notifyIcon.Icon = _iconOffline;
            _notifyIcon.Text = "Cerbere Security Shield - serveur indisponible";
            _statusItem.Text = "⚫ Cerbere : serveur indisponible";
            _enableItem.Enabled = false;
            _disableItem.Enabled = false;
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

    /// <summary>Applique un plan de durcissement/libération en lançant
    /// security_hardening.ps1 directement dans une console PowerShell cachée
    /// (élevée via UAC si nécessaire) — aucune fenêtre n'apparaît.</summary>
    private void RunHardeningScript(string action)
    {
        try
        {
            string scriptPath = GetFullPath(System.IO.Path.Combine("powershell", "security_hardening.ps1"));
            if (!System.IO.File.Exists(scriptPath))
            {
                throw new Exception($"Fichier introuvable : {scriptPath}");
            }

            bool isElevated = new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{scriptPath}\" -Action \"{action}\"",
            };
            if (isElevated)
            {
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
            }
            else
            {
                // UAC requis : on élève powershell lui-même en mode caché —
                // tous les sous-processus héritent de la console invisible.
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
            }

            Process? p = Process.Start(psi);
            if (p != null)
            {
                p.EnableRaisingEvents = true;
                p.Exited += (s, e) =>
                {
                    _notifyIcon.BalloonTipTitle = "Cerbere Security Shield";
                    _notifyIcon.BalloonTipText = (p.ExitCode == 0)
                        ? (action == "release" ? "Libération des ports effectuée." : "Plan de durcissement appliqué.")
                        : ("Échec du script (code " + p.ExitCode + ")");
                    _notifyIcon.ShowBalloonTip(5000);
                };
            }
        }
        catch (Exception ex)
        {
            _notifyIcon.BalloonTipTitle = "Cerbere Security Shield";
            _notifyIcon.BalloonTipText = "Erreur script : " + ex.Message;
            _notifyIcon.ShowBalloonTip(3000);
        }
    }

    private string GetFullPath(string relativeScriptPath)
    {
        string currentDir = AppDomain.CurrentDomain.BaseDirectory;

        // Mode installé : {app}\scripts\... à côté de WebPortSystray.exe
        string scriptPath = System.IO.Path.Combine(currentDir, "scripts", relativeScriptPath);
        if (System.IO.File.Exists(scriptPath))
        {
            return scriptPath;
        }

        // Mode dev : remonter à la racine du projet selon le layout de build
        // (4 niveaux depuis bin/Debug|Release/net6.0-windows, 6 depuis .../win-x64/publish)
        foreach (var rootDir in new[]
        {
            System.IO.Path.GetFullPath(System.IO.Path.Combine(currentDir, "..", "..", "..", "..")),
            System.IO.Path.GetFullPath(System.IO.Path.Combine(currentDir, "..", "..", "..", "..", "..", "..")),
        })
        {
            string candidate = System.IO.Path.Combine(rootDir, "scripts", relativeScriptPath);
            if (System.IO.File.Exists(candidate))
            {
                return candidate;
            }
            scriptPath = candidate;
        }

        if (!System.IO.File.Exists(scriptPath))
        {
            // Compatibilité : ancien emplacement à la racine du projet
            scriptPath = System.IO.Path.GetFullPath(System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(scriptPath)!, "..", relativeScriptPath));
        }

        if (!System.IO.File.Exists(scriptPath))
        {
            // Fallback si on est lancé autrement
            scriptPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "scripts", relativeScriptPath);
        }

        return scriptPath;
    }
}
