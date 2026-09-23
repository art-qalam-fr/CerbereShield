import { useCallback, useEffect, useState } from 'react'
import './App.css'

type TabId = 'ports' | 'intrusion' | 'filter' | 'adblock' | 'parental' | 'domestic' | 'history' | 'alerts' | 'help' | 'settings'
type LaunchMode = 'browser' | 'desktop' | 'both'
type HealthCheck = { id: string; status: 'pass' | 'warn' | 'fail'; message: string }
type HealthReport = { summary?: { pass?: number; warn?: number; fail?: number }; checks?: HealthCheck[] }
type Alert = { timestamp?: string; message?: string; severity?: number; score?: number }
type Snapshot = { timestamp?: string; risk_score?: number; total_ports?: number; exposed_ports?: number }
type FilterStatus = { enabled?: boolean; running?: boolean; domains_count?: number; blocked_total?: number; error?: string }
type IntrusionDashboard = { stats?: { total_events?: number; banned_ips?: number }; recent_events?: Array<{ timestamp?: string; type?: string; source_ip?: string; severity?: string; details?: string }>; active_bans?: number }
type ScopeStatus = { enabled?: boolean; available?: boolean; pin_set?: boolean; categories?: Record<string, unknown>; domains?: Record<string, unknown> }
type AdblockStats = { enabled_lists?: string[]; domains?: number; blocked_total?: number; lists?: Record<string, unknown> }

type Port = {
  port?: number
  protocol?: string
  local_ip?: string
  risk?: string
  firewall_blocked?: boolean
  process?: { name?: string }
}

const tabs: Array<{ id: TabId; label: string; hint: string }> = [
  { id: 'ports', label: 'Ports Actifs', hint: 'Vue temps réel des ports ouverts sur cette machine.' },
  { id: 'intrusion', label: "Détection d'Intrusion", hint: 'Surveillance des connexions et IP bannies.' },
  { id: 'filter', label: 'Filtrage & Trackers', hint: 'Blocage DNS des trackers et publicités.' },
  { id: 'adblock', label: 'Bloqueur de pub', hint: 'Listes EasyList, AdGuard, OISD et HaGeZi.' },
  { id: 'parental', label: 'Contrôle parental', hint: 'Catégories, horaires et quotas.' },
  { id: 'domestic', label: 'Contrôle domestique', hint: 'Paiements, VPN et contournement DNS.' },
  { id: 'history', label: 'Historique', hint: 'Évolution des snapshots réseau.' },
  { id: 'alerts', label: 'Alertes de Sécurité', hint: 'Journal des événements suspects.' },
  { id: 'help', label: 'Aide', hint: "Guide d'utilisation de Cerbere." },
  { id: 'settings', label: 'Paramètres', hint: "Réglages de l'application." },
]

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: 'no-store', ...init })
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.json() as Promise<T>
}

function App() {
  const [activeTab, setActiveTab] = useState<TabId>('ports')
  const [ports, setPorts] = useState<Port[]>([])
  const [backend, setBackend] = useState<'online' | 'offline'>('offline')
  const [protection, setProtection] = useState(false)
  const [health, setHealth] = useState<HealthReport | null>(null)
  const [healthLoading, setHealthLoading] = useState(false)
  const [portQuery, setPortQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [selectedPort, setSelectedPort] = useState<Port | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [history, setHistory] = useState<Snapshot[]>([])
  const [tabLoading, setTabLoading] = useState(false)
  const [filterStatus, setFilterStatus] = useState<FilterStatus | null>(null)
  const [intrusion, setIntrusion] = useState<IntrusionDashboard | null>(null)
  const [intrusionAction, setIntrusionAction] = useState(false)
  const [adblock, setAdblock] = useState<AdblockStats | null>(null)
  const [parental, setParental] = useState<ScopeStatus | null>(null)
  const [domestic, setDomestic] = useState<ScopeStatus | null>(null)
  const [launchMode, setLaunchMode] = useState<LaunchMode>(() => (localStorage.getItem('cerbere.launch_mode') as LaunchMode) || 'browser')

  const refresh = useCallback(async () => {
    try {
      const [state, snapshot] = await Promise.all([
        api<{ enabled?: boolean }>('/api/protection/state'),
        api<{ ports?: Port[] }>('/api/ports/current'),
      ])
      setProtection(Boolean(state.enabled))
      setPorts(snapshot.ports ?? [])
      setBackend('online')
    } catch {
      setBackend('offline')
    }
  }, [])

  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0)
    const timer = window.setInterval(() => void refresh(), 10000)
    return () => {
      window.clearTimeout(initial)
      window.clearInterval(timer)
    }
  }, [refresh])

  useEffect(() => {
    if (!['alerts', 'history', 'intrusion', 'filter', 'adblock', 'parental', 'domestic'].includes(activeTab)) return
    window.setTimeout(() => setTabLoading(true), 0)
    const load = activeTab === 'alerts'
      ? api<Alert[]>('/api/alerts?limit=50').then(setAlerts)
      : activeTab === 'history'
        ? api<Snapshot[]>('/api/history?limit=50').then(setHistory)
        : activeTab === 'intrusion'
          ? api<IntrusionDashboard>('/api/intrusion/dashboard').then(setIntrusion)
          : activeTab === 'filter'
            ? api<FilterStatus>('/api/filter/status').then(setFilterStatus)
            : activeTab === 'adblock'
              ? api<AdblockStats>('/api/adblock/stats').then(setAdblock)
              : activeTab === 'parental'
                ? api<ScopeStatus>('/api/parental/status').then(setParental)
                : api<ScopeStatus>('/api/domestic/status').then(setDomestic)
    void load.catch(() => {
      if (activeTab === 'alerts') setAlerts([])
      if (activeTab === 'history') setHistory([])
      if (activeTab === 'intrusion') setIntrusion(null)
      if (activeTab === 'filter') setFilterStatus(null)
      if (activeTab === 'adblock') setAdblock(null)
      if (activeTab === 'parental') setParental(null)
      if (activeTab === 'domestic') setDomestic(null)
    }).finally(() => setTabLoading(false))
  }, [activeTab])

  const visiblePorts = ports.filter((port) => {
    const haystack = [port.port, port.protocol, port.local_ip, port.process?.name, port.risk].join(' ').toLowerCase()
    const matchesQuery = haystack.includes(portQuery.toLowerCase())
    const matchesRisk = riskFilter === 'all' || (port.risk ?? 'authorized') === riskFilter
    return matchesQuery && matchesRisk
  })

  async function runHealthcheck() {
    setHealthLoading(true)
    try {
      setHealth(await api<HealthReport>('/api/healthcheck/run', { method: 'POST' }))
    } catch {
      setHealth({ summary: { fail: 1 }, checks: [{ id: 'frontend.api', status: 'fail', message: 'Backend health-check indisponible' }] })
    } finally {
      setHealthLoading(false)
    }
  }

  async function changeLaunchMode(mode: LaunchMode) {
    setLaunchMode(mode)
    localStorage.setItem('cerbere.launch_mode', mode)
    try {
      await api('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ui: { launch_mode: mode } }) })
    } catch {
      // Le prototype conserve le choix local si le backend est indisponible.
    }
  }

  async function postIntrusion(path: string) {
    setIntrusionAction(true)
    try {
      const data = await api<IntrusionDashboard & { message?: string }>(path, { method: 'POST' })
      setIntrusion(data)
    } finally {
      setIntrusionAction(false)
    }
  }

  async function toggleFilter() {
    setIntrusionAction(true)
    try {
      const endpoint = filterStatus?.running ? '/api/filter/stop' : '/api/filter/start'
      setFilterStatus(await api<FilterStatus>(endpoint, { method: 'POST' }))
    } finally {
      setIntrusionAction(false)
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <img src="/img/cerbere_banner.png" alt="Cerbere Security Shield" />
        <div className="header-overlay header-left">
          <h1>Cerbere Security Shield</h1>
          <span className={`backend-status ${backend}`}>{backend === 'online' ? 'Backend opérationnel' : 'Backend indisponible'}</span>
        </div>
        <div className="header-overlay header-right">
          <span className={`protection-badge ${protection ? 'on' : 'off'}`}>{protection ? 'Protection active' : 'Protection inactive'}</span>
          <a href="https://www.grc.com/shieldsup" target="_blank" rel="noreferrer">Tester depuis Internet ↗</a>
        </div>
      </header>

      <nav className="tabs" aria-label="Navigation principale">
        {tabs.map((tab) => (
          <button className={activeTab === tab.id ? 'tab active' : 'tab'} key={tab.id} onClick={() => setActiveTab(tab.id)} title={tab.hint}>
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {activeTab === 'ports' && (
          <section className="panel">
            <div className="panel-heading"><div><h2>Ports actifs</h2><p>Prototype React — données servies par le backend existant.</p></div><button className="primary" onClick={() => void refresh()}>Actualiser</button></div>
            <div className="port-controls"><input value={portQuery} onChange={(event) => setPortQuery(event.target.value)} placeholder="Rechercher processus, port, protocole, IP…" /><select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}><option value="all">Tous les risques</option><option value="critical">Critiques</option><option value="unexpected">Inattendus</option><option value="authorized">Autorisés</option></select></div>
            <div className="table-wrap"><table><thead><tr><th>Port</th><th>Protocole</th><th>Adresse</th><th>Processus</th><th>Risque</th><th>Pare-feu</th><th></th></tr></thead><tbody>
              {visiblePorts.length === 0 ? <tr><td colSpan={7} className="empty">Aucun port correspondant ou backend indisponible.</td></tr> : visiblePorts.map((port, index) => <tr key={`${port.port}-${index}`}><td>{port.port ?? '—'}</td><td>{(port.protocol ?? 'TCP').toUpperCase()}</td><td>{port.local_ip ?? '—'}</td><td>{port.process?.name ?? '—'}</td><td><span className={`risk ${port.risk ?? 'authorized'}`}>{port.risk ?? 'authorized'}</span></td><td>{port.firewall_blocked ? 'Protégé' : 'Non bloqué'}</td><td><button className="inspect" onClick={() => setSelectedPort(port)}>Inspecter</button></td></tr>)}
            </tbody></table></div>
            {selectedPort && <div className="modal-backdrop" onClick={() => setSelectedPort(null)}><div className="inspect-modal" onClick={(event) => event.stopPropagation()}><button className="modal-close" onClick={() => setSelectedPort(null)}>×</button><h2>Détails du port</h2><p><strong>Port :</strong> {selectedPort.port ?? '—'} / {(selectedPort.protocol ?? 'TCP').toUpperCase()}</p><p><strong>Adresse :</strong> {selectedPort.local_ip ?? '—'}</p><p><strong>Processus :</strong> {selectedPort.process?.name ?? '—'}</p><p><strong>État pare-feu :</strong> {selectedPort.firewall_blocked ? 'Protégé' : 'Non bloqué'}</p><div className="modal-links"><a href={selectedPort.port === 0 ? 'https://www.grc.com/port_0.htm' : `http://www.grc.com/port_${selectedPort.port}.htm`} target="_blank" rel="noreferrer">Vérifier ce port sur GRC ↗</a><a href={`https://www.speedguide.net/port.php?port=${selectedPort.port ?? ''}`} target="_blank" rel="noreferrer">SpeedGuide ↗</a></div></div></div>}
          </section>
        )}

        {activeTab === 'intrusion' && (
          <section className="panel"><div className="panel-heading"><div><h2>Détection d'intrusion</h2><p>État et événements du détecteur réel.</p></div><div className="panel-actions"><button className="primary" disabled={intrusionAction} onClick={() => void postIntrusion('/api/intrusion/test')}>Tester la détection</button><button className="secondary" disabled={intrusionAction} onClick={() => void postIntrusion('/api/intrusion/start')}>Démarrer</button></div></div>{tabLoading ? <p className="empty">Chargement…</p> : <><div className="stats-row"><div className="stat-card"><strong>{intrusion?.stats?.total_events ?? 0}</strong><span>Événements</span></div><div className="stat-card"><strong>{intrusion?.active_bans ?? 0}</strong><span>IPs bannies</span></div></div><div className="alert-list">{(intrusion?.recent_events ?? []).slice(0, 20).map((event, index) => <article className="alert-card" key={`${event.timestamp}-${index}`}><div className="alert-card-top"><strong>{event.severity ?? '—'}</strong><time>{event.timestamp ?? '—'}</time></div><p>{event.type} — {event.source_ip} — {event.details}</p></article>)}</div></>}</section>
        )}

        {activeTab === 'filter' && (
          <section className="panel"><div className="panel-heading"><div><h2>Filtrage DNS &amp; Trackers</h2><p>État réel du sinkhole DNS et de WinDivert.</p></div><button className="primary" disabled={intrusionAction} onClick={() => void toggleFilter()}>{filterStatus?.running ? 'Arrêter le filtrage' : 'Démarrer le filtrage'}</button></div>{filterStatus ? <div className="filter-state"><span className={`state-dot ${filterStatus.running ? 'on' : 'off'}`} />{filterStatus.running ? 'Filtrage actif — interception confirmée' : filterStatus.error ? `Erreur : ${filterStatus.error}` : 'Filtrage arrêté'}<div className="stats-row"><div className="stat-card"><strong>{filterStatus.domains_count ?? 0}</strong><span>Domaines chargés</span></div><div className="stat-card"><strong>{filterStatus.blocked_total ?? 0}</strong><span>Requêtes bloquées</span></div></div></div> : <p className="empty">Statut du filtre indisponible.</p>}</section>
        )}

        {activeTab === 'adblock' && <section className="panel"><h2>Bloqueur de publicité</h2><p className="muted">Listes activées et domaines disponibles.</p>{adblock ? <div className="stats-row"><div className="stat-card"><strong>{adblock.enabled_lists?.length ?? 0}</strong><span>Listes activées</span></div><div className="stat-card"><strong>{adblock.domains ?? 0}</strong><span>Domaines</span></div><div className="stat-card"><strong>{adblock.blocked_total ?? 0}</strong><span>Requêtes bloquées</span></div></div> : <p className="empty">Statut du bloqueur indisponible.</p>}</section>}

        {activeTab === 'parental' && <section className="panel"><h2>Contrôle parental</h2><p className="muted">État fourni par le moteur parental. Les actions restent protégées par le PIN.</p><div className="state-summary"><span className={`state-dot ${parental?.enabled ? 'on' : 'off'}`} />{parental?.enabled ? 'Protection parentale active' : 'Protection parentale inactive'}{parental?.pin_set ? ' — PIN configuré' : ' — PIN non configuré'}</div></section>}

        {activeTab === 'domestic' && <section className="panel"><h2>Contrôle domestique</h2><p className="muted">État fourni par le moteur domestique. Les actions restent protégées par le PIN.</p><div className="state-summary"><span className={`state-dot ${domestic?.enabled ? 'on' : 'off'}`} />{domestic?.enabled ? 'Protection domestique active' : 'Protection domestique inactive'}</div></section>}

        {activeTab === 'help' && <section className="panel help-panel"><h2>Aide</h2><p>Cette version React reprend progressivement les parcours de l'interface actuelle.</p><div className="help-box"><strong>Mode Browser/Desktop</strong><br />Le même frontend est prévu pour le navigateur et le futur wrapper Desktop Tauri.</div><div className="help-box"><strong>Limites</strong><br />Les tests de sécurité modifiant le pare-feu nécessitent les privilèges administrateur et restent contrôlés par le backend.</div></section>}

        {activeTab === 'alerts' && (
          <section className="panel"><div className="panel-heading"><div><h2>Alertes de sécurité</h2><p>Journal des événements suspects fourni par le backend.</p></div><button className="primary" onClick={() => setActiveTab('alerts')}>Actualiser</button></div>{tabLoading ? <p className="empty">Chargement…</p> : <div className="alert-list">{alerts.length === 0 ? <p className="empty">Aucune alerte récente.</p> : alerts.map((alert, index) => <article className="alert-card" key={`${alert.timestamp}-${index}`}><div className="alert-card-top"><strong>{alert.severity ?? alert.score ?? '—'}</strong><time>{alert.timestamp ?? '—'}</time></div><p>{alert.message ?? 'Événement de sécurité sans message.'}</p></article>)}</div>}</section>
        )}

        {activeTab === 'history' && (
          <section className="panel"><div className="panel-heading"><div><h2>Historique des snapshots</h2><p>Évolution des états réseau enregistrés localement.</p></div><button className="primary" onClick={() => setActiveTab('history')}>Actualiser</button></div>{tabLoading ? <p className="empty">Chargement…</p> : <div className="table-wrap"><table><thead><tr><th>Date</th><th>Score</th><th>Ports</th><th>Exposés</th></tr></thead><tbody>{history.length === 0 ? <tr><td colSpan={4} className="empty">Aucun snapshot disponible.</td></tr> : history.map((snapshot, index) => <tr key={`${snapshot.timestamp}-${index}`}><td>{snapshot.timestamp ?? '—'}</td><td>{snapshot.risk_score ?? '—'}</td><td>{snapshot.total_ports ?? '—'}</td><td>{snapshot.exposed_ports ?? '—'}</td></tr>)}</tbody></table></div>}</section>
        )}

        {activeTab === 'settings' && (
          <section className="panel settings-panel"><h2>Paramètres</h2><div className="settings-grid"><article className="card"><h3>Mode d'ouverture</h3><label><input type="radio" name="launch-mode" checked={launchMode === 'browser'} onChange={() => void changeLaunchMode('browser')} /> Browser uniquement</label><label><input type="radio" name="launch-mode" checked={launchMode === 'desktop'} onChange={() => void changeLaunchMode('desktop')} /> Desktop uniquement</label><label><input type="radio" name="launch-mode" checked={launchMode === 'both'} onChange={() => void changeLaunchMode('both')} /> Desktop + Browser</label><p className="muted">Choix mémorisé dans le prototype. Le wrapper Desktop sera branché lors de la phase Tauri.</p></article><article className="card"><h3>Vérification de santé</h3><p className="muted">Contrôle local non destructif du backend, de l'intrusion, du DNS et des chemins installés.</p><button className="primary" onClick={() => void runHealthcheck()} disabled={healthLoading}>{healthLoading ? 'Vérification…' : 'Lancer le test de santé'}</button>{health && <div className="health-report"><strong>{health.summary?.pass ?? 0} PASS · {health.summary?.warn ?? 0} WARN · {health.summary?.fail ?? 0} FAIL</strong>{health.checks?.map((check) => <div className={`health-line ${check.status}`} key={check.id}>{check.status.toUpperCase()} — {check.id} : {check.message}</div>)}</div>}</article></div></section>
        )}

      </main>
    </div>
  )
}

export default App
