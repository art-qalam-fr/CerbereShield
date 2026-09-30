import { useCallback, useEffect, useRef, useState } from 'react'
import { API_BASE, getLanguage, initI18n, setLanguage, useI18n } from './i18n'
import './App.css'

type TabId = 'ports' | 'intrusion' | 'filter' | 'adblock' | 'parental' | 'domestic' | 'history' | 'alerts' | 'help' | 'settings' | 'about'
type HealthCheck = { id: string; status: 'pass' | 'warn' | 'fail'; message: string }
type HealthReport = { summary?: { pass?: number; warn?: number; fail?: number }; checks?: HealthCheck[] }
type Alert = { id?: string | number; timestamp?: string; message?: string; severity?: number; score?: number; risk_score?: number; pid?: number | string; process?: string | { name?: string; exe?: string }; port?: number | string }
type AlertInspectData = { notFound?: boolean; networkError?: boolean; exe_path?: string; sha256?: string; reputation?: string; signature?: string; links?: { virustotal_hash?: string } }
type SettingsForm = {
  uiLanguage: string
  launchMode: string
  accessEnabled: boolean
  accessMethod: string
  appPassword: string
  scanInterval: string
  criticalPorts: string
  allowedPorts: string
  allowedProc: string
  filterAutostart: boolean
  remoteWhitelist: boolean
  grace: string
  listsAutoUpdate: boolean
  extEnabled: boolean
  minSev: string
  alertEmail: string
  webhook: string
  smtpHost: string
  smtpPort: string
  smtpUser: string
  smtpPass: string
}
type ListStatusEntry = { name?: string; enabled?: boolean; domains_loaded?: number; last_update?: string; status?: string; count?: number; last_updated?: string; source?: string }
type ListsStatus = { adblock?: Record<string, ListStatusEntry>; parental?: Record<string, ListStatusEntry> }
type Snapshot = { timestamp?: string; risk_score?: number; ports?: unknown[]; total_ports?: number; exposed_ports?: number }
type FilterStatus = { enabled?: boolean; running?: boolean; domains_count?: number; blocked_total?: number; error?: string }
type FilterStats = { queries_total?: number; blocked_total?: number; domains_count?: number; top_domains?: Array<{ domain?: string; count?: number } | [string, number]> }
type BlockedDomain = { domain?: string; count?: number; sources?: string[]; rule?: string; first_seen?: string; last_seen?: string; whitelisted?: boolean; matched_domain?: string }
type FilterWhitelist = { defaults?: string[]; custom?: string[]; disabled_defaults?: string[] }
type DomainEnrich = { rdap?: { available?: boolean; registrar?: string; created?: string }; urlhaus?: { available?: boolean; listed?: boolean; url_count?: number }; dns?: { available?: boolean; ips?: string[] }; error?: string }
type IntrusionDashboard = { statistics?: { total_events?: number; banned_ips?: number; unique_ips?: number; high_severity?: number; critical_severity?: number }; recent_events?: Array<{ timestamp?: string; type?: string; source_ip?: string; severity?: string; details?: string; target_service?: string }>; active_bans?: number; top_attacks?: Array<{ type?: string; count?: number }> }
type BannedIp = { ip?: string; ip_address?: string; reason?: string; attempt_count?: number; ban_time?: string; unban_time?: string; active?: boolean }
type IntrusionStatus = { running?: boolean; active_bans?: number }
type PcRule = { mode?: 'blocked' | 'window' | 'quota'; quota_minutes?: number; windows?: [string, string][] }
type ScopeStatus = { enabled?: boolean; available?: boolean; pin_set?: boolean; categories?: Record<string, PcRule>; domains?: Record<string, PcRule>; quotas?: Record<string, { used?: number; quota?: number }>; lists?: Record<string, { count?: number; source?: string }> }
type PcJournalItem = { domain?: string; count?: number; rule?: string; reason?: string; last_seen?: string; matched_domain?: string }
type PcCatDraft = { enabled: boolean; mode: 'blocked' | 'window' | 'quota'; quota: number; windows: [string, string][] }

const PARENTAL_CATS: Array<[string, string]> = [
  ['adult', 'pc.cat.adult'],
  ['gambling', 'pc.cat.gambling'],
  ['drugs', 'pc.cat.drugs'],
  ['scam', 'pc.cat.scam'],
  ['malware', 'pc.cat.malware'],
  ['social_facebook', 'pc.cat.social_facebook'],
  ['social_twitter', 'pc.cat.social_twitter'],
  ['social_tiktok', 'pc.cat.social_tiktok'],
  ['social_youtube', 'pc.cat.social_youtube'],
  ['social_whatsapp', 'pc.cat.social_whatsapp'],
]
const PC_MODE_LABELS: Record<string, string> = { blocked: 'pc.mode_short.blocked', window: 'pc.mode_short.window', quota: 'pc.mode_short.quota' }
type PcScope = 'parental' | 'domestic'
const PC_APIS: Record<PcScope, string> = { parental: '/api/parental', domestic: '/api/domestic' }
const DOMESTIC_CATS: Array<[string, string]> = [
  ['payment', 'pc.cat.payment'],
  ['doh_bypass', 'pc.cat.doh_bypass'],
  ['vpn', 'pc.cat.vpn'],
]
const PC_CATS: Record<PcScope, Array<[string, string]>> = { parental: PARENTAL_CATS, domestic: DOMESTIC_CATS }
const COOKIE_BROWSER_LABELS: Record<string, string> = { chrome: 'Google Chrome', edge: 'Microsoft Edge', firefox: 'Mozilla Firefox' }
const HELP_SECTIONS: Array<[string, string]> = [
  ['help-welcome', 'help.nav.welcome'],
  ['help-risk', 'help.nav.risk'],
  ['help-port', 'help.nav.port'],
  ['help-broken', 'help.nav.broken'],
  ['help-filter', 'help.nav.filter'],
  ['help-parental', 'help.nav.parental'],
  ['help-plans', 'help.nav.plans'],
  ['help-ai', 'help.nav.ai'],
  ['help-glossary', 'help.nav.glossary'],
  ['help-links', 'help.nav.links'],
  ['help-faq', 'help.nav.faq'],
  ['help-liability', 'help.nav.liability'],
]
type CookieFinding = { browser?: string; profile?: string; host_key?: string; cookie_name?: string; matched_domain?: string }
type AdblockStats = { available?: boolean; enabled_lists?: string[]; running?: boolean; blocked_domains?: number; blocked_total?: number; domains?: number; scheduler?: { running?: boolean; last_run?: { finished_at?: string } } }
type AdblockList = { enabled?: boolean; name?: string; description?: string; license?: string; domains_loaded?: number; file_size_kb?: number; last_update?: string; status?: string }
type AdblockListsResponse = { available?: boolean; lists?: Record<string, AdblockList> }

const LIST_STATUS_STYLES: Record<string, { label: string; bg: string; fg: string }> = {
  ok: { label: 'lists.st.ok', bg: '#14532d', fg: '#bbf7d0' },
  cached: { label: 'lists.st.cached', bg: '#14532d', fg: '#bbf7d0' },
  stale: { label: 'lists.st.stale', bg: '#451a03', fg: '#fde68a' },
  missing: { label: 'lists.st.missing', bg: '#1f2937', fg: '#9ca3af' },
  error: { label: 'lists.st.error', bg: '#7f1d1d', fg: '#fecaca' },
}

const HEALTH_STATUS_LABELS: Record<string, string> = { pass: 'health.pass', warn: 'health.warn', fail: 'health.fail' }

const NUM_LOCALES: Record<string, string> = { fr: 'fr-FR', en: 'en-US', de: 'de-DE', es: 'es-ES' }
function fmtNum(n: number): string { return n.toLocaleString(NUM_LOCALES[getLanguage()] ?? 'fr-FR') }

const COOKIE_STATUS_LABELS: Record<string, string> = {
  ok: 'cookies.st.ok', locked: 'cookies.st.locked', inaccessible: 'cookies.st.inaccessible', partial: 'cookies.st.partial', error: 'cookies.st.error',
}

type Port = {
  port?: number
  protocol?: string
  proto?: string
  local_ip?: string
  ip?: string
  state?: string
  pid?: number
  username?: string
  sha256?: string
  risk?: string
  firewall_blocked?: boolean
  process?: { name?: string; exe?: string; cmdline?: string | string[]; pid?: number; username?: string; sha256?: string }
}

const tabs: Array<{ id: TabId; labelKey: string; hintKey: string }> = [
  { id: 'ports', labelKey: 'tabs.ports', hintKey: 'tabs.ports.title' },
  { id: 'intrusion', labelKey: 'tabs.intrusion', hintKey: 'tabs.intrusion.title' },
  { id: 'filter', labelKey: 'tabs.filter', hintKey: 'tabs.filter.title' },
  { id: 'adblock', labelKey: 'tabs.adblock', hintKey: 'tabs.adblock.title' },
  { id: 'parental', labelKey: 'tabs.parental', hintKey: 'tabs.parental.title' },
  { id: 'domestic', labelKey: 'tabs.domestic', hintKey: 'tabs.domestic.title' },
  { id: 'history', labelKey: 'tabs.history', hintKey: 'tabs.history.title' },
  { id: 'alerts', labelKey: 'tabs.alerts', hintKey: 'tabs.alerts.title' },
  { id: 'help', labelKey: 'tabs.help', hintKey: 'tabs.help.title' },
  { id: 'settings', labelKey: 'tabs.settings', hintKey: 'tabs.settings.title' },
  { id: 'about', labelKey: 'tabs.about', hintKey: 'tabs.about.title' },
]

let unauthorizedHandler: (() => void) | null = null

// Sessions applicatives : cookie en même-origine (navigateur), en-têtes
// X-Cerbere-* en cross-origin (shell desktop Tauri — tauri.localhost).
const SESSION_TOKEN_KEY = 'cerbere_session_token'
const PARENTAL_TOKEN_KEY = 'cerbere_parental_token'

function sessionHeaders(): Record<string, string> {
  const headers: Record<string, string> = {}
  const session = localStorage.getItem(SESSION_TOKEN_KEY)
  const parental = localStorage.getItem(PARENTAL_TOKEN_KEY)
  if (session) headers['X-Cerbere-Session'] = session
  if (parental) headers['X-Cerbere-Parental'] = parental
  return headers
}

function mergeHeaders(init?: RequestInit): Record<string, string> {
  const extra = init?.headers
  const plain: Record<string, string> = extra instanceof Headers
    ? Object.fromEntries(extra.entries())
    : { ...(extra as Record<string, string> | undefined) }
  return { ...sessionHeaders(), ...plain }
}

function notifyUnauthorized(path: string, status: number) {
  if (status === 401 && !path.includes('/api/unlock') && !path.includes('/api/parental/verify')) {
    localStorage.removeItem(SESSION_TOKEN_KEY)
    unauthorizedHandler?.()
  }
}

// Shell desktop Tauri : la webview n'ouvre ni target="_blank" ni
// window.open vers l'extérieur — on délègue à la commande Rust open_url.
const IS_TAURI = Boolean((window as unknown as { __TAURI__?: unknown }).__TAURI__)

function openExternal(url: string) {
  if (IS_TAURI) {
    const invoke = (window as unknown as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: Record<string, unknown>) => void } } }).__TAURI__?.core?.invoke
    if (invoke) { invoke('open_url', { url }); return }
  }
  window.open(url, '_blank', 'noopener,noreferrer')
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { cache: 'no-store', credentials: 'include', ...init, headers: mergeHeaders(init) })
  notifyUnauthorized(path, response.status)
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.json() as Promise<T>
}

function App() {
  const { t } = useI18n()
  const [activeTab, setActiveTab] = useState<TabId>('ports')
  const [ports, setPorts] = useState<Port[]>([])
  const [backend, setBackend] = useState<'online' | 'offline'>('offline')
  const [protection, setProtection] = useState(false)
  const [riskScore, setRiskScore] = useState<number | null>(null)
  const [snapshotTs, setSnapshotTs] = useState('')
  const [health, setHealth] = useState<HealthReport | null>(null)
  const [healthLoading, setHealthLoading] = useState(false)
  const [portQuery, setPortQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [selectedPort, setSelectedPort] = useState<Port | null>(null)
  const [inspectResult, setInspectResult] = useState<Record<string, unknown> | null>(null)
  const [inspectError, setInspectError] = useState('')
  const [inspectLoading, setInspectLoading] = useState(false)
  const [selectedKeys, setSelectedKeys] = useState<Record<string, boolean>>({})
  const [planMessage, setPlanMessage] = useState('')
  const [portsStatus, setPortsStatus] = useState('')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [history, setHistory] = useState<Snapshot[]>([])
  const [tabLoading, setTabLoading] = useState(false)
  const [filterStatus, setFilterStatus] = useState<FilterStatus | null>(null)
  const [filterStats, setFilterStats] = useState<FilterStats | null>(null)
  const [blockedDomains, setBlockedDomains] = useState<BlockedDomain[]>([])
  const [filterWhitelist, setFilterWhitelist] = useState<FilterWhitelist | null>(null)
  const [filterDomainInput, setFilterDomainInput] = useState('')
  const [filterSearch, setFilterSearch] = useState('')
  const [selectedDomain, setSelectedDomain] = useState<BlockedDomain | null>(null)
  const [domainDetail, setDomainDetail] = useState<DomainEnrich | null>(null)
  const [domainEnriching, setDomainEnriching] = useState(false)
  const [intrusion, setIntrusion] = useState<IntrusionDashboard | null>(null)
  const [intrusionStatus, setIntrusionStatus] = useState<IntrusionStatus | null>(null)
  const [bannedIps, setBannedIps] = useState<BannedIp[]>([])
  const [whitelistIps, setWhitelistIps] = useState<string[]>([])
  const [whitelistInput, setWhitelistInput] = useState('')
  const [intrusionAction, setIntrusionAction] = useState(false)
  const [adblock, setAdblock] = useState<AdblockStats | null>(null)
  const [adblockLists, setAdblockLists] = useState<AdblockListsResponse | null>(null)
  const [adblockHint, setAdblockHint] = useState('')
  const [adblockHintTone, setAdblockHintTone] = useState<'muted' | 'ok' | 'warn' | 'err'>('muted')
  const [adblockUpdating, setAdblockUpdating] = useState<string | null>(null)
  const [parental, setParental] = useState<ScopeStatus | null>(null)
  const [parentalJournal, setParentalJournal] = useState<PcJournalItem[] | null>(null)
  const [parentalHint, setParentalHint] = useState('')
  const [pcRulesStatus, setPcRulesStatus] = useState('')
  const [pcRulesTone, setPcRulesTone] = useState<'muted' | 'ok' | 'err'>('muted')
  const [pinCardOpen, setPinCardOpen] = useState(false)
  const [pinOld, setPinOld] = useState('')
  const [pinNew, setPinNew] = useState('')
  const [pinConfirm, setPinConfirm] = useState('')
  const [pinMsg, setPinMsg] = useState('')
  const [pinMsgOk, setPinMsgOk] = useState(false)
  const [pinModalOpen, setPinModalOpen] = useState(false)
  const [pinInput, setPinInput] = useState('')
  const [pinError, setPinError] = useState('')
  const [pcDraftCats, setPcDraftCats] = useState<Record<string, PcCatDraft>>({})
  const [pcDraftDomains, setPcDraftDomains] = useState<Record<string, PcRule>>({})
  const [pcDomInput, setPcDomInput] = useState('')
  const [pcDomMode, setPcDomMode] = useState<'blocked' | 'window' | 'quota'>('blocked')
  const [pcDomQuota, setPcDomQuota] = useState(60)
  const [pcDomWinStart, setPcDomWinStart] = useState('17:00')
  const [pcDomWinEnd, setPcDomWinEnd] = useState('19:00')
  const pinRetryRef = useRef<(() => void) | null>(null)
  const pinCancelRef = useRef<(() => void) | null>(null)
  const [domestic, setDomestic] = useState<ScopeStatus | null>(null)
  const [domesticJournal, setDomesticJournal] = useState<PcJournalItem[] | null>(null)
  const [domesticHint, setDomesticHint] = useState('')
  const [domRulesStatus, setDomRulesStatus] = useState('')
  const [domRulesTone, setDomRulesTone] = useState<'muted' | 'ok' | 'err'>('muted')
  const [domDraftCats, setDomDraftCats] = useState<Record<string, PcCatDraft>>({})
  const [domDraftDomains, setDomDraftDomains] = useState<Record<string, PcRule>>({})
  const [domDomInput, setDomDomInput] = useState('')
  const [domDomMode, setDomDomMode] = useState<'blocked' | 'window' | 'quota'>('blocked')
  const [domDomQuota, setDomDomQuota] = useState(60)
  const [domDomWinStart, setDomDomWinStart] = useState('17:00')
  const [domDomWinEnd, setDomDomWinEnd] = useState('19:00')
  const [cookieFindings, setCookieFindings] = useState<CookieFinding[] | null>(null)
  const [cookieChecked, setCookieChecked] = useState<Record<number, boolean>>({})
  const [cookieStatus, setCookieStatus] = useState('')
  const [cookieTone, setCookieTone] = useState<'muted' | 'ok' | 'err'>('muted')
  const [cookieScanning, setCookieScanning] = useState(false)
  const [cookiePurging, setCookiePurging] = useState(false)
  const [cookieReport, setCookieReport] = useState<{ deleted_total?: number; browsers?: Record<string, { status?: string; deleted?: number }> } | null>(null)
  const [cookieError, setCookieError] = useState('')
  const [alertDetailOpen, setAlertDetailOpen] = useState<Record<string, boolean>>({})
  const [alertInspect, setAlertInspect] = useState<Record<string, AlertInspectData>>({})
  const [alertInspectLoading, setAlertInspectLoading] = useState<string | null>(null)
  const [shaCopiedPid, setShaCopiedPid] = useState<string | null>(null)
  const [helpSection, setHelpSection] = useState('help-welcome')
  const [settingsForm, setSettingsForm] = useState<SettingsForm>({
    uiLanguage: 'fr', launchMode: 'browser', accessEnabled: true, accessMethod: 'windows', appPassword: '',
    scanInterval: '30', criticalPorts: '', allowedPorts: '', allowedProc: '',
    filterAutostart: false, remoteWhitelist: true, grace: '60', listsAutoUpdate: true,
    extEnabled: true, minSev: '90', alertEmail: '', webhook: '',
    smtpHost: '', smtpPort: '', smtpUser: '', smtpPass: '',
  })
  const [settingsStatus, setSettingsStatus] = useState('')
  const [settingsTone, setSettingsTone] = useState<'muted' | 'ok' | 'err'>('muted')
  const [listsStatus, setListsStatus] = useState<ListsStatus | null>(null)
  const [listsStatusErr, setListsStatusErr] = useState('')
  const [updateAllStatus, setUpdateAllStatus] = useState('')
  const [updateAllTone, setUpdateAllTone] = useState<'muted' | 'ok' | 'warn' | 'err'>('muted')
  const [updateAllReport, setUpdateAllReport] = useState<Array<{ text: string; color: string }>>([])
  const [locked, setLocked] = useState(false)
  const [lockMethod, setLockMethod] = useState('windows')
  const [lockNeedsSetup, setLockNeedsSetup] = useState(false)
  const [lockPassword, setLockPassword] = useState('')
  const [lockError, setLockError] = useState('')
  const [updateAllBusy, setUpdateAllBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const [state, snapshot] = await Promise.all([
        api<{ enabled?: boolean }>('/api/protection/state'),
        api<{ ports?: Port[]; risk_score?: number; timestamp?: string }>('/api/ports/current'),
      ])
      setProtection(Boolean(state.enabled))
      setPorts(snapshot.ports ?? [])
      setRiskScore(typeof snapshot.risk_score === 'number' ? snapshot.risk_score : null)
      setSnapshotTs(snapshot.timestamp ?? '')
      setBackend('online')
    } catch {
      setBackend('offline')
    }
  }, [])

  useEffect(() => {
    void initI18n()
    unauthorizedHandler = () => void checkAuth()
    void checkAuth()
    // Sous Tauri, les liens http(s) externes doivent passer par le shell.
    const onClick = (event: MouseEvent) => {
      if (!IS_TAURI) return
      const anchor = (event.target as HTMLElement).closest('a[href^="http"]') as HTMLAnchorElement | null
      if (anchor) { event.preventDefault(); openExternal(anchor.href) }
    }
    document.addEventListener('click', onClick, true)
    return () => { unauthorizedHandler = null; document.removeEventListener('click', onClick, true) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    if (!['alerts', 'history', 'intrusion', 'filter', 'adblock', 'parental', 'domestic', 'settings'].includes(activeTab)) return
    window.setTimeout(() => setTabLoading(true), 0)
    const load = activeTab === 'alerts'
      ? api<Alert[]>('/api/alerts').then(setAlerts)
      : activeTab === 'history'
        ? api<Snapshot[]>('/api/history').then(setHistory)
        : activeTab === 'intrusion'
          ? Promise.all([api<IntrusionDashboard>('/api/intrusion/dashboard'), api<BannedIp[]>('/api/intrusion/banned'), api<{ whitelist?: string[] }>('/api/intrusion/whitelist'), api<IntrusionStatus>('/api/intrusion/status')]).then(([dashboard, banned, whitelist, status]) => { setIntrusion(dashboard); setBannedIps(banned); setWhitelistIps(whitelist.whitelist ?? []); setIntrusionStatus(status) })
          : activeTab === 'filter'
            ? Promise.all([api<FilterStatus>('/api/filter/status'), api<FilterStats>('/api/filter/stats'), api<BlockedDomain[]>('/api/filter/blocked'), api<FilterWhitelist>('/api/filter/whitelist')]).then(([status, stats, blocked, whitelist]) => { setFilterStatus(status); setFilterStats(stats); setBlockedDomains(blocked); setFilterWhitelist(whitelist) })
            : activeTab === 'adblock'
              ? refreshAdblock()
              : activeTab === 'parental'
                ? refreshPcScope('parental')
                : activeTab === 'domestic'
                  ? refreshPcScope('domestic')
                  : activeTab === 'settings'
                    ? loadSettings()
                    : Promise.resolve()
    void load.catch(() => {
      if (activeTab === 'alerts') setAlerts([])
      if (activeTab === 'history') setHistory([])
      if (activeTab === 'intrusion') { setIntrusion(null); setBannedIps([]); setWhitelistIps([]); setIntrusionStatus(null) }
      if (activeTab === 'filter') { setFilterStatus(null); setFilterStats(null); setBlockedDomains([]); setFilterWhitelist(null) }
      if (activeTab === 'adblock') { setAdblock(null); setAdblockLists(null) }
      if (activeTab === 'parental') { setParental(null); setParentalJournal(null) }
      if (activeTab === 'domestic') { setDomestic(null); setDomesticJournal(null) }
    }).finally(() => setTabLoading(false))
  }, [activeTab])

  const portKey = (port: Port) => `${port.port ?? ''}|${(port.protocol ?? port.proto ?? 'TCP').toUpperCase()}`
  const selectedRecords = ports.filter((port) => selectedKeys[portKey(port)])

  async function loadInspection(port: Port) {
    setSelectedPort(port)
    setInspectResult(null)
    setInspectError('')
    const pid = port.pid ?? port.process?.pid
    if (!pid) return
    setInspectLoading(true)
    try {
      const result = await api<Record<string, unknown>>(`/api/inspect/process/${pid}`)
      setInspectResult(result)
      setSelectedPort((current) => current ? { ...current, sha256: String(result.sha256 ?? current.sha256 ?? '') } : current)
    } catch (error) {
      setInspectError(error instanceof Error ? error.message : t('modal.process.inspect_failed'))
      setInspectResult({ reputation: t('common.na') })
    } finally {
      setInspectLoading(false)
    }
  }

  function openInspection(port: Port) {
    void loadInspection(port)
  }

  function togglePort(port: Port, checked: boolean) {
    setSelectedKeys((current) => ({ ...current, [portKey(port)]: checked }))
  }

  function selectAllVisible(checked: boolean) {
    setSelectedKeys((current) => {
      const next = { ...current }
      visiblePorts.forEach((port) => { next[portKey(port)] = checked })
      return next
    })
  }

  async function createPlan(action: 'harden' | 'release') {
    const selected = selectedRecords.map((port) => ({ port: Number(port.port), protocol: (port.protocol ?? port.proto ?? 'TCP').toUpperCase(), risk: port.risk ?? null }))
    if (!selected.length) { setPlanMessage(''); setPortsStatus(t(action === 'harden' ? 'status.no_ports_harden' : 'status.no_ports_release')); return }
    try {
      setPortsStatus(t(action === 'harden' ? 'status.harden_generating' : 'status.release_generating'))
      const data = await api<{ ports_count?: number; plan_file?: string }>('/api/hardening/plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, ports: selected }) })
      setPlanMessage(t(action === 'harden' ? 'plan.harden_written' : 'plan.release_written', { file: data.plan_file ?? '' }))
      setPortsStatus(t(action === 'harden' ? 'status.harden_done' : 'status.release_done', { count: data.ports_count ?? selected.length }))
    } catch { setPortsStatus(t(action === 'harden' ? 'status.harden_error' : 'status.release_error')) }
  }

  async function applyAuditRecommendations() {
    try {
      setPortsStatus(t('status.audit_generating'))
      const data = await api<{ ports_count?: number; plan_path?: string; plan_file?: string }>('/api/audit/generate-plan', { method: 'POST' })
      setPlanMessage(t('plan.audit_written', { path: data.plan_path ?? data.plan_file ?? '', count: data.ports_count ?? 0 }))
      setPortsStatus(t('status.audit_done', { count: data.ports_count ?? 0 }))
    } catch (error) { setPortsStatus(t('status.audit_error', { msg: error instanceof Error ? error.message : String(error) })) }
  }

  async function savePortConfiguration() {
    if (!ports.length) { setPortsStatus(t('status.no_ports_save')); return }
    try {
      await api('/api/config/selection', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ports: selectedRecords.map((port) => ({ port: Number(port.port), protocol: (port.protocol ?? port.proto ?? 'TCP').toUpperCase() })) }) })
      setPortsStatus(t('status.config_saved'))
    } catch { setPortsStatus(t('status.config_save_error')) }
  }

  function applySuggestedConfiguration() {
    if (!ports.length) { setPortsStatus(t('status.no_ports_suggested')); return }
    const next: Record<string, boolean> = {}
    ports.forEach((port) => { next[portKey(port)] = ['critical', 'unexpected'].includes((port.risk ?? '').toLowerCase()) })
    setSelectedKeys(next)
    setPortsStatus(t('status.suggested_applied'))
  }

  function exportPorts(format: 'csv' | 'json') {
    openExternal(`${API_BASE}/api/export/ports?format=${format}`)
  }

  const portFilterCounts: Record<string, number> = { all: ports.length, critical: 0, unexpected: 0, fw: 0, vulnerable: 0 }
  ports.forEach((port) => {
    const r = (port.risk ?? '').toLowerCase()
    const isBlocked = Boolean(port.firewall_blocked)
    const isCritOrUnexp = r === 'critical' || r === 'unexpected'
    if (r === 'critical') portFilterCounts.critical += 1
    if (r === 'unexpected') portFilterCounts.unexpected += 1
    if (isBlocked) portFilterCounts.fw += 1
    if ((r === 'vulnerable' || isCritOrUnexp) && !isBlocked) portFilterCounts.vulnerable += 1
  })

  const visiblePorts = ports.filter((port) => {
    const riskLower = (port.risk ?? '').toLowerCase()
    const isBlocked = Boolean(port.firewall_blocked)
    const isCritOrUnexp = riskLower === 'critical' || riskLower === 'unexpected'
    if (riskFilter === 'critical' && riskLower !== 'critical') return false
    if (riskFilter === 'unexpected' && riskLower !== 'unexpected') return false
    if (riskFilter === 'fw' && !isBlocked) return false
    if (riskFilter === 'vulnerable' && !((riskLower === 'vulnerable' || isCritOrUnexp) && !isBlocked)) return false
    if (portQuery) {
      const q = portQuery.toLowerCase()
      const pid = String(port.pid ?? port.process?.pid ?? '')
      const haystack = [port.process?.name ?? port.process?.exe ?? '', port.port, port.protocol ?? port.proto, port.local_ip ?? port.ip, pid].join(' ').toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  }).slice().sort((a, b) => (a.port ?? 0) - (b.port ?? 0))

  function riskChip(risk?: string) {
    switch ((risk ?? '').toLowerCase()) {
      case 'critical': return { cls: 'risk-chip risk-critical', label: t('risk.critical') }
      case 'unexpected': return { cls: 'risk-chip risk-unexpected', label: t('risk.unexpected') }
      default: return { cls: 'risk-chip risk-authorized', label: t('risk.authorized') }
    }
  }

  async function runHealthcheck() {
    setHealthLoading(true)
    try {
      setHealth(await api<HealthReport>('/api/healthcheck/run', { method: 'POST' }))
    } catch {
      setHealth({ summary: { fail: 1 }, checks: [{ id: 'frontend.api', status: 'fail', message: t('settings.health.failed') }] })
    } finally {
      setHealthLoading(false)
    }
  }

  async function deleteAlert(alert: Alert) {
    if (!window.confirm(t('alerts.confirm_delete'))) return
    try {
      await api('/api/alerts/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ timestamp: alert.timestamp, message: alert.message }) })
      setAlerts((current) => current.filter((item) => item !== alert))
    } catch {
      window.alert(t('alerts.delete_error'))
    }
  }

  function alertExtract(item: Alert) {
    let pid = item.pid !== undefined && item.pid !== null && item.pid !== '' ? String(item.pid) : null
    let processName: string | null = null
    if (typeof item.process === 'string' && item.process.trim()) {
      processName = item.process.trim()
    } else if (item.process && typeof item.process === 'object') {
      processName = item.process.name || (item.process.exe ? item.process.exe.split(/[\\/]/).pop() ?? null : null)
    }
    let port = item.port !== undefined && item.port !== null && item.port !== '' ? String(item.port) : null
    const msg = item.message || ''
    if (!processName || !pid) {
      const m = msg.match(/([\w.-]+\.exe|[\w.-]+)\s*\(?PID\s*(\d+)\)?/i)
      if (m) { if (!processName) processName = m[1]; if (!pid) pid = m[2] }
    }
    if (!pid) {
      const m = msg.match(/PID\s*(\d+)/i)
      if (m) pid = m[1]
    }
    if (!port) {
      const m = msg.match(/port\s+(\d+)/i)
      if (m) port = m[1]
    }
    return { pid, processName, port }
  }

  function copyAlertForAI(item: Alert) {
    const { pid, processName, port } = alertExtract(item)
    const lines = [
      t('ai.intro'),
      t('ai.alert.intro'),
      '',
      t('ai.line.date', {v: item.timestamp ?? ''}),
      t('ai.line.score', {v: item.risk_score ?? item.score ?? '—'}),
      t('ai.line.msg', {v: item.message ?? ''}),
      processName ? t('ai.line.process', {name: processName, pid: pid ? ` (PID ${pid})` : ''}) : '',
      port ? t('ai.line.port', {v: port}) : '',
      '',
      t('ai.alert.question'),
    ].filter(Boolean)
    void navigator.clipboard?.writeText(lines.join('\n'))
  }

  async function toggleAlertInfo(pid: string, alertKey: string) {
    if (alertDetailOpen[alertKey]) {
      setAlertDetailOpen((cur) => ({ ...cur, [alertKey]: false }))
      return
    }
    setAlertDetailOpen((cur) => ({ ...cur, [alertKey]: true }))
    const cached = alertInspect[pid]
    if (cached && !cached.networkError) return
    setAlertInspectLoading(pid)
    const r = await pcFetch(`/api/inspect/process/${encodeURIComponent(pid)}`)
    setAlertInspectLoading(null)
    if (r.status === 404) setAlertInspect((cur) => ({ ...cur, [pid]: { notFound: true } }))
    else if (!r.ok || !r.data) setAlertInspect((cur) => ({ ...cur, [pid]: { networkError: true } }))
    else setAlertInspect((cur) => ({ ...cur, [pid]: r.data as AlertInspectData }))
  }

  function copyAlertSha(sha: string, pid: string) {
    void navigator.clipboard?.writeText(sha).then(() => {
      setShaCopiedPid(pid)
      window.setTimeout(() => setShaCopiedPid(null), 1500)
    })
  }

  function alertRepBadge(data: AlertInspectData) {
    const rep = (data.reputation ? String(data.reputation) : '').toLowerCase()
    if (rep === 'clean') return <span className="reputation-badge reputation-badge-clean">{t('rep.clean')}</span>
    if (rep === 'malicious') return <span className="reputation-badge reputation-badge-malicious">{t('rep.malicious')}{data.signature ? ` : ${data.signature}` : ''}</span>
    if (rep === 'unknown') return <span className="reputation-badge reputation-badge-unknown">{t('rep.unknown')}</span>
    return <span className="reputation-badge reputation-badge-error">{t('rep.error')}</span>
  }

  function listStatusBadge(status?: string) {
    const st = LIST_STATUS_STYLES[status ?? '']
    return <span className="badge" style={{ background: st?.bg ?? '#1f2937', color: st?.fg ?? '#9ca3af', fontWeight: 600 }}>{st ? t(st.label) : (status || '?')}</span>
  }

  const setSettingsField = <K extends keyof SettingsForm>(key: K, value: SettingsForm[K]) =>
    setSettingsForm((cur) => ({ ...cur, [key]: value }))

  async function loadListsStatusCard() {
    const r = await pcFetch('/api/lists/status')
    if (r.ok && r.data) {
      setListsStatus(r.data as ListsStatus)
      setListsStatusErr('')
    } else {
      setListsStatus(null)
      setListsStatusErr(t('lists.status.unavailable', {status: r.status}))
    }
  }

  async function loadSettings() {
    const [s, sched, lang] = await Promise.all([
      pcFetch('/api/settings'),
      pcFetch('/api/lists/scheduler_config'),
      pcFetch('/api/ui/language'),
    ])
    if (s.ok && s.data) {
      const d = s.data as Record<string, unknown>
      const access = (d.access ?? {}) as { enabled?: boolean; method?: string }
      setSettingsForm((f) => ({
        ...f,
        accessEnabled: access.enabled !== false,
        accessMethod: access.method || 'windows',
        appPassword: '',
        launchMode: ((d.ui ?? {}) as { launch_mode?: string }).launch_mode || 'browser',
        scanInterval: String(d.scan_interval_seconds ?? 30),
        criticalPorts: ((d.critical_ports ?? []) as number[]).join(', '),
        allowedPorts: ((d.allowed_ports ?? []) as number[]).join(', '),
        allowedProc: ((d.allowed_processes ?? []) as string[]).join(', '),
        filterAutostart: Boolean(d.filter_autostart),
        remoteWhitelist: d.use_remote_whitelist !== false,
        grace: String(d.notify_grace_seconds ?? 60),
        extEnabled: d.external_alerts_enabled !== false,
        minSev: String(d.external_min_severity ?? 90),
        alertEmail: String(d.alert_email ?? ''),
        webhook: String(d.webhook_url ?? ''),
        smtpHost: String(d.smtp_host ?? ''),
        smtpPort: d.smtp_port ? String(d.smtp_port) : '',
        smtpUser: String(d.smtp_user ?? ''),
        smtpPass: '',
      }))
    }
    if (sched.ok && sched.data) {
      setSettingsField('listsAutoUpdate', (sched.data as { enabled?: boolean }).enabled !== false)
    }
    const langData = lang.data as { language?: string } | null
    setSettingsField('uiLanguage', langData?.language || localStorage.getItem('cerbere_lang') || 'fr')
    void loadListsStatusCard()
  }

  function changeUiLanguage(lang: string) {
    if (!['fr', 'en', 'de', 'es'].includes(lang)) lang = 'fr'
    setSettingsField('uiLanguage', lang)
    void setLanguage(lang)
  }

  async function toggleListsAutoUpdate(enabled: boolean) {
    setSettingsField('listsAutoUpdate', enabled)
    const r = await pcFetch('/api/lists/scheduler_config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) })
    if (!r.ok) setSettingsField('listsAutoUpdate', !enabled)
  }

  async function saveSettings() {
    const parsePorts = (v: string) => v.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n) && n >= 0 && n <= 65535)
    const payload = {
      scan_interval_seconds: parseInt(settingsForm.scanInterval, 10) || 30,
      critical_ports: parsePorts(settingsForm.criticalPorts),
      allowed_ports: parsePorts(settingsForm.allowedPorts),
      allowed_processes: settingsForm.allowedProc.split(',').map((s) => s.trim()).filter(Boolean),
      filter_autostart: settingsForm.filterAutostart,
      use_remote_whitelist: settingsForm.remoteWhitelist,
      notify_grace_seconds: parseInt(settingsForm.grace, 10) || 0,
      external_alerts_enabled: settingsForm.extEnabled,
      external_min_severity: parseInt(settingsForm.minSev, 10) || 90,
      alert_email: settingsForm.alertEmail,
      webhook_url: settingsForm.webhook,
      smtp_host: settingsForm.smtpHost,
      smtp_port: parseInt(settingsForm.smtpPort, 10) || 465,
      smtp_user: settingsForm.smtpUser,
      smtp_password: settingsForm.smtpPass,
      access: {
        enabled: settingsForm.accessEnabled,
        method: settingsForm.accessMethod,
        new_app_password: settingsForm.appPassword || undefined,
      },
      ui: { launch_mode: settingsForm.launchMode },
    }
    const r = await pcFetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    if (r.ok) {
      setSettingsStatus(t('settings.status.saved'))
      setSettingsTone('ok')
      setSettingsForm((f) => ({ ...f, appPassword: '', smtpPass: '' }))
    } else if (r.status === 0) {
      setSettingsStatus(t('settings.status.comm_error'))
      setSettingsTone('err')
    } else {
      setSettingsStatus(t('settings.status.failed'))
      setSettingsTone('err')
    }
  }

  async function lockNow() {
    await pcFetch('/api/lock', { method: 'POST' })
    localStorage.removeItem(SESSION_TOKEN_KEY)
    void checkAuth()
  }

  async function checkAuth() {
    const r = await pcFetch('/api/auth/status')
    if (!r.ok || !r.data) return
    const d = r.data as { enabled?: boolean; unlocked?: boolean; method?: string; needs_setup?: boolean }
    if (d.enabled && !d.unlocked) {
      setLockMethod(d.method || 'windows')
      setLockNeedsSetup(Boolean(d.needs_setup))
      setLockPassword('')
      setLockError('')
      setLocked(true)
    } else {
      setLocked(false)
    }
  }

  async function submitUnlock() {
    const r = await pcFetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: lockPassword }),
    })
    if (r.ok) {
      const token = (r.data as { session_token?: string } | null)?.session_token
      if (token) localStorage.setItem(SESSION_TOKEN_KEY, token)
      setLocked(false)
      setLockPassword('')
      setLockError('')
      void refresh()
    } else if (r.status === 0) {
      setLockError(t('lock.error.comm'))
    } else {
      setLockError(String((r.data as { detail?: string } | null)?.detail ?? t('lock.error.wrong')))
    }
  }

  async function updateAllLists() {
    setUpdateAllBusy(true)
    setUpdateAllStatus(t('lists.downloading'))
    setUpdateAllTone('muted')
    setUpdateAllReport([])
    const r = await pcFetch('/api/lists/update_all', { method: 'POST' })
    setUpdateAllBusy(false)
    const data = r.data as { success?: boolean; detail?: string; report?: { adblock?: Record<string, { status?: string; domains?: number; count?: number; error?: string }>; parental?: Record<string, { status?: string; domains?: number; count?: number; error?: string }>; errors?: string[]; duration_s?: number }; blocked_domains?: number } | null
    if (!r.ok || !data?.success) {
      setUpdateAllStatus(data?.detail || t('adblock.update.failed', {status: r.status}))
      setUpdateAllTone('err')
    } else {
      const report = data.report ?? {}
      const adblock = report.adblock ?? {}
      const parental = report.parental ?? {}
      const errors = Array.isArray(report.errors) ? report.errors : []
      const all = Object.values(adblock).concat(Object.values(parental))
      const okCount = all.filter((x) => x && (x.status === 'ok' || x.status === 'cached')).length
      const errCount = all.filter((x) => x && x.status === 'error').length + errors.length
      const dur = report.duration_s != null ? t('lists.dur', {s: report.duration_s}) : ''
      setUpdateAllStatus(errCount
        ? t('lists.done_err', {dur: dur, ok: okCount, err: errCount})
        : t('lists.done_ok', {dur: dur, ok: okCount, domains: fmtNum((data.blocked_domains ?? 0))}))
      setUpdateAllTone(errCount ? 'warn' : 'ok')
      const lines: Array<{ text: string; color: string }> = []
      const lineFor = (prefix: string, id: string, x?: { status?: string; domains?: number; count?: number; error?: string }) => {
        const st = x?.status || '?'
        const color = st === 'error' ? '#fca5a5' : (st === 'cached' || st === 'stale' ? '#fde68a' : '#86efac')
        const n = x ? (x.domains ?? x.count) : null
        const nTxt = n != null ? t('lists.domains_suffix', {n: fmtNum(Number(n))}) : ''
        const errTxt = x?.error ? ` (${x.error})` : ''
        lines.push({ text: `${prefix}/${id} : ${LIST_STATUS_STYLES[st] ? t(LIST_STATUS_STYLES[st].label) : st}${nTxt}${errTxt}`, color })
      }
      Object.keys(adblock).forEach((lid) => lineFor('adblock', lid, adblock[lid]))
      Object.keys(parental).forEach((cat) => lineFor('parental', cat, parental[cat]))
      errors.forEach((e) => lines.push({ text: t('lists.error', {msg: e}), color: '#fca5a5' }))
      setUpdateAllReport(lines)
    }
    void loadListsStatusCard()
  }

  function exportAlerts(format: 'csv' | 'json') {
    openExternal(`${API_BASE}/api/export/alerts?format=${format}`)
  }

  async function modifyFilterWhitelist(domain: string, action: 'add' | 'remove') {
    setIntrusionAction(true)
    try {
      await api('/api/filter/whitelist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain, action }) })
      setFilterDomainInput('')
      const whitelist = await api<FilterWhitelist>('/api/filter/whitelist')
      setFilterWhitelist(whitelist)
    } finally { setIntrusionAction(false) }
  }

  async function resetFilterWhitelist() {
    if (!window.confirm(t('filter.reset.confirm'))) return
    setIntrusionAction(true)
    try { await api('/api/filter/whitelist/reset', { method: 'POST' }); setFilterWhitelist(await api<FilterWhitelist>('/api/filter/whitelist')) } catch (e) { window.alert(t('filter.reset.failed', {status: (e as Error).message})) } finally { setIntrusionAction(false) }
  }

  function openDomainModal(item: BlockedDomain) {
    setSelectedDomain(item)
    setDomainDetail(null)
    setDomainEnriching(false)
  }

  async function enrichDomain() {
    if (!selectedDomain?.domain) return
    setDomainEnriching(true)
    try { setDomainDetail(await api<DomainEnrich>(`/api/filter/inspect/${encodeURIComponent(selectedDomain.domain)}`)) } catch { setDomainDetail({ error: t('enrich.unavailable') }) }
    finally { setDomainEnriching(false) }
  }

  async function authorizeDomain(item: BlockedDomain) {
    if (!item.domain) return
    await modifyFilterWhitelist(item.domain, 'add')
    setBlockedDomains((current) => current.map((entry) => entry.domain === item.domain ? { ...entry, whitelisted: true } : entry))
  }

  async function reblockDomain(item: BlockedDomain) {
    if (!item.domain) return
    await modifyFilterWhitelist(item.domain, 'remove')
    setBlockedDomains((current) => current.map((entry) => entry.domain === item.domain ? { ...entry, whitelisted: false } : entry))
  }

  async function refreshAdblock() {
    const [lists, stats, blocked] = await Promise.all([
      api<AdblockListsResponse>('/api/adblock/lists'),
      api<AdblockStats>('/api/adblock/stats'),
      api<BlockedDomain[]>('/api/filter/blocked'),
    ])
    setAdblockLists(lists)
    setAdblock(stats)
    setBlockedDomains(blocked)
  }

  async function adblockToggleList(listId: string, enabled: boolean) {
    try {
      await api('/api/adblock/lists', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ list_id: listId, enabled }) })
    } finally {
      await refreshAdblock().catch(() => {})
    }
  }

  async function adblockUpdateList(listId?: string) {
    setAdblockUpdating(listId ?? 'all')
    setAdblockHint(t('adblock.downloading'))
    setAdblockHintTone('muted')
    try {
      const data = await api<{ success?: boolean; report?: Record<string, { status?: string }>; blocked_domains?: number; detail?: string }>('/api/adblock/lists/update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(listId ? { list_id: listId } : {}) })
      if (data.success) {
        const entries = Object.values(data.report ?? {})
        const errCount = entries.filter((r) => r?.status === 'error').length
        const okCount = entries.filter((r) => r?.status === 'ok' || r?.status === 'cached').length
        setAdblockHint(errCount ? t('adblock.update.done_err', {ok: okCount, err: errCount}) : t('adblock.update.done_ok', {domains: fmtNum((data.blocked_domains ?? 0))}))
        setAdblockHintTone(errCount ? 'warn' : 'ok')
      } else {
        setAdblockHint(data.detail || t('adblock.update.failed_plain'))
        setAdblockHintTone('err')
      }
    } catch (error) {
      setAdblockHint(t('common.comm_error', {msg: error instanceof Error ? error.message : String(error)}))
      setAdblockHintTone('err')
    } finally {
      setAdblockUpdating(null)
      await refreshAdblock().catch(() => {})
    }
  }

  function fmtListDate(iso?: string) {
    if (!iso) return '—'
    const d = new Date(iso)
    return isNaN(d.getTime()) ? iso : d.toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
  }

  function copyAdblockDomainForAI(item: BlockedDomain) {
    const lines = [
      t('ai.adblock.intro'),
      ``,
      t('ai.line.domain', {v: item.domain ?? ''}),
      t('ai.line.rule', {v: item.rule || ''}),
      t('ai.line.source', {v: (item.sources ?? []).join(', ') || t('common.unknown')}),
      t('ai.line.blocked_count', {v: item.count ?? 0}),
      ``,
      t('ai.domain.question_short'),
    ]
    void navigator.clipboard?.writeText(lines.join('\n'))
  }

  // ---- Contrôle parental (structure reprise du dashboard Electron) ----

  async function pcFetch(url: string, init?: RequestInit): Promise<{ status: number; ok: boolean; data: Record<string, unknown> | null }> {
    try {
      const res = await fetch(`${API_BASE}${url}`, { credentials: 'include', ...init, headers: mergeHeaders(init) })
      notifyUnauthorized(url, res.status)
      const data = await res.json().catch(() => null)
      return { status: res.status, ok: res.ok, data }
    } catch {
      return { status: 0, ok: false, data: null }
    }
  }

  function pcGuarded(scope: PcScope, path: string, init?: RequestInit): Promise<{ status: number; ok: boolean; data: Record<string, unknown> | null; cancelled?: boolean }> {
    return pcFetch(`${PC_APIS[scope]}${path}`, init).then((r) => {
      if (r.status === 403) {
        localStorage.removeItem(PARENTAL_TOKEN_KEY)
        return new Promise((resolve) => {
          pinRetryRef.current = () => { void pcGuarded(scope, path, init).then(resolve) }
          pinCancelRef.current = () => resolve({ status: 403, ok: false, data: r.data, cancelled: true })
          setPinInput('')
          setPinError('')
          setPinModalOpen(true)
        })
      }
      return r
    })
  }

  async function pcSubmitPinModal() {
    const pin = pinInput.trim()
    if (!pin) { setPinError(t('pin.enter')); return }
    const r = await pcFetch('/api/parental/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pin }) })
    if (r.ok) {
      const ptoken = (r.data as { session_token?: string } | null)?.session_token
      if (ptoken) localStorage.setItem(PARENTAL_TOKEN_KEY, ptoken)
      const fn = pinRetryRef.current
      pinRetryRef.current = null
      pinCancelRef.current = null
      setPinModalOpen(false)
      if (fn) fn()
      return
    }
    const detail = r.data?.detail
    setPinError(typeof detail === 'string' && detail ? detail : r.status === 401 ? t('pin.wrong') : r.status === 429 ? t('pin.too_many') : t('pin.error_http', {status: r.status}))
  }

  function closePinModal() {
    setPinModalOpen(false)
    const cb = pinCancelRef.current
    pinRetryRef.current = null
    pinCancelRef.current = null
    if (cb) cb()
  }

  async function refreshPcScope(scope: PcScope) {
    const api = PC_APIS[scope]
    const setStatus = scope === 'parental' ? setParental : setDomestic
    const setJournal = scope === 'parental' ? setParentalJournal : setDomesticJournal
    const setDrafts = scope === 'parental' ? setPcDraftCats : setDomDraftCats
    const setDomains = scope === 'parental' ? setPcDraftDomains : setDomDraftDomains
    const setHint = scope === 'parental' ? setParentalHint : setDomesticHint
    const reqs = [pcFetch(`${api}/status`), pcFetch(`${api}/blocked`)]
    if (scope === 'domestic') reqs.push(pcFetch('/api/parental/status'))
    const [status, journal, pinStatus] = await Promise.all(reqs)
    if (status.ok && status.data) {
      const s = status.data as ScopeStatus
      if (scope === 'domestic' && pinStatus?.ok && pinStatus.data) {
        s.pin_set = (pinStatus.data as ScopeStatus).pin_set
      }
      setStatus(s)
      const known = PC_CATS[scope].map(([k]) => k)
      const keys = known.concat(Object.keys(s.categories ?? {}).filter((k) => !known.includes(k)).sort())
      const drafts: Record<string, PcCatDraft> = {}
      keys.forEach((key) => {
        const rule = s.categories?.[key]
        drafts[key] = rule
          ? { enabled: true, mode: rule.mode ?? 'blocked', quota: rule.quota_minutes ?? 60, windows: rule.windows?.length ? rule.windows.map((w) => [...w] as [string, string]) : [['17:00', '19:00']] }
          : { enabled: false, mode: 'blocked', quota: 60, windows: [['17:00', '19:00']] }
      })
      setDrafts(drafts)
      setDomains(s.domains ?? {})
      if (scope === 'parental' && !s.pin_set) setPinCardOpen(true)
      setHint(s.pin_set ? '' : scope === 'parental' ? t('pc.pin.hint_here') : t('pc.pin.hint_missing'))
    } else {
      setStatus({ available: false })
    }
    const items = (journal.data as { items?: PcJournalItem[] } | null)?.items
    setJournal(journal.ok && Array.isArray(items) ? items : null)
  }

  const refreshParental = () => refreshPcScope('parental')

  async function pcSubmitPin() {
    const newPin = pinNew.trim()
    if (!/^\d{4,8}$/.test(newPin)) { setPinMsg(t('pin.err.digits')); setPinMsgOk(false); return }
    if (newPin !== pinConfirm.trim()) { setPinMsg(t('pin.err.mismatch')); setPinMsgOk(false); return }
    setPinMsg(t('pc.saving'))
    setPinMsgOk(true)
    const r = await pcFetch('/api/parental/pin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ old_pin: pinOld.trim(), new_pin: newPin }) })
    if (r.ok) {
      setPinMsg(t('pin.saved'))
      setPinMsgOk(true)
      setPinOld('')
      setPinNew('')
      setPinConfirm('')
      await refreshParental()
    } else {
      setPinMsg(typeof r.data?.detail === 'string' ? r.data.detail : t('pc.save_failed', {status: r.status}))
      setPinMsgOk(false)
    }
  }

  async function pcToggleScope(scope: PcScope) {
    const cur = scope === 'parental' ? parental : domestic
    const setHint = scope === 'parental' ? setParentalHint : setDomesticHint
    const r = await pcGuarded(scope, '/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !cur?.enabled }) })
    if (r.cancelled) { await refreshPcScope(scope); return }
    if (!r.ok) setHint(typeof r.data?.detail === 'string' ? r.data.detail : t('pc.action_failed', {status: r.status}))
    await refreshPcScope(scope)
  }

  async function pcSaveRules(scope: PcScope, domainsOverride?: Record<string, PcRule>) {
    const drafts = scope === 'parental' ? pcDraftCats : domDraftCats
    const domains = scope === 'parental' ? pcDraftDomains : domDraftDomains
    const setStatus = scope === 'parental' ? setPcRulesStatus : setDomRulesStatus
    const setTone = scope === 'parental' ? setPcRulesTone : setDomRulesTone
    const categories: Record<string, PcRule> = {}
    for (const [key, d] of Object.entries(drafts)) {
      if (!d.enabled) continue
      if (d.mode === 'quota') {
        if (!Number.isInteger(d.quota) || d.quota <= 0) { setStatus(t('pc.quota.invalid_for', {key: key})); setTone('err'); return }
        categories[key] = { mode: 'quota', quota_minutes: d.quota }
      } else if (d.mode === 'window') {
        const wins = d.windows.filter(([s, e]) => s && e)
        if (!wins.length) { setStatus(t('pc.window.missing_for', {key: key})); setTone('err'); return }
        categories[key] = { mode: 'window', windows: wins }
      } else {
        categories[key] = { mode: 'blocked' }
      }
    }
    setStatus(t('pc.saving'))
    setTone('muted')
    const r = await pcGuarded(scope, '/rules', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ categories, domains: domainsOverride ?? domains }) })
    if (r.cancelled) { setStatus(t('pc.cancelled_pin')); setTone('err'); await refreshPcScope(scope); return }
    if (r.ok) {
      setStatus(t('pc.saved'))
      setTone('ok')
      await refreshPcScope(scope)
    } else {
      setStatus(typeof r.data?.detail === 'string' ? r.data.detail : t('pc.save_failed', {status: r.status}))
      setTone('err')
    }
  }

  async function pcResetScope(scope: PcScope) {
    const name = scope === 'parental' ? t('ai.journal.src.parental') : t('ai.journal.src.domestic')
    const setStatus = scope === 'parental' ? setPcRulesStatus : setDomRulesStatus
    const setTone = scope === 'parental' ? setPcRulesTone : setDomRulesTone
    if (!window.confirm(t('pc.reset.confirm', {label: name}))) return
    const r = await pcGuarded(scope, '/reset', { method: 'POST' })
    if (r.cancelled) return
    if (!r.ok) { setStatus(typeof r.data?.detail === 'string' ? r.data.detail : t('pc.reset.failed', {status: r.status})); setTone('err'); return }
    await refreshPcScope(scope)
  }

  function pcNormalizeDomain(v: string) {
    return v.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^[*\.]+/, '').split('/')[0].replace(/\.$/, '')
  }

  async function pcAddDomainRule(scope: PcScope) {
    const input = scope === 'parental' ? pcDomInput : domDomInput
    const mode = scope === 'parental' ? pcDomMode : domDomMode
    const quota = scope === 'parental' ? pcDomQuota : domDomQuota
    const winStart = scope === 'parental' ? pcDomWinStart : domDomWinStart
    const winEnd = scope === 'parental' ? pcDomWinEnd : domDomWinEnd
    const domains = scope === 'parental' ? pcDraftDomains : domDraftDomains
    const setDomains = scope === 'parental' ? setPcDraftDomains : setDomDraftDomains
    const setInput = scope === 'parental' ? setPcDomInput : setDomDomInput
    const setStatus = scope === 'parental' ? setPcRulesStatus : setDomRulesStatus
    const setTone = scope === 'parental' ? setPcRulesTone : setDomRulesTone
    const dom = pcNormalizeDomain(input)
    if (!dom || !/^[a-z0-9.-]+$/.test(dom) || !dom.includes('.')) { setStatus(t('pc.domain.invalid')); setTone('err'); return }
    let rule: PcRule
    if (mode === 'quota') {
      if (!Number.isInteger(quota) || quota <= 0) { setStatus(t('pc.quota.invalid')); setTone('err'); return }
      rule = { mode: 'quota', quota_minutes: quota }
    } else if (mode === 'window') {
      if (!winStart || !winEnd) { setStatus(t('pc.window.incomplete')); setTone('err'); return }
      rule = { mode: 'window', windows: [[winStart, winEnd]] }
    } else {
      rule = { mode: 'blocked' }
    }
    const next = { ...domains, [dom]: rule }
    setDomains(next)
    setInput('')
    await pcSaveRules(scope, next)
  }

  async function pcRemoveDomainRule(scope: PcScope, dom: string) {
    const domains = scope === 'parental' ? pcDraftDomains : domDraftDomains
    const setDomains = scope === 'parental' ? setPcDraftDomains : setDomDraftDomains
    const next = { ...domains }
    delete next[dom]
    setDomains(next)
    await pcSaveRules(scope, next)
  }

  function updatePcCat(scope: PcScope, key: string, patch: Partial<PcCatDraft>) {
    const setDrafts = scope === 'parental' ? setPcDraftCats : setDomDraftCats
    setDrafts((cur) => ({ ...cur, [key]: { ...cur[key], ...patch } }))
  }

  function copyPcItemForAI(scope: PcScope, item: PcJournalItem) {
    const ctx = scope === 'parental' ? t('pc.scope.parental') : t('pc.scope.domestic')
    const lines = [
      t('ai.pc.intro', {scope: ctx}),
      ``,
      t('ai.line.domain', {v: item.domain ?? ''}),
      t('ai.line.rule2', {v: item.rule || ''}),
      t('ai.line.reason', {v: item.reason || ''}),
      t('ai.line.blocks', {v: item.count ?? 0}),
      ``,
      t('ai.pc.question'),
    ]
    void navigator.clipboard?.writeText(lines.join('\n'))
  }

  function copyPcJournalForAI(scope: PcScope) {
    const journal = scope === 'parental' ? parentalJournal : domesticJournal
    if (!journal?.length) return
    const srcKey = scope === 'parental' ? 'ai.journal.src.parental' : 'ai.journal.src.domestic'
    const lines = journal.slice(0, 100).map((it) => {
      const parts = [`- ${it.domain}`]
      if (it.rule) parts.push(t('ai.journal.seg.rule', {v: it.rule}))
      if (it.reason) parts.push(t('ai.journal.seg.reason', {v: it.reason}))
      parts.push(t('ai.journal.seg.count', {v: it.count ?? 0}))
      if (it.last_seen) parts.push(t('ai.journal.seg.last', {v: it.last_seen}))
      return parts.join(' — ')
    }).join('\n')
    const extra = journal.length > 100 ? t('ai.journal.more', {n: journal.length - 100}) : ''
    void navigator.clipboard?.writeText(t('ai.journal.body', {label: t(srcKey), lines: lines + extra}))
  }

  async function domesticScanCookies(keepReport = false) {
    setCookieScanning(true)
    if (!keepReport) { setCookieReport(null); setCookieError('') }
    setCookieStatus(t('cookies.scanning'))
    setCookieTone('muted')
    const r = await pcFetch('/api/domestic/cookies/scan', { method: 'POST' })
    setCookieScanning(false)
    if (r.ok && r.data) {
      const findings = (r.data.findings ?? r.data.items ?? []) as CookieFinding[]
      setCookieFindings(Array.isArray(findings) ? findings : [])
      const checked: Record<number, boolean> = {}
      findings.forEach((_, i) => { checked[i] = true })
      setCookieChecked(checked)
      setCookieStatus(findings.length ? t('cookies.found', {count: findings.length}) : t('cookies.none_found'))
      setCookieTone(findings.length ? 'ok' : 'muted')
    } else {
      setCookieFindings(null)
      setCookieStatus(t('cookies.scan_failed', {status: r.status}))
      setCookieTone('err')
    }
  }

  async function domesticPurgeCookies() {
    const findings = cookieFindings ?? []
    const selected = findings.filter((_, i) => cookieChecked[i])
    if (!selected.length) { setCookieStatus(t('cookies.none_selected')); setCookieTone('err'); return }
    setCookiePurging(true)
    setCookieStatus(t('cookies.purging'))
    setCookieTone('muted')
    setCookieError('')
    const r = await pcGuarded('domestic', '/cookies/purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings: selected.map((f) => ({ browser: f.browser, profile: f.profile, host_key: f.host_key, cookie_name: f.cookie_name, matched_domain: f.matched_domain })) }),
    })
    setCookiePurging(false)
    if (r.cancelled) { setCookieStatus(t('cookies.purge_cancelled')); setCookieTone('err'); return }
    if (r.ok && r.data) {
      const rep = (r.data.report ?? {}) as { deleted_total?: number; browsers?: Record<string, { status?: string; deleted?: number }> }
      setCookieReport(rep)
      void domesticScanCookies(true)
    } else {
      const detail = typeof r.data?.detail === 'string' ? r.data.detail : t('cookies.purge_failed', {status: r.status})
      setCookieError(`${detail}${r.status >= 500 ? t('cookies.purge_locked_hint') : ''}`)
      setCookieStatus(t('cookies.purge_failed_status'))
      setCookieTone('err')
    }
  }

  const disabledDefaultSet = new Set((filterWhitelist?.disabled_defaults ?? []).map((d) => d.toLowerCase()))
  const activeDefaultDomains = (filterWhitelist?.defaults ?? []).filter((d) => !disabledDefaultSet.has(d.toLowerCase()))
  const adblockListEntries = Object.entries(adblockLists?.lists ?? {})
  const adblockEnabledCount = adblockListEntries.filter(([, l]) => l?.enabled).length || (adblock?.enabled_lists?.length ?? 0)
  const adblockRunning = Boolean(adblock?.running)
  const adblockSched = adblock?.scheduler
  const adblockSchedText = t('adblock.sched', {state: adblockSched?.running ? t('adblock.sched.active') : t('adblock.sched.inactive'), last: adblockSched?.last_run?.finished_at ? fmtListDate(adblockSched.last_run.finished_at) : t('adblock.never')})

  function isWhitelistedDomain(domain: string) {
    const effective = [...activeDefaultDomains, ...(filterWhitelist?.custom ?? [])].map((d) => d.toLowerCase())
    const parts = domain.toLowerCase().split('.')
    for (let i = 0; i < parts.length; i++) {
      if (effective.includes(parts.slice(i).join('.'))) return true
    }
    return false
  }

  function copyDomainForAI(item: BlockedDomain, enrich?: DomainEnrich | null) {
    const lines = [
      t('ai.domain.intro'),
      ``,
      t('ai.line.domain', {v: item.domain ?? ''}),
      t('ai.line.rule', {v: item.rule || t('common.unknown')}),
      t('ai.line.source', {v: (item.sources ?? []).join(', ') || t('common.unknown')}),
      t('ai.line.blocked_count', {v: item.count ?? 0}),
    ]
    if (item.first_seen) lines.push(t('ai.line.first', {v: item.first_seen}))
    if (item.last_seen) lines.push(t('ai.line.last', {v: item.last_seen}))
    if (enrich?.rdap?.available && enrich.rdap.registrar) lines.push(t('ai.line.registrar', {v: enrich.rdap.registrar}))
    if (enrich?.rdap?.available && enrich.rdap.created) lines.push(t('ai.line.created', {v: enrich.rdap.created.slice(0, 10)}))
    if (enrich?.urlhaus?.available) lines.push(t('ai.line.urlhaus', {v: enrich.urlhaus.listed ? t('ai.urlhaus.listed') : t('ai.urlhaus.not_listed')}))
    if (enrich?.dns?.available && enrich.dns.ips?.length) lines.push(t('ai.line.real_ip', {v: enrich.dns.ips.join(', ')}))
    lines.push(``, t('ai.domain.question'))
    void navigator.clipboard?.writeText(lines.join('\n'))
  }

  function copyAllBlockedForAI() {
    if (blockedDomains.length === 0) return
    const lines = blockedDomains.slice(0, 100).map((it) => {
      const parts = [`- ${it.domain}`]
      if (it.rule) parts.push(t('ai.journal.seg.rule', {v: it.rule}))
      if (it.matched_domain && it.matched_domain !== it.domain) parts.push(t('ai.journal.seg.via', {v: it.matched_domain}))
      if ((it.sources ?? []).length) parts.push(t('ai.journal.seg.sources', {v: (it.sources ?? []).join(', ')}))
      parts.push(t('ai.journal.seg.count', {v: it.count ?? 0}))
      if (it.last_seen) parts.push(t('ai.journal.seg.last', {v: it.last_seen}))
      return parts.join(' — ')
    }).join('\n')
    const extra = blockedDomains.length > 100 ? t('ai.journal.more', {n: blockedDomains.length - 100}) : ''
    void navigator.clipboard?.writeText(t('ai.journal.body', {label: t('ai.journal.src.filter'), lines: lines + extra}))
  }

  async function refreshIntrusionData() {
    const [dashboard, banned, whitelist, status] = await Promise.all([api<IntrusionDashboard>('/api/intrusion/dashboard'), api<BannedIp[]>('/api/intrusion/banned'), api<{ whitelist?: string[] }>('/api/intrusion/whitelist'), api<IntrusionStatus>('/api/intrusion/status')])
    setIntrusion(dashboard); setBannedIps(banned); setWhitelistIps(whitelist.whitelist ?? []); setIntrusionStatus(status)
  }

  async function postIntrusion(path: string) {
    setIntrusionAction(true)
    try { await api(path, { method: 'POST' }); await refreshIntrusionData() } finally { setIntrusionAction(false) }
  }

  async function testDetection() {
    setIntrusionAction(true)
    try {
      const data = await api<{ success?: boolean; message?: string; source_ip?: string; event_count?: number }>('/api/intrusion/test', { method: 'POST' })
      window.alert(`${data.message ?? (data.success ? t('intrusion.test.ok') : t('intrusion.test.error'))}\n\n${t('intrusion.test.ip')} ${data.source_ip ?? '—'}\n${t('intrusion.test.persisted')} ${data.event_count ?? 0}`)
      await refreshIntrusionData()
    } catch {
      window.alert(t('intrusion.test.error'))
    } finally {
      setIntrusionAction(false)
    }
  }

  async function unbanIp(ip: string) {
    if (!ip || !window.confirm(t('intrusion.unban.confirm', { ip }))) return
    setIntrusionAction(true)
    try {
      const data = await api<{ success?: boolean; message?: string }>('/api/intrusion/unban', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) })
      if (data.success) await refreshIntrusionData()
      else window.alert(t('common.error', { msg: data.message ?? '' }))
    } catch {
      window.alert(t('intrusion.unban.error'))
    } finally {
      setIntrusionAction(false)
    }
  }

  async function addWhitelistIp() {
    const ip = whitelistInput.trim()
    if (!ip) return
    setIntrusionAction(true)
    try {
      const data = await api<{ success?: boolean; message?: string }>('/api/intrusion/whitelist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'add', ip }) })
      if (data.success) { setWhitelistInput(''); await refreshIntrusionData() }
      else window.alert(t('common.error', { msg: data.message ?? '' }))
    } catch {
      window.alert(t('intrusion.whitelist.error'))
    } finally {
      setIntrusionAction(false)
    }
  }

  function intrusionSeverityColor(severity?: string): string {
    switch ((severity ?? '').toLowerCase()) {
      case 'critical': return '#dc2626'
      case 'high': return '#ea580c'
      case 'medium': return '#ca8a04'
      case 'low': return '#16a34a'
      default: return '#6b7280'
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
          <span className={`backend-status ${backend}`}>{backend === 'online' ? t('app.backend.online') : t('app.backend.offline')}</span>
        </div>
        <div className="header-overlay header-right">
          <span className="badge header-badge">{snapshotTs ? t('status.snapshot', {ts: snapshotTs}) : '—'}</span>
          <span className={`score ${riskScore === null || riskScore < 30 ? 'score-low' : riskScore < 70 ? 'score-medium' : 'score-high'}`}>{t('status.risk_score', {score: riskScore ?? '—'})}</span>
          <a href="https://www.grc.com/shieldsup" target="_blank" rel="noreferrer">{t('app.shieldsup')}</a>
          <span className={`protection-badge ${protection ? 'on' : 'off'}`}>{protection ? t('protection.on') : t('protection.off')}</span>
        </div>
      </header>

      <nav className="tabs" aria-label={t('app.nav.aria')}>
        {tabs.map((tab) => (
          <button className={activeTab === tab.id ? 'tab active' : 'tab'} key={tab.id} onClick={() => setActiveTab(tab.id)} title={t(tab.hintKey)}>
            {t(tab.labelKey)}
          </button>
        ))}
        <a className="tab tab-github" href="https://github.com/art-qalam-fr/CerbereShield" target="_blank" rel="noreferrer" title={t('tabs.github.title')}>
          <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>
          {t('tabs.github')}
        </a>
      </nav>

      <main className="content">
        {activeTab === 'ports' && (
          <section className="panel">
            <div className="panel-heading"><div><h2>{t('tabs.ports')}</h2><p>{t('tabs.ports.title')}</p></div><div className="panel-actions"><button className="primary" onClick={() => void refresh()}>{t('btn.refresh')}</button></div></div>
            <div className="actions">
              <button className="secondary" disabled={selectedRecords.filter((port) => ['critical', 'unexpected'].includes((port.risk ?? '').toLowerCase())).length === 0} title={t('ports.btn.harden.title')} onClick={() => void createPlan('harden')}>{t('ports.btn.harden')}</button>
              <button className="secondary" disabled={!selectedRecords.length} title={t('ports.btn.release.title')} onClick={() => void createPlan('release')}>{t('ports.btn.release')}</button>
              <button className="secondary" title={t('ports.btn.audit.title')} onClick={() => void applyAuditRecommendations()}>{t('ports.btn.audit')}</button>
              <button className="secondary" title={t('ports.btn.save_config.title')} onClick={() => void savePortConfiguration()}>{t('ports.btn.save_config')}</button>
              <button className="secondary" title={t('ports.btn.suggested.title')} onClick={applySuggestedConfiguration}>{t('ports.btn.suggested')}</button>
              <button className="secondary" title={t('ports.btn.export_csv.title')} onClick={() => exportPorts('csv')}>{t('btn.export_csv')}</button>
              <button className="secondary" title={t('ports.btn.export_json.title')} onClick={() => exportPorts('json')}>{t('btn.export_json')}</button>
            </div>
            {planMessage && <div className="command-box">{planMessage}</div>}
            {portsStatus && <div className="inline-status">{portsStatus}</div>}
            <div className="table-controls">
              <div className="search-box">
                <input type="text" className="search-input" value={portQuery} onChange={(event) => setPortQuery(event.target.value)} placeholder={t('ports.search.placeholder')} title={t('ports.search.title')} />
                {portQuery && <button type="button" className="search-clear-btn" title={t('ports.search.clear.title')} onClick={() => setPortQuery('')}>✕</button>}
              </div>
              <div className="filter-group">
                <span className="filter-label">{t('ports.filter.label')}</span>
                {(['all', 'critical', 'unexpected', 'fw', 'vulnerable'] as const).map((f) => <button key={f} type="button" className={riskFilter === f ? 'filter-btn active' : 'filter-btn'} title={t(`ports.filter.${f}.title`)} onClick={() => setRiskFilter(f)}>{t(`ports.filter.${f}`)} <span className="filter-count">{portFilterCounts[f] ?? 0}</span></button>)}
              </div>
            </div>
            <div className="table-wrap"><table><thead><tr><th><input type="checkbox" title={t('ports.th.select_all.title')} checked={visiblePorts.length > 0 && visiblePorts.every((port) => selectedKeys[portKey(port)])} onChange={(event) => selectAllVisible(event.target.checked)} /></th><th title={t('ports.th.port.title')}>{t('ports.th.port')}</th><th title={t('ports.th.protocol.title')}>{t('ports.th.protocol')}</th><th title={t('ports.th.ip.title')}>{t('ports.th.ip')}</th><th title={t('ports.th.state.title')}>{t('ports.th.state')}</th><th title={t('ports.th.pid.title')}>PID</th><th title={t('ports.th.process.title')}>{t('ports.th.process')}</th><th title={t('ports.th.risk.title')}>{t('ports.th.risk')}</th><th title={t('ports.th.action.title')}>{t('ports.th.action')}</th></tr></thead><tbody>
              {ports.length === 0 ? <tr><td colSpan={9} className="empty">{t('ports.empty')}</td></tr> : visiblePorts.length === 0 ? <tr><td colSpan={9} className="empty">{t('ports.empty_filtered')}</td></tr> : visiblePorts.map((port, index) => { const riskInfo = riskChip(port.risk); return <tr key={`${port.port}-${index}`} className="port-row" title={t('ports.row.title')} onClick={() => openInspection(port)}><td onClick={(event) => event.stopPropagation()}><input type="checkbox" className="port-select" checked={Boolean(selectedKeys[portKey(port)])} onChange={(event) => togglePort(port, event.target.checked)} /></td><td>{port.port ?? ''}{port.port != null && <a href={`https://www.speedguide.net/port.php?port=${encodeURIComponent(port.port)}`} target="_blank" rel="noopener noreferrer" className="port-ext-link" title={t('links.sg.title')} onClick={(event) => event.stopPropagation()}>↗</a>}</td><td>{(port.protocol ?? port.proto ?? 'TCP').toUpperCase()}</td><td>{port.local_ip ?? port.ip ?? ''}</td><td>{port.state ?? ''}</td><td>{port.pid ?? port.process?.pid ?? '—'}</td><td>{port.process?.name ?? port.process?.exe ?? '—'}</td><td><span className={riskInfo.cls}>{riskInfo.label}{port.firewall_blocked ? ' (FW)' : ''}</span></td><td><button type="button" className="btn-inspect" title={t('ports.btn.inspect.title')} onClick={(event) => { event.stopPropagation(); openInspection(port) }}>{t('ports.btn.inspect')}</button></td></tr> })}
            </tbody></table></div>
            {selectedPort && <div className="modal-backdrop" onClick={() => setSelectedPort(null)}><div className="inspect-modal" onClick={(event) => event.stopPropagation()}><button className="modal-close" title={t('modal.close.title')} onClick={() => setSelectedPort(null)}>×</button><h2>{t('modal.process.title')}</h2><div className="modal-detail-grid"><p><strong>{t('modal.process.name')}</strong> {selectedPort.process?.name ?? '—'}</p><p><strong>PID :</strong> {selectedPort.pid ?? selectedPort.process?.pid ?? '—'}</p><p><strong>{t('modal.process.endpoint')}</strong> {(selectedPort.local_ip ?? selectedPort.ip ?? '—')}:{selectedPort.port ?? '—'} ({(selectedPort.protocol ?? selectedPort.proto ?? 'TCP').toUpperCase()})</p><p><strong>{t('modal.process.user')}</strong> {selectedPort.username ?? selectedPort.process?.username ?? t('common.na')}</p></div><p><strong>{t('modal.process.exe')}</strong></p><pre>{selectedPort.process?.exe ?? t('common.na')}</pre><p><strong>{t('modal.process.cmdline')}</strong></p><pre>{Array.isArray(selectedPort.process?.cmdline) ? selectedPort.process?.cmdline.join(' ') : selectedPort.process?.cmdline ?? t('common.na')}</pre><p><strong>{t('modal.process.sha256')}</strong></p><pre>{selectedPort.sha256 ?? selectedPort.process?.sha256 ?? String(inspectResult?.sha256 ?? (inspectLoading ? t('modal.process.sha_progress') : t('modal.process.sha_unavailable')))}</pre>{inspectError && <div className="inspection-error">{t('modal.process.inspect_failed')} {inspectError}</div>}{inspectLoading && <div className="reputation-pending">{t('modal.process.rep_checking')}</div>}{inspectResult && <div className="reputation-result"><strong>{t('modal.process.verdict')}</strong> {String(inspectResult.reputation ?? inspectResult.verdict ?? t('common.na'))}{inspectResult.cached ? t('common.cached') : ''}</div>}<div className="modal-links"><a href={inspectResult?.links && typeof inspectResult.links === 'object' && 'virustotal_hash' in inspectResult.links ? String(inspectResult.links.virustotal_hash) : `https://www.virustotal.com/gui/search/${encodeURIComponent(String(selectedPort.sha256 ?? selectedPort.process?.name ?? ''))}`} target="_blank" rel="noreferrer" title={t('links.vt_hash.title')}>VirusTotal ↗</a><a href={`https://www.processlibrary.com/en/directory/files/${encodeURIComponent((selectedPort.process?.name ?? '').replace(/\.exe$/i, '').toLowerCase())}/`} target="_blank" rel="noreferrer" title={t('links.pl.title')}>ProcessLibrary ↗</a><a href={selectedPort.port === 0 ? 'https://www.grc.com/port_0.htm' : `http://www.grc.com/port_${selectedPort.port}.htm`} target="_blank" rel="noreferrer" title={t('links.grc.title')}>GRC ↗</a><a href={`https://www.speedguide.net/port.php?port=${selectedPort.port ?? ''}`} target="_blank" rel="noreferrer" title={t('links.sg.title')}>SpeedGuide ↗</a><a href={`https://isc.sans.edu/port.html?port=${selectedPort.port ?? ''}`} target="_blank" rel="noreferrer" title={t('links.sans.title')}>SANS ISC ↗</a><a href="https://www.grc.com/shieldsup" target="_blank" rel="noreferrer" title={t('links.grc.title')}>ShieldsUP ↗</a></div></div></div>}
          </section>
        )}

        {activeTab === 'intrusion' && (
          <section className="panel"><div className="panel-heading"><div><h2>{t('tabs.intrusion')}</h2><p>{t('tabs.intrusion.title')}</p></div><div className="panel-actions"><button className="primary" onClick={() => void refreshIntrusionData()}>{t('btn.refresh')}</button></div></div>
            <div className="actions">
              <button className="secondary" disabled={intrusionAction} title={t('intrusion.btn.toggle.title')} onClick={() => void postIntrusion(intrusionStatus?.running ? '/api/intrusion/stop' : '/api/intrusion/start')}>{intrusionStatus?.running ? t('intrusion.btn.stop') : t('intrusion.btn.start')}</button>
              <button className="secondary" disabled={intrusionAction} title={t('intrusion.btn.refresh.title')} onClick={() => void refreshIntrusionData()}>{t('btn.refresh')}</button>
              <button className="secondary" disabled={intrusionAction} style={{ background: '#7c3aed', borderColor: '#7c3aed', color: '#fff' }} title={t('intrusion.btn.test.title')} onClick={() => void testDetection()}>{t('intrusion.btn.test')}</button>
              <span className="hint" style={{ color: intrusionStatus?.running ? '#bbf7d0' : '#9ca3af' }}>{intrusionStatus?.running ? t('intrusion.status.active', { count: intrusionStatus.active_bans ?? 0 }) : t('intrusion.status.stopped')}</span>
            </div>
            <div className="intrusion-stats"><div className="intrusion-stat"><span>{t('intrusion.stats.events')}</span><strong>{intrusion?.statistics?.total_events ?? 0}</strong></div><div className="intrusion-stat"><span>{t('intrusion.stats.unique_ips')}</span><strong>{intrusion?.statistics?.unique_ips ?? 0}</strong></div><div className="intrusion-stat danger"><span>{t('intrusion.stats.high')}</span><strong>{intrusion?.statistics?.high_severity ?? 0}</strong></div><div className="intrusion-stat safe"><span>{t('intrusion.stats.banned')}</span><strong>{intrusion?.statistics?.banned_ips ?? 0}</strong></div></div>
            <div className="intrusion-columns"><div><h3>{t('intrusion.events.title')}</h3><div className="intrusion-list">{intrusion === null ? <span className="muted">{t('common.loading')}</span> : (intrusion.recent_events ?? []).length === 0 ? <span className="muted">{t('intrusion.empty_events')}</span> : (intrusion.recent_events ?? []).map((event, index) => <div className="intrusion-event" key={`${event.timestamp}-${index}`} style={{ borderLeftColor: intrusionSeverityColor(event.severity) }}><div className="intrusion-event-type">{event.type}</div><div className="intrusion-event-meta">IP: <span className="intrusion-ip">{event.source_ip}</span> | {event.timestamp ? new Date(event.timestamp).toLocaleString() : '—'}</div><div className="intrusion-event-detail">{event.target_service ?? event.details}</div></div>)}</div></div><div><h3>{t('intrusion.banned.title')}</h3><div className="intrusion-list">{intrusion === null ? <span className="muted">{t('common.loading')}</span> : bannedIps.length === 0 ? <span className="muted">{t('intrusion.empty_banned')}</span> : bannedIps.map((item, index) => <div className="intrusion-banned" key={`${item.ip ?? item.ip_address}-${index}`}><div><div className="intrusion-banned-ip">{item.ip ?? item.ip_address}</div><div className="intrusion-banned-reason">{item.reason}</div><div className="intrusion-banned-time">{item.ban_time ? new Date(item.ban_time).toLocaleString() : ''}</div></div>{item.active !== false && <button type="button" className="secondary compact" title={t('intrusion.unban.title')} onClick={() => void unbanIp(item.ip ?? item.ip_address ?? '')}>{t('intrusion.unban')}</button>}</div>)}</div></div></div><div className="whitelist-box"><h3>{t('common.whitelist_mgmt')}</h3><div className="whitelist-add"><input value={whitelistInput} onChange={(event) => setWhitelistInput(event.target.value)} placeholder={t('intrusion.whitelist.placeholder')} title={t('intrusion.whitelist.ip.title')} /><button className="secondary" disabled={intrusionAction} title={t('intrusion.whitelist.add.title')} onClick={() => void addWhitelistIp()}>{t('btn.add')}</button></div><div className="whitelist-chips">{whitelistIps.length ? whitelistIps.map((ip) => <span className="wl-chip" key={ip}>{ip}</span>) : <span className="muted">{t('intrusion.empty_whitelist')}</span>}</div></div></section>
        )}

                {activeTab === 'filter' && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>{t('tabs.filter')}</h2>
                <p>{t('filter.subtitle')}</p>
              </div>
              <div className="panel-actions">
                <button className="primary" disabled={intrusionAction} onClick={() => void toggleFilter()}>{filterStatus?.running ? t('filter.btn.deactivate') : t('filter.btn.activate')}</button>
                <button className="secondary" onClick={() => setActiveTab('filter')}>{t('btn.refresh')}</button>
                <button className="secondary" disabled={intrusionAction} title={t('filter.btn.reset.title')} onClick={() => void resetFilterWhitelist()}>{t('filter.btn.reset')}</button>
              </div>
            </div>

            <div className="filter-info-banner" dangerouslySetInnerHTML={{ __html: t('filter.info_banner') }} />

            {filterStatus ? (
              <>
                <div className="filter-status-line">
                  <span className={`state-dot ${filterStatus.running ? 'on' : 'off'}`} />
                  {filterStatus.running ? t('filter.status.running') : filterStatus.error ? t('common.error', {msg: filterStatus.error}) : t('filter.status.inactive')}
                </div>

                <div className="stats-row">
                  <div className="stat-card"><strong>{filterStats?.queries_total ?? 0}</strong><span>{t('filter.stats.queries')}</span></div>
                  <div className="stat-card danger"><strong>{filterStats?.blocked_total ?? filterStatus.blocked_total ?? 0}</strong><span>{t('modal.domain.count')}</span></div>
                  <div className="stat-card"><strong>{filterStats?.domains_count ?? filterStatus.domains_count ?? 0}</strong><span>{t('filter.stats.domains')}</span></div>
                </div>

                <div className="filter-dual">
                  <div className="filter-panel">
                    <h3>{t('filter.top.title')}</h3>
                    <div className="filter-scroll">
                      {(filterStats?.top_domains ?? []).length === 0 && <p className="empty">{t('common.no_blocked')}</p>}
                      {(filterStats?.top_domains ?? []).map((item, index) => {
                        const domain = Array.isArray(item) ? item[0] : item.domain;
                        const count = Array.isArray(item) ? item[1] : item.count;
                        const whitelisted = isWhitelistedDomain(String(domain ?? ''));
                        return (
                          <div className="domain-row" key={`${domain}-${index}`}>
                            <span className="domain-name"><em className="domain-rank">{index + 1}.</em>{domain ?? '—'}</span>
                            <strong>{count ?? 0}</strong>
                            <div className="domain-actions">
                              <button className="domain-icon" title={t('domain.inspect.title')} aria-label={t('domain.inspect.title')} onClick={() => openDomainModal({ domain: String(domain ?? ''), count: Number(count ?? 0) })}>🔎</button>
                              <button className="domain-icon" title={t('ai.copy_block.title')} aria-label={t('ai.copy_block.title')} onClick={() => void copyDomainForAI({ domain: String(domain ?? ''), count: Number(count ?? 0) })}>🤖</button>
                              {whitelisted
                                ? <button className="domain-state reblock" title={t('btn.reblock.title')} onClick={() => void modifyFilterWhitelist(String(domain ?? ''), 'remove')}>{t('btn.reblock')}</button>
                                : <button className="domain-state allow" title={t('btn.allow.title')} onClick={() => void modifyFilterWhitelist(String(domain ?? ''), 'add')}>{t('btn.allow')}</button>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="filter-panel">
                    <div className="filter-panel-head">
                      <h3>{t('filter.detail.title')}</h3>
                      <button className="domain-icon" title={t('filter.journal.ai_all.title')} onClick={() => void copyAllBlockedForAI()}>🤖</button>
                    </div>
                    <div className="filter-scroll">
                      {blockedDomains.length === 0 && <p className="empty">{t('common.no_blocked')}</p>}
                      {blockedDomains.slice(0, 50).map((item, index) => (
                        <div className="domain-row detail" key={`${item.domain}-${index}`}>
                          <div className="domain-main">
                            <span className="domain-name">{item.domain ?? '—'}</span>
                            <strong>{item.count ?? 0}</strong>
                          </div>
                          {item.matched_domain && item.matched_domain !== item.domain && <div className="domain-via">{t('common.via')} {item.matched_domain}</div>}
                          <div className="domain-meta">
                            <span>{t('filter.th.rule')} : <code>{item.rule || '—'}</code></span>
                            <span>{t('filter.th.source')} : {(item.sources ?? []).join(', ') || '—'}</span>
                          </div>
                          <div className="domain-actions">
                            <button className="domain-icon" title={t('domain.inspect.title')} onClick={() => openDomainModal(item)}>🔎</button>
                            <button className="domain-icon" title={t('ai.copy_block.title')} onClick={() => void copyDomainForAI(item)}>🤖</button>
                            {item.whitelisted
                              ? <button className="domain-state reblock" title={t('btn.reblock.title')} onClick={() => void reblockDomain(item)}>{t('btn.reblock')}</button>
                              : <button className="domain-state allow" title={t('btn.allow.title')} onClick={() => void authorizeDomain(item)}>{t('btn.allow')}</button>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="whitelist-mgmt">
                  <h3>{t('common.whitelist_mgmt')}</h3>
                  <div className="filter-add-row">
                    <input value={filterDomainInput} onChange={(event) => setFilterDomainInput(event.target.value)} placeholder={t('filter.whitelist.placeholder')} />
                    <button className="secondary" disabled={intrusionAction || !filterDomainInput.trim()} onClick={() => void modifyFilterWhitelist(filterDomainInput.trim(), 'add')}>{t('btn.add')}</button>
                    <button className="secondary danger" disabled={intrusionAction || !filterDomainInput.trim()} onClick={() => void modifyFilterWhitelist(filterDomainInput.trim(), 'remove')}>{t('filter.whitelist.remove')}</button>
                  </div>
                  <div className="filter-search-row">
                    <input value={filterSearch} onChange={(event) => setFilterSearch(event.target.value)} placeholder={t('filter.wl.search.placeholder')} />
                  </div>
                  <div className="whitelist-grid">
                    <div className="wl-block">
                      <div className="whitelist-section-label">{t('filter.wl.section_default')}</div>
                      <div className="whitelist-chips">
                        {activeDefaultDomains.filter((d) => d.toLowerCase().includes(filterSearch.toLowerCase())).map((d) => <button className="ip-chip default" key={d} title={t('filter.wl.default_disable.title')} onClick={() => void modifyFilterWhitelist(d, 'remove')}>{d} <span className="chip-badge">{t('filter.wl.badge_default')}</span> ✕</button>)}
                        {activeDefaultDomains.filter((d) => d.toLowerCase().includes(filterSearch.toLowerCase())).length === 0 && <span className="empty">{t('filter.wl.none')}</span>}
                      </div>
                    </div>
                    <div className="wl-block">
                      <div className="whitelist-section-label">{t('pc.domains.title')}</div>
                      <div className="whitelist-chips">
                        {(filterWhitelist?.custom ?? []).filter((d) => d.toLowerCase().includes(filterSearch.toLowerCase())).map((d) => <button className="ip-chip" key={d} title={t('filter.wl.remove.title')} onClick={() => void modifyFilterWhitelist(d, 'remove')}>{d} ✕</button>)}
                        {(filterWhitelist?.custom ?? []).filter((d) => d.toLowerCase().includes(filterSearch.toLowerCase())).length === 0 && <span className="empty">{t('filter.wl.none')}</span>}
                      </div>
                    </div>
                    <div className="wl-block">
                      <div className="whitelist-section-label">{t('filter.wl.section_disabled')}</div>
                      <div className="whitelist-chips">
                        {(filterWhitelist?.disabled_defaults ?? []).filter((d) => d.toLowerCase().includes(filterSearch.toLowerCase())).map((d) => <button className="ip-chip disabled" key={d} title={t('filter.wl.reactivate.title')} onClick={() => void modifyFilterWhitelist(d, 'add')}>{d} ↺</button>)}
                        {(filterWhitelist?.disabled_defaults ?? []).filter((d) => d.toLowerCase().includes(filterSearch.toLowerCase())).length === 0 && <span className="empty">{t('filter.wl.none')}</span>}
                      </div>
                    </div>
                  </div>
                </div>

              </>
            ) : <p className="empty">{t('filter.unavailable')}</p>}
          </section>
        )}

        {selectedDomain && (activeTab === 'filter' || activeTab === 'adblock' || activeTab === 'parental' || activeTab === 'domestic') && (
          <div className="modal-backdrop" onClick={() => setSelectedDomain(null)}>
            <div className="inspect-modal domain-modal" onClick={(event) => event.stopPropagation()}>
              <button className="modal-close" onClick={() => setSelectedDomain(null)}>×</button>
              <div className="domain-modal-title"><h2>{t('modal.domain.title')}</h2><span className="blocked-badge">{t('modal.domain.badge')}</span></div>
              <label className="domain-field-label">{t('adblock.th.domain')}</label>
              <input className="domain-readonly" readOnly value={selectedDomain.domain ?? ''} />
              <div className="domain-info-grid">
                <p><strong>{t('modal.domain.count')}</strong><br />{selectedDomain.count ?? '—'}</p>
                <p><strong>{t('modal.domain.sources')}</strong><br />{selectedDomain.sources?.join(', ') || '—'}</p>
                <p><strong>{t('modal.domain.first')}</strong><br />{selectedDomain.first_seen ?? '—'}</p>
                <p><strong>{t('modal.domain.last')}</strong><br />{selectedDomain.last_seen ?? '—'}</p>
              </div>
              <label className="domain-field-label">{t('modal.domain.rule')}</label>
              <pre>{selectedDomain.rule || '—'}</pre>

              <h3 className="domain-section-title">{t('modal.domain.info_external')}</h3>
              <button className="primary" disabled={domainEnriching} onClick={() => void enrichDomain()}>
                {domainEnriching ? t('enrich.verifying') : domainDetail?.error ? t('enrich.retry') : domainDetail ? t('enrich.verify_done') : t('modal.domain.verify')}
              </button>
              {domainDetail?.error && <div className="inspection-error">{t('enrich.error', {msg: domainDetail.error})}</div>}
              {domainDetail && !domainDetail.error && (
                <div className="domain-enrich-result">
                  {domainDetail.rdap?.available ? (
                    <>
                      {domainDetail.rdap.registrar && <div><strong>{t('enrich.registrar')}</strong> {domainDetail.rdap.registrar}</div>}
                      {domainDetail.rdap.created && (
                        <div><strong>{t('enrich.created')}</strong> {domainDetail.rdap.created.slice(0, 10)}{(() => {
                          const ageDays = Math.floor((Date.now() - new Date(domainDetail.rdap!.created!.slice(0, 10)).getTime()) / 86400000)
                          return ageDays < 90 ? <span className="enrich-bad">{t('enrich.recent')}</span> : <span className="enrich-muted"> {t('enrich.months_ago', {n: Math.round(ageDays / 30)})}</span>
                        })()}</div>
                      )}
                    </>
                  ) : <div className="enrich-muted">{t('enrich.rdap_unavailable')}</div>}
                  {domainDetail.urlhaus?.available ? (
                    domainDetail.urlhaus.listed
                      ? <div><strong>URLhaus :</strong> <span className="enrich-bad">{t('enrich.urlhaus_listed', {count: domainDetail.urlhaus.url_count ?? 0})}</span></div>
                      : <div><strong>URLhaus :</strong> <span className="enrich-good">{t('enrich.urlhaus_clean')}</span></div>
                  ) : <div className="enrich-muted">{t('enrich.urlhaus_unavailable')}</div>}
                  {domainDetail.dns?.available ? (
                    domainDetail.dns.ips?.length
                      ? <div><strong>{t('enrich.real_ips')}</strong> <code>{domainDetail.dns.ips.join(', ')}</code></div>
                      : <div><strong>DNS :</strong> <span className="enrich-muted">{t('enrich.dns_dead')}</span></div>
                  ) : <div className="enrich-muted">{t('enrich.dns_unavailable')}</div>}
                </div>
              )}

              <div className="domain-section-title">{t('modal.ext_links')}</div>
              <div className="modal-links">
                <a href={`https://www.virustotal.com/gui/domain/${encodeURIComponent(selectedDomain.domain ?? '')}`} target="_blank" rel="noreferrer" title={t('links.vt_domain.title')}>VirusTotal ↗</a>
                <a href={`https://urlscan.io/search/#${encodeURIComponent(selectedDomain.domain ?? '')}`} target="_blank" rel="noreferrer" title={t('links.urlscan.title')}>urlscan.io ↗</a>
                <a href={`https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(selectedDomain.domain ?? '')}`} target="_blank" rel="noreferrer" title={t('links.talos.title')}>Talos ↗</a>
                <a href={`https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(selectedDomain.domain ?? '')}`} target="_blank" rel="noreferrer" title={t('links.sb.title')}>Safe Browsing ↗</a>
                <a href={`https://www.whois.com/whois/${encodeURIComponent(selectedDomain.domain ?? '')}`} target="_blank" rel="noreferrer" title={t('links.whois.title')}>Whois ↗</a>
              </div>
              <div className="modal-footer">
                <button className="ai-copy-button" title={t('ai.copy_block.title')} onClick={() => copyDomainForAI(selectedDomain, domainDetail)}>🤖</button>
                <button className="secondary" onClick={() => setSelectedDomain(null)}>{t('btn.close')}</button>
              </div>
            </div>
          </div>
        )}

        {pinModalOpen && (
          <div className="modal-backdrop" onClick={() => closePinModal()}>
            <div className="inspect-modal pin-modal" onClick={(event) => event.stopPropagation()}>
              <button className="modal-close" onClick={() => closePinModal()}>×</button>
              <h2 style={{ fontSize: '1.05rem' }}>{t('modal.pin.title')}</h2>
              <p className="muted">{t('modal.pin.desc')}</p>
              <input
                type="password"
                className="pin-input"
                inputMode="numeric"
                maxLength={8}
                autoComplete="off"
                placeholder={t('modal.pin.placeholder')}
                value={pinInput}
                onChange={(e) => setPinInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') void pcSubmitPinModal() }}
                autoFocus
              />
              <div className="pin-error">{pinError}</div>
              <div className="modal-footer" style={{ justifyContent: 'flex-end' }}>
                <button className="secondary" onClick={() => void pcSubmitPinModal()}>{t('modal.pin.validate')}</button>
                <button className="secondary" onClick={() => closePinModal()}>{t('btn.cancel')}</button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'adblock' && (
          <section className="panel">
            <h2>{t('tabs.adblock')}</h2>
            <p className="muted">{t('adblock.subtitle')}</p>

            <div className="adblock-actions">
              <button className="secondary" title={t('adblock.btn.refresh.title')} onClick={() => void refreshAdblock()}>{t('btn.refresh')}</button>
              <button className="secondary" disabled={adblockUpdating === 'all'} title={t('adblock.btn.update_enabled.title')} onClick={() => void adblockUpdateList()}>
                {adblockUpdating === 'all' ? t('adblock.downloading') : t('adblock.btn.update_enabled')}
              </button>
              <span className={`adblock-hint ${adblockHintTone}`}>{adblockHint}</span>
            </div>

            <div className={`pc-banner ${adblockLists === null && adblock === null ? 'pc-banner-off' : !adblockLists?.available && !adblock?.available ? 'pc-banner-warn' : adblockRunning ? 'pc-banner-on' : 'pc-banner-off'}`}>
              {adblockLists === null && adblock === null
                ? t('adblock.banner.loading')
                : !adblockLists?.available && !adblock?.available
                  ? <span dangerouslySetInnerHTML={{ __html: t('adblock.banner.unavailable') }} />
                  : adblockRunning
                    ? <span dangerouslySetInnerHTML={{ __html: t('adblock.banner.active', { domains: fmtNum((adblock?.blocked_domains ?? 0)), lists: adblockEnabledCount, blocked: fmtNum((adblock?.blocked_total ?? 0)), sched: adblockSchedText }) }} />
                    : <span dangerouslySetInnerHTML={{ __html: t('adblock.banner.inactive', { lists: adblockEnabledCount, domains: fmtNum((adblock?.blocked_domains ?? 0)), sched: adblockSchedText }) }} />}
            </div>

            <div className="filter-info-banner" dangerouslySetInnerHTML={{ __html: t('adblock.info') }} />

            <div className="pc-card">
              <h4>{t('adblock.lists.title')}</h4>
              <div className="adblock-table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>{t('adblock.th.enabled')}</th>
                      <th>{t('adblock.th.list')}</th>
                      <th>{t('adblock.th.domains')}</th>
                      <th>{t('adblock.th.updated')}</th>
                      <th>{t('adblock.th.status')}</th>
                      <th style={{ textAlign: 'right' }}>{t('adblock.journal.th.action')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {adblockLists === null ? (
                      <tr><td colSpan={6} className="cell-empty">{t('common.loading')}</td></tr>
                    ) : !adblockLists.available ? (
                      <tr><td colSpan={6} className="cell-empty">{t('adblock.lists.unavailable')}</td></tr>
                    ) : adblockListEntries.length === 0 ? (
                      <tr><td colSpan={6} className="cell-empty">{t('adblock.lists.empty')}</td></tr>
                    ) : adblockListEntries.map(([lid, l]) => {
                      const st = LIST_STATUS_STYLES[l.status ?? '']
                      return (
                        <tr key={lid}>
                          <td><input type="checkbox" checked={Boolean(l.enabled)} disabled={adblockUpdating === lid} title={t('adblock.list.check.title')} onChange={(e) => void adblockToggleList(lid, e.target.checked)} /></td>
                          <td className="list-name">
                            {l.name || lid}
                            {l.license && <span className="badge license" title={t('adblock.list.license.title', {license: l.license})}>{l.license}</span>}
                            {l.description && <div className="list-desc">{l.description}</div>}
                          </td>
                          <td>
                            <span className="badge">{fmtNum((l.domains_loaded ?? 0))}</span>
                            {l.file_size_kb != null && <div className="list-size">{t('adblock.kb', {n: fmtNum(Math.round(l.file_size_kb))})}</div>}
                          </td>
                          <td className="list-date">{fmtListDate(l.last_update)}</td>
                          <td><span className="badge" style={{ background: st?.bg ?? '#1f2937', color: st?.fg ?? '#9ca3af', fontWeight: 600 }}>{st ? t(st.label) : (l.status || '?')}</span></td>
                          <td style={{ textAlign: 'right' }}>
                            <button className="secondary compact" disabled={adblockUpdating !== null} title={t('adblock.list.update.title')} onClick={() => void adblockUpdateList(lid)}>
                              {adblockUpdating === lid ? '…' : t('adblock.list.update')}
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pc-card">
              <h4 className="adblock-journal-title">
                <span>{t('adblock.journal.title')}</span>
                <button className="domain-icon" title={t('filter.journal.ai_all.title')} onClick={() => copyAllBlockedForAI()}>🤖</button>
              </h4>
              <div className="adblock-journal-wrap">
                <table className="journal-table">
                  <thead>
                    <tr>
                      <th>{t('adblock.th.domain')}</th>
                      <th>{t('filter.th.requests')}</th>
                      <th>{t('adblock.th.rule')}</th>
                      <th>{t('adblock.th.source')}</th>
                      <th style={{ textAlign: 'right' }}>{t('adblock.journal.th.action')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blockedDomains.length === 0 ? (
                      <tr><td colSpan={5} className="cell-empty">{t('common.no_blocked')}</td></tr>
                    ) : blockedDomains.map((item) => {
                      const isWl = Boolean(item.whitelisted) || isWhitelistedDomain(item.domain ?? '')
                      return (
                        <tr key={item.domain}>
                          <td className="list-name">
                            {item.domain}
                            {item.matched_domain && item.matched_domain !== item.domain && <div className="domain-via">{t('common.via')} {item.matched_domain}</div>}
                          </td>
                          <td><span className="badge" style={{ background: '#7f1d1d', color: '#fecaca', fontWeight: 600 }}>{item.count ?? 0}</span></td>
                          <td>{item.rule ? <code className="rule-code">{item.rule}</code> : <span className="enrich-muted">—</span>}</td>
                          <td className="journal-source">{(item.sources ?? []).join(', ') || '—'}</td>
                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <span className="domain-actions">
                              <button className="domain-icon" title={t('domain.inspect.title')} onClick={() => openDomainModal(item)}>🔎</button>
                              <button className="domain-icon" title={t('ai.copy_block.title')} onClick={() => copyAdblockDomainForAI(item)}>🤖</button>
                              {isWl
                                ? <button className="domain-state reblock" title={t('btn.reblock.title')} onClick={() => void reblockDomain(item)}>{t('btn.reblock')}</button>
                                : <button className="domain-state allow" title={t('btn.allow.title')} onClick={() => void authorizeDomain(item)}>{t('btn.allow')}</button>}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="adblock-footer">{t('adblock.footer')}</div>
          </section>
        )}

        {activeTab === 'parental' && (
          <section className="panel">
            <h2>{t('pc.name.parental')}</h2>
            <p className="muted">{t('parental.subtitle')}</p>

            <div className={`pc-banner ${parental === null ? 'pc-banner-off' : parental.available === false ? 'pc-banner-warn' : parental.enabled ? 'pc-banner-on' : 'pc-banner-off'}`}>
              {parental === null
                ? t('parental.banner.loading')
                : parental.available === false
                  ? t('pc.banner.unavailable')
                  : parental.enabled
                    ? <><span dangerouslySetInnerHTML={{ __html: t('pc.banner.active', {name: t('pc.name.parental')}) }} />{parental.pin_set ? t('pc.pin.defined') : t('pc.pin.missing')}</>
                    : <><span dangerouslySetInnerHTML={{ __html: t('pc.banner.inactive', {name: t('pc.name.parental')}) }} />{parental.pin_set ? t('pc.pin.defined') : t('pc.pin.missing')}</>}
            </div>

            <div className="adblock-actions">
              <button
                className="secondary"
                style={{ background: parental?.enabled ? '#b91c1c' : '#1d4ed8', borderColor: 'transparent', color: '#fff' }}
                disabled={parental?.available === false || !parental?.pin_set}
                title={!parental?.pin_set ? t('pc.pin.title_set_here') : t('pc.pin.title_required')}
                onClick={() => void pcToggleScope('parental')}
              >
                {t(parental?.enabled ? 'pc.toggle.disable' : 'pc.toggle.enable', {name: t('pc.name.parental')})}
              </button>
              <button className="secondary" title={t('parental.btn.pin.title')} onClick={() => setPinCardOpen((v) => !v)}>
                {parental?.pin_set ? t('pin.btn.change') : t('pin.btn.define')}
              </button>
              <button className="secondary" title={t('domestic.btn.refresh.title')} onClick={() => void refreshPcScope('parental')}>{t('btn.refresh')}</button>
              <span className="adblock-hint warn">{parentalHint}</span>
            </div>

            {(pinCardOpen || (parental && !parental.pin_set)) && (
              <div className="pc-card">
                <h4>{parental?.pin_set ? t('pin.card.title_change') : t('parental.pin.title_define')}</h4>
                {parental?.pin_set && (
                  <label className="settings-row"><span>{t('parental.pin.old')}</span>
                    <input type="password" inputMode="numeric" maxLength={8} autoComplete="off" value={pinOld} onChange={(e) => setPinOld(e.target.value)} />
                  </label>
                )}
                <label className="settings-row"><span>{t('parental.pin.new')}</span>
                  <input type="password" inputMode="numeric" maxLength={8} autoComplete="off" value={pinNew} onChange={(e) => setPinNew(e.target.value)} />
                </label>
                <label className="settings-row"><span>{t('parental.pin.confirm')}</span>
                  <input type="password" inputMode="numeric" maxLength={8} autoComplete="off" value={pinConfirm} onChange={(e) => setPinConfirm(e.target.value)} />
                </label>
                <button className="secondary" title={t('parental.pin.submit.title')} onClick={() => void pcSubmitPin()}>{t('parental.pin.submit')}</button>
                <span className={`adblock-hint ${pinMsgOk ? 'ok' : 'err'}`} style={{ marginLeft: '.6rem' }}>{pinMsg}</span>
              </div>
            )}

            <div className="pc-card">
              <h4>{t('parental.cats.title')}</h4>
              <p className="muted" style={{ marginTop: 0 }} dangerouslySetInnerHTML={{ __html: t('parental.cats.hint') }} />
              <div className="adblock-table-wrap" style={{ maxHeight: '420px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>{t('parental.th.filter')}</th>
                      <th>{t('parental.th.category')}</th>
                      <th>{t('parental.th.mode')}</th>
                      <th>{t('parental.th.params')}</th>
                      <th>{t('parental.th.usage')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parental === null ? (
                      <tr><td colSpan={5} className="cell-empty">{t('common.loading')}</td></tr>
                    ) : Object.keys(pcDraftCats).length === 0 ? (
                      <tr><td colSpan={5} className="cell-empty">{t('pc.cats.none')}</td></tr>
                    ) : Object.entries(pcDraftCats).map(([key, draft]) => {
                      const label = t(PARENTAL_CATS.find(([k]) => k === key)?.[1] ?? key)
                      const info = parental?.lists?.[key]
                      const usage = parental?.quotas?.[`cat:${key}`]
                      return (
                        <tr key={key}>
                          <td><input type="checkbox" checked={draft.enabled} title={t('pc.cat.enable.title')} onChange={(e) => updatePcCat('parental', key, { enabled: e.target.checked })} /></td>
                          <td>
                            <strong className="list-name">{label}</strong>
                            {info?.count != null && <div className="pc-quota-usage">{t('pc.cat.count', {count: info.count, src: info.source === 'curated' ? t('pc.src.internal') : t('pc.src.remote')})}{info.count === 0 ? t('pc.cat.download_first') : ''}</div>}
                          </td>
                          <td>
                            <select className="pc-select" value={draft.mode} title={t('pc.cat.mode.title')} onChange={(e) => updatePcCat('parental', key, { mode: e.target.value as PcCatDraft['mode'] })}>
                              <option value="blocked">{t('pc.mode.blocked')}</option>
                              <option value="window">{t('pc.mode.window')}</option>
                              <option value="quota">{t('pc.mode.quota')}</option>
                            </select>
                          </td>
                          <td>
                            {draft.mode === 'quota' && (
                              <span className="pc-inline">
                                <input type="number" className="pc-input" min={5} step={5} style={{ width: '4.5rem' }} title={t('pc.quota.title')} value={draft.quota} onChange={(e) => updatePcCat('parental', key, { quota: parseInt(e.target.value, 10) || 0 })} />
                                <span className="pc-quota-usage">{t('pc.quota.per_day')}</span>
                              </span>
                            )}
                            {draft.mode === 'window' && (
                              <span className="pc-inline" style={{ flexWrap: 'wrap' }}>
                                {draft.windows.map((w, wi) => (
                                  <span className="pc-win-row" key={wi}>
                                    <input type="time" className="pc-input" value={w[0]} onChange={(e) => updatePcCat('parental', key, { windows: draft.windows.map((x, xi) => xi === wi ? [e.target.value, x[1]] : x) })} />
                                    <span style={{ color: '#64748b' }}>–</span>
                                    <input type="time" className="pc-input" value={w[1]} onChange={(e) => updatePcCat('parental', key, { windows: draft.windows.map((x, xi) => xi === wi ? [x[0], e.target.value] : x) })} />
                                    <button type="button" className="domain-icon" title={t('pc.win.remove.title')} onClick={() => updatePcCat('parental', key, { windows: draft.windows.filter((_, xi) => xi !== wi) })}>✕</button>
                                  </span>
                                ))}
                                <button type="button" className="domain-icon" title={t('pc.win.add.title')} onClick={() => updatePcCat('parental', key, { windows: [...draft.windows, ['18:00', '19:00']] })}>{t('pc.win.add')}</button>
                              </span>
                            )}
                            {draft.mode === 'blocked' && <span className="pc-quota-usage">{t('pc.blocked_permanent')}</span>}
                          </td>
                          <td className="pc-quota-usage">{usage ? t('pc.cat.used', {used: usage.used ?? 0, quota: usage.quota ?? 0}) : ''}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pc-card">
              <h4>{t('pc.domains.title')}</h4>
              <p className="muted" style={{ marginTop: 0 }}>{t('parental.domains.hint')}</p>
              <div className="pc-inline" style={{ flexWrap: 'wrap' }}>
                <input type="text" className="pc-input" placeholder={t('pc.domain.placeholder')} title={t('pc.domain.title')} style={{ maxWidth: '220px' }} value={pcDomInput} onChange={(e) => setPcDomInput(e.target.value)} />
                <select className="pc-select" title={t('pc.domain.mode.title')} value={pcDomMode} onChange={(e) => setPcDomMode(e.target.value as PcCatDraft['mode'])}>
                  <option value="blocked">{t('pc.mode.blocked')}</option>
                  <option value="window">{t('pc.mode.window')}</option>
                  <option value="quota">{t('pc.mode.quota')}</option>
                </select>
                {pcDomMode === 'quota' && (
                  <span className="pc-inline">
                    <input type="number" className="pc-input" min={5} step={5} style={{ width: '4.5rem' }} title={t('pc.quota.title')} value={pcDomQuota} onChange={(e) => setPcDomQuota(parseInt(e.target.value, 10) || 0)} />
                    <span className="pc-quota-usage">{t('pc.quota.per_day')}</span>
                  </span>
                )}
                {pcDomMode === 'window' && (
                  <span className="pc-inline">
                    <span className="pc-quota-usage">{t('pc.window.from')}</span>
                    <input type="time" className="pc-input" value={pcDomWinStart} onChange={(e) => setPcDomWinStart(e.target.value)} />
                    <span className="pc-quota-usage">{t('pc.window.to')}</span>
                    <input type="time" className="pc-input" value={pcDomWinEnd} onChange={(e) => setPcDomWinEnd(e.target.value)} />
                  </span>
                )}
                <button className="secondary" title={t('pc.domain.add.title')} onClick={() => void pcAddDomainRule('parental')}>{t('pc.domain.add')}</button>
              </div>
              <div style={{ marginTop: '.6rem' }}>
                {Object.keys(pcDraftDomains).length === 0 ? (
                  <span className="adblock-hint">{t('pc.domain.none')}</span>
                ) : Object.keys(pcDraftDomains).sort().map((dom) => {
                  const rule = pcDraftDomains[dom]
                  const params = rule.mode === 'quota' ? ` · ${t('pc.quota.min_per_day', {n: rule.quota_minutes ?? 0})}` : rule.mode === 'window' && rule.windows?.length ? ` · ${rule.windows.map((w) => `${w[0]}–${w[1]}`).join(', ')}` : ''
                  return (
                    <span className="pc-chip" key={dom}>
                      <span><strong>{dom}</strong> — {t(PC_MODE_LABELS[rule.mode ?? 'blocked'])}{params}</span>
                      <button type="button" className="pc-chip-x" title={t('pc.domain.remove.title')} onClick={() => void pcRemoveDomainRule('parental', dom)}>✕</button>
                    </span>
                  )
                })}
              </div>
            </div>

            <div className="adblock-actions" style={{ marginTop: '1rem' }}>
              <button className="secondary" title={t('parental.btn.save_rules.title')} onClick={() => void pcSaveRules('parental')}>{t('pc.btn.save_rules')}</button>
              <button className="secondary danger" title={t('parental.btn.reset.title')} onClick={() => void pcResetScope('parental')}>{t('pc.btn.reset')}</button>
              <span className={`adblock-hint ${pcRulesTone}`}>{pcRulesStatus}</span>
            </div>

            <div className="pc-card">
              <h4 className="adblock-journal-title">
                <span>{t('parental.journal.title')}</span>
                <button className="domain-icon" title={t('parental.journal.ai_all.title')} onClick={() => copyPcJournalForAI('parental')}>🤖</button>
              </h4>
              <div className="adblock-table-wrap" style={{ maxHeight: '320px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>{t('adblock.th.domain')}</th>
                      <th>{t('parental.th.blocks')}</th>
                      <th>{t('parental.th.rule')}</th>
                      <th>{t('domestic.th.reason')}</th>
                      <th>{t('modal.domain.last')}</th>
                      <th style={{ textAlign: 'right' }}>{t('parental.th.actions')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parentalJournal === null ? (
                      <tr><td colSpan={6} className="cell-empty" style={{ color: '#fca5a5' }}>{t('pc.journal.unavailable')}</td></tr>
                    ) : parentalJournal.length === 0 ? (
                      <tr><td colSpan={6} className="cell-empty">{t('pc.journal.empty')}</td></tr>
                    ) : parentalJournal.map((item) => (
                      <tr key={item.domain}>
                        <td className="list-name">
                          {item.domain}
                          {item.matched_domain && item.matched_domain !== item.domain && <div className="domain-via">{t('common.via')} {item.matched_domain}</div>}
                        </td>
                        <td><span className="badge" style={{ background: '#7f1d1d', color: '#fecaca', fontWeight: 600 }}>{item.count ?? 0}</span></td>
                        <td>{item.rule ? <code className="rule-code">{item.rule}</code> : <span className="enrich-muted">—</span>}</td>
                        <td style={{ fontSize: '.78rem', color: '#cbd5e1' }}>{item.reason || '—'}</td>
                        <td className="list-date">{item.last_seen || '—'}</td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <span className="domain-actions">
                            <button className="domain-icon" title={t('domain.inspect.title')} onClick={() => openDomainModal(item)}>🔎</button>
                            <button className="domain-icon" title={t('ai.copy_block.title')} onClick={() => copyPcItemForAI('parental', item)}>🤖</button>
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}

        {activeTab === 'domestic' && (
          <section className="panel">
            <h2>{t('tabs.domestic')}</h2>
            <p className="muted">{t('domestic.subtitle')}</p>

            <div className={`pc-banner ${domestic === null ? 'pc-banner-off' : domestic.available === false ? 'pc-banner-warn' : domestic.enabled ? 'pc-banner-on' : 'pc-banner-off'}`}>
              {domestic === null
                ? t('domestic.banner.loading')
                : domestic.available === false
                  ? t('pc.banner.unavailable')
                  : domestic.enabled
                    ? <><span dangerouslySetInnerHTML={{ __html: t('pc.banner.active', {name: t('pc.name.domestic')}) }} />{domestic.pin_set ? t('pc.pin.defined') : t('pc.pin.missing')}</>
                    : <><span dangerouslySetInnerHTML={{ __html: t('pc.banner.inactive', {name: t('pc.name.domestic')}) }} />{domestic.pin_set ? t('pc.pin.defined') : t('pc.pin.missing')}</>}
            </div>

            <div className="adblock-actions">
              <button
                className="secondary"
                style={{ background: domestic?.enabled ? '#b91c1c' : '#1d4ed8', borderColor: 'transparent', color: '#fff' }}
                disabled={domestic?.available === false || !domestic?.pin_set}
                title={!domestic?.pin_set ? t('pc.pin.title_set') : t('domestic.btn.toggle.title')}
                onClick={() => void pcToggleScope('domestic')}
              >
                {t(domestic?.enabled ? 'pc.toggle.disable' : 'pc.toggle.enable', {name: t('pc.name.domestic')})}
              </button>
              <button className="secondary" title={t('domestic.btn.refresh.title')} onClick={() => void refreshPcScope('domestic')}>{t('btn.refresh')}</button>
              <span className="adblock-hint warn">{domesticHint}</span>
            </div>

            <div className="pc-card">
              <h4>{t('domestic.cats.title')}</h4>
              <p className="muted" style={{ marginTop: 0 }}>{t('domestic.cats.hint')}</p>
              <div className="adblock-table-wrap" style={{ maxHeight: '420px' }}>
                <table>
                  <thead>
                    <tr>
                      <th title={t('parental.th.filter.title')}>{t('parental.th.filter')}</th>
                      <th title={t('domestic.th.category.title')}>{t('parental.th.category')}</th>
                      <th title={t('parental.th.mode.title')}>{t('parental.th.mode')}</th>
                      <th title={t('domestic.th.params.title')}>{t('parental.th.params')}</th>
                      <th title={t('domestic.th.usage.title')}>{t('parental.th.usage')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {domestic === null ? (
                      <tr><td colSpan={5} className="cell-empty">{t('common.loading')}</td></tr>
                    ) : Object.keys(domDraftCats).length === 0 ? (
                      <tr><td colSpan={5} className="cell-empty">{t('pc.cats.none')}</td></tr>
                    ) : Object.entries(domDraftCats).map(([key, draft]) => {
                      const label = t(DOMESTIC_CATS.find(([k]) => k === key)?.[1] ?? key)
                      const info = domestic?.lists?.[key]
                      const usage = domestic?.quotas?.[`cat:${key}`]
                      return (
                        <tr key={key}>
                          <td><input type="checkbox" checked={draft.enabled} title={t('pc.cat.enable.title')} onChange={(e) => updatePcCat('domestic', key, { enabled: e.target.checked })} /></td>
                          <td>
                            <strong className="list-name">{label}</strong>
                            {info?.count != null && <div className="pc-quota-usage">{t('pc.cat.count', {count: info.count, src: info.source === 'curated' ? t('pc.src.internal') : t('pc.src.remote')})}{info.count === 0 ? t('pc.cat.download_first') : ''}</div>}
                          </td>
                          <td>
                            <select className="pc-select" value={draft.mode} title={t('pc.cat.mode.title')} onChange={(e) => updatePcCat('domestic', key, { mode: e.target.value as PcCatDraft['mode'] })}>
                              <option value="blocked">{t('pc.mode.blocked')}</option>
                              <option value="window">{t('pc.mode.window')}</option>
                              <option value="quota">{t('pc.mode.quota')}</option>
                            </select>
                          </td>
                          <td>
                            {draft.mode === 'quota' && (
                              <span className="pc-inline">
                                <input type="number" className="pc-input" min={5} step={5} style={{ width: '4.5rem' }} title={t('pc.quota.title')} value={draft.quota} onChange={(e) => updatePcCat('domestic', key, { quota: parseInt(e.target.value, 10) || 0 })} />
                                <span className="pc-quota-usage">{t('pc.quota.per_day')}</span>
                              </span>
                            )}
                            {draft.mode === 'window' && (
                              <span className="pc-inline" style={{ flexWrap: 'wrap' }}>
                                {draft.windows.map((w, wi) => (
                                  <span className="pc-win-row" key={wi}>
                                    <input type="time" className="pc-input" value={w[0]} onChange={(e) => updatePcCat('domestic', key, { windows: draft.windows.map((x, xi) => xi === wi ? [e.target.value, x[1]] : x) })} />
                                    <span style={{ color: '#64748b' }}>–</span>
                                    <input type="time" className="pc-input" value={w[1]} onChange={(e) => updatePcCat('domestic', key, { windows: draft.windows.map((x, xi) => xi === wi ? [x[0], e.target.value] : x) })} />
                                    <button type="button" className="domain-icon" title={t('pc.win.remove.title')} onClick={() => updatePcCat('domestic', key, { windows: draft.windows.filter((_, xi) => xi !== wi) })}>✕</button>
                                  </span>
                                ))}
                                <button type="button" className="domain-icon" title={t('pc.win.add.title')} onClick={() => updatePcCat('domestic', key, { windows: [...draft.windows, ['18:00', '19:00']] })}>{t('pc.win.add')}</button>
                              </span>
                            )}
                            {draft.mode === 'blocked' && <span className="pc-quota-usage">{t('pc.blocked_permanent')}</span>}
                          </td>
                          <td className="pc-quota-usage">{usage ? t('pc.cat.used', {used: usage.used ?? 0, quota: usage.quota ?? 0}) : ''}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pc-card">
              <h4>{t('pc.domains.title')}</h4>
              <p className="muted" style={{ marginTop: 0 }}>{t('parental.domains.hint')}</p>
              <div className="pc-inline" style={{ flexWrap: 'wrap' }}>
                <input type="text" className="pc-input" placeholder={t('pc.domain.placeholder')} title={t('pc.domain.title')} style={{ maxWidth: '220px' }} value={domDomInput} onChange={(e) => setDomDomInput(e.target.value)} />
                <select className="pc-select" title={t('pc.domain.mode.title')} value={domDomMode} onChange={(e) => setDomDomMode(e.target.value as PcCatDraft['mode'])}>
                  <option value="blocked">{t('pc.mode.blocked')}</option>
                  <option value="window">{t('pc.mode.window')}</option>
                  <option value="quota">{t('pc.mode.quota')}</option>
                </select>
                {domDomMode === 'quota' && (
                  <span className="pc-inline">
                    <input type="number" className="pc-input" min={5} step={5} style={{ width: '4.5rem' }} title={t('pc.quota.title')} value={domDomQuota} onChange={(e) => setDomDomQuota(parseInt(e.target.value, 10) || 0)} />
                    <span className="pc-quota-usage">{t('pc.quota.per_day')}</span>
                  </span>
                )}
                {domDomMode === 'window' && (
                  <span className="pc-inline">
                    <span className="pc-quota-usage">{t('pc.window.from')}</span>
                    <input type="time" className="pc-input" value={domDomWinStart} onChange={(e) => setDomDomWinStart(e.target.value)} />
                    <span className="pc-quota-usage">{t('pc.window.to')}</span>
                    <input type="time" className="pc-input" value={domDomWinEnd} onChange={(e) => setDomDomWinEnd(e.target.value)} />
                  </span>
                )}
                <button className="secondary" title={t('pc.domain.add.title')} onClick={() => void pcAddDomainRule('domestic')}>{t('pc.domain.add')}</button>
              </div>
              <div style={{ marginTop: '.6rem' }}>
                {Object.keys(domDraftDomains).length === 0 ? (
                  <span className="adblock-hint">{t('pc.domain.none')}</span>
                ) : Object.keys(domDraftDomains).sort().map((dom) => {
                  const rule = domDraftDomains[dom]
                  const params = rule.mode === 'quota' ? ` · ${t('pc.quota.min_per_day', {n: rule.quota_minutes ?? 0})}` : rule.mode === 'window' && rule.windows?.length ? ` · ${rule.windows.map((w) => `${w[0]}–${w[1]}`).join(', ')}` : ''
                  return (
                    <span className="pc-chip" key={dom}>
                      <span><strong>{dom}</strong> — {t(PC_MODE_LABELS[rule.mode ?? 'blocked'])}{params}</span>
                      <button type="button" className="pc-chip-x" title={t('pc.domain.remove.title')} onClick={() => void pcRemoveDomainRule('domestic', dom)}>✕</button>
                    </span>
                  )
                })}
              </div>
            </div>

            <div className="adblock-actions" style={{ marginTop: '1rem' }}>
              <button className="secondary" title={t('domestic.btn.save_rules.title')} onClick={() => void pcSaveRules('domestic')}>{t('pc.btn.save_rules')}</button>
              <button className="secondary danger" title={t('domestic.btn.reset.title')} onClick={() => void pcResetScope('domestic')}>{t('pc.btn.reset')}</button>
              <span className={`adblock-hint ${domRulesTone}`}>{domRulesStatus}</span>
            </div>

            <div className="pc-card">
              <h4>{t('domestic.cookies.title')}</h4>
              <div className="help-box help-box-warn" style={{ marginTop: 0 }}>{t('domestic.cookies.warn')}</div>
              <div className="adblock-actions" style={{ marginTop: '.75rem' }}>
                <button className="secondary" disabled={cookieScanning} title={t('domestic.cookies.scan.title')} onClick={() => void domesticScanCookies()}>{t('domestic.cookies.scan')}</button>
                <button className="secondary" style={{ background: '#b91c1c', borderColor: 'transparent', color: '#fff' }} disabled={!cookieFindings?.length || cookiePurging} title={t('domestic.cookies.purge.title')} onClick={() => void domesticPurgeCookies()}>{t('domestic.cookies.purge')}</button>
                <span className={`adblock-hint ${cookieTone}`}>{cookieStatus}</span>
              </div>
              {cookieFindings !== null && cookieFindings.length > 0 && (
                <div style={{ maxHeight: '280px', overflowY: 'auto', marginTop: '.75rem', border: '1px solid #1e293b', borderRadius: '.5rem' }}>
                  <table style={{ marginTop: 0 }}>
                    <thead>
                      <tr>
                        <th><input type="checkbox" checked={cookieFindings.every((_, i) => cookieChecked[i])} title={t('cookies.select_all.title')} onChange={(e) => { const next: Record<number, boolean> = {}; cookieFindings.forEach((_, i) => { next[i] = e.target.checked }); setCookieChecked(next) }} /></th>
                        <th>{t('cookies.th.profile')}</th>
                        <th title={t('cookies.host.title')}>{t('cookies.th.host')}</th>
                        <th>{t('cookies.th.name')}</th>
                        <th title={t('cookies.domain.title')}>{t('cookies.th.domain')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {['chrome', 'edge', 'firefox'].concat([...new Set(cookieFindings.map((f) => f.browser ?? ''))].filter((b) => b && !['chrome', 'edge', 'firefox'].includes(b))).map((browser) => {
                        const idxs = cookieFindings.map((f, i) => ({ f, i })).filter(({ f }) => (f.browser ?? '') === browser)
                        if (!idxs.length) return null
                        return [
                          <tr key={`group-${browser}`}><td colSpan={5} style={{ background: '#0f172a', color: '#93c5fd', fontWeight: 600 }}>{t('cookies.browser_group', {label: COOKIE_BROWSER_LABELS[browser] ?? browser, count: idxs.length})}</td></tr>,
                          ...idxs.map(({ f, i }) => (
                            <tr key={i}>
                              <td><input type="checkbox" checked={Boolean(cookieChecked[i])} onChange={(e) => setCookieChecked((cur) => ({ ...cur, [i]: e.target.checked }))} /></td>
                              <td style={{ fontSize: '.78rem', color: '#9ca3af' }}>{f.profile || '—'}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: '.78rem', color: '#e2e8f0', wordBreak: 'break-all' }}>{f.host_key || ''}</td>
                              <td style={{ fontSize: '.78rem', color: '#cbd5e1', wordBreak: 'break-all' }}>{f.cookie_name || ''}</td>
                              <td style={{ fontSize: '.78rem', color: '#93c5fd' }}>{f.matched_domain || ''}</td>
                            </tr>
                          )),
                        ]
                      })}
                    </tbody>
                  </table>
                </div>
              )}
              {cookieReport && (
                <div style={{ marginTop: '.6rem' }}>
                  <div style={{ color: '#86efac' }}><strong>{t('cookies.purged', {count: cookieReport.deleted_total ?? 0})}</strong></div>
                  {Object.entries(cookieReport.browsers ?? {}).map(([b, e]) => (
                    <div key={b} style={{ fontSize: '.8rem', color: '#cbd5e1' }}>{t('cookies.browser_line', {label: COOKIE_BROWSER_LABELS[b] ?? b, status: t(COOKIE_STATUS_LABELS[e.status ?? ''] ?? 'common.na'), count: e.deleted ?? 0})}</div>
                  ))}
                </div>
              )}
              {cookieError && <div style={{ color: '#fca5a5', fontSize: '.82rem', marginTop: '.6rem' }}>{cookieError}</div>}
            </div>

            <div className="pc-card">
              <h4 className="adblock-journal-title">
                <span>{t('domestic.journal.title')}</span>
                <button className="domain-icon" title={t('domestic.journal.ai_all.title')} onClick={() => copyPcJournalForAI('domestic')}>🤖</button>
              </h4>
              <div className="adblock-table-wrap" style={{ maxHeight: '320px' }}>
                <table>
                  <thead>
                    <tr>
                      <th title={t('filter.th.domain.title')}>{t('adblock.th.domain')}</th>
                      <th title={t('parental.th.blocks.title')}>{t('parental.th.blocks')}</th>
                      <th title={t('parental.th.rule.title')}>{t('parental.th.rule')}</th>
                      <th title={t('domestic.th.reason.title')}>{t('domestic.th.reason')}</th>
                      <th title={t('parental.th.last.title')}>{t('modal.domain.last')}</th>
                      <th style={{ textAlign: 'right' }} title={t('parental.th.actions.title')}>{t('parental.th.actions')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {domesticJournal === null ? (
                      <tr><td colSpan={6} className="cell-empty" style={{ color: '#fca5a5' }}>{t('pc.journal.unavailable')}</td></tr>
                    ) : domesticJournal.length === 0 ? (
                      <tr><td colSpan={6} className="cell-empty">{t('pc.journal.empty')}</td></tr>
                    ) : domesticJournal.map((item) => (
                      <tr key={item.domain}>
                        <td className="list-name">
                          {item.domain}
                          {item.matched_domain && item.matched_domain !== item.domain && <div className="domain-via">{t('common.via')} {item.matched_domain}</div>}
                        </td>
                        <td><span className="badge" style={{ background: '#7f1d1d', color: '#fecaca', fontWeight: 600 }}>{item.count ?? 0}</span></td>
                        <td>{item.rule ? <code className="rule-code">{item.rule}</code> : <span className="enrich-muted">—</span>}</td>
                        <td style={{ fontSize: '.78rem', color: '#cbd5e1' }}>{item.reason || '—'}</td>
                        <td className="list-date">{item.last_seen || '—'}</td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <span className="domain-actions">
                            <button className="domain-icon" title={t('domain.inspect.title')} onClick={() => openDomainModal(item)}>🔎</button>
                            <button className="domain-icon" title={t('ai.copy_block.title')} onClick={() => copyPcItemForAI('domestic', item)}>🤖</button>
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}

        {activeTab === 'help' && (
          <section className="panel">
            <div className="help-layout">
              <nav className="help-nav">
                <div className="help-nav-title">{t('help.nav.title')}</div>
                {HELP_SECTIONS.map(([id, labelKey]) => (
                  <button key={id} type="button" className={`help-nav-btn ${helpSection === id ? 'active' : ''}`} onClick={() => setHelpSection(id)}>{t(labelKey)}</button>
                ))}
              </nav>
              <div className="help-content">
                {helpSection === 'help-welcome' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.welcome.title')}</h4>
                <p>${t('help.welcome.intro')}</p>
                <ul>
                    <li>${t('help.welcome.li1')}</li>
                    <li>${t('help.welcome.li2')}</li>
                    <li>${t('help.welcome.li3')}</li>
                </ul>
                <p>${t('help.welcome.nav')}</p>
                <div class="help-box help-box-info">${t('help.welcome.box')}</div>` }} />
                )}

                {helpSection === 'help-risk' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.risk.title')}</h4>
                <p>${t('help.risk.intro')}</p>
                <table class="help-table">
                    <tr><td><span class="badge" style="background:#7f1d1d;color:#fecaca;">${t('risk.critical')}</span></td><td>${t('help.risk.critical')}</td></tr>
                    <tr><td><span class="badge" style="background:#78350f;color:#fde68a;">${t('risk.unexpected')}</span></td><td>${t('help.risk.unexpected')}</td></tr>
                    <tr><td><span class="badge" style="background:#14532d;color:#bbf7d0;">${t('risk.protected')}</span></td><td>${t('help.risk.protected')}</td></tr>
                    <tr><td><span class="badge" style="background:#991b1b;color:#fecaca;">${t('risk.vulnerable')}</span></td><td>${t('help.risk.vulnerable')}</td></tr>
                </table>
                <div class="help-box help-box-warn">${t('help.risk.box')}</div>` }} />
                )}

                {helpSection === 'help-port' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.port.title')}</h4>
                <ol>
                    <li>${t('help.port.li1')}</li>
                    <li>${t('help.port.li2')}</li>
                    <li>${t('help.port.li3')}</li>
                    <li>${t('help.port.li4')}</li>
                    <li>${t('help.port.li5')}</li>
                </ol>
                <div class="help-box help-box-info">${t('help.port.box')}</div>` }} />
                )}

                {helpSection === 'help-broken' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.broken.title')}</h4>
                <p>${t('help.broken.intro')}</p>
                <ol>
                    <li>${t('help.broken.li1')}</li>
                    <li>${t('help.broken.li2')}</li>
                    <li>${t('help.broken.li3')}</li>
                    <li>${t('help.broken.li4')}</li>
                </ol>
                <div class="help-box help-box-info">${t('help.broken.box')}</div>` }} />
                )}

                {helpSection === 'help-filter' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.filter.title')}</h4>
                <ul>
                    <li>${t('help.filter.li1')}</li>
                    <li>${t('help.filter.li2')}</li>
                    <li>${t('help.filter.li3')}</li>
                    <li>${t('help.filter.li4')}</li>
                    <li>${t('help.filter.li5')}</li>
                </ul>
                <p style="margin-top: 0.6rem;">${t('help.filter.actions_intro')}</p>
                <ul>
                    <li>${t('help.filter.act1')}</li>
                    <li>${t('help.filter.act2')}</li>
                    <li>${t('help.filter.act3')}</li>
                </ul>` }} />
                )}

                {helpSection === 'help-parental' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.parental.title')}</h4>
                <p>${t('help.parental.intro')}</p>
                <ul>
                    <li>${t('help.parental.li1')}</li>
                    <li>${t('help.parental.li2')}</li>
                </ul>
                <p>${t('help.parental.keypoints')}</p>
                <ul>
                    <li>${t('help.parental.kp1')}</li>
                    <li>${t('help.parental.kp2')}</li>
                    <li>${t('help.parental.kp3')}</li>
                    <li>${t('help.parental.kp4')}</li>
                    <li>${t('help.parental.kp5')}</li>
                </ul>
                <div class="help-box help-box-warn">${t('help.parental.box')}</div>` }} />
                )}

                {helpSection === 'help-plans' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.plans.title')}</h4>
                <ol>
                    <li>${t('help.plans.li1')}</li>
                    <li>${t('help.plans.li2')}</li>
                    <li>${t('help.plans.li3')}</li>
                    <li>${t('help.plans.li4')}</li>
                </ol>
                <div class="help-box help-box-warn">${t('help.plans.box')}</div>` }} />
                )}

                {helpSection === 'help-ai' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.ai.title')}</h4>
                <p>${t('help.ai.intro')}</p>
                <p>${t('help.ai.levels')}</p>
                <ul>
                    <li>${t('help.ai.li1')}</li>
                    <li>${t('help.ai.li2')}</li>
                </ul>
                <div class="help-box help-box-warn">${t('help.ai.box')}</div>` }} />
                )}

                {helpSection === 'help-glossary' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.glossary.title')}</h4>
                <table class="help-table">
                    <tr><td><strong>${t('help.glossary.port.term')}</strong></td><td>${t('help.glossary.port.def')}</td></tr>
                    <tr><td><strong>LISTENING</strong></td><td>${t('help.glossary.listening.def')}</td></tr>
                    <tr><td><strong>0.0.0.0</strong></td><td>${t('help.glossary.zero.def')}</td></tr>
                    <tr><td><strong>127.0.0.1</strong></td><td>${t('help.glossary.loopback.def')}</td></tr>
                    <tr><td><strong>PID</strong></td><td>${t('help.glossary.pid.def')}</td></tr>
                    <tr><td><strong>DNS</strong></td><td>${t('help.glossary.dns.def')}</td></tr>
                    <tr><td><strong>${t('help.glossary.whitelist.term')}</strong></td><td>${t('help.glossary.whitelist.def')}</td></tr>
                    <tr><td><strong>${t('help.glossary.tracker.term')}</strong></td><td>${t('help.glossary.tracker.def')}</td></tr>
                    <tr><td><strong>SHA-256</strong></td><td>${t('help.glossary.sha.def')}</td></tr>
                    <tr><td><strong>DGA</strong></td><td>${t('help.glossary.dga.def')}</td></tr>
                    <tr><td><strong>${t('help.glossary.fw.term')}</strong></td><td>${t('help.glossary.fw.def')}</td></tr>
                </table>` }} />
                )}

                {helpSection === 'help-links' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.links.title')}</h4>
                <table class="help-table">
                    <tr><td><strong>VirusTotal</strong></td><td>${t('help.links.vt')}</td></tr>
                    <tr><td><strong>MalwareBazaar</strong></td><td>${t('help.links.mb')}</td></tr>
                    <tr><td><strong>SpeedGuide</strong></td><td>${t('help.links.sg')}</td></tr>
                    <tr><td><strong>SANS ISC</strong></td><td>${t('help.links.sans')}</td></tr>
                    <tr><td><strong>ProcessLibrary</strong></td><td>${t('help.links.pl')}</td></tr>
                    <tr><td><strong>ShieldsUP (GRC)</strong></td><td>${t('help.links.grc')}</td></tr>
                </table>` }} />
                )}

                {helpSection === 'help-faq' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.faq.title')}</h4>
                <p>${t('help.faq.q1')}</p>
                <p>${t('help.faq.q2')}</p>
                <p>${t('help.faq.q3')}</p>
                <p>${t('help.faq.q4')}</p>
                <p>${t('help.faq.q5')}</p>` }} />
                )}

                {helpSection === 'help-liability' && (
                  <section className="help-section" dangerouslySetInnerHTML={{ __html: `<h4>${t('help.liability.title')}</h4>
                <div class="help-box help-box-warn">${t('help.liability.box')}</div>
                <p style="margin-top: 0.6rem;">${t('help.liability.lock')}</p>

                <h4 style="margin-top: 1rem;">${t('help.liability.pc_title')}</h4>
                <div class="help-box help-box-warn">${t('help.liability.pc_box')}</div>
                <ul style="margin: 0.5rem 0 0; padding-left: 1.2rem; font-size: 0.82rem; color: #9ca3af;">
                    <li>${t('help.liability.li1')}</li>
                    <li>${t('help.liability.li2')}</li>
                    <li>${t('help.liability.li3')}</li>
                    <li>${t('help.liability.li4')}</li>
                    <li>${t('help.liability.li5')}</li>
                    <li>${t('help.liability.li6')}</li>
                </ul>` }} />
                )}
              </div>
            </div>
          </section>
        )}

        {activeTab === 'alerts' && (
          <section className="panel">
            <div className="adblock-actions" style={{ marginTop: 0, marginBottom: '1rem' }}>
              <button className="secondary" title={t('alerts.btn.export_csv.title')} onClick={() => exportAlerts('csv')}>{t('btn.export_csv')}</button>
              <button className="secondary" title={t('alerts.btn.export_json.title')} onClick={() => exportAlerts('json')}>{t('btn.export_json')}</button>
            </div>
            {tabLoading ? (
              <p className="empty">{t('alerts.loading')}</p>
            ) : alerts.length === 0 ? (
              <p className="empty">{t('alerts.empty')}</p>
            ) : (
              <div>
                {alerts.map((item, idx) => {
                  const { pid, processName, port } = alertExtract(item)
                  const alertKey = `alert_${idx}_${pid || 'nopid'}_${port || 'noport'}`
                  const detail = pid ? alertInspect[pid] : undefined
                  const open = Boolean(alertDetailOpen[alertKey])
                  return (
                    <div className="alert-item" key={alertKey}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '.5rem' }}>
                        <div>
                          <strong>{item.timestamp ? new Date(item.timestamp).toLocaleString() : '—'}</strong> -{' '}
                          <span style={{ color: '#fca5a5' }}>{t('alerts.risk', {score: item.risk_score ?? item.score ?? '—'})}</span>
                        </div>
                        <button type="button" className="btn-inspect" style={{ background: '#991b1b', color: '#fecaca', border: '1px solid #b91c1c', padding: '.2rem .5rem', fontSize: '.75rem', marginLeft: 'auto' }} title={t('alerts.delete.title')} onClick={() => void deleteAlert(item)}>{t('alerts.delete')}</button>
                      </div>
                      <p style={{ margin: '.25rem 0 0' }}>{item.message ?? ''}</p>
                      <div className="alert-actions">
                        <button type="button" className="btn-inspect" title={t('alerts.ai.title')} onClick={() => copyAlertForAI(item)}>🤖 IA</button>
                        {pid && (
                          <button type="button" className="btn-inspect alert-btn-info" disabled={alertInspectLoading === pid} title={t('alerts.info.title')} onClick={() => void toggleAlertInfo(pid, alertKey)}>
                            {alertInspectLoading === pid ? t('common.loading') : t('alerts.info')}
                          </button>
                        )}
                        {processName && (
                          <>
                            <a href={`https://www.virustotal.com/gui/search/${encodeURIComponent(processName)}`} target="_blank" rel="noopener" className="ext-link-btn" title={t('links.vt.title')}>VirusTotal ↗</a>
                            <a href={`https://www.processlibrary.com/en/directory/files/${encodeURIComponent(processName.replace(/\.exe$/i, '').toLowerCase())}/`} target="_blank" rel="noopener" className="ext-link-btn" title={t('links.pl.title')}>ProcessLibrary ↗</a>
                          </>
                        )}
                        {port && (
                          <>
                            <a href={`https://www.speedguide.net/port.php?port=${encodeURIComponent(port)}`} target="_blank" rel="noopener" className="ext-link-btn" title={t('links.sg.title')}>SpeedGuide ↗</a>
                            <a href={`https://isc.sans.edu/port.html?port=${encodeURIComponent(port)}`} target="_blank" rel="noopener" className="ext-link-btn" title={t('links.sans.title')}>SANS ISC ↗</a>
                          </>
                        )}
                      </div>
                      {pid && open && (
                        detail?.notFound ? (
                          <div className="alert-detail"><span className="reputation-badge reputation-badge-error">{t('alerts.detail.not_found')}</span></div>
                        ) : detail?.networkError ? (
                          <div className="alert-detail"><span className="reputation-badge reputation-badge-error">{t('rep.error')}</span></div>
                        ) : !detail ? (
                          <div className="alert-detail" style={{ color: '#94a3b8', fontStyle: 'italic' }}>{t('common.loading')}</div>
                        ) : (
                          <div className="alert-detail">
                            <div className="alert-detail-row">
                              <span className="alert-detail-label">{t('alerts.detail.exe')}</span>
                              <span className="alert-detail-value" style={{ fontFamily: 'ui-monospace, Consolas, monospace', fontSize: '.75rem' }} title={detail.exe_path ?? ''}>{detail.exe_path || t('common.na')}</span>
                            </div>
                            <div className="alert-detail-row">
                              <span className="alert-detail-label">SHA-256 :</span>
                              {detail.sha256 ? (
                                <>
                                  <span className="alert-sha-trunc" title={detail.sha256}>{detail.sha256.length > 24 ? `${detail.sha256.slice(0, 12)}…${detail.sha256.slice(-8)}` : detail.sha256}</span>
                                  <button type="button" className="btn-inspect" style={{ padding: '.15rem .45rem', fontSize: '.72rem' }} title={t('modal.process.copy_sha.title')} onClick={() => copyAlertSha(detail.sha256!, pid)}>{shaCopiedPid === pid ? t('btn.copied') : t('btn.copy')}</button>
                                </>
                              ) : (
                                <span className="alert-detail-value" style={{ color: '#64748b', fontSize: '.75rem' }}>{t('common.na')}</span>
                              )}
                            </div>
                            <div className="alert-detail-row" style={{ marginTop: '.15rem' }}>
                              <span className="alert-detail-label">{t('alerts.detail.rep')}</span>
                              {alertRepBadge(detail)}
                              {detail.sha256 && (
                                <a href={detail.links?.virustotal_hash ?? `https://www.virustotal.com/gui/search/${encodeURIComponent(detail.sha256)}`} target="_blank" rel="noopener" className="ext-link-btn" style={{ padding: '.15rem .45rem', fontSize: '.72rem' }} title={t('links.vt_hash.title')}>VirusTotal hash ↗</a>
                              )}
                            </div>
                          </div>
                        )
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </section>
        )}

        {activeTab === 'history' && (
          <section className="panel">
            {tabLoading ? (
              <p className="empty">{t('history.loading')}</p>
            ) : history.length === 0 ? (
              <p className="empty">{t('history.empty')}</p>
            ) : (
              <div>
                {history.map((item, index) => (
                  <div className="history-item" key={`${item.timestamp}-${index}`}>
                    <div>
                      <strong>{item.timestamp ? new Date(item.timestamp).toLocaleString() : '—'}</strong> -{' '}
                      {t('history.score')} <span className="badge">{item.risk_score ?? '—'}/100</span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#9ca3af' }}>
                      {t('history.ports', {count: item.ports?.length ?? item.total_ports ?? 0})}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {activeTab === 'settings' && (
          <section className="panel">
            <div className="settings-grid">
              <div className="settings-card">
                <h4>{t('settings.language.title')}</h4>
                <label className="settings-row"><span>{t('settings.language.label')}</span>
                  <select value={settingsForm.uiLanguage} onChange={(e) => changeUiLanguage(e.target.value)}>
                    <option value="fr">Français</option>
                    <option value="en">English</option>
                    <option value="de">Deutsch</option>
                    <option value="es">Español</option>
                  </select>
                </label>
                <span className="hint">{t('settings.language.hint')}</span>
              </div>
              <div className="settings-card">
                <h4>{t('settings.launch.title')}</h4>
                <label className="settings-row"><input type="radio" name="launch-mode" checked={settingsForm.launchMode === 'browser'} onChange={() => setSettingsField('launchMode', 'browser')} /><span>{t('settings.launch.browser')}</span></label>
                <label className="settings-row"><input type="radio" name="launch-mode" checked={settingsForm.launchMode === 'desktop'} onChange={() => setSettingsField('launchMode', 'desktop')} /><span>{t('settings.launch.desktop')}</span></label>
                <label className="settings-row"><input type="radio" name="launch-mode" checked={settingsForm.launchMode === 'both'} onChange={() => setSettingsField('launchMode', 'both')} /><span>{t('settings.launch.both')}</span></label>
                <span className="hint">{t('settings.launch.hint')}</span>
              </div>
              <div className="settings-card">
                <h4>{t('settings.access.title')}</h4>
                <label className="settings-row"><input type="checkbox" checked={settingsForm.accessEnabled} onChange={(e) => setSettingsField('accessEnabled', e.target.checked)} /> <span>{t('settings.access.enabled')}</span></label>
                <label className="settings-row"><span>{t('settings.access.method')}</span>
                  <select value={settingsForm.accessMethod} onChange={(e) => setSettingsField('accessMethod', e.target.value)}>
                    <option value="windows">{t('settings.access.method.windows')}</option>
                    <option value="app">{t('settings.access.method.app')}</option>
                  </select>
                </label>
                {settingsForm.accessMethod === 'app' && (
                  <div className="settings-row">
                    <input type="password" placeholder={t('settings.access.app_password.placeholder')} value={settingsForm.appPassword} onChange={(e) => setSettingsField('appPassword', e.target.value)} />
                    <span className="hint">{t('settings.access.app_password.hint')}</span>
                  </div>
                )}
                <button className="secondary" title={t('settings.access.lock_now.title')} onClick={() => void lockNow()}>{t('settings.access.lock_now')}</button>
              </div>
              <div className="settings-card">
                <h4>{t('settings.scan.title')}</h4>
                <label className="settings-row"><span>{t('settings.scan.interval')}</span>
                  <input type="number" min={5} max={3600} style={{ width: '6rem' }} value={settingsForm.scanInterval} onChange={(e) => setSettingsField('scanInterval', e.target.value)} />
                </label>
                <span className="hint">{t('settings.scan.hint')}</span>
              </div>
              <div className="settings-card" style={{ gridColumn: '1 / -1' }}>
                <h4>{t('settings.health.title')}</h4>
                <p className="hint">{t('settings.health.desc')}</p>
                <div className="adblock-actions" style={{ marginTop: '.6rem' }}>
                  <button className="secondary" disabled={healthLoading} onClick={() => void runHealthcheck()}>{t('settings.health.run')}</button>
                  <span className="adblock-hint">{healthLoading ? t('enrich.verifying') : health ? `${health.summary?.pass ?? 0} ${t('health.pass')} · ${health.summary?.warn ?? 0} ${t('health.warn')} · ${health.summary?.fail ?? 0} ${t('health.fail')}` : ''}</span>
                </div>
                {health && (
                  <div style={{ marginTop: '.6rem' }}>
                    {health.checks?.map((check) => (
                      <div key={check.id} style={{ color: check.status === 'pass' ? '#86efac' : check.status === 'warn' ? '#fde68a' : '#fca5a5', margin: '.25rem 0', fontSize: '.8rem' }}>
                        <strong>{t(HEALTH_STATUS_LABELS[check.status ?? ''] ?? 'common.na').toUpperCase()}</strong> — {check.id} : {check.message}
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div className="settings-card">
                <h4>{t('settings.classif.title')}</h4>
                <label className="settings-row"><span>{t('settings.classif.critical')}</span> <input type="text" placeholder="22, 80, 443, 3389…" style={{ width: '100%' }} value={settingsForm.criticalPorts} onChange={(e) => setSettingsField('criticalPorts', e.target.value)} /></label>
                <label className="settings-row"><span>{t('settings.classif.allowed_ports')}</span> <input type="text" placeholder="8080, 3000…" style={{ width: '100%' }} value={settingsForm.allowedPorts} onChange={(e) => setSettingsField('allowedPorts', e.target.value)} /></label>
                <label className="settings-row"><span>{t('settings.classif.allowed_proc')}</span> <input type="text" placeholder="python.exe, node.exe…" style={{ width: '100%' }} value={settingsForm.allowedProc} onChange={(e) => setSettingsField('allowedProc', e.target.value)} /></label>
                <span className="hint">{t('settings.classif.hint')}</span>
              </div>
              <div className="settings-card">
                <h4>{t('settings.filter.title')}</h4>
                <label className="settings-row"><input type="checkbox" checked={settingsForm.filterAutostart} onChange={(e) => setSettingsField('filterAutostart', e.target.checked)} /> <span>{t('settings.filter.autostart')}</span></label>
                <label className="settings-row"><input type="checkbox" checked={settingsForm.remoteWhitelist} onChange={(e) => setSettingsField('remoteWhitelist', e.target.checked)} /> <span>{t('settings.filter.remote_whitelist')}</span></label>
                <label className="settings-row"><span>{t('settings.filter.grace')}</span> <input type="number" min={0} max={600} style={{ width: '5rem' }} value={settingsForm.grace} onChange={(e) => setSettingsField('grace', e.target.value)} /></label>
                <span className="hint">{t('settings.filter.grace.hint')}</span>
              </div>
              <div className="settings-card" style={{ gridColumn: '1 / -1' }}>
                <h4>{t('adblock.lists.title')}</h4>
                <div className="adblock-actions" style={{ marginTop: 0 }}>
                  <button className="secondary" disabled={updateAllBusy} title={t('settings.lists.update_all.title')} onClick={() => void updateAllLists()}>{updateAllBusy ? t('lists.updating') : t('settings.lists.update_all')}</button>
                  <span className={`adblock-hint ${updateAllTone}`}>{updateAllStatus}</span>
                </div>
                {updateAllReport.length > 0 && (
                  <div style={{ marginTop: '.4rem' }}>
                    {updateAllReport.map((l, i) => <div key={i} style={{ fontSize: '.8rem', color: l.color }}>{l.text}</div>)}
                  </div>
                )}
                <div className="adblock-table-wrap" style={{ maxHeight: '240px', marginTop: '.6rem' }}>
                  <table style={{ marginTop: 0, fontSize: '.82rem' }}>
                    <thead>
                      <tr>
                        <th title={t('settings.lists.th.list.title')}>{t('adblock.th.list')}</th>
                        <th title={t('settings.lists.th.family.title')}>{t('settings.lists.th.family')}</th>
                        <th title={t('settings.lists.th.domains.title')}>{t('adblock.th.domains')}</th>
                        <th title={t('adblock.th.updated.title')}>{t('adblock.th.updated')}</th>
                        <th title={t('settings.lists.th.status.title')}>{t('adblock.th.status')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {listsStatusErr ? (
                        <tr><td colSpan={5} className="cell-empty" style={{ color: '#fca5a5' }}>{listsStatusErr}</td></tr>
                      ) : listsStatus === null ? (
                        <tr><td colSpan={5} className="cell-empty">{t('common.loading')}</td></tr>
                      ) : (() => {
                        const rows: React.ReactNode[] = []
                        Object.entries(listsStatus.adblock ?? {}).forEach(([lid, l]) => {
                          rows.push(
                            <tr key={`ab-${lid}`}>
                              <td className="list-name">{l.name || lid}{l.enabled ? '' : <span style={{ fontSize: '.68rem', color: '#64748b' }}>{t('lists.disabled_badge')}</span>}</td>
                              <td><span className="badge" style={{ fontSize: '.68rem' }}>{t('lists.family.adblock')}</span></td>
                              <td><span className="badge">{fmtNum((l.domains_loaded ?? 0))}</span></td>
                              <td className="list-date">{fmtListDate(l.last_update)}</td>
                              <td>{listStatusBadge(l.status)}</td>
                            </tr>,
                          )
                        })
                        Object.entries(listsStatus.parental ?? {}).forEach(([cat, c]) => {
                          rows.push(
                            <tr key={`pc-${cat}`}>
                              <td className="list-name">{cat}</td>
                              <td><span className="badge" style={{ fontSize: '.68rem' }}>{c.source === 'curated' ? t('lists.family.internal') : t('lists.family.parental')}</span></td>
                              <td><span className="badge">{fmtNum((c.count ?? 0))}</span></td>
                              <td className="list-date">{fmtListDate(c.last_updated)}</td>
                              <td>{listStatusBadge(c.enabled ? 'ok' : 'missing')}</td>
                            </tr>,
                          )
                        })
                        return rows.length ? rows : <tr><td colSpan={5} className="cell-empty">{t('lists.none')}</td></tr>
                      })()}
                    </tbody>
                  </table>
                </div>
                <label className="settings-row" style={{ marginTop: '.6rem' }}><input type="checkbox" checked={settingsForm.listsAutoUpdate} onChange={(e) => void toggleListsAutoUpdate(e.target.checked)} /> <span>{t('settings.lists.auto_update')}</span></label>
                <span className="hint">{t('settings.lists.auto_update.hint')}</span>
              </div>
              <div className="settings-card" style={{ gridColumn: '1 / -1' }}>
                <h4>{t('settings.ext.title')}</h4>
                <label className="settings-row"><input type="checkbox" checked={settingsForm.extEnabled} onChange={(e) => setSettingsField('extEnabled', e.target.checked)} /> <span>{t('settings.ext.enabled')}</span></label>
                <label className="settings-row"><span>{t('settings.ext.min_sev')}</span> <input type="number" min={0} max={100} style={{ width: '5rem' }} value={settingsForm.minSev} onChange={(e) => setSettingsField('minSev', e.target.value)} /></label>
                <label className="settings-row"><span>{t('settings.ext.webhook')}</span> <input type="text" placeholder="https://…" style={{ width: '100%' }} value={settingsForm.webhook} onChange={(e) => setSettingsField('webhook', e.target.value)} /></label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '.5rem' }}>
                  <label className="settings-row"><span>{t('settings.ext.email')}</span> <input type="text" placeholder={t('settings.ext.email.placeholder')} value={settingsForm.alertEmail} onChange={(e) => setSettingsField('alertEmail', e.target.value)} /></label>
                  <label className="settings-row"><span>{t('settings.ext.smtp_host')}</span> <input type="text" placeholder="smtp.gmail.com" value={settingsForm.smtpHost} onChange={(e) => setSettingsField('smtpHost', e.target.value)} /></label>
                  <label className="settings-row"><span>{t('settings.ext.smtp_port')}</span> <input type="number" placeholder="465" value={settingsForm.smtpPort} onChange={(e) => setSettingsField('smtpPort', e.target.value)} /></label>
                  <label className="settings-row"><span>{t('settings.ext.smtp_user')}</span> <input type="text" placeholder={t('settings.ext.smtp_user.placeholder')} value={settingsForm.smtpUser} onChange={(e) => setSettingsField('smtpUser', e.target.value)} /></label>
                  <label className="settings-row"><span>{t('settings.ext.smtp_pass')}</span> <input type="password" placeholder={t('settings.ext.smtp_pass.placeholder')} value={settingsForm.smtpPass} onChange={(e) => setSettingsField('smtpPass', e.target.value)} /></label>
                </div>
                <span className="hint">{t('settings.ext.hint')}</span>
              </div>
            </div>
            <div className="adblock-actions" style={{ marginTop: '1rem' }}>
              <button className="secondary" title={t('settings.btn.save.title')} onClick={() => void saveSettings()}>{t('settings.btn.save')}</button>
              <span className={`adblock-hint ${settingsTone}`}>{settingsStatus}</span>
            </div>
          </section>
        )}
        {activeTab === 'about' && (
          <section className="panel">
            <div className="panel-heading"><div><h2>{t('tabs.about')}</h2><p>{t('tabs.about.title')}</p></div></div>
            <div className="about-body">
              <h3>{t('about.s1')}</h3>
              <p>{t('about.s1p1')}</p>
              <p>{t('about.s1p2')}</p>
              <h3>{t('about.s2')}</h3>
              <p>{t('about.s2p1')}</p>
              <p>{t('about.s2p2')}</p>
              <h3>{t('about.s3')}</h3>
              <p>{t('about.s3p1')}</p>
              <p>{t('about.s3p2')}</p>
              <h3>{t('about.s4')}</h3>
              <p>{t('about.s4p1')}</p>
              <h3>{t('about.s5')}</h3>
              <p>{t('about.s5p1')}</p>
              <h3>{t('about.s6')}</h3>
              <p>{t('about.s6p1')}</p>
              <div className="about-links">
                <a className="secondary" href="https://github.com/art-qalam-fr/CerbereShield" target="_blank" rel="noreferrer">{t('about.link.repo')}</a>
                <a className="secondary" href="https://cerbere-security-shield.art-qalam.fr" target="_blank" rel="noreferrer">{t('about.link.site')}</a>
              </div>
            </div>
          </section>
        )}
      </main>
      {locked && (
        <div className="lock-overlay">
          <div className="lock-card">
            <img src={`${API_BASE}/static/img/cerbere_logo.png`} alt="Cerbere" className="lock-logo" />
            <h3>Cerbere Security Shield</h3>
            <p className="lock-subtitle">{lockNeedsSetup ? t('lock.subtitle.setup') : lockMethod === 'app' ? t('lock.subtitle.app') : t('lock.subtitle.windows')}</p>
            <input type="password" className="lock-input" value={lockPassword} placeholder={t('lock.password.placeholder')} autoFocus
              onChange={(e) => setLockPassword(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void submitUnlock() }} />
            <button className="primary lock-btn" onClick={() => void submitUnlock()}>{lockNeedsSetup ? t('lock.create') : t('lock.unlock')}</button>
            <div className="lock-error">{lockError}</div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App