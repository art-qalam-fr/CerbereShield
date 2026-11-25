import { useSyncExternalStore } from 'react'

export type Lang = 'fr' | 'en' | 'de' | 'es'
export const SUPPORTED_LANGS: Lang[] = ['fr', 'en', 'de', 'es']

type Dict = Record<string, string>

const STORAGE_KEY = 'cerbere_lang'

// En dev (Vite) et en mode "browser" les appels relatifs atteignent le backend
// via le proxy ou l'origine partagée. Sous Tauri, l'origine est tauri.localhost :
// il faut viser explicitement le backend local.
export const API_BASE =
  window.location.protocol === 'tauri:' || window.location.hostname.endsWith('tauri.localhost')
    ? 'http://localhost:4050'
    : ''
const dicts: Partial<Record<Lang, Dict>> = {}
let currentLang: Lang = 'fr'
// Incrémenté à chaque chargement de dict/langue : sert de snapshot à
// useSyncExternalStore pour forcer le re-render même quand la langue ne
// change pas (dict arrivé après le premier rendu).
let dictVersion = 0
const listeners = new Set<() => void>()

function normalizeLang(value: string | null | undefined): Lang {
  const v = (value || 'fr').toLowerCase()
  return (SUPPORTED_LANGS as string[]).includes(v) ? (v as Lang) : 'fr'
}

async function loadDict(lang: Lang, attempts = 8): Promise<Dict> {
  if (dicts[lang]) return dicts[lang] as Dict
  try {
    const resp = await fetch(`${API_BASE}/static/locales/${lang}.json`, { cache: 'no-store' })
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const data = (await resp.json()) as Dict
    dicts[lang] = data
    return data
  } catch {
    // Le backend peut ne pas encore écouter (démarrage desktop/navigateur) —
    // on réessaie avant d'abandonner, sinon les clés restent affichées en brut.
    if (attempts > 0) {
      await new Promise((resolve) => setTimeout(resolve, 600))
      return loadDict(lang, attempts - 1)
    }
    if (lang !== 'fr') return loadDict('fr')
    dicts[lang] = {}
    return {}
  }
}

function emit() {
  dictVersion += 1
  listeners.forEach((fn) => fn())
}

export function t(key: string, vars?: Record<string, string | number>): string {
  const dict = dicts[currentLang] ?? {}
  const fallback = dicts.fr ?? {}
  let value = dict[key] ?? fallback[key] ?? key
  if (vars) {
    Object.entries(vars).forEach(([name, v]) => {
      value = value.replace(new RegExp(`\\{${name}\\}`, 'g'), String(v))
    })
  }
  return value
}

export function getLanguage(): Lang {
  return currentLang
}

export async function setLanguage(lang: string, persist = true): Promise<void> {
  const next = normalizeLang(lang)
  await loadDict(next)
  currentLang = next
  document.documentElement.lang = next
  if (persist) {
    localStorage.setItem(STORAGE_KEY, next)
    fetch(`${API_BASE}/api/ui/language`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ language: next }),
    }).catch(() => undefined)
  }
  emit()
}

export async function initI18n(): Promise<void> {
  await loadDict('fr')
  let lang = normalizeLang(localStorage.getItem(STORAGE_KEY))
  try {
    const resp = await fetch(`${API_BASE}/api/ui/language`, { cache: 'no-store' })
    if (resp.ok) {
      const data = (await resp.json()) as { language?: string }
      if (data.language) lang = normalizeLang(data.language)
    }
  } catch {
    /* backend hors ligne : on garde localStorage */
  }
  await loadDict(lang)
  currentLang = lang
  document.documentElement.lang = lang
  emit()
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

export function useI18n(): { lang: Lang; t: typeof t; setLanguage: typeof setLanguage } {
  useSyncExternalStore(subscribe, () => dictVersion)
  return { lang: currentLang, t, setLanguage }
}
