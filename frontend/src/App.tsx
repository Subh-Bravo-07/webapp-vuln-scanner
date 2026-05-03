import { useEffect, useMemo, useRef, useState } from 'react'

type NoticeKind = 'ok' | 'warn' | 'danger'
type Notice = { kind: NoticeKind; text: string }

type ScanProfile = 'quick' | 'full' | 'custom'

type ScanSummary = {
  id: number
  target_url?: string
  status?: string
  updated_at?: string
}

type ScanFinding = {
  module?: string
  title?: string
  severity?: string
  description?: string
  remediation?: string
  evidence?: unknown
}

const profileDetails: Record<ScanProfile, string> = {
  quick: 'Crawler plus passive checks: headers, CORS, fingerprinting, sensitive data, and CSRF form heuristics.',
  full: 'Everything in quick, plus active XSS/SQLi heuristics and external adapters when installed server-side.',
  custom: 'Currently mirrors full; module-level selection is planned for the next backend slice.',
}

const moduleGroups = [
  {
    title: 'Passive coverage',
    modules: ['Crawler', 'Headers', 'CORS', 'Tech fingerprinting', 'Sensitive data', 'CSRF forms'],
  },
  {
    title: 'Full profile adds',
    modules: ['Reflected XSS', 'Error-based SQLi', 'Nuclei', 'Nikto', 'sqlmap'],
  },
]

function LogoMark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="hs_g" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#22D3EE" />
          <stop offset="1" stopColor="#A78BFA" />
        </linearGradient>
      </defs>
      <path d="M32 6c10 6 18 8 18 8v18c0 13-8 21-18 26C22 53 14 45 14 32V14s8-2 18-8z" fill="url(#hs_g)" />
      <path
        d="M32 16a2 2 0 0 1 2 2v8h8a2 2 0 1 1 0 4h-8v8a2 2 0 1 1-4 0v-8h-8a2 2 0 1 1 0-4h8v-8a2 2 0 0 1 2-2z"
        fill="rgba(11,16,32,.92)"
      />
    </svg>
  )
}

function safeJson(x: unknown) {
  try {
    return JSON.stringify(x, null, 2)
  } catch {
    return String(x)
  }
}

function statusBadge(status?: string) {
  const s = String(status ?? '').toLowerCase()
  if (['succeeded', 'success', 'done', 'completed'].includes(s)) return { cls: 'ok', label: status ?? 'succeeded' }
  if (['failed', 'error'].includes(s)) return { cls: 'danger', label: status ?? 'failed' }
  if (['running', 'queued', 'started', 'in_progress'].includes(s)) return { cls: 'warn', label: status ?? 'running' }
  return { cls: '', label: status ?? 'unknown' }
}

function severityClasses(severity?: string) {
  const s = String(severity ?? '').toLowerCase()
  if (['critical', 'high'].includes(s)) return 'border-rose-400/30 bg-rose-400/10 text-rose-100'
  if (s === 'medium') return 'border-amber-400/25 bg-amber-400/10 text-amber-100'
  if (s === 'low') return 'border-cyan-300/25 bg-cyan-300/10 text-cyan-100'
  return 'border-white/10 bg-black/20 text-hs-muted'
}

function parseFindings(scanData: unknown): ScanFinding[] {
  if (!scanData || typeof scanData !== 'object' || !('findings_json' in scanData)) return []
  const raw = (scanData as { findings_json?: unknown }).findings_json
  if (typeof raw !== 'string' || !raw.trim()) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? (parsed as ScanFinding[]) : []
  } catch {
    return []
  }
}

export function App() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState<ScanProfile>('quick')
  const [scope, setScope] = useState('')
  const [exclusions, setExclusions] = useState('')
  const [authorized, setAuthorized] = useState(false)

  const [scanId, setScanId] = useState('')
  const [authStatus, setAuthStatus] = useState<Notice | null>(null)
  const [createStatus, setCreateStatus] = useState<Notice | null>(null)
  const [streamStatus, setStreamStatus] = useState<Notice | null>(null)
  const [scanData, setScanData] = useState<unknown>(null)

  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loadingScans, setLoadingScans] = useState(false)

  const wsRef = useRef<WebSocket | null>(null)

  const token = useMemo(() => localStorage.getItem('access_token') || '', [authStatus?.text])
  const isAuthed = Boolean(token)
  const authHeaders = (): Record<string, string> => {
    const h: Record<string, string> = {}
    if (token) h.Authorization = `Bearer ${token}`
    return h
  }

  const reportUrl = (ext: 'json' | 'html' | 'pdf') =>
    `/api/reports/${encodeURIComponent(scanId)}.${ext}?token=${encodeURIComponent(token)}`

  const logout = () => {
    localStorage.removeItem('access_token')
    setAuthStatus({ kind: 'warn', text: 'Logged out (token cleared from this browser).' })
    setScanData(null)
    setStreamStatus(null)
    setScans([])
  }

  const register = async () => {
    setAuthStatus(null)
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    const data = await res.json().catch(() => ({}))
    setAuthStatus(
      res.ok
        ? { kind: 'ok', text: `Registered ${data.email ?? email}. You can login now.` }
        : { kind: 'danger', text: `Register error: ${safeJson(data)}` },
    )
  }

  const login = async () => {
    setAuthStatus(null)
    const form = new URLSearchParams()
    form.append('username', email)
    form.append('password', password)
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    })
    const data = await res.json().catch(() => ({}))
    if (res.ok && data.access_token) {
      localStorage.setItem('access_token', data.access_token)
      setAuthStatus({ kind: 'ok', text: 'Logged in. Your token is stored locally in this browser.' })
    } else {
      setAuthStatus({ kind: 'danger', text: `Login error: ${safeJson(data)}` })
    }
  }

  const refreshScans = async (silent?: boolean) => {
    if (!isAuthed) return
    if (!silent) setLoadingScans(true)
    try {
      const res = await fetch('/api/scans', { headers: authHeaders() })
      const data = await res.json().catch(() => [])
      if (res.ok) setScans(Array.isArray(data) ? data : [])
    } finally {
      if (!silent) setLoadingScans(false)
    }
  }

  const createScan = async () => {
    setCreateStatus(null)
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({
        target_url: target,
        profile,
        authorization_confirmed: authorized,
        in_scope_urls: scope
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        exclusions: exclusions
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (res.ok) {
      setCreateStatus({ kind: 'ok', text: `Created scan #${data.id}.` })
      setScanId(String(data.id))
      setScanData(null)
      refreshScans(true)
    } else {
      setCreateStatus({ kind: 'danger', text: `Create error: ${safeJson(data)}` })
    }
  }

  const fetchScan = async () => {
    setScanData(null)
    const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, { headers: authHeaders() })
    const data = await res.json().catch(() => ({}))
    setScanData(data)
  }

  const watchScan = () => {
    if (wsRef.current) wsRef.current.close()
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/api/scans/ws/${encodeURIComponent(scanId)}?token=${encodeURIComponent(token)}`)
    wsRef.current = ws
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.error) {
        setStreamStatus({ kind: 'danger', text: String(data.error) })
        return
      }
      setStreamStatus({ kind: 'warn', text: `Scan #${data.id}: ${data.status} (${data.updated_at})` })
      refreshScans(true)
    }
    ws.onerror = () => setStreamStatus({ kind: 'danger', text: 'WebSocket error.' })
  }

  useEffect(() => {
    refreshScans()
    return () => wsRef.current?.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthed])

  const canSubmit = isAuthed && target.trim().length > 0 && authorized
  const findings = useMemo(() => parseFindings(scanData), [scanData])
  const severitySummary = useMemo(
    () =>
      findings.reduce<Record<string, number>>((acc, finding) => {
        const severity = String(finding.severity || 'info').toLowerCase()
        acc[severity] = (acc[severity] || 0) + 1
        return acc
      }, {}),
    [findings],
  )

  return (
    <div>
      <header className="sticky top-0 z-10 border-b border-white/10 bg-[#070A14]/70 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-4 py-3">
          <div className="flex min-w-[220px] items-center gap-3">
            <LogoMark />
            <div className="leading-tight">
              <div className="text-sm font-extrabold tracking-tight text-white">HyperScan</div>
              <div className="text-xs text-hs-muted">Authorized webapp vulnerability scanning dashboard</div>
            </div>
          </div>

          <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-hs-muted">
            <span
              className="h-2 w-2 rounded-full"
              style={{
                background: isAuthed ? 'rgba(52,211,153,.95)' : 'rgba(251,113,133,.9)',
                boxShadow: isAuthed ? '0 0 0 4px rgba(52,211,153,.18)' : '0 0 0 4px rgba(251,113,133,.16)',
              }}
            />
            {isAuthed ? 'Token loaded' : 'Not logged in'}
            {isAuthed ? <span className="rounded-lg border border-white/10 bg-black/20 px-2 py-0.5 font-mono text-[10px] text-[#CFE3FF]">Bearer</span> : null}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 pb-14 pt-5">
        <div className="mb-4 rounded-hs border border-amber-400/25 bg-amber-400/10 px-4 py-3 text-sm text-amber-100">
          <span className="font-semibold text-white">Ethical use only.</span> Scan only targets you own or have explicit written permission to test.
        </div>

        <div className="grid gap-4 lg:grid-cols-[1.15fr_.85fr]">
          <section className="space-y-4">
            <div className="rounded-hs border border-white/10 bg-white/5 shadow-hs">
              <div className="flex items-start justify-between gap-4 px-5 pt-5">
                <div>
                  <h2 className="text-sm font-bold text-white">Start scan</h2>
                  <p className="mt-1 text-xs leading-relaxed text-hs-muted">
                    Quick = passive checks. Full/Custom may run active heuristics and external adapters (if installed server-side).
                  </p>
                </div>
                <span className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-[11px] text-hs-muted">
                  <span className="font-mono">POST</span> /api/scans
                </span>
              </div>

              <div className="grid gap-3 px-5 pb-5 pt-4 sm:grid-cols-2">
                <div className="sm:col-span-1">
                  <label className="text-xs text-hs-muted">Target URL</label>
                  <input
                    className="mt-1 w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-cyan-300/50 focus:ring-4 focus:ring-cyan-300/10"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://example.com"
                  />
                </div>
                <div className="sm:col-span-1">
                  <label className="text-xs text-hs-muted">Profile</label>
                  <select
                    className="mt-1 w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-cyan-300/50 focus:ring-4 focus:ring-cyan-300/10"
                    value={profile}
                    onChange={(e) => setProfile(e.target.value as ScanProfile)}
                  >
                    <option value="quick">quick (passive)</option>
                    <option value="full">full (active)</option>
                    <option value="custom">custom</option>
                  </select>
                  <p className="mt-2 text-xs leading-relaxed text-hs-muted">{profileDetails[profile]}</p>
                </div>

                <div className="sm:col-span-2 grid gap-2 sm:grid-cols-2">
                  {moduleGroups.map((group) => (
                    <div key={group.title} className="rounded-xl border border-white/10 bg-black/10 p-3">
                      <div className="text-xs font-semibold text-white">{group.title}</div>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {group.modules.map((module) => (
                          <span key={module} className="rounded-full border border-white/10 bg-black/20 px-2 py-0.5 text-[11px] text-hs-muted">
                            {module}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="sm:col-span-1">
                  <label className="text-xs text-hs-muted">In-scope URLs (comma separated)</label>
                  <textarea
                    className="mt-1 min-h-[86px] w-full resize-y rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-cyan-300/50 focus:ring-4 focus:ring-cyan-300/10"
                    value={scope}
                    onChange={(e) => setScope(e.target.value)}
                    placeholder="https://example.com/app, https://example.com/api"
                  />
                </div>
                <div className="sm:col-span-1">
                  <label className="text-xs text-hs-muted">Exclusions (comma separated)</label>
                  <textarea
                    className="mt-1 min-h-[86px] w-full resize-y rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-cyan-300/50 focus:ring-4 focus:ring-cyan-300/10"
                    value={exclusions}
                    onChange={(e) => setExclusions(e.target.value)}
                    placeholder="/logout, /admin/delete"
                  />
                </div>

                <div className="sm:col-span-2 rounded-xl border border-white/10 bg-black/10 px-3 py-2">
                  <label className="flex items-center gap-3 text-sm text-white">
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-cyan-300"
                      checked={authorized}
                      onChange={(e) => setAuthorized(e.target.checked)}
                    />
                    I confirm I have explicit written authorization for this target.
                  </label>
                </div>

                <div className="sm:col-span-2 flex flex-wrap gap-2 pt-1">
                  <button
                    className="rounded-xl bg-gradient-to-r from-cyan-300 to-violet-400 px-4 py-2 text-sm font-semibold text-[#06121f] disabled:opacity-50"
                    onClick={createScan}
                    disabled={!canSubmit}
                  >
                    Submit scan
                  </button>
                  <button
                    className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                    onClick={() => refreshScans(false)}
                    disabled={!isAuthed || loadingScans}
                  >
                    {loadingScans ? 'Refreshing…' : 'Refresh history'}
                  </button>
                  <button
                    className="rounded-xl border border-rose-400/25 bg-rose-400/10 px-4 py-2 text-sm font-semibold text-rose-100 disabled:opacity-50"
                    onClick={logout}
                    disabled={!isAuthed}
                  >
                    Logout
                  </button>
                </div>

                {!isAuthed ? (
                  <div className="sm:col-span-2 rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm text-rose-100">
                    Login required before you can create scans.
                  </div>
                ) : null}

                {isAuthed && !authorized ? (
                  <div className="sm:col-span-2 rounded-xl border border-amber-400/25 bg-amber-400/10 px-3 py-2 text-sm text-amber-100">
                    Authorization checkbox is required to submit a scan.
                  </div>
                ) : null}

                {createStatus ? (
                  <div
                    className={`sm:col-span-2 rounded-xl border px-3 py-2 text-sm ${
                      createStatus.kind === 'ok'
                        ? 'border-emerald-400/25 bg-emerald-400/10 text-emerald-100'
                        : createStatus.kind === 'danger'
                          ? 'border-rose-400/30 bg-rose-400/10 text-rose-100'
                          : 'border-amber-400/25 bg-amber-400/10 text-amber-100'
                    }`}
                  >
                    {createStatus.text}
                  </div>
                ) : null}
              </div>
            </div>

            <div className="rounded-hs border border-white/10 bg-white/5 shadow-hs">
              <div className="flex items-start justify-between gap-4 px-5 pt-5">
                <div>
                  <h2 className="text-sm font-bold text-white">Scan details</h2>
                  <p className="mt-1 text-xs leading-relaxed text-hs-muted">
                    Load a scan by ID, watch live status over WebSocket, and open reports.
                  </p>
                </div>
                <span className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-[11px] text-hs-muted">
                  <span className="font-mono">GET</span> /api/scans/{'{id}'}
                </span>
              </div>

              <div className="grid gap-3 px-5 pb-5 pt-4 sm:grid-cols-2">
                <div>
                  <label className="text-xs text-hs-muted">Scan ID</label>
                  <input
                    className="mt-1 w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-cyan-300/50 focus:ring-4 focus:ring-cyan-300/10"
                    value={scanId}
                    onChange={(e) => setScanId(e.target.value)}
                    placeholder="e.g. 1"
                  />
                </div>
                <div className="flex items-end gap-2">
                  <button
                    className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                    onClick={fetchScan}
                    disabled={!isAuthed || !scanId.trim()}
                  >
                    Load JSON
                  </button>
                  <button
                    className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                    onClick={watchScan}
                    disabled={!isAuthed || !scanId.trim()}
                  >
                    Watch live
                  </button>
                </div>

                {streamStatus ? (
                  <div
                    className={`sm:col-span-2 rounded-xl border px-3 py-2 text-sm ${
                      streamStatus.kind === 'danger'
                        ? 'border-rose-400/30 bg-rose-400/10 text-rose-100'
                        : 'border-amber-400/25 bg-amber-400/10 text-amber-100'
                    }`}
                  >
                    {streamStatus.text}
                  </div>
                ) : null}

                {scanId.trim() ? (
                  <div className="sm:col-span-2 flex flex-wrap gap-2">
                    <a className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-xs text-hs-muted" href={reportUrl('json')} target="_blank" rel="noreferrer">
                      Open JSON
                    </a>
                    <a className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-xs text-hs-muted" href={reportUrl('html')} target="_blank" rel="noreferrer">
                      Open HTML
                    </a>
                    <a className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-xs text-hs-muted" href={reportUrl('pdf')} target="_blank" rel="noreferrer">
                      Open PDF
                    </a>
                  </div>
                ) : null}

                <div className="sm:col-span-2 rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-white">Findings</h3>
                      <p className="mt-1 text-xs text-hs-muted">Parsed from the loaded scan response.</p>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(severitySummary).length > 0 ? (
                        Object.entries(severitySummary).map(([severity, count]) => (
                          <span key={severity} className={`rounded-full border px-2 py-0.5 text-[11px] ${severityClasses(severity)}`}>
                            {severity}: {count}
                          </span>
                        ))
                      ) : (
                        <span className="rounded-full border border-white/10 bg-black/20 px-2 py-0.5 text-[11px] text-hs-muted">No loaded findings</span>
                      )}
                    </div>
                  </div>

                  {findings.length > 0 ? (
                    <div className="mt-3 overflow-hidden rounded-xl border border-white/10">
                      <table className="w-full border-collapse text-left text-xs">
                        <thead className="bg-black/30 text-hs-muted">
                          <tr>
                            <th className="px-3 py-2 font-semibold">Severity</th>
                            <th className="px-3 py-2 font-semibold">Module</th>
                            <th className="px-3 py-2 font-semibold">Finding</th>
                          </tr>
                        </thead>
                        <tbody className="bg-black/10">
                          {findings.slice(0, 20).map((finding, index) => (
                            <tr key={`${finding.module ?? 'module'}-${finding.title ?? 'finding'}-${index}`} className="border-t border-white/10 align-top">
                              <td className="px-3 py-2">
                                <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] ${severityClasses(finding.severity)}`}>
                                  {finding.severity || 'info'}
                                </span>
                              </td>
                              <td className="px-3 py-2 font-mono text-[11px] text-hs-muted">{finding.module || 'unknown'}</td>
                              <td className="px-3 py-2">
                                <div className="font-semibold text-white">{finding.title || 'Untitled finding'}</div>
                                <div className="mt-1 leading-relaxed text-hs-muted">{finding.description || 'No description provided.'}</div>
                                {finding.remediation ? <div className="mt-2 leading-relaxed text-[#CFE3FF]">{finding.remediation}</div> : null}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {findings.length > 20 ? <div className="border-t border-white/10 px-3 py-2 text-xs text-hs-muted">Showing first 20 findings. Open the full report for all results.</div> : null}
                    </div>
                  ) : (
                    <div className="mt-3 rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-hs-muted">
                      Load a completed scan to see findings here.
                    </div>
                  )}
                </div>

                <div className="sm:col-span-2">
                  <div className="mb-2 rounded-full border border-white/10 bg-black/20 px-3 py-1 text-xs text-hs-muted inline-flex">Raw response preview</div>
                  <pre className="max-h-[420px] overflow-auto rounded-2xl border border-white/10 bg-black/30 p-4 text-xs leading-relaxed text-[#D7E2F6] shadow-inner">
                    {scanData ? safeJson(scanData) : '{\n  \"hint\": \"Load a scan to view its JSON response here.\"\n}'}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <aside className="space-y-4">
            <div className="rounded-hs border border-white/10 bg-white/5 shadow-hs">
              <div className="flex items-start justify-between gap-4 px-5 pt-5">
                <div>
                  <h2 className="text-sm font-bold text-white">Authentication</h2>
                  <p className="mt-1 text-xs leading-relaxed text-hs-muted">Register + login to get a JWT (stored in localStorage).</p>
                </div>
                <span className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-[11px] text-hs-muted">
                  <span className="font-mono">POST</span> /api/auth/login
                </span>
              </div>

              <div className="space-y-3 px-5 pb-5 pt-4">
                <div>
                  <label className="text-xs text-hs-muted">Email</label>
                  <input
                    className="mt-1 w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-cyan-300/50 focus:ring-4 focus:ring-cyan-300/10"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                  />
                </div>
                <div>
                  <label className="text-xs text-hs-muted">Password</label>
                  <input
                    className="mt-1 w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-cyan-300/50 focus:ring-4 focus:ring-cyan-300/10"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    type="password"
                    placeholder="••••••••"
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                    onClick={register}
                    disabled={!email.trim() || !password}
                  >
                    Register
                  </button>
                  <button
                    className="rounded-xl bg-gradient-to-r from-cyan-300 to-violet-400 px-4 py-2 text-sm font-semibold text-[#06121f] disabled:opacity-50"
                    onClick={login}
                    disabled={!email.trim() || !password}
                  >
                    Login
                  </button>
                </div>
                {authStatus ? (
                  <div
                    className={`rounded-xl border px-3 py-2 text-sm ${
                      authStatus.kind === 'ok'
                        ? 'border-emerald-400/25 bg-emerald-400/10 text-emerald-100'
                        : authStatus.kind === 'danger'
                          ? 'border-rose-400/30 bg-rose-400/10 text-rose-100'
                          : 'border-amber-400/25 bg-amber-400/10 text-amber-100'
                    }`}
                  >
                    {authStatus.text}
                  </div>
                ) : null}
              </div>
            </div>

            <div className="rounded-hs border border-white/10 bg-white/5 shadow-hs">
              <div className="flex items-start justify-between gap-4 px-5 pt-5">
                <div>
                  <h2 className="text-sm font-bold text-white">Scan history</h2>
                  <p className="mt-1 text-xs leading-relaxed text-hs-muted">Recent scans. Click a row to load its ID.</p>
                </div>
                <span className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-[11px] text-hs-muted">
                  <span className="font-mono">GET</span> /api/scans
                </span>
              </div>

              <div className="px-5 pb-5 pt-4">
                {!isAuthed ? (
                  <div className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm text-rose-100">
                    Login to view your scan history.
                  </div>
                ) : null}

                {isAuthed && scans.length === 0 ? (
                  <div className="rounded-xl border border-white/10 bg-black/10 px-3 py-2 text-sm text-hs-muted">
                    No scans yet. Create one on the left.
                  </div>
                ) : null}

                {isAuthed && scans.length > 0 ? (
                  <div className="overflow-hidden rounded-2xl border border-white/10">
                    <table className="w-full border-collapse text-left text-xs">
                      <thead className="bg-black/20 text-hs-muted">
                        <tr>
                          <th className="px-3 py-2 font-semibold">ID</th>
                          <th className="px-3 py-2 font-semibold">Target</th>
                          <th className="px-3 py-2 font-semibold">Status</th>
                          <th className="px-3 py-2 font-semibold">Updated</th>
                        </tr>
                      </thead>
                      <tbody className="bg-black/10">
                        {scans.slice(0, 15).map((s) => {
                          const b = statusBadge(s.status)
                          return (
                            <tr
                              key={s.id}
                              className="cursor-pointer border-t border-white/10 hover:bg-white/5"
                              onClick={() => {
                                setScanId(String(s.id))
                                setStreamStatus(null)
                                setScanData(null)
                              }}
                            >
                              <td className="px-3 py-2">
                                <span className="rounded-lg border border-white/10 bg-black/20 px-2 py-0.5 font-mono text-[10px] text-[#CFE3FF]">
                                  {s.id}
                                </span>
                              </td>
                              <td className="px-3 py-2 font-mono text-[11px] text-hs-muted">{s.target_url ?? ''}</td>
                              <td className="px-3 py-2">
                                <span
                                  className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] ${
                                    b.cls === 'ok'
                                      ? 'border-emerald-400/25 bg-emerald-400/10 text-emerald-100'
                                      : b.cls === 'danger'
                                        ? 'border-rose-400/30 bg-rose-400/10 text-rose-100'
                                        : b.cls === 'warn'
                                          ? 'border-amber-400/25 bg-amber-400/10 text-amber-100'
                                          : 'border-white/10 bg-black/20 text-hs-muted'
                                  }`}
                                >
                                  {b.label}
                                </span>
                              </td>
                              <td className="px-3 py-2 font-mono text-[11px] text-hs-muted">{s.updated_at ?? ''}</td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="rounded-hs border border-white/10 bg-black/10 px-4 py-3 text-sm text-hs-muted">
              Tip: open API docs at{' '}
              <a className="text-[#BBD7FF] hover:underline" href="http://localhost:8000/docs" target="_blank" rel="noreferrer">
                /docs
              </a>
              .
            </div>
          </aside>
        </div>
      </main>
    </div>
  )
}
