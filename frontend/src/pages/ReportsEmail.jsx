import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Mail, RefreshCw, Clock3, CalendarDays, Plus, Trash2, Power, PowerOff, Send } from 'lucide-react'
import { emailReportsAPI } from '../services/api'
import { PageHeader, EmptyState, Spinner } from '../components/ui'

const DAYS = [
  { value: 'daily', label: 'Daily' },
  { value: 'monday', label: 'Monday' },
  { value: 'tuesday', label: 'Tuesday' },
  { value: 'wednesday', label: 'Wednesday' },
  { value: 'thursday', label: 'Thursday' },
  { value: 'friday', label: 'Friday' },
  { value: 'saturday', label: 'Saturday' },
  { value: 'sunday', label: 'Sunday' },
]

export default function ReportsEmail() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [contacts, setContacts] = useState([])
  const [schedules, setSchedules] = useState([])
  const [runs, setRuns] = useState([])

  const [name, setName] = useState('SOC Email Report')
  const [dayOfWeek, setDayOfWeek] = useState('daily')
  const [timeOfDay, setTimeOfDay] = useState('09:00')
  const [intervalMinutes, setIntervalMinutes] = useState(1440)
  const [lookbackHours, setLookbackHours] = useState(24)
  const [severity, setSeverity] = useState('all')
  const [selectedEmails, setSelectedEmails] = useState([])
  const [newEmail, setNewEmail] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [contactsRes, schedulesRes, runsRes] = await Promise.allSettled([
        emailReportsAPI.contacts(),
        emailReportsAPI.listSchedules(),
        emailReportsAPI.listRuns(50),
      ])

      if (contactsRes.status === 'fulfilled') {
        setContacts(contactsRes.value.data.contacts || [])
      }
      if (schedulesRes.status === 'fulfilled') {
        setSchedules(schedulesRes.value.data.schedules || [])
      }
      if (runsRes.status === 'fulfilled') {
        setRuns(runsRes.value.data.runs || [])
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const allEmails = useMemo(() => {
    const set = new Set(contacts)
    selectedEmails.forEach((item) => set.add(item))
    return Array.from(set).sort()
  }, [contacts, selectedEmails])

  const toggleEmail = useCallback((email) => {
    setSelectedEmails((prev) => (
      prev.includes(email) ? prev.filter((item) => item !== email) : [...prev, email]
    ))
  }, [])

  const addCustomEmail = useCallback(() => {
    const value = (newEmail || '').trim().toLowerCase()
    if (!value) return
    if (!value.includes('@') || !value.includes('.')) return
    setSelectedEmails((prev) => (prev.includes(value) ? prev : [...prev, value]))
    setNewEmail('')
  }, [newEmail])

  // Convert "HH:MM" in IST to "HH:MM" in UTC
  const istToUtcTime = useCallback((hhmm) => {
    if (!hhmm) return hhmm
    const [hStr, mStr] = hhmm.split(':')
    let h = Number(hStr || 0)
    let m = Number(mStr || 0)
    // Subtract 5 hours 30 minutes
    m -= 30
    if (m < 0) { m += 60; h -= 1 }
    h -= 5
    h = ((h % 24) + 24) % 24
    const hh = String(h).padStart(2, '0')
    const mm = String(m).padStart(2, '0')
    return `${hh}:${mm}`
  }, [])

  // Convert UTC "HH:MM" to IST "HH:MM"
  const utcToIstTime = useCallback((hhmm) => {
    if (!hhmm) return hhmm
    const [hStr, mStr] = hhmm.split(':')
    let h = Number(hStr || 0)
    let m = Number(mStr || 0)
    // Add 5 hours 30 minutes
    m += 30
    if (m >= 60) { m -= 60; h += 1 }
    h += 5
    h = ((h % 24) + 24) % 24
    const hh = String(h).padStart(2, '0')
    const mm = String(m).padStart(2, '0')
    return `${hh}:${mm}`
  }, [])

  const formatToIst = useCallback((iso) => {
    if (!iso) return '—'
    try {
      const d = new Date(iso)
      return d.toLocaleString('en-GB', { timeZone: 'Asia/Kolkata' })
    } catch {
      return iso
    }
  }, [])

  // Compute day shift when converting IST time to UTC (-1 if previous day, +1 if next day)
  const istToUtcDayShift = useCallback((hhmm) => {
    if (!hhmm) return 0
    const [hStr, mStr] = hhmm.split(':')
    const h = Number(hStr || 0)
    const m = Number(mStr || 0)
    const total = h * 60 + m
    const shifted = total - 330 // IST -> UTC is minus 5h30m
    if (shifted < 0) return -1
    if (shifted >= 24 * 60) return 1
    return 0
  }, [])

  const weekdays = ['monday','tuesday','wednesday','thursday','friday','saturday','sunday']

  const adjustDayForUtc = useCallback((day, shift) => {
    if (!day || day === 'daily') return day
    const idx = weekdays.indexOf(day)
    if (idx === -1) return day
    const newIdx = ((idx + shift) % 7 + 7) % 7
    return weekdays[newIdx]
  }, [])

  // Convert stored UTC schedule day/time back to IST-day for display
  const utcDayToIstDay = useCallback((utcDay, utcTime) => {
    if (!utcDay || utcDay === 'daily') return utcDay
    // adding 5h30 may roll to next day
    const [hStr, mStr] = (utcTime || '').split(':')
    const h = Number(hStr || 0)
    const m = Number(mStr || 0)
    const total = h * 60 + m
    const shifted = total + 330
    let shift = 0
    if (shifted >= 24 * 60) shift = 1
    if (shifted < 0) shift = -1
    return adjustDayForUtc(utcDay, shift)
  }, [adjustDayForUtc])

  const createSchedule = useCallback(async () => {
    if (!name.trim() || selectedEmails.length === 0) return
    setSaving(true)
    try {
      // Convert IST input to UTC time and adjust day_of_week if needed
      const shift = istToUtcDayShift(timeOfDay)
      const utcDay = adjustDayForUtc(dayOfWeek, shift)
      await emailReportsAPI.createSchedule({
        name: name.trim(),
        day_of_week: utcDay,
        time_of_day: istToUtcTime(timeOfDay),
        interval_minutes: Number(intervalMinutes),
        lookback_hours: Number(lookbackHours),
        severity: severity === 'all' ? null : severity,
        recipients: selectedEmails,
        threat_types: [],
      })
      await load()
    } finally {
      setSaving(false)
    }
  }, [name, selectedEmails, dayOfWeek, timeOfDay, intervalMinutes, lookbackHours, severity, load])

  const toggleEnabled = useCallback(async (schedule) => {
    await emailReportsAPI.toggleSchedule(schedule.id, !schedule.enabled)
    await load()
  }, [load])

  const deleteSchedule = useCallback(async (scheduleId) => {
    await emailReportsAPI.deleteSchedule(scheduleId)
    await load()
  }, [load])

  return (
    <div className="p-4 lg:p-6 space-y-5 animate-fade-in">
      <PageHeader
        title="Email Reports"
        subtitle="Schedule report emails by day, time, interval, and recipients"
        icon={Mail}
      >
        <button onClick={load} className="btn-cyber text-xs px-3 py-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </PageHeader>

      <div className="cyber-card p-4 space-y-4">
        <div className="flex items-center gap-2">
          <Plus className="w-4 h-4 text-cyan-400" />
          <p className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">Create Email Schedule</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <div>
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Schedule Name</p>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            />
          </div>

          <div>
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Day</p>
            <select
              value={dayOfWeek}
              onChange={(e) => setDayOfWeek(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            >
              {DAYS.map((item) => (
                <option key={item.value} value={item.value}>{item.label}</option>
              ))}
            </select>
          </div>

          <div>
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Time (IST)</p>
            <input
              type="time"
              value={timeOfDay}
              onChange={(e) => setTimeOfDay(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            />
            <p className="text-[10px] font-mono text-slate-500 mt-1">Will be scheduled in IST (converted to UTC for server)</p>
          </div>

          <div>
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Interval Between Sends (minutes)</p>
            <input
              type="number"
              min={5}
              max={10080}
              value={intervalMinutes}
              onChange={(e) => setIntervalMinutes(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            />
          </div>

          <div>
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Report Time Period (hours)</p>
            <input
              type="number"
              min={1}
              max={336}
              value={lookbackHours}
              onChange={(e) => setLookbackHours(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            />
          </div>

          <div>
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Severity</p>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            >
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-[10px] font-mono text-slate-600 uppercase">Select Recipient Emails</p>
          {allEmails.length === 0 ? (
            <p className="font-mono text-xs text-slate-600">No saved contacts yet. Add one below.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {allEmails.map((email) => {
                const selected = selectedEmails.includes(email)
                return (
                  <button
                    key={email}
                    type="button"
                    onClick={() => toggleEmail(email)}
                    className={`px-2.5 py-1 rounded border text-[10px] font-mono transition-all ${selected ? 'border-cyan-500/40 text-cyan-300 bg-cyan-500/10' : 'border-slate-700 text-slate-500 hover:text-slate-300'}`}
                  >
                    {email}
                  </button>
                )
              })}
            </div>
          )}

          <div className="flex gap-2">
            <input
              type="email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="name@company.com"
              className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            />
            <button onClick={addCustomEmail} className="btn-cyber text-xs px-3 py-2">
              <Plus className="w-3.5 h-3.5" /> Add Email
            </button>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={createSchedule}
            disabled={saving || !name.trim() || selectedEmails.length === 0}
            className="btn-cyber text-xs px-3 py-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Saving...</> : <><Send className="w-3.5 h-3.5" /> Create Email Schedule</>}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <CalendarDays className="w-4 h-4 text-cyan-400" />
            <p className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">Active Email Schedules ({schedules.length})</p>
          </div>

          {loading ? (
            <div className="py-8 flex justify-center"><Spinner /></div>
          ) : schedules.length === 0 ? (
            <EmptyState icon={Mail} message="No email schedules yet" />
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {schedules.map((schedule) => (
                <div key={schedule.id} className="rounded border border-slate-800 bg-slate-900/60 p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="font-mono text-xs text-slate-200 font-semibold">{schedule.name}</p>
                      <p className="font-mono text-[10px] text-slate-500 mt-0.5">
                        {utcDayToIstDay(schedule.day_of_week, schedule.time_of_day) || schedule.day_of_week} at {utcToIstTime(schedule.time_of_day)} IST • every {schedule.interval_minutes} min
                      </p>
                      <p className="font-mono text-[10px] text-slate-600">Recipients: {(schedule.recipients || []).join(', ')}</p>
                      <p className="font-mono text-[10px] text-slate-600">Next run: {schedule.next_run_at ? formatToIst(schedule.next_run_at) : '—'}</p>
                      {schedule.last_error && (
                        <p className="font-mono text-[10px] text-rose-400 mt-1">Last error: {schedule.last_error}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => toggleEnabled(schedule)}
                        className={`px-2 py-1 rounded border text-[10px] font-mono ${schedule.enabled ? 'border-emerald-500/40 text-emerald-400' : 'border-yellow-500/40 text-yellow-400'}`}
                      >
                        {schedule.enabled ? <><Power className="w-3 h-3 inline" /> On</> : <><PowerOff className="w-3 h-3 inline" /> Off</>}
                      </button>
                      <button
                        onClick={() => deleteSchedule(schedule.id)}
                        className="px-2 py-1 rounded border border-rose-500/40 text-[10px] font-mono text-rose-400"
                      >
                        <Trash2 className="w-3 h-3 inline" /> Delete
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Clock3 className="w-4 h-4 text-cyan-400" />
            <p className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">Email Send History ({runs.length})</p>
          </div>

          {loading ? (
            <div className="py-8 flex justify-center"><Spinner /></div>
          ) : runs.length === 0 ? (
            <EmptyState icon={Clock3} message="No email report runs yet" />
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {runs.map((run) => (
                <div key={run.id} className="rounded border border-slate-800 bg-slate-900/60 p-3">
                  <p className="font-mono text-xs text-slate-200 font-semibold">{run.schedule_name || 'Email report run'}</p>
                  <p className="font-mono text-[10px] text-slate-500 mt-0.5">Rows: {run.row_count || 0} • {run.status || 'sent'}</p>
                  <p className="font-mono text-[10px] text-slate-600">Sent at: {run.sent_at ? formatToIst(run.sent_at) : '—'}</p>
                  <p className="font-mono text-[10px] text-slate-600">Recipients: {(run.recipients || []).join(', ')}</p>
                  {run.error && <p className="font-mono text-[10px] text-rose-400 mt-1">Error: {run.error}</p>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
