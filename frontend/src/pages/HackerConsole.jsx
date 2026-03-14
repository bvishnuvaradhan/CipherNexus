import { useState, useCallback, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Skull, Terminal, Play, LogOut, Wifi, Shield, Database,
  Globe, Code, Bug, Zap, Radio, Server, Eye, ChevronDown, ChevronUp,
  Activity, Target, Upload, Cpu, CheckCircle, XCircle, AlertTriangle
} from 'lucide-react'
import { useHackerAuth } from '../context/HackerAuthContext'
import { hackerAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'

// ── Attack Stage Definitions ─────────────────────────────────────────────────
const ATTACK_STAGES = [
  { id: 'init', label: 'INITIALIZING', icon: Cpu, duration: 400 },
  { id: 'probe', label: 'PROBING TARGET', icon: Target, duration: 600 },
  { id: 'deliver', label: 'DELIVERING PAYLOAD', icon: Upload, duration: 800 },
  { id: 'execute', label: 'EXECUTING ATTACK', icon: Activity, duration: 1000 },
  { id: 'detect', label: 'AWAITING DETECTION', icon: AlertTriangle, duration: 500 },
  { id: 'complete', label: 'COMPLETE', icon: CheckCircle, duration: 0 },
]

// ── Attack catalog ─────────────────────────────────────────────────────────
const ATTACKS = [
  {
    id: 'brute_force',
    label: 'Brute Force',
    icon: Terminal,
    color: '#ef4444',
    category: 'AUTH',
    severity: 'HIGH',
    desc: 'Systematically tries credential combinations against SSH/admin login endpoints until access is gained or account locked.',
    detects: 'Detective Agent — failed login burst analysis',
    params: [
      { key: 'username', label: 'Target Username', type: 'text', placeholder: 'root', default: 'root' },
      { key: 'attempt_count', label: 'Attempt Count', type: 'number', placeholder: '15', min: 5, max: 200, default: 15 },
      {
        key: 'auth_protocol', label: 'Auth Protocol', type: 'select', default: 'ssh',
        options: [
          { value: 'ssh', label: 'SSH (port 22)' },
          { value: 'rdp', label: 'RDP (port 3389)' },
          { value: 'http_basic', label: 'HTTP Basic Auth' },
          { value: 'ldap', label: 'LDAP (Active Directory)' },
        ],
      },
      {
        key: 'password_list', label: 'Password Wordlist', type: 'select', default: 'dictionary',
        options: [
          { value: 'rockyou', label: 'RockYou (14M passwords)' },
          { value: 'dictionary', label: 'Dictionary (common words)' },
          { value: 'custom', label: 'Custom (targeted)' },
        ],
      },
    ],
  },
  {
    id: 'port_scan',
    label: 'Port Scan',
    icon: Wifi,
    color: '#06b6d4',
    category: 'RECON',
    severity: 'MEDIUM',
    desc: 'Probes target ports sequentially or randomly to map open services, identify OS fingerprints, and find attack vectors.',
    detects: 'Sentry Agent — network anomaly detection',
    params: [
      { key: 'port_range_start', label: 'Port Range Start', type: 'number', placeholder: '1', min: 1, max: 65535, default: 1 },
      { key: 'port_range_end', label: 'Port Range End', type: 'number', placeholder: '65535', min: 1, max: 65535, default: 65535 },
      {
        key: 'scan_technique', label: 'Scan Technique', type: 'select', default: 'syn_stealth',
        options: [
          { value: 'syn_stealth', label: 'SYN Stealth (half-open)' },
          { value: 'tcp_connect', label: 'TCP Connect (full handshake)' },
          { value: 'udp', label: 'UDP Scan (stateless)' },
          { value: 'xmas', label: 'XMAS Tree (FIN+URG+PSH)' },
          { value: 'null_scan', label: 'NULL Scan (no flags)' },
        ],
      },
      {
        key: 'scan_timing', label: 'Scan Timing', type: 'select', default: 'normal',
        options: [
          { value: 'paranoid', label: 'Paranoid (5min between probes)' },
          { value: 'sneaky', label: 'Sneaky (15s between probes)' },
          { value: 'normal', label: 'Normal (default timing)' },
          { value: 'aggressive', label: 'Aggressive (minimal delay)' },
        ],
      },
    ],
  },
  {
    id: 'suspicious_login',
    label: 'Geo-Anomaly Login',
    icon: Globe,
    color: '#a855f7',
    category: 'AUTH',
    severity: 'MEDIUM',
    desc: 'Attempts authentication from a suspicious geographic location (TOR exit node, nation-state IP) to test geo-based detection.',
    detects: 'Detective Agent — login location analysis',
    params: [
      { key: 'username', label: 'Target Username', type: 'text', placeholder: 'admin', default: 'admin' },
      {
        key: 'device_fingerprint', label: 'Device Fingerprint', type: 'select', default: 'unknown_device',
        options: [
          { value: 'unknown_device', label: 'Unknown Device' },
          { value: 'mobile_emulator', label: 'Mobile Emulator' },
          { value: 'headless_browser', label: 'Headless Browser' },
        ],
      },
    ],
  },
  {
    id: 'data_exfiltration',
    label: 'Data Exfiltration',
    icon: Database,
    color: '#eab308',
    category: 'EXFIL',
    severity: 'CRITICAL',
    desc: 'Transfers abnormally large data volumes to external destinations via encrypted channels to evade shallow inspection.',
    detects: 'Detective Agent — outbound transfer analysis',
    params: [
      { key: 'payload_size_mb', label: 'Payload Size (MB)', type: 'number', placeholder: '150', min: 50, max: 1000, default: 150 },
      {
        key: 'exfil_protocol', label: 'Exfil Protocol', type: 'select', default: 'https',
        options: [
          { value: 'https', label: 'HTTPS (encrypted web)' },
          { value: 'dns_tunnel', label: 'DNS Tunnel (covert)' },
          { value: 'ftp', label: 'FTP (legacy)' },
          { value: 'sftp', label: 'SFTP (secure shell)' },
          { value: 'icmp', label: 'ICMP (ping tunnel)' },
        ],
      },
      {
        key: 'destination_type', label: 'Destination Type', type: 'select', default: 'external_cloud',
        options: [
          { value: 'external_cloud', label: 'External Cloud Storage' },
          { value: 'tor_exit', label: 'TOR Exit Node' },
          { value: 'foreign_asn', label: 'Foreign ASN' },
        ],
      },
      {
        key: 'exfil_encryption', label: 'Encryption', type: 'select', default: 'aes256',
        options: [
          { value: 'none', label: 'None (plaintext)' },
          { value: 'aes256', label: 'AES-256' },
          { value: 'custom', label: 'Custom Cipher' },
        ],
      },
    ],
  },
  {
    id: 'ddos',
    label: 'DDoS Flood',
    icon: Zap,
    color: '#f97316',
    category: 'NETWORK',
    severity: 'CRITICAL',
    desc: 'Launches massive volumetric flood attack using UDP/TCP SYN/HTTP flood techniques to overwhelm target infrastructure.',
    detects: 'Sentry Agent — volumetric anomaly & rate analysis',
    params: [
      { key: 'packet_rate', label: 'Packet Rate (pkt/s)', type: 'number', placeholder: '15000', min: 1000, max: 100000, default: 15000 },
      {
        key: 'flood_type', label: 'Flood Type', type: 'select', default: 'tcp_syn',
        options: [
          { value: 'udp', label: 'UDP Flood (stateless)' },
          { value: 'tcp_syn', label: 'TCP SYN Flood (half-open)' },
          { value: 'http', label: 'HTTP Flood (layer 7)' },
          { value: 'slowloris', label: 'Slowloris (slow connections)' },
          { value: 'amplification', label: 'Amplification (DNS/NTP)' },
        ],
      },
      { key: 'botnet_size', label: 'Simulated Botnet Size', type: 'number', placeholder: '1000', min: 100, max: 10000, default: 1000 },
    ],
  },
  {
    id: 'sql_injection',
    label: 'SQL Injection',
    icon: Code,
    color: '#ef4444',
    category: 'WEB',
    severity: 'CRITICAL',
    desc: 'Injects malicious SQL payloads into application input fields to extract database contents, bypass auth, or drop tables.',
    detects: 'Detective Agent — WAF & query pattern analysis',
    params: [
      {
        key: 'injection_type', label: 'Injection Technique', type: 'select', default: 'union',
        options: [
          { value: 'union', label: 'UNION-based (extract data)' },
          { value: 'blind', label: 'Blind Boolean (yes/no inference)' },
          { value: 'time_based', label: 'Time-based Blind (delay inference)' },
        ],
      },
      { key: 'target_endpoint', label: 'Target Endpoint', type: 'text', placeholder: '/api/login', default: '/api/login' },
      {
        key: 'waf_evasion', label: 'WAF Evasion', type: 'select', default: 'none',
        options: [
          { value: 'none', label: 'None (direct)' },
          { value: 'encoding', label: 'URL/Hex Encoding' },
          { value: 'case_switch', label: 'Case Switching' },
          { value: 'comment_injection', label: 'Comment Injection' },
        ],
      },
      {
        key: 'database_type', label: 'Target Database', type: 'select', default: 'mysql',
        options: [
          { value: 'mysql', label: 'MySQL' },
          { value: 'postgresql', label: 'PostgreSQL' },
          { value: 'mssql', label: 'MSSQL' },
          { value: 'oracle', label: 'Oracle' },
        ],
      },
    ],
  },
  {
    id: 'xss',
    label: 'XSS Attack',
    icon: Bug,
    color: '#ec4899',
    category: 'WEB',
    severity: 'HIGH',
    desc: 'Injects JavaScript payloads into web pages to steal session cookies, redirect users, or perform actions on their behalf.',
    detects: 'Detective Agent — input sanitization & script injection',
    params: [
      {
        key: 'xss_type', label: 'XSS Vector', type: 'select', default: 'reflected',
        options: [
          { value: 'reflected', label: 'Reflected (URL-based, immediate)' },
          { value: 'stored', label: 'Stored (persistent, affects all users)' },
          { value: 'dom', label: 'DOM-based (client-side sink exploitation)' },
        ],
      },
      {
        key: 'payload_encoding', label: 'Payload Encoding', type: 'select', default: 'none',
        options: [
          { value: 'none', label: 'None (raw payload)' },
          { value: 'base64', label: 'Base64 Encoded' },
          { value: 'url_encode', label: 'URL Encoded' },
          { value: 'html_entities', label: 'HTML Entities' },
        ],
      },
    ],
  },
  {
    id: 'ransomware',
    label: 'Ransomware',
    icon: Shield,
    color: '#dc2626',
    category: 'MALWARE',
    severity: 'CRITICAL',
    desc: 'Deploys ransomware payload that encrypts filesystem, establishes C2 communication, and spreads laterally across the network.',
    detects: 'Detective Agent — file system & behavioral analysis',
    params: [
      {
        key: 'spread_rate', label: 'Lateral Spread Rate', type: 'select', default: 'medium',
        options: [
          { value: 'slow', label: 'Slow (2-5 hosts, stealthy)' },
          { value: 'medium', label: 'Medium (5-20 hosts, balanced)' },
          { value: 'fast', label: 'Fast (20-100 hosts, aggressive)' },
        ],
      },
      {
        key: 'encryption_algo', label: 'Encryption Algorithm', type: 'select', default: 'aes256',
        options: [
          { value: 'aes256', label: 'AES-256 (symmetric)' },
          { value: 'rsa2048', label: 'RSA-2048 (asymmetric)' },
          { value: 'chacha20', label: 'ChaCha20 (stream cipher)' },
        ],
      },
      {
        key: 'ransom_family', label: 'Ransom Family', type: 'select', default: 'lockbit',
        options: [
          { value: 'lockbit', label: 'LockBit 3.0' },
          { value: 'blackcat', label: 'BlackCat/ALPHV' },
          { value: 'cl0p', label: 'Cl0p' },
          { value: 'revil', label: 'REvil/Sodinokibi' },
        ],
      },
    ],
  },
  {
    id: 'mitm',
    label: 'Man-in-the-Middle',
    icon: Eye,
    color: '#8b5cf6',
    category: 'NETWORK',
    severity: 'CRITICAL',
    desc: 'Positions between client and server using ARP poisoning / SSL stripping to intercept and modify encrypted communications.',
    detects: 'Sentry Agent — ARP anomaly & certificate validation',
    params: [
      {
        key: 'target_protocol', label: 'Intercept Protocol', type: 'select', default: 'http',
        options: [
          { value: 'http', label: 'HTTP (clear-text, easiest)' },
          { value: 'https', label: 'HTTPS (SSL strip / cert forgery)' },
          { value: 'ftp', label: 'FTP (credential sniffing)' },
        ],
      },
      {
        key: 'mitm_technique', label: 'Attack Technique', type: 'select', default: 'arp_poison',
        options: [
          { value: 'arp_poison', label: 'ARP Poisoning' },
          { value: 'ssl_strip', label: 'SSL Stripping' },
          { value: 'dns_hijack', label: 'DNS Hijacking' },
        ],
      },
      {
        key: 'capture_type', label: 'Capture Mode', type: 'select', default: 'credentials',
        options: [
          { value: 'credentials', label: 'Credentials Only' },
          { value: 'full_traffic', label: 'Full Traffic Capture' },
          { value: 'selective', label: 'Selective (keywords)' },
        ],
      },
    ],
  },
  {
    id: 'dns_spoofing',
    label: 'DNS Spoofing',
    icon: Server,
    color: '#10b981',
    category: 'NETWORK',
    severity: 'HIGH',
    desc: 'Poisons DNS cache to redirect legitimate domain requests to malicious servers for credential harvesting or malware delivery.',
    detects: 'Sentry Agent — DNS response integrity analysis',
    params: [
      { key: 'target_domain', label: 'Target Domain', type: 'text', placeholder: 'internal.corp', default: 'internal.corp' },
      { key: 'redirect_target', label: 'Redirect IP', type: 'text', placeholder: '10.0.0.99', default: '' },
      {
        key: 'record_type', label: 'DNS Record Type', type: 'select', default: 'A',
        options: [
          { value: 'A', label: 'A Record (IPv4)' },
          { value: 'AAAA', label: 'AAAA Record (IPv6)' },
          { value: 'CNAME', label: 'CNAME (alias)' },
          { value: 'MX', label: 'MX Record (mail)' },
        ],
      },
    ],
  },
  {
    id: 'command_control',
    label: 'C2 Beacon',
    icon: Radio,
    color: '#f59e0b',
    category: 'MALWARE',
    severity: 'CRITICAL',
    desc: 'Establishes covert Command & Control channel with periodic beacons using DNS tunnel/HTTPS to exfiltrate data and receive commands.',
    detects: 'Sentry Agent — beacon interval & C2 pattern analysis',
    params: [
      { key: 'beacon_interval', label: 'Beacon Interval (sec)', type: 'number', placeholder: '60', min: 5, max: 600, default: 60 },
      {
        key: 'c2_protocol', label: 'C2 Protocol', type: 'select', default: 'https',
        options: [
          { value: 'https', label: 'HTTPS (encrypted web)' },
          { value: 'dns_tunnel', label: 'DNS Tunnel (covert)' },
          { value: 'irc', label: 'IRC (legacy)' },
          { value: 'custom', label: 'Custom Protocol' },
        ],
      },
      {
        key: 'persistence_method', label: 'Persistence Method', type: 'select', default: 'registry',
        options: [
          { value: 'registry', label: 'Registry Autorun' },
          { value: 'scheduled_task', label: 'Scheduled Task' },
          { value: 'wmi', label: 'WMI Subscription' },
          { value: 'service', label: 'System Service' },
        ],
      },
      { key: 'jitter_percent', label: 'Jitter %', type: 'number', placeholder: '10', min: 0, max: 50, default: 10 },
    ],
  },
  {
    id: 'traffic_spike',
    label: 'Traffic Spike',
    icon: Zap,
    color: '#22d3ee',
    category: 'NETWORK',
    severity: 'HIGH',
    desc: 'Generates abnormal traffic volume burst from a single source to trigger network anomaly detection and stress test thresholds.',
    detects: 'Sentry Agent — packet rate threshold monitoring',
    params: [
      { key: 'packet_rate', label: 'Packet Rate (pkt/s)', type: 'number', placeholder: '5000', min: 1000, max: 20000, default: 5000 },
      {
        key: 'spike_protocol', label: 'Protocol', type: 'select', default: 'tcp',
        options: [
          { value: 'tcp', label: 'TCP' },
          { value: 'udp', label: 'UDP' },
          { value: 'icmp', label: 'ICMP' },
          { value: 'http', label: 'HTTP' },
        ],
      },
      {
        key: 'source_spoofing', label: 'Source Spoofing', type: 'select', default: 'false',
        options: [
          { value: 'false', label: 'Disabled' },
          { value: 'true', label: 'Enabled' },
        ],
      },
    ],
  },
]

const INTENSITIES = [
  { value: 'low',    label: 'LOW',    color: '#10b981' },
  { value: 'medium', label: 'MEDIUM', color: '#eab308' },
  { value: 'high',   label: 'HIGH',   color: '#ef4444' },
]

const CATEGORY_COLORS = {
  AUTH:    '#a855f7',
  RECON:   '#06b6d4',
  EXFIL:   '#eab308',
  NETWORK: '#f97316',
  WEB:     '#ef4444',
  MALWARE: '#dc2626',
}

function buildDefaultParams(attack) {
  return Object.fromEntries((attack.params || []).map((param) => [param.key, param.default ?? '']))
}

// ── Attack Progress Indicator ────────────────────────────────────────────────
function AttackProgress({ currentStage, attack, startTime }) {
  const [elapsed, setElapsed] = useState(0)
  const currentIdx = ATTACK_STAGES.findIndex(s => s.id === currentStage)

  useEffect(() => {
    if (!startTime) return
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime) / 1000))
    }, 100)
    return () => clearInterval(interval)
  }, [startTime])

  if (!attack) return null

  return (
    <div className="rounded-xl border overflow-hidden animate-fade-in"
      style={{ background: 'rgba(10,5,5,0.95)', borderColor: attack.color + '40' }}
    >
      {/* Header with attack info */}
      <div className="px-4 py-3 border-b flex items-center gap-3"
        style={{ borderColor: attack.color + '20', background: attack.color + '08' }}
      >
        <div className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ background: attack.color + '20', border: `1px solid ${attack.color}40` }}
        >
          <attack.icon className="w-4 h-4" style={{ color: attack.color }} />
        </div>
        <div className="flex-1">
          <p className="font-mono font-bold text-sm" style={{ color: attack.color }}>{attack.label}</p>
          <p className="font-mono text-[10px]" style={{ color: '#6b2020' }}>Active execution in progress</p>
        </div>
        <div className="text-right">
          <p className="font-mono text-lg font-bold tabular-nums" style={{ color: attack.color }}>{elapsed}s</p>
          <p className="font-mono text-[9px]" style={{ color: '#4a1515' }}>ELAPSED</p>
        </div>
      </div>

      {/* Stage progress */}
      <div className="p-4">
        <div className="relative">
          {/* Progress line */}
          <div className="absolute top-4 left-4 right-4 h-0.5" style={{ background: '#1a0808' }}>
            <div
              className="h-full transition-all duration-300"
              style={{
                width: `${(currentIdx / (ATTACK_STAGES.length - 1)) * 100}%`,
                background: `linear-gradient(90deg, ${attack.color}, ${attack.color}80)`,
                boxShadow: `0 0 8px ${attack.color}60`
              }}
            />
          </div>

          {/* Stage indicators */}
          <div className="relative flex justify-between">
            {ATTACK_STAGES.map((stage, idx) => {
              const isActive = idx === currentIdx
              const isComplete = idx < currentIdx
              const isPending = idx > currentIdx
              const Icon = stage.icon

              return (
                <div key={stage.id} className="flex flex-col items-center" style={{ width: 70 }}>
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-all duration-300 ${isActive ? 'animate-pulse' : ''}`}
                    style={{
                      background: isComplete ? attack.color + '30' : isActive ? attack.color + '20' : '#0a0505',
                      borderColor: isComplete || isActive ? attack.color : '#2a0a0a',
                      boxShadow: isActive ? `0 0 12px ${attack.color}50` : 'none',
                    }}
                  >
                    <Icon
                      className={`w-4 h-4 transition-all ${isActive ? 'animate-pulse' : ''}`}
                      style={{ color: isComplete || isActive ? attack.color : '#3d1515' }}
                    />
                  </div>
                  <p
                    className="font-mono text-[8px] mt-2 text-center leading-tight uppercase"
                    style={{ color: isComplete || isActive ? attack.color : '#3d1515' }}
                  >
                    {stage.label}
                  </p>
                </div>
              )
            })}
          </div>
        </div>

        {/* Current stage detail */}
        <div className="mt-6 p-3 rounded-lg" style={{ background: attack.color + '08', border: `1px solid ${attack.color}15` }}>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: attack.color }} />
            <span className="font-mono text-xs font-bold" style={{ color: attack.color }}>
              {ATTACK_STAGES[currentIdx]?.label || 'PROCESSING'}
            </span>
          </div>
          <p className="font-mono text-[11px] mt-1" style={{ color: '#64748b' }}>
            {currentStage === 'init' && 'Initializing attack payload and configuring parameters...'}
            {currentStage === 'probe' && 'Scanning target for vulnerabilities and open services...'}
            {currentStage === 'deliver' && 'Transmitting payload to target system...'}
            {currentStage === 'execute' && 'Executing attack vector on target infrastructure...'}
            {currentStage === 'detect' && 'Attack complete — defense agents analyzing traffic...'}
            {currentStage === 'complete' && 'Attack simulation complete — view results below'}
          </p>
        </div>
      </div>
    </div>
  )
}

// ── Terminal log ────────────────────────────────────────────────────────────
function HackerTerminal({ logs }) {
  const bottomRef = useRef(null)
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [logs])

  return (
    <div className="rounded-xl border overflow-hidden"
      style={{ background: '#050305', borderColor: 'rgba(239,68,68,0.15)' }}
    >
      <div className="flex items-center gap-2 px-4 py-2.5 border-b"
        style={{ background: '#0a0505', borderColor: 'rgba(239,68,68,0.12)' }}
      >
        <div className="flex gap-1.5">
          <span className="w-3 h-3 rounded-full bg-red-500/60" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/30" />
          <span className="w-3 h-3 rounded-full bg-green-500/30" />
        </div>
        <span className="font-mono text-xs ml-2" style={{ color: '#6b2020' }}>
          hacker@nexus:~$ — attack_console v2.0
        </span>
        <div className="ml-auto flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          <span className="font-mono text-[10px]" style={{ color: '#ef4444' }}>LIVE</span>
        </div>
      </div>
      <div className="p-4 font-mono text-xs space-y-1 h-52 overflow-y-auto">
        {logs.length === 0 ? (
          <span style={{ color: '#3d0f0f' }}>_ select an attack vector and launch...</span>
        ) : (
          logs.map((l, i) => (
            <div key={i} className="flex gap-3">
              <span style={{ color: '#3d1515' }} className="shrink-0">[{l.time}]</span>
              <span className="shrink-0 font-bold" style={{ color:
                l.type === 'error'   ? '#ef4444' :
                l.type === 'success' ? '#10b981' :
                l.type === 'warn'    ? '#eab308' :
                l.type === 'detect'  ? '#f97316' :
                '#94a3b8'
              }}>{l.tag}</span>
              <span style={{ color: '#94a3b8' }}>{l.msg}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── Attack result ───────────────────────────────────────────────────────────
function AttackResult({ result, attackLabel }) {
  if (!result) return null
  const alert = result.agent_result?.alert
  const severity = alert?.severity?.toUpperCase() || 'DETECTED'
  const sevColor = severity === 'CRITICAL' ? '#ef4444' : severity === 'HIGH' ? '#f97316' : '#eab308'

  return (
    <div className="rounded-xl border p-5 animate-fade-in"
      style={{ background: 'rgba(16,5,5,0.8)', borderColor: 'rgba(239,68,68,0.25)' }}
    >
      <div className="flex items-center gap-2 mb-4 pb-3 border-b" style={{ borderColor: 'rgba(239,68,68,0.12)' }}>
        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
        <span className="font-mono text-sm font-bold" style={{ color: '#ef4444' }}>ATTACK EXECUTED</span>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        {[
          { label: 'ATTACK TYPE', val: attackLabel, color: '#ef4444' },
          { label: 'SOURCE IP',   val: result.attack?.source_ip, color: '#06b6d4' },
          { label: 'AGENT TRIGGERED', val: result.agent_result?.triggered, color: '#a855f7' },
          { label: 'MITIGATED', val: result.attack?.mitigated ? 'YES' : 'PENDING',
            color: result.attack?.mitigated ? '#10b981' : '#eab308' },
        ].map(({ label, val, color }) => (
          <div key={label}>
            <p className="font-mono text-[10px] mb-1 uppercase" style={{ color: '#4a1515' }}>{label}</p>
            <p className="font-mono text-sm font-bold" style={{ color }}>{val || '—'}</p>
          </div>
        ))}
      </div>

      {alert && (
        <div className="pt-3 border-t space-y-2" style={{ borderColor: 'rgba(239,68,68,0.12)' }}>
          <p className="font-mono text-[10px] uppercase" style={{ color: '#4a1515' }}>DETECTION RESULT</p>
          <div className="flex items-center gap-3 flex-wrap">
            <span className="px-2 py-0.5 rounded font-mono text-xs font-bold border"
              style={{ color: sevColor, borderColor: sevColor + '40', background: sevColor + '15' }}>
              {severity}
            </span>
            <span className="font-mono text-xs" style={{ color: '#94a3b8' }}>{alert.event}</span>
            <div className="flex items-center gap-2 ml-auto">
              <span className="font-mono text-[11px]" style={{ color: '#6b2020' }}>CONFIDENCE</span>
              <div className="w-20 h-1.5 rounded-full" style={{ background: '#1a0505' }}>
                <div className="h-full rounded-full" style={{
                  width: `${Math.round((alert.confidence || 0) * 100)}%`,
                  background: '#ef4444',
                }} />
              </div>
              <span className="font-mono text-xs font-bold" style={{ color: '#ef4444' }}>
                {Math.round((alert.confidence || 0) * 100)}%
              </span>
            </div>
          </div>
          {alert.details && (
            <div className="mt-2 p-2 rounded" style={{ background: 'rgba(239,68,68,0.04)' }}>
              <p className="font-mono text-[10px] uppercase mb-1" style={{ color: '#4a1515' }}>ATTACK DETAILS</p>
              {Object.entries(alert.details).slice(0, 4).map(([k, v]) => (
                <p key={k} className="font-mono text-[11px]" style={{ color: '#64748b' }}>
                  <span style={{ color: '#6b2020' }}>{k}:</span>{' '}
                  <span style={{ color: '#94a3b8' }}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Attack card ─────────────────────────────────────────────────────────────
function AttackCard({ attack, intensity, running, onLaunch }) {
  const [expanded, setExpanded] = useState(false)
  const [paramValues, setParamValues] = useState(
    Object.fromEntries(attack.params.map(p => [p.key, p.default ?? '']))
  )
  const isRunning = running === attack.id
  const Icon = attack.icon

  return (
    <div className="rounded-xl border overflow-hidden transition-all duration-200"
      style={{
        background: 'rgba(10,5,5,0.8)',
        borderColor: isRunning ? attack.color + '60' : 'rgba(239,68,68,0.12)',
        boxShadow: isRunning ? `0 0 20px ${attack.color}25` : 'none',
      }}
    >
      {/* Header */}
      <div className="flex items-start gap-3 p-4">
        <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
          style={{ background: attack.color + '15', border: `1px solid ${attack.color}30` }}
        >
          <Icon className="w-5 h-5" style={{ color: attack.color }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5 flex-wrap">
            <span className="font-mono font-bold text-sm" style={{ color: attack.color }}>{attack.label}</span>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold"
              style={{ background: CATEGORY_COLORS[attack.category] + '20', color: CATEGORY_COLORS[attack.category] }}>
              {attack.category}
            </span>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ml-auto"
              style={{
                background: attack.severity === 'CRITICAL' ? '#ef444420' : attack.severity === 'HIGH' ? '#f9731620' : '#eab30820',
                color: attack.severity === 'CRITICAL' ? '#ef4444' : attack.severity === 'HIGH' ? '#f97316' : '#eab308',
              }}>
              {attack.severity}
            </span>
          </div>
          <p className="font-mono text-[11px]" style={{ color: '#4a1515' }}>→ {attack.detects}</p>
        </div>
      </div>

      {/* Description */}
      <p className="font-mono text-xs px-4 pb-3 leading-relaxed" style={{ color: '#64748b' }}>
        {attack.desc}
      </p>

      {/* Expandable params */}
      {attack.params.length > 0 && (
        <div className="px-4 pb-3">
          <button
            onClick={() => setExpanded(e => !e)}
            className="flex items-center gap-1.5 font-mono text-[11px] transition-colors"
            style={{ color: expanded ? attack.color : '#4a1515' }}
          >
            {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            {expanded ? 'Hide Parameters' : 'Configure Parameters'}
          </button>
          {expanded && (
            <div className="mt-3 space-y-3">
              {attack.params.map(param => (
                <div key={param.key}>
                  <label className="block font-mono text-[10px] uppercase mb-1" style={{ color: '#4a1515' }}>
                    {param.label}
                  </label>
                  {param.type === 'select' ? (
                    <select
                      value={paramValues[param.key]}
                      onChange={e => setParamValues(p => ({ ...p, [param.key]: e.target.value }))}
                      className="w-full px-3 py-2 rounded-lg font-mono text-xs outline-none"
                      style={{ background: '#0a0505', border: `1px solid ${attack.color}25`, color: '#94a3b8' }}
                    >
                      {param.options.map(o => (
                        <option key={o.value} value={o.value}>{o.label}</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type={param.type}
                      value={paramValues[param.key]}
                      onChange={e => setParamValues(p => ({ ...p, [param.key]: param.type === 'number' ? Number(e.target.value) : e.target.value }))}
                      placeholder={param.placeholder}
                      min={param.min}
                      max={param.max}
                      className="w-full px-3 py-2 rounded-lg font-mono text-xs outline-none"
                      style={{ background: '#0a0505', border: `1px solid ${attack.color}25`, color: '#94a3b8' }}
                    />
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Launch */}
      <div className="px-4 pb-4">
        <button
          onClick={() => onLaunch(attack.id, paramValues)}
          disabled={!!running}
          className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg font-mono text-sm font-bold uppercase tracking-wider transition-all duration-200"
          style={{
            background: isRunning ? attack.color + '25' : attack.color + '15',
            border: `1px solid ${attack.color}40`,
            color: attack.color,
            opacity: running && !isRunning ? 0.35 : 1,
            cursor: running ? (isRunning ? 'wait' : 'not-allowed') : 'pointer',
          }}
        >
          {isRunning ? (
            <><span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />EXECUTING...</>
          ) : (
            <><Play className="w-3.5 h-3.5" />Launch Attack</>
          )}
        </button>
      </div>
    </div>
  )
}

// ── Main Console ───────────────────────────────────────────────────────────
export default function HackerConsole() {
  const { hacker, hackerLogout } = useHackerAuth()
  const navigate = useNavigate()
  const [intensity, setIntensity] = useState('medium')
  const [sourceIp, setSourceIp] = useState('')
  const [targetIp, setTargetIp] = useState('192.168.0.1')
  const [running, setRunning] = useState(null)
  const [currentStage, setCurrentStage] = useState(null)
  const [attackStartTime, setAttackStartTime] = useState(null)
  const [activeAttack, setActiveAttack] = useState(null)
  const [termLogs, setTermLogs] = useState([])
  const [lastResult, setLastResult] = useState(null)
  const [lastAttackLabel, setLastAttackLabel] = useState('')
  const [filterCat, setFilterCat] = useState('ALL')

  const addLog = useCallback((type, tag, msg) => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false })
    setTermLogs(p => [...p, { type, tag, msg, time }].slice(-60))
  }, [])

  const handleWs = useCallback((msg) => {
    if (msg.type === 'simulation_started') {
      addLog('warn', '[BROADCAST]', `Attack signal propagating — defense agents notified`)
    }
    if (msg.type === 'alert') {
      addLog('detect', '[DETECTED]', `${msg.data.event} — severity: ${msg.data.severity?.toUpperCase()} — agents responding`)
    }
    if (msg.type === 'response') {
      addLog('success', '[MITIGATED]', `Commander: ${msg.data.action} — confidence: ${Math.round((msg.data.confidence || 0) * 100)}%`)
    }
  }, [addLog])
  useWebSocket(handleWs)

  const executeAttackRequest = useCallback(async (attackId, params) => {
    return hackerAPI.launchAttack({
      attack_type: attackId,
      source_ip: sourceIp || null,
      target_ip: targetIp,
      intensity,
      ...params,
    })
  }, [intensity, sourceIp, targetIp])

  const launchAttack = useCallback(async (attackId, params) => {
    const attack = ATTACKS.find(a => a.id === attackId)
    setRunning(attackId)
    setLastResult(null)
    setLastAttackLabel(attack?.label || attackId)
    setActiveAttack(attack)
    setAttackStartTime(Date.now())
    setCurrentStage('init')

    // Stage 1: Initialize
    addLog('warn', '[INIT]', `Initializing ${attack?.label || attackId} payload...`)
    addLog('info', '[CONFIG]', `Intensity: ${intensity.toUpperCase()} | Protocol: ${params.auth_protocol || params.scan_technique || params.flood_type || 'default'}`)
    await new Promise(r => setTimeout(r, 400))

    // Stage 2: Probe
    setCurrentStage('probe')
    addLog('info', '[PROBE]', `Scanning target ${targetIp} for attack vectors...`)
    addLog('info', '[ROUTE]', `Source: ${sourceIp || 'auto-assigned'} → Target: ${targetIp}`)
    await new Promise(r => setTimeout(r, 600))

    // Stage 3: Deliver
    setCurrentStage('deliver')
    addLog('warn', '[PAYLOAD]', `Transmitting attack payload (${attack?.category} vector)...`)
    addLog('info', '[STREAM]', `Establishing connection through agent pipeline...`)
    await new Promise(r => setTimeout(r, 500))

    try {
      // Stage 4: Execute
      setCurrentStage('execute')
      addLog('error', '[EXECUTE]', `>>> ATTACK VECTOR DEPLOYED <<<`)

      const res = await executeAttackRequest(attackId, params)

      // Stage 5: Detection
      setCurrentStage('detect')
      addLog('warn', '[DISPATCH]', `Attack traffic entering defense perimeter...`)
      await new Promise(r => setTimeout(r, 300))

      const data = res.data
      setLastResult(data)

      const alert = data.agent_result?.alert
      if (alert) {
        addLog('detect', '[DETECTED]', `Defense agents identified: ${alert.event}`)
        addLog('detect', '[SEVERITY]', `${alert.severity?.toUpperCase()} threat — ${Math.round((alert.confidence || 0) * 100)}% confidence`)
        addLog('info', '[AGENT]', `${data.agent_result?.triggered || 'System'} agent responded to threat`)
      }

      // Stage 6: Complete
      setCurrentStage('complete')
      await new Promise(r => setTimeout(r, 500))
      addLog('success', '[COMPLETE]', `Attack simulation finished — check SOC dashboard for defense response`)
    } catch (err) {
      setCurrentStage('complete')
      addLog('error', '[ERROR]', err.response?.data?.detail || 'Attack failed — backend unreachable')
    } finally {
      setTimeout(() => {
        setRunning(null)
        setCurrentStage(null)
        setActiveAttack(null)
        setAttackStartTime(null)
      }, 1500)
    }
  }, [addLog, executeAttackRequest])

  const launchAllAttacks = useCallback(async () => {
    setRunning('all_attacks')
    setCurrentStage(null)
    setActiveAttack(null)
    setAttackStartTime(Date.now())
    setLastResult(null)
    setLastAttackLabel('All Attacks')

    addLog('warn', '[BATCH]', `Launching all ${ATTACKS.length} attack vectors simultaneously...`)
    addLog('info', '[CONFIG]', `Intensity: ${intensity.toUpperCase()} | Source: ${sourceIp || 'auto-assigned'} | Target: ${targetIp}`)

    const results = await Promise.allSettled(
      ATTACKS.map(async (attack) => {
        addLog('warn', '[QUEUE]', `${attack.label} queued for dispatch`)
        const res = await executeAttackRequest(attack.id, buildDefaultParams(attack))
        return { attack, data: res.data }
      })
    )

    const successes = results.filter((result) => result.status === 'fulfilled')
    const failures = results.filter((result) => result.status === 'rejected')

    successes.forEach((result) => {
      const { attack, data } = result.value
      const alert = data.agent_result?.alert
      addLog(
        'success',
        '[BATCH-OK]',
        `${attack.label} launched${alert ? ` — ${alert.event} (${String(alert.severity || '').toUpperCase()})` : ''}`
      )
    })

    failures.forEach((result) => {
      addLog('error', '[BATCH-ERR]', result.reason?.response?.data?.detail || result.reason?.message || 'Attack dispatch failed')
    })

    addLog('success', '[BATCH]', `Completed batch dispatch: ${successes.length} succeeded, ${failures.length} failed`)

    if (successes.length > 0) {
      const latest = successes[successes.length - 1].value
      setLastResult(latest.data)
      setLastAttackLabel(`${latest.attack.label} (batch result)`)
    }

    setTimeout(() => {
      setRunning(null)
      setAttackStartTime(null)
    }, 1200)
  }, [addLog, executeAttackRequest, intensity, sourceIp, targetIp])

  const handleLogout = () => {
    hackerLogout()
    navigate('/hacker/login')
  }

  const categories = ['ALL', ...new Set(ATTACKS.map(a => a.category))]
  const filtered = filterCat === 'ALL' ? ATTACKS : ATTACKS.filter(a => a.category === filterCat)

  return (
    <div className="min-h-screen" style={{ background: '#060305' }}>
      {/* Header */}
      <header className="border-b px-6 py-3 flex items-center gap-4"
        style={{ background: '#0a0505', borderColor: 'rgba(239,68,68,0.15)' }}
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}
          >
            <Skull className="w-4 h-4" style={{ color: '#ef4444' }} />
          </div>
          <div>
            <p className="font-mono font-bold text-sm" style={{ color: '#ef4444' }}>HACKER CONSOLE</p>
            <p className="font-mono text-[10px]" style={{ color: '#4a1515' }}>CipherNexus Attack Simulation Platform</p>
          </div>
        </div>

        <div className="flex items-center gap-4 ml-auto">
          <div className="flex items-center gap-2 px-3 py-1 rounded border font-mono text-xs"
            style={{ background: 'rgba(239,68,68,0.05)', borderColor: 'rgba(239,68,68,0.2)', color: '#6b2020' }}
          >
            <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
            operator: <span style={{ color: '#ef4444' }}>{hacker?.username}</span>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border font-mono text-xs transition-all"
            style={{ borderColor: 'rgba(239,68,68,0.2)', color: '#6b2020' }}
            onMouseEnter={e => e.currentTarget.style.color = '#ef4444'}
            onMouseLeave={e => e.currentTarget.style.color = '#6b2020'}
          >
            <LogOut className="w-3.5 h-3.5" />
            Disconnect
          </button>
        </div>
      </header>

      <div className="p-6 space-y-6">
        {/* Warning banner */}
        <div className="rounded-xl p-4 border font-mono text-xs flex items-start gap-3"
          style={{ background: 'rgba(239,68,68,0.04)', borderColor: 'rgba(239,68,68,0.2)', color: '#94a3b8' }}
        >
          <Terminal className="w-4 h-4 shrink-0 mt-0.5" style={{ color: '#ef4444' }} />
          <div>
            <span className="font-bold" style={{ color: '#ef4444' }}>SIMULATION ENVIRONMENT — </span>
            All attacks are synthetic and contained within the platform. Each attack triggers the real AI agent
            detection pipeline — Sentry, Detective, and Commander will detect, analyze, and respond in real-time.
            Monitor the SOC Dashboard to observe defense responses.
          </div>
        </div>

        {/* Global controls */}
        <div className="rounded-xl border p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
          style={{ background: 'rgba(10,5,5,0.8)', borderColor: 'rgba(239,68,68,0.12)' }}
        >
          {/* Intensity */}
          <div>
            <label className="block font-mono text-[10px] uppercase mb-2" style={{ color: '#4a1515' }}>Attack Intensity</label>
            <div className="flex gap-1">
              {INTENSITIES.map(({ value, label, color }) => (
                <button
                  key={value}
                  onClick={() => setIntensity(value)}
                  className="flex-1 py-1.5 rounded font-mono text-[10px] font-bold uppercase transition-all"
                  style={{
                    background: intensity === value ? color + '20' : 'transparent',
                    border: `1px solid ${intensity === value ? color + '50' : 'rgba(239,68,68,0.1)'}`,
                    color: intensity === value ? color : '#4a1515',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Source IP */}
          <div>
            <label className="block font-mono text-[10px] uppercase mb-2" style={{ color: '#4a1515' }}>Source IP (optional)</label>
            <input
              type="text"
              value={sourceIp}
              onChange={e => setSourceIp(e.target.value)}
              placeholder="auto-assign"
              className="w-full px-3 py-2 rounded-lg font-mono text-xs outline-none"
              style={{ background: '#060305', border: '1px solid rgba(239,68,68,0.15)', color: '#94a3b8' }}
            />
          </div>

          {/* Target IP */}
          <div>
            <label className="block font-mono text-[10px] uppercase mb-2" style={{ color: '#4a1515' }}>Target IP</label>
            <input
              type="text"
              value={targetIp}
              onChange={e => setTargetIp(e.target.value)}
              placeholder="192.168.0.1"
              className="w-full px-3 py-2 rounded-lg font-mono text-xs outline-none"
              style={{ background: '#060305', border: '1px solid rgba(239,68,68,0.15)', color: '#94a3b8' }}
            />
          </div>

          {/* Category filter */}
          <div>
            <label className="block font-mono text-[10px] uppercase mb-2" style={{ color: '#4a1515' }}>Filter Category</label>
            <select
              value={filterCat}
              onChange={e => setFilterCat(e.target.value)}
              className="w-full px-3 py-2 rounded-lg font-mono text-xs outline-none"
              style={{ background: '#060305', border: '1px solid rgba(239,68,68,0.15)', color: '#94a3b8' }}
            >
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={launchAllAttacks}
            disabled={!!running}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg font-mono text-sm font-bold uppercase tracking-wider transition-all duration-200"
            style={{
              background: 'rgba(239,68,68,0.15)',
              border: '1px solid rgba(239,68,68,0.35)',
              color: '#ef4444',
              opacity: running ? 0.4 : 1,
              cursor: running ? 'not-allowed' : 'pointer',
            }}
          >
            {running === 'all_attacks' ? (
              <><span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />Launching All...</>
            ) : (
              <><Play className="w-3.5 h-3.5" />Launch All Attacks</>
            )}
          </button>
        </div>

        {/* Attack grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(attack => (
            <AttackCard
              key={attack.id}
              attack={attack}
              intensity={intensity}
              running={running}
              onLaunch={launchAttack}
            />
          ))}
        </div>

        {/* Terminal + Progress + Result */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-4">
            <HackerTerminal logs={termLogs} />
            {currentStage && activeAttack && (
              <AttackProgress
                currentStage={currentStage}
                attack={activeAttack}
                startTime={attackStartTime}
              />
            )}
          </div>
          {lastResult ? (
            <AttackResult result={lastResult} attackLabel={lastAttackLabel} />
          ) : (
            <div className="rounded-xl border flex flex-col items-center justify-center py-12 text-center gap-3"
              style={{ background: 'rgba(10,5,5,0.8)', borderColor: 'rgba(239,68,68,0.12)' }}
            >
              <Skull className="w-12 h-12" style={{ color: '#1a0505' }} />
              <p className="font-mono text-xs" style={{ color: '#3d0f0f' }}>Launch an attack to see results</p>
              <p className="font-mono text-[11px]" style={{ color: '#2a0a0a' }}>Detection reports, confidence scores and attack details will appear here</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
