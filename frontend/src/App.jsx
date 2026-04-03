import { useState, useEffect, useRef } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Terminal, Server, Play, RotateCcw, Activity, Search, Brain, Globe, AlertTriangle, CheckCircle, XCircle, Loader2 } from 'lucide-react';
import './index.css';

const API_BASE = 'http://localhost:7860';

function App() {
  const [tasks, setTasks] = useState([]);
  const [envState, setEnvState] = useState(null);
  const [selectedTask, setSelectedTask] = useState('easy');
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState([{ msg: 'System initialized. Ready for triage.', type: 'info', time: new Date().toLocaleTimeString() }]);
  const [reward, setReward] = useState(null);

  // NEW: CVE Search + AI Analysis
  const [searchCveId, setSearchCveId] = useState('');
  const [fetchedCve, setFetchedCve] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [fetchingCve, setFetchingCve] = useState(false);
  const [analyzingAi, setAnalyzingAi] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard'); // 'dashboard' | 'search'

  const terminalRef = useRef(null);

  useEffect(() => {
    fetchTasks();
    checkHealth();
  }, []);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const addLog = (msg, type = 'info') => {
    setLogs(prev => [...prev, { msg, type, time: new Date().toLocaleTimeString() }]);
  };

  const fetchTasks = async () => {
    try {
      const res = await fetch(`${API_BASE}/tasks`);
      const data = await res.json();
      setTasks(data);
    } catch (e) {
      addLog('Failed to fetch tasks API', 'error');
    }
  };

  const checkHealth = async () => {
    try {
      const res = await fetch(`${API_BASE}/health`);
      await res.json();
      addLog('Backend API connected (v2.0 — AI + NVD enabled)', 'success');
    } catch (e) {
      addLog('Backend disconnected. Run: python run.py', 'error');
    }
  };

  const resetEnv = async () => {
    setLoading(true);
    setReward(null);
    try {
      const res = await fetch(`${API_BASE}/reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task_id: selectedTask })
      });
      const data = await res.json();
      setEnvState(data);
      addLog(`Environment reset → Task: ${selectedTask}`, 'success');
      addLog(`Objective: ${data.current_output?.message || 'Ready'}`, 'info');
    } catch (e) {
      addLog('Failed to reset environment', 'error');
    }
    setLoading(false);
  };

  const stepEnv = async (actionType) => {
    if (envState?.episode_done) {
      addLog('Episode complete. Click Init Workspace to restart.', 'warning');
      return;
    }
    setLoading(true);
    try {
      addLog(`→ ${actionType}`, 'action');
      const res = await fetch(`${API_BASE}/step`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_type: actionType, parameters: {} })
      });
      const data = await res.json();
      setEnvState(data.observation);
      if (data.done) {
        setReward(data.reward);
        addLog(`✓ Episode done — Score: ${(data.reward.value * 100).toFixed(0)}%`, 'success');
      } else {
        addLog(`← Data received: ${Object.keys(data.observation.current_output || {}).join(', ')}`, 'info');
      }
    } catch (e) {
      addLog(`✗ Step failed: ${actionType}`, 'error');
    }
    setLoading(false);
  };

  const submitFinal = async () => {
    if (envState?.episode_done || !envState) return;
    setLoading(true);
    try {
      addLog('Submitting security report...', 'action');
      const parameters = selectedTask === 'easy' ? {
        group: "org.apache.commons", artifact: "commons-text", safe_version: "1.10.0"
      } : selectedTask === 'medium' ? {
        group: "org.apache.logging.log4j", artifact: "log4j-core", vulnerable_method: "lookup", safe_version: "2.15.0"
      } : {
        group: "org.springframework", artifact: "spring-webmvc", vulnerable_method: "bind", invoked: false, safe_version: "5.3.18"
      };
      const res = await fetch(`${API_BASE}/step`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_type: "submit", parameters })
      });
      const data = await res.json();
      setEnvState(data.observation);
      setReward(data.reward);
      addLog(`✓ Report submitted — Score: ${(data.reward.value * 100).toFixed(0)}%`, 'success');
    } catch (e) {
      addLog(`✗ Submission failed`, 'error');
    }
    setLoading(false);
  };

  // ------- NEW: Fetch CVE from NVD -------
  const fetchCveFromNvd = async () => {
    if (!searchCveId.trim()) return;
    setFetchingCve(true);
    setFetchedCve(null);
    setAiAnalysis(null);
    addLog(`🌐 Fetching ${searchCveId} from NVD...`, 'action');
    try {
      const res = await fetch(`${API_BASE}/fetch_cve/${searchCveId.trim()}`);
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Not found');
      }
      const data = await res.json();
      setFetchedCve(data);
      addLog(`✓ Fetched ${data.cve_id}: CVSS ${data.cvss_score || 'N/A'} (${data.severity})`, 'success');
    } catch (e) {
      addLog(`✗ NVD fetch failed: ${e.message}`, 'error');
    }
    setFetchingCve(false);
  };

  // ------- NEW: AI Analysis with Gemini -------
  const runAiAnalysis = async () => {
    if (!fetchedCve) return;
    setAnalyzingAi(true);
    addLog(`🧠 Gemini AI analyzing ${fetchedCve.cve_id}...`, 'action');
    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cve_id: fetchedCve.cve_id,
          description: fetchedCve.description
        })
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'AI error');
      }
      const data = await res.json();
      setAiAnalysis(data);
      addLog(`✓ AI analysis complete for ${data.cve_id}`, 'success');
    } catch (e) {
      addLog(`✗ AI analysis failed: ${e.message}`, 'error');
    }
    setAnalyzingAi(false);
  };

  return (
    <div className="app-container">
      <header>
        <ShieldAlert className="logo-icon" size={32} />
        <div>
          <h1>CVE-Triage-Env</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '2px' }}>
            AI-Powered Security Operations Center
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
          <button
            onClick={() => setActiveTab('dashboard')}
            className={activeTab === 'dashboard' ? '' : 'secondary'}
            style={{ width: 'auto', padding: '0.5rem 1rem', fontSize: '0.8rem' }}
          >
            <Activity size={14} /> RL Environment
          </button>
          <button
            onClick={() => setActiveTab('search')}
            className={activeTab === 'search' ? '' : 'secondary'}
            style={{ width: 'auto', padding: '0.5rem 1rem', fontSize: '0.8rem' }}
          >
            <Brain size={14} /> AI CVE Analyzer
          </button>
        </div>
      </header>

      {/* ========== TAB 1: RL ENVIRONMENT DASHBOARD ========== */}
      {activeTab === 'dashboard' && (
        <div className="dashboard-grid">
          <div className="left-column">
            <div className="panel" style={{ marginBottom: '1.5rem' }}>
              <h2 className="panel-title"><Server size={16} /> Environment Config</h2>
              <div className="form-group">
                <label>Select CVE Task</label>
                <select value={selectedTask} onChange={(e) => setSelectedTask(e.target.value)} disabled={loading}>
                  {tasks.map(t => (
                    <option key={t.task_id} value={t.task_id}>
                      {t.difficulty?.toUpperCase() || t.task_id.toUpperCase()} — {t.cve_id}
                    </option>
                  ))}
                </select>
              </div>
              <button onClick={resetEnv} disabled={loading}>
                <RotateCcw size={16} /> Init Workspace
              </button>
            </div>

            <div className="panel">
              <h2 className="panel-title"><Activity size={16} /> Investigation Actions</h2>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {[
                  ['search_nvd', '🔍 Query NVD Database'],
                  ['fetch_advisory', '📋 Fetch GitHub Advisory'],
                  ['lookup_gav', '📦 Lookup GAV Metadata'],
                  ['search_method', '🔬 Analyze Patch Diffs'],
                  ['scan_code', '🛡️ Reachability Scan']
                ].map(([action, label]) => (
                  <button key={action} className="secondary" onClick={() => stepEnv(action)}
                    disabled={loading || envState?.episode_done || !envState}>
                    {label}
                  </button>
                ))}
                <button onClick={submitFinal}
                  disabled={loading || envState?.episode_done || !envState}
                  style={{ marginTop: '0.75rem', background: 'var(--success)', color: '#fff' }}>
                  <ShieldCheck size={16} /> Submit Report
                </button>
              </div>
            </div>
          </div>

          <div className="right-column">
            <div className="panel" style={{ marginBottom: '1.5rem' }}>
              <h2 className="panel-title"><Terminal size={16} /> Terminal</h2>
              <div className="terminal" ref={terminalRef}>
                {logs.map((log, i) => (
                  <div key={i} className="terminal-line">
                    <span className="terminal-prompt">[{log.time}]</span>
                    <span style={{
                      color: log.type === 'error' ? 'var(--danger)' :
                             log.type === 'success' ? 'var(--success)' :
                             log.type === 'action' ? 'var(--warning)' :
                             log.type === 'warning' ? '#f59e0b' : '#cbd5e1'
                    }}>{log.msg}</span>
                  </div>
                ))}
                {loading && <div className="terminal-line"><Loader2 size={14} className="spin" style={{color:'var(--primary-accent)'}}/><span style={{color:'var(--text-muted)'}}>processing...</span></div>}
              </div>
            </div>

            {reward && (
              <div className="panel fade-in">
                <h2 className="panel-title"><Shield size={16} /> Grading Results</h2>
                <div className={`score-display ${reward.value >= 0.8 ? 'score-high' : reward.value >= 0.5 ? 'score-med' : 'score-low'}`}>
                  {(reward.value * 100).toFixed(0)}%
                </div>
                <div className="result-card">
                  {Object.entries(reward.breakdown).map(([key, value]) => (
                    <div className="result-row" key={key}>
                      <span style={{display:'flex',alignItems:'center',gap:'0.5rem'}}>
                        {value > 0 ? <CheckCircle size={14} color="var(--success)"/> : value < 0 ? <XCircle size={14} color="var(--danger)"/> : <span style={{width:14}}/>}
                        {key.replace(/_/g, ' ')}
                      </span>
                      <span className={`badge ${value > 0 ? 'safe' : value < 0 ? 'danger' : 'neutral'}`}>
                        {value > 0 ? '+' : ''}{value.toFixed(2)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========== TAB 2: AI CVE ANALYZER ========== */}
      {activeTab === 'search' && (
        <div className="dashboard-grid">
          <div className="left-column">
            <div className="panel" style={{ marginBottom: '1.5rem' }}>
              <h2 className="panel-title"><Globe size={16} /> Live CVE Lookup</h2>
              <div className="form-group">
                <label>Enter any CVE ID</label>
                <input
                  type="text"
                  placeholder="e.g. CVE-2021-44228"
                  value={searchCveId}
                  onChange={(e) => setSearchCveId(e.target.value.toUpperCase())}
                  onKeyDown={(e) => e.key === 'Enter' && fetchCveFromNvd()}
                />
              </div>
              <button onClick={fetchCveFromNvd} disabled={fetchingCve || !searchCveId.trim()}>
                {fetchingCve ? <><Loader2 size={16} className="spin"/> Fetching...</> : <><Search size={16}/> Fetch from NVD</>}
              </button>
              {fetchedCve && (
                <button onClick={runAiAnalysis} disabled={analyzingAi}
                  style={{ marginTop: '0.75rem', background: 'linear-gradient(135deg, #8b5cf6, #6366f1)', color: '#fff' }}>
                  {analyzingAi ? <><Loader2 size={16} className="spin"/> Analyzing...</> : <><Brain size={16}/> Run AI Analysis</>}
                </button>
              )}
            </div>

            {fetchedCve && (
              <div className="panel">
                <h2 className="panel-title"><AlertTriangle size={16} /> CVE Details</h2>
                <div className="result-card" style={{ marginTop: 0 }}>
                  <div className="result-row">
                    <span style={{color:'var(--text-muted)'}}>CVE ID</span>
                    <span style={{fontFamily:'JetBrains Mono', fontWeight:600}}>{fetchedCve.cve_id}</span>
                  </div>
                  <div className="result-row">
                    <span style={{color:'var(--text-muted)'}}>CVSS Score</span>
                    <span className={`badge ${fetchedCve.cvss_score >= 9 ? 'danger' : fetchedCve.cvss_score >= 7 ? 'danger' : fetchedCve.cvss_score >= 4 ? 'neutral' : 'safe'}`}>
                      {fetchedCve.cvss_score || 'N/A'} — {fetchedCve.severity}
                    </span>
                  </div>
                  <div className="result-row">
                    <span style={{color:'var(--text-muted)'}}>Published</span>
                    <span>{fetchedCve.published}</span>
                  </div>
                  <div className="result-row">
                    <span style={{color:'var(--text-muted)'}}>Source</span>
                    <span style={{fontSize:'0.75rem'}}>{fetchedCve.raw_source}</span>
                  </div>
                </div>
                <div style={{ marginTop: '1rem' }}>
                  <label style={{fontSize:'0.75rem',color:'var(--text-muted)'}}>DESCRIPTION</label>
                  <p style={{ fontSize: '0.85rem', lineHeight: 1.5, marginTop: '0.25rem', color: '#e2e8f0' }}>
                    {fetchedCve.description}
                  </p>
                </div>
                {fetchedCve.weaknesses?.length > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <label style={{fontSize:'0.75rem',color:'var(--text-muted)'}}>WEAKNESSES</label>
                    <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                      {fetchedCve.weaknesses.map((w, i) => <span key={i} className="badge neutral">{w}</span>)}
                    </div>
                  </div>
                )}
                {fetchedCve.affected_products?.length > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <label style={{fontSize:'0.75rem',color:'var(--text-muted)'}}>AFFECTED PRODUCTS</label>
                    <div style={{ marginTop: '0.25rem' }}>
                      {fetchedCve.affected_products.map((p, i) => (
                        <div key={i} style={{ fontSize: '0.8rem', fontFamily: 'JetBrains Mono', color: '#fbbf24', padding: '2px 0' }}>{p}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="right-column">
            {!aiAnalysis && !fetchedCve && (
              <div className="panel" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 300, textAlign: 'center' }}>
                <Brain size={64} color="var(--glass-border)" style={{ marginBottom: '1rem' }} />
                <h3 style={{ color: 'var(--text-muted)', fontWeight: 400 }}>Enter a CVE ID to begin</h3>
                <p style={{ color: 'var(--glass-border)', fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  Search the NVD database, then let Gemini AI<br/>analyze the cause and remediation.
                </p>
              </div>
            )}

            {fetchedCve && !aiAnalysis && !analyzingAi && (
              <div className="panel" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 300, textAlign: 'center' }}>
                <Brain size={64} color="rgba(139,92,246,0.3)" style={{ marginBottom: '1rem' }} />
                <h3 style={{ color: 'var(--text-muted)', fontWeight: 400 }}>CVE data loaded</h3>
                <p style={{ color: 'var(--glass-border)', fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  Click "Run AI Analysis" to get Gemini's<br/>cause, remediation, and severity assessment.
                </p>
              </div>
            )}

            {analyzingAi && (
              <div className="panel" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
                <Loader2 size={48} className="spin" color="var(--primary-accent)" />
                <h3 style={{ color: 'var(--text-muted)', fontWeight: 400, marginTop: '1rem' }}>Gemini AI is analyzing...</h3>
              </div>
            )}

            {aiAnalysis && (
              <div className="panel fade-in">
                <h2 className="panel-title" style={{ color: '#a78bfa' }}>
                  <Brain size={16} /> AI Security Report — {aiAnalysis.cve_id}
                </h2>

                <div className="ai-section">
                  <div className="ai-section-header danger-glow">
                    <XCircle size={16} /> Root Cause
                  </div>
                  <div className="ai-section-body">{aiAnalysis.cause}</div>
                </div>

                <div className="ai-section">
                  <div className="ai-section-header success-glow">
                    <CheckCircle size={16} /> Remediation
                  </div>
                  <div className="ai-section-body">{aiAnalysis.remediation}</div>
                </div>

                <div className="ai-section">
                  <div className="ai-section-header warning-glow">
                    <AlertTriangle size={16} /> Severity Assessment
                  </div>
                  <div className="ai-section-body">{aiAnalysis.severity_assessment}</div>
                </div>

                <div className="ai-section">
                  <div className="ai-section-header neutral-glow">
                    <Shield size={16} /> Affected Components
                  </div>
                  <div className="ai-section-body">{aiAnalysis.affected_components}</div>
                </div>

                <div className="ai-section">
                  <div className="ai-section-header primary-glow">
                    <ShieldCheck size={16} /> Recommendation
                  </div>
                  <div className="ai-section-body">{aiAnalysis.recommendation}</div>
                </div>
              </div>
            )}

            {/* Terminal on search tab too */}
            <div className="panel" style={{ marginTop: '1.5rem' }}>
              <h2 className="panel-title"><Terminal size={16} /> Activity Log</h2>
              <div className="terminal" ref={terminalRef} style={{ maxHeight: 200 }}>
                {logs.slice(-10).map((log, i) => (
                  <div key={i} className="terminal-line">
                    <span className="terminal-prompt">[{log.time}]</span>
                    <span style={{
                      color: log.type === 'error' ? 'var(--danger)' :
                             log.type === 'success' ? 'var(--success)' :
                             log.type === 'action' ? 'var(--warning)' : '#cbd5e1'
                    }}>{log.msg}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
