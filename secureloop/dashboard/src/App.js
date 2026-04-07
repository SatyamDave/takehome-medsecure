import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const COLORS = {
  critical: '#dc3545',
  high: '#fd7e14',
  medium: '#ffc107',
  low: '#20c997',
  open_findings: '#6c757d',
  in_progress: '#0d6efd',
  auto_remediated: '#6610f2',
  needs_review: '#fd7e14',
  deployed: '#198754',
  failed: '#dc3545'
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

function App() {
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchState = async () => {
    try {
      const response = await fetch('/state.json');
      if (!response.ok) throw new Error('Failed to fetch pipeline state');
      const data = await response.json();
      setState(data);
      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchState();
    const interval = setInterval(fetchState, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div style={styles.loadingContainer}>
        <div style={styles.spinner}></div>
        <p style={styles.loadingText}>Loading pipeline data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={styles.errorContainer}>
        <h2 style={styles.errorTitle}>Unable to load dashboard</h2>
        <p style={styles.errorText}>{error}</p>
        <button onClick={fetchState} style={styles.retryButton}>Retry</button>
      </div>
    );
  }

  const metrics = state?.metrics || {};
  const sessions = state?.sessions || [];
  const issues = state?.issues || [];

  const totalOpen = issues.length;
  const autoRemediated = sessions.filter(s => s.status === 'completed' && s.pr_url).length;
  const inProgress = sessions.filter(s => s.status === 'pending').length;
  const needsReview = sessions.filter(s => s.status === 'needs_review').length;
  const deployed = autoRemediated;

  const pipelineStages = [
    { name: 'Open Findings', value: totalOpen, fill: COLORS.open_findings },
    { name: 'In Progress', value: inProgress, fill: COLORS.in_progress },
    { name: 'Auto-Remediated', value: autoRemediated, fill: COLORS.auto_remediated },
    { name: 'Awaiting Review', value: needsReview, fill: COLORS.needs_review },
    { name: 'Deployed', value: deployed, fill: COLORS.deployed }
  ];

  const severityData = SEVERITY_ORDER.map(sev => ({
    name: sev.charAt(0).toUpperCase() + sev.slice(1),
    value: metrics.severity_breakdown?.[sev] || 0,
    fill: COLORS[sev]
  })).filter(d => d.value > 0);

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <div style={styles.headerContent}>
          <div style={styles.logoRow}>
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none" style={styles.logo}>
              <path d="M16 2L4 9V23L16 30L28 23V9L16 2Z" stroke="#00d4aa" strokeWidth="2" fill="none"/>
              <path d="M16 10L10 13.5V20.5L16 24L22 20.5V13.5L16 10Z" fill="#00d4aa"/>
            </svg>
            <h1 style={styles.title}>SecureLoop</h1>
          </div>
          <p style={styles.subtitle}>Security Remediation Pipeline • MedSecure</p>
        </div>
        <div style={styles.headerRight}>
          <span style={styles.lastRefresh}>
            Updated {lastRefresh ? lastRefresh.toLocaleTimeString() : '--'}
          </span>
          <button onClick={fetchState} style={styles.refreshButton}>↻ Refresh</button>
        </div>
      </header>

      <main style={styles.main}>
        <section style={styles.metricsGrid}>
          <div style={styles.metricCard}>
            <div style={styles.metricIcon}>📋</div>
            <h3 style={styles.metricLabel}>Open Findings</h3>
            <p style={styles.metricValue}>{metrics.total_issues || 0}</p>
            <p style={styles.metricSubtext}>Total in backlog</p>
          </div>
          <div style={styles.metricCard}>
            <div style={styles.metricIcon}>✅</div>
            <h3 style={styles.metricLabel}>Auto-Remediated</h3>
            <p style={{...styles.metricValue, color: '#6610f2'}}>{autoRemediated}</p>
            <p style={styles.metricSubtext}>Fixes applied</p>
          </div>
          <div style={styles.metricCard}>
            <div style={styles.metricIcon}>⏳</div>
            <h3 style={styles.metricLabel}>In Progress</h3>
            <p style={{...styles.metricValue, color: '#0d6efd'}}>{inProgress}</p>
            <p style={styles.metricSubtext}>Being processed</p>
          </div>
          <div style={styles.metricCard}>
            <div style={styles.metricIcon}>⚠️</div>
            <h3 style={styles.metricLabel}>Awaiting Review</h3>
            <p style={{...styles.metricValue, color: '#fd7e14'}}>{needsReview}</p>
            <p style={styles.metricSubtext}>Need human input</p>
          </div>
          <div style={styles.metricCard}>
            <div style={styles.metricIcon}>🚀</div>
            <h3 style={styles.metricLabel}>Mean Time to Remediation</h3>
            <p style={styles.metricValue}>{metrics.mean_time_to_remediation_hours || 0}h</p>
            <p style={styles.metricSubtext}>Average resolution</p>
          </div>
        </section>

        <section style={styles.chartsGrid}>
          <div style={styles.chartCard}>
            <h3 style={styles.chartTitle}>Pipeline Status</h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pipelineStages}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pipelineStages.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={styles.tooltip}
                  itemStyle={styles.tooltipItem}
                />
              </PieChart>
            </ResponsiveContainer>
            <div style={styles.legend}>
              {pipelineStages.map((item, index) => (
                <div key={index} style={styles.legendItem}>
                  <span style={{...styles.legendDot, backgroundColor: item.fill}}></span>
                  <span style={styles.legendLabel}>{item.name}</span>
                  <span style={styles.legendValue}>{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div style={styles.chartCard}>
            <h3 style={styles.chartTitle}>Findings by Severity</h3>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severityData} layout="vertical" barSize={28}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" horizontal={false} />
                <XAxis type="number" stroke="#6c757d" fontSize={12} />
                <YAxis dataKey="name" type="category" stroke="#6c757d" fontSize={12} width={70} />
                <Tooltip contentStyle={styles.tooltip} itemStyle={styles.tooltipItem} cursor={{fill: '#2a2a3e'}} />
                <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section style={styles.tableSection}>
          <div style={styles.tableHeader}>
            <h3 style={styles.sectionTitle}>Recent Activity</h3>
            <span style={styles.activityCount}>{sessions.length} sessions</span>
          </div>
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Finding ID</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Devin Session</th>
                  <th style={styles.th}>Started</th>
                  <th style={styles.th}>PR Link</th>
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 ? (
                  <tr>
                    <td colSpan="5" style={styles.emptyRow}>No remediation sessions yet</td>
                  </tr>
                ) : (
                  sessions.slice(-10).reverse().map((session, idx) => (
                    <tr key={idx} style={styles.tr}>
                      <td style={styles.td}>
                        <span style={styles.issueId}>{session.issue_id}</span>
                      </td>
                      <td style={styles.td}>
                        <span style={{...styles.statusBadge, backgroundColor: getStatusColor(session.status)}}>
                          {formatStatus(session.status)}
                        </span>
                      </td>
                      <td style={styles.tdMono}>{session.session_id.substring(0, 16)}...</td>
                      <td style={styles.td}>{new Date(session.started_at).toLocaleString()}</td>
                      <td style={styles.td}>
                        {session.pr_url ? (
                          <a href={session.pr_url} target="_blank" rel="noopener noreferrer" style={styles.prLink}>
                            View PR →
                          </a>
                        ) : <span style={styles.noPr}>—</span>}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}

function getStatusColor(status) {
  const colors = {
    'pending': '#0d6efd',
    'completed': '#198754',
    'needs_review': '#fd7e14',
    'failed': '#dc3545'
  };
  return colors[status] || '#6c757d';
}

function formatStatus(status) {
  const labels = {
    'pending': 'In Progress',
    'completed': 'Remediated',
    'needs_review': 'Needs Review',
    'failed': 'Failed'
  };
  return labels[status] || status;
}

const styles = {
  container: {
    minHeight: '100vh',
    backgroundColor: '#0d0d14',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  loadingContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
    backgroundColor: '#0d0d14',
  },
  spinner: {
    width: '48px',
    height: '48px',
    border: '3px solid #1e1e2e',
    borderTopColor: '#00d4aa',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
    marginBottom: '16px',
  },
  loadingText: {
    color: '#888',
    fontSize: '14px',
  },
  errorContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
    backgroundColor: '#0d0d14',
  },
  errorTitle: {
    color: '#dc3545',
    fontSize: '18px',
    marginBottom: '8px',
  },
  errorText: {
    color: '#888',
    fontSize: '14px',
    marginBottom: '20px',
  },
  retryButton: {
    padding: '10px 20px',
    backgroundColor: '#00d4aa',
    color: '#0d0d14',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '600',
  },
  header: {
    backgroundColor: '#13131f',
    padding: '20px 32px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    borderBottom: '1px solid #1e1e2e',
  },
  headerContent: {},
  logoRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  logo: {
    flexShrink: 0,
  },
  title: {
    fontSize: '24px',
    fontWeight: '700',
    color: '#ffffff',
    margin: 0,
    letterSpacing: '-0.5px',
  },
  subtitle: {
    fontSize: '13px',
    color: '#6c757d',
    marginTop: '2px',
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '16px',
  },
  lastRefresh: {
    fontSize: '12px',
    color: '#4a4a5a',
  },
  refreshButton: {
    padding: '8px 14px',
    backgroundColor: '#1e1e2e',
    color: '#a0a0b0',
    border: '1px solid #2a2a3e',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: '500',
  },
  main: {
    padding: '28px 32px',
    maxWidth: '1400px',
    margin: '0 auto',
  },
  metricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(5, 1fr)',
    gap: '16px',
    marginBottom: '24px',
  },
  metricCard: {
    backgroundColor: '#13131f',
    borderRadius: '12px',
    padding: '20px',
    border: '1px solid #1e1e2e',
  },
  metricIcon: {
    fontSize: '20px',
    marginBottom: '8px',
  },
  metricLabel: {
    fontSize: '12px',
    color: '#6c757d',
    marginBottom: '4px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontWeight: '600',
  },
  metricValue: {
    fontSize: '28px',
    fontWeight: '700',
    color: '#ffffff',
    marginBottom: '2px',
  },
  metricSubtext: {
    fontSize: '11px',
    color: '#4a4a5a',
  },
  chartsGrid: {
    display: 'grid',
    gridTemplateColumns: '1.2fr 1fr',
    gap: '16px',
    marginBottom: '24px',
  },
  chartCard: {
    backgroundColor: '#13131f',
    borderRadius: '12px',
    padding: '20px',
    border: '1px solid #1e1e2e',
  },
  chartTitle: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#a0a0b0',
    marginBottom: '16px',
  },
  legend: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '12px',
    justifyContent: 'center',
    marginTop: '12px',
    paddingTop: '12px',
    borderTop: '1px solid #1e1e2e',
  },
  legendItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  },
  legendDot: {
    width: '10px',
    height: '10px',
    borderRadius: '2px',
  },
  legendLabel: {
    fontSize: '12px',
    color: '#888',
  },
  legendValue: {
    fontSize: '12px',
    color: '#aaa',
    fontWeight: '600',
  },
  tableSection: {
    backgroundColor: '#13131f',
    borderRadius: '12px',
    padding: '20px',
    border: '1px solid #1e1e2e',
  },
  tableHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '16px',
  },
  sectionTitle: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#a0a0b0',
  },
  activityCount: {
    fontSize: '12px',
    color: '#4a4a5a',
  },
  tableWrapper: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
  },
  th: {
    textAlign: 'left',
    padding: '10px 12px',
    borderBottom: '1px solid #1e1e2e',
    color: '#6c757d',
    fontSize: '11px',
    fontWeight: '600',
    textTransform: 'uppercase',
  },
  tr: {
    borderBottom: '1px solid #1a1a28',
  },
  td: {
    padding: '12px',
    fontSize: '13px',
    color: '#c0c0d0',
  },
  tdMono: {
    padding: '12px',
    fontSize: '12px',
    color: '#6c757d',
    fontFamily: 'monospace',
  },
  issueId: {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: '#00d4aa',
    fontWeight: '500',
  },
  emptyRow: {
    textAlign: 'center',
    padding: '40px',
    color: '#4a4a5a',
    fontSize: '14px',
  },
  statusBadge: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '12px',
    fontSize: '11px',
    fontWeight: '600',
    textTransform: 'uppercase',
    color: '#fff',
  },
  prLink: {
    color: '#00d4aa',
    textDecoration: 'none',
    fontWeight: '500',
  },
  noPr: {
    color: '#4a4a5a',
  },
  tooltip: {
    backgroundColor: '#1e1e2e',
    border: '1px solid #2a2a3e',
    borderRadius: '8px',
    padding: '8px 12px',
  },
  tooltipItem: {
    color: '#c0c0d0',
    fontSize: '12px',
  },
};

export default App;
