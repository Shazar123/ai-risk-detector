import React, { useState, useEffect } from 'react';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || "http://127.0.0.1:8000";

function App() {
  const [view, setView] = useState('login'); // 'login', 'signup', 'dashboard'
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(null);
  
  
  // Form states
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  
  // Analysis states
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    if (token) {
      fetchUser();
      fetchHistory();
      fetchStats();
    }
  }, [token]);

  const fetchUser = async () => {
    try {
      const response = await fetch(`${API_URL}/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await response.json();
      setUser(data);
      setView('dashboard');
    } catch (err) {
      console.error('Failed to fetch user');
      logout();
    }
  };

  const fetchHistory = async () => {
    try {
      const response = await fetch(`${API_URL}/my-analyses`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await response.json();
      if (data.success) {
        setHistory(data.analyses);
      }
    } catch (err) {
      console.error('Failed to fetch history');
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_URL}/stats`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await response.json();
      setStats(data);
    } catch (err) {
      console.error('Failed to fetch stats');
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    setError(null);

    try {
      const response =  await fetch(`${API_URL}/auth/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          full_name: fullName
        })
      });

      const data = await response.json();

      if (data.success) {
        localStorage.setItem('token', data.access_token);
        setToken(data.access_token);
        setUser(data.user);
        setView('dashboard');
      } else {
        setError(data.detail || 'Signup failed');
      }
    } catch (err) {
      setError('Failed to connect to server');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);

    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (data.success) {
        localStorage.setItem('token', data.access_token);
        setToken(data.access_token);
        setUser(data.user);
        setView('dashboard');
      } else {
        setError(data.detail || 'Login failed');
      }
    } catch (err) {
      setError('Failed to connect to server');
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setView('login');
    setHistory([]);
    setStats(null);
  };

  const analyzeText = async () => {
    if (!inputText.trim()) {
      alert('Please enter some text to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response =  await fetch(`${API_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ text: inputText })
      });

      const data = await response.json();

      if (data.success) {
        setResult(data);
        fetchHistory();
        fetchStats();
      } else {
        setError(data.error || 'Analysis failed');
      }
    } catch (err) {
      setError('Failed to connect to API: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score) => {
    if (score < 30) return '#10b981';
    if (score < 70) return '#f59e0b';
    return '#ef4444';
  };

  const getRiskLevel = (score) => {
    if (score < 30) return 'LOW RISK';
    if (score < 70) return 'MEDIUM RISK';
    return 'HIGH RISK';
  };

  // Login View
  if (view === 'login') {
    return (
      <div className="App">
        <div className="auth-container">
          <div className="auth-box">
            <h1>🛡️ AI Risk Detector</h1>
            <h2>Login</h2>
            {error && <div className="error-message">{error}</div>}
            <form onSubmit={handleLogin}>
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="auth-button">Login</button>
            </form>
            <p className="auth-switch">
              Don't have an account?{' '}
              <span onClick={() => setView('signup')}>Sign up</span>
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Signup View
  if (view === 'signup') {
    return (
      <div className="App">
        <div className="auth-container">
          <div className="auth-box">
            <h1>🛡️ AI Risk Detector</h1>
            <h2>Sign Up</h2>
            {error && <div className="error-message">{error}</div>}
            <form onSubmit={handleSignup}>
              <input
                type="text"
                placeholder="Full Name"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
              />
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="auth-button">Sign Up</button>
            </form>
            <p className="auth-switch">
              Already have an account?{' '}
              <span onClick={() => setView('login')}>Login</span>
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Dashboard View
  return (
    <div className="App">
      <div className="container">
        <header className="header">
          <h1>🛡️ AI Risk Detector</h1>
          <div className="user-info">
            <span>Welcome, {user?.full_name}</span>
            <button onClick={logout} className="logout-btn">Logout</button>
          </div>
        </header>

        {stats && (
          <div className="stats-row">
            <div className="stat-box">
              <div className="stat-number">{stats.total_analyses}</div>
              <div className="stat-label">Total Analyses</div>
            </div>
            <div className="stat-box">
              <div className="stat-number">{stats.high_risk_count}</div>
              <div className="stat-label">High Risk Detected</div>
            </div>
            <div className="stat-box">
              <div className="stat-number">{stats.avg_risk_score}</div>
              <div className="stat-label">Avg Risk Score</div>
            </div>
          </div>
        )}

        <div className="input-section">
          <textarea
            className="text-input"
            placeholder="Paste AI-generated text here to analyze for hallucinations, bias, and other risks..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            rows={10}
          />
          
          <button 
            className="analyze-button"
            onClick={analyzeText}
            disabled={loading}
          >
            {loading ? 'Analyzing...' : 'Analyze Text'}
          </button>
        </div>

        {error && (
          <div className="error-box">
            <h3>❌ Error</h3>
            <p>{error}</p>
          </div>
        )}

        {result && (
          <div className="results-section">
            <div className="risk-score-card" style={{ borderColor: getRiskColor(result.risk_score) }}>
              <div className="risk-score-circle" style={{ borderColor: getRiskColor(result.risk_score) }}>
                <span className="score-number">{result.risk_score}</span>
                <span className="score-label">/ 100</span>
              </div>
              <h2 style={{ color: getRiskColor(result.risk_score) }}>
                {getRiskLevel(result.risk_score)}
              </h2>
              <p className="hallucination-status">
                Hallucination Detected: <strong>{result.is_hallucination}</strong>
              </p>
            </div>

            <div className="analysis-details">
              <div className="detail-box">
                <h3>🔍 Analysis</h3>
                <p>{result.reason}</p>
              </div>

              <div className="detail-box">
                <h3>💡 Recommendations</h3>
                <p>{result.recommendations}</p>
              </div>

                 {result?.full_analysis && (
              <div className="full-analysis detail-box">
                <h3>📄 Full Analysis</h3>
                <pre>{result.full_analysis}</pre>
              </div>
            )}
  
              {result.bias_detection && (
        <div className="detail-box">
          <h3>⚖️ Bias Detection</h3>
          <div style={{ fontSize: '2rem', fontWeight: 'bold', color: getRiskColor(result.bias_detection.bias_score), marginBottom: '10px' }}>
            {result.bias_detection.bias_score}/100
          </div>
          <p><strong>Bias Detected:</strong> {result.bias_detection.bias_detected}</p>
          {result.bias_detection.bias_types !== "NONE" && (
            <p><strong>Types:</strong> {result.bias_detection.bias_types}</p>
          )}
          <p>{result.bias_detection.explanation}</p>
        </div>
      )}

      {result.privacy_detection && (
        <div className="detail-box">
          <h3>🔒 Privacy Risk Check</h3>
          <div style={{ fontSize: '2rem', fontWeight: 'bold', color: getRiskColor(result.privacy_detection.privacy_score), marginBottom: '10px' }}>
            {result.privacy_detection.privacy_score}/100
          </div>
          <p><strong>PII Found:</strong> {result.privacy_detection.has_pii}</p>
          <p><strong>Issues Detected:</strong> {result.privacy_detection.risks_found}</p>
          <ul style={{ marginLeft: '20px', marginTop: '10px' }}>
            {result.privacy_detection.risk_details.map((risk, i) => (
              <li key={i} style={{ marginBottom: '5px' }}>{risk}</li>
            ))}
          </ul>
        </div>


          )}
        </div>
            </div>
              

        )}

        {history.length > 0 && (
          <div className="history-section">
            <h2>Recent Analyses</h2>
            <div className="history-list">
              {history.map((item) => (
                <div key={item.id} className="history-item">
                  <div className="history-score" style={{ color: getRiskColor(item.risk_score) }}>
                    {item.risk_score}
                  </div>
                  <div className="history-content">
                    <p className="history-preview">{item.preview}</p>
                    <p className="history-date">
                      {new Date(item.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;