import React, { useState, useEffect } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import axios from "axios";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Alert, AlertDescription } from "./components/ui/alert";
import { Badge } from "./components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { Progress } from "./components/ui/progress";
import { Shield, Zap, Search, Globe, Plus, BarChart3, AlertTriangle, CheckCircle, Clock, Users } from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = React.createContext();

const useAuth = () => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    if (token) {
      const userData = localStorage.getItem('user');
      if (userData) {
        setUser(JSON.parse(userData));
      }
    }
  }, [token]);

  const login = (userData, authToken) => {
    setUser(userData);
    setToken(authToken);
    localStorage.setItem('token', authToken);
    localStorage.setItem('user', JSON.stringify(userData));
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  return { user, token, login, logout };
};

// Login Component
const Login = ({ onLogin, switchToSignup }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post(`${API}/login`, { email, password });
      onLogin(response.data.user, response.data.token);
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold">Website Audit Tool</CardTitle>
          <CardDescription>Sign in to analyze your websites</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <Alert className="border-red-200 bg-red-50">
                <AlertTriangle className="h-4 w-4 text-red-600" />
                <AlertDescription className="text-red-600">{error}</AlertDescription>
              </Alert>
            )}
            <div>
              <Input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full"
              />
            </div>
            <div>
              <Input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full"
              />
            </div>
            <Button type="submit" disabled={loading} className="w-full">
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
          <div className="mt-4 text-center">
            <button
              onClick={switchToSignup}
              className="text-sm text-blue-600 hover:underline"
            >
              Don't have an account? Sign up
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Signup Component
const Signup = ({ onLogin, switchToLogin }) => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post(`${API}/signup`, { name, email, password });
      onLogin(response.data.user, response.data.token);
    } catch (err) {
      setError(err.response?.data?.detail || 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold">Create Account</CardTitle>
          <CardDescription>Join Website Audit Tool today</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <Alert className="border-red-200 bg-red-50">
                <AlertTriangle className="h-4 w-4 text-red-600" />
                <AlertDescription className="text-red-600">{error}</AlertDescription>
              </Alert>
            )}
            <div>
              <Input
                type="text"
                placeholder="Full Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full"
              />
            </div>
            <div>
              <Input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full"
              />
            </div>
            <div>
              <Input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full"
              />
            </div>
            <Button type="submit" disabled={loading} className="w-full">
              {loading ? 'Creating account...' : 'Create Account'}
            </Button>
          </form>
          <div className="mt-4 text-center">
            <button
              onClick={switchToLogin}
              className="text-sm text-blue-600 hover:underline"
            >
              Already have an account? Sign in
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Dashboard Component
const Dashboard = ({ user, token, onLogout }) => {
  const [websites, setWebsites] = useState([]);
  const [reports, setReports] = useState([]);
  const [newWebsiteUrl, setNewWebsiteUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [auditLoading, setAuditLoading] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);

  const axiosConfig = {
    headers: { Authorization: `Bearer ${token}` }
  };

  useEffect(() => {
    fetchWebsites();
    fetchReports();
  }, []);

  const fetchWebsites = async () => {
    try {
      const response = await axios.get(`${API}/websites`, axiosConfig);
      setWebsites(response.data);
    } catch (err) {
      console.error('Failed to fetch websites:', err);
    }
  };

  const fetchReports = async () => {
    try {
      const response = await axios.get(`${API}/audit/reports`, axiosConfig);
      setReports(response.data);
    } catch (err) {
      console.error('Failed to fetch reports:', err);
    }
  };

  const addWebsite = async (e) => {
    e.preventDefault();
    if (!newWebsiteUrl.trim()) return;

    setLoading(true);
    try {
      await axios.post(`${API}/websites`, { url: newWebsiteUrl }, axiosConfig);
      setNewWebsiteUrl('');
      fetchWebsites();
    } catch (err) {
      console.error('Failed to add website:', err);
    } finally {
      setLoading(false);
    }
  };

  const runAudit = async (websiteId, auditType = 'All') => {
    setAuditLoading(websiteId);
    try {
      await axios.post(`${API}/audit/run`, { website_id: websiteId, audit_type: auditType }, axiosConfig);
      fetchReports();
    } catch (err) {
      console.error('Failed to run audit:', err);
    } finally {
      setAuditLoading(null);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600 bg-green-100';
    if (score >= 60) return 'text-yellow-600 bg-yellow-100';
    return 'text-red-600 bg-red-100';
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-700 bg-red-100 border-red-200';
      case 'high': return 'text-red-600 bg-red-50 border-red-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getSeverityBadgeVariant = (severity) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'secondary';
    }
  };

  const getLatestReports = () => {
    const websiteReports = {};
    reports.forEach(report => {
      if (!websiteReports[report.website_id] || 
          new Date(report.created_at) > new Date(websiteReports[report.website_id].created_at)) {
        websiteReports[report.website_id] = report;
      }
    });
    return websiteReports;
  };

  const latestReports = getLatestReports();

  if (selectedReport) {
    return (
      <div className="min-h-screen bg-gray-50">
        <header className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <Button
                  variant="ghost"
                  onClick={() => setSelectedReport(null)}
                  className="text-blue-600"
                >
                  ← Back to Dashboard
                </Button>
                <h1 className="text-2xl font-bold text-gray-900">Audit Report</h1>
              </div>
              <Button variant="outline" onClick={onLogout}>
                Sign Out
              </Button>
            </div>
          </div>
        </header>

        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-semibold">{selectedReport.audit_type} Audit</h2>
                <p className="text-gray-600">
                  {websites.find(w => w.id === selectedReport.website_id)?.url}
                </p>
              </div>
              <div className="text-right">
                <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getScoreColor(selectedReport.score)}`}>
                  Score: {selectedReport.score}/100
                </div>
                <p className="text-sm text-gray-500 mt-1">
                  {new Date(selectedReport.created_at).toLocaleDateString()}
                </p>
              </div>
            </div>
            <Progress value={selectedReport.score} className="h-2" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2 text-red-500" />
                  Issues Found ({selectedReport.issues.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {selectedReport.issues.map((issue, index) => (
                    <div key={index} className={`border-l-4 pl-4 py-3 rounded-r-lg ${getSeverityColor(issue.severity)}`}>
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium text-gray-900">{issue.issue}</h4>
                        <Badge variant={getSeverityBadgeVariant(issue.severity)} className="capitalize">
                          {issue.severity}
                        </Badge>
                      </div>
                      <p className="text-sm text-gray-700 mb-2">{issue.description}</p>
                      {issue.impact && (
                        <p className="text-xs text-gray-600 italic">Impact: {issue.impact}</p>
                      )}
                    </div>
                  ))}
                  {selectedReport.issues.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      <CheckCircle className="w-12 h-12 mx-auto mb-2 text-green-500" />
                      <p>No issues found! Great job!</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <CheckCircle className="w-5 h-5 mr-2 text-green-500" />
                  Recommendations
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {selectedReport.recommendations.map((rec, index) => (
                    <div key={index} className="flex items-start">
                      <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 mr-3 flex-shrink-0"></div>
                      <p className="text-sm text-gray-700">{rec}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Website Audit Tool</h1>
                <p className="text-gray-600">Welcome back, {user.name}</p>
              </div>
            </div>
            <Button variant="outline" onClick={onLogout}>
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Add Website Form */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Plus className="w-5 h-5 mr-2" />
              Add New Website
            </CardTitle>
            <CardDescription>Enter a website URL to start auditing</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={addWebsite} className="flex space-x-4">
              <Input
                type="url"
                placeholder="https://example.com"
                value={newWebsiteUrl}
                onChange={(e) => setNewWebsiteUrl(e.target.value)}
                className="flex-1"
              />
              <Button type="submit" disabled={loading}>
                {loading ? 'Adding...' : 'Add Website'}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Websites Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {websites.map(website => {
            const report = latestReports[website.id];
            return (
              <Card key={website.id} className="hover:shadow-lg transition-shadow">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      <Globe className="w-5 h-5 mr-2 text-blue-500" />
                      <CardTitle className="text-lg truncate">{website.url}</CardTitle>
                    </div>
                    {report && (
                      <Badge className={getScoreColor(report.score)}>
                        {report.score}/100
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {report ? (
                      <div>
                        <Progress value={report.score} className="h-2 mb-2" />
                        <div className="flex items-center justify-between text-sm text-gray-600">
                          <span>Last audit: {new Date(report.created_at).toLocaleDateString()}</span>
                          <button
                            onClick={() => setSelectedReport(report)}
                            className="text-blue-600 hover:underline"
                          >
                            View Details
                          </button>
                        </div>
                      </div>
                    ) : (
                      <p className="text-gray-500 text-sm">No audits yet</p>
                    )}

                    <div className="grid grid-cols-2 gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => runAudit(website.id, 'Security')}
                        disabled={auditLoading === website.id}
                        className="flex items-center"
                      >
                        <Shield className="w-4 h-4 mr-1" />
                        Security
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => runAudit(website.id, 'Performance')}
                        disabled={auditLoading === website.id}
                        className="flex items-center"
                      >
                        <Zap className="w-4 h-4 mr-1" />
                        Speed
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => runAudit(website.id, 'SEO')}
                        disabled={auditLoading === website.id}
                        className="flex items-center"
                      >
                        <Search className="w-4 h-4 mr-1" />
                        SEO
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => runAudit(website.id, 'Accessibility')}
                        disabled={auditLoading === website.id}
                        className="flex items-center"
                      >
                        <Users className="w-4 h-4 mr-1" />
                        A11y
                      </Button>
                    </div>
                    <Button
                      size="sm"
                      onClick={() => runAudit(website.id, 'All')}
                      disabled={auditLoading === website.id}
                      className="flex items-center w-full mt-2"
                    >
                      {auditLoading === website.id ? (
                        <Clock className="w-4 h-4 mr-1 animate-spin" />
                      ) : (
                        <BarChart3 className="w-4 h-4 mr-1" />
                      )}
                      Full Audit
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {websites.length === 0 && (
          <div className="text-center py-12">
            <Globe className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No websites yet</h3>
            <p className="text-gray-600">Add your first website to start auditing</p>
          </div>
        )}
      </main>
    </div>
  );
};

// Main App Component
function App() {
  const { user, token, login, logout } = useAuth();
  const [showSignup, setShowSignup] = useState(false);

  if (user && token) {
    return <Dashboard user={user} token={token} onLogout={logout} />;
  }

  if (showSignup) {
    return (
      <Signup
        onLogin={login}
        switchToLogin={() => setShowSignup(false)}
      />
    );
  }

  return (
    <Login
      onLogin={login}
      switchToSignup={() => setShowSignup(true)}
    />
  );
}

export default App;