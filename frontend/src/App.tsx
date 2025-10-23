import React, { useState, useEffect } from 'react';
import { Lock, Shield, Upload, FileText, AlertTriangle, CheckCircle, Activity, LogOut, Search, Filter, Download } from 'lucide-react';

const API_URL = 'http://localhost:8000';

// Type definitions
interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
  last_login: string | null;
}

interface AuthResponse {
  access_token: string;
  user: User;
}

interface AuditLog {
  id?: string;
  timestamp: string;
  event_type: string;
  user_id: string;
  action: string;
  outcome: string;
  severity: string;
  ip_address?: string;
}

interface Document {
  id: string;
  filename: string;
  classification: string;
  owner_id: string;
  uploaded_at: string;
  size_bytes: number;
  encrypted: boolean;
}

interface UploadStatus {
  status: 'idle' | 'uploading' | 'success' | 'error';
  message: string;
}

// Authentication hook
const useAuth = () => {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);

  const login = async (email: string, password: string): Promise<AuthResponse> => {
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, ip_address: '127.0.0.1' })
      });
      
      if (!response.ok) throw new Error('Login failed');
      
      const data = await response.json();
      setToken(data.access_token);
      setUser(data.user);
      return data;
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
  };

  return { token, user, login, logout, isAuthenticated: !!token };
};

// Login Component
interface LoginPageProps {
  onLogin: (email: string, password: string) => Promise<AuthResponse>;
}

const LoginPage: React.FC<LoginPageProps> = ({ onLogin }) => {
  const [email, setEmail] = useState('demo@securevault.io');
  const [password, setPassword] = useState('Demo123!');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setError('');
    setLoading(true);
    
    try {
      await onLogin(email, password);
    } catch (err) {
      setError('Invalid credentials. Try demo@securevault.io / Demo123!');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-indigo-100 rounded-full mb-4">
            <Shield className="w-8 h-8 text-indigo-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">SecureVault</h1>
          <p className="text-gray-600 mt-2">Enterprise Document Security Platform</p>
        </div>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>

          {error && (
            <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
              <AlertTriangle className="w-4 h-4" />
              {error}
            </div>
          )}

          <button
            onClick={handleSubmit}
            disabled={loading}
            className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 transition-colors disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </div>

        <div className="mt-6 p-4 bg-blue-50 rounded-lg">
          <p className="text-sm text-gray-600">
            <strong>Demo Credentials:</strong><br />
            Email: demo@securevault.io<br />
            Password: Demo123!
          </p>
        </div>

        <div className="mt-6 text-center">
          <div className="flex items-center justify-center gap-2 text-sm text-gray-500">
            <Lock className="w-4 h-4" />
            <span>OAuth 2.0 + PKCE | AES-256 Encryption</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Dashboard Component
interface DashboardProps {
  user: User;
  token: string;
  onLogout: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ user, token, onLogout }) => {
  const [activeTab, setActiveTab] = useState('documents');
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [documents, setDocuments] = useState<Document[]>([]);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>({ status: 'idle', message: '' });
  const [searchQuery, setSearchQuery] = useState('');

  const fetchData = async () => {
    try {
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      const [logsRes, docsRes] = await Promise.all([
        fetch(`${API_URL}/audit/logs`, { headers }).catch(() => ({ ok: false, json: () => ({ logs: [] }) })),
        fetch(`${API_URL}/documents`, { headers }).catch(() => ({ ok: false, json: () => ({ documents: [] }) }))
      ]);

      if (logsRes.ok) {
        const logsData = await logsRes.json();
        setAuditLogs(logsData.logs || logsData || []);
      }

      if (docsRes.ok) {
        const docsData = await docsRes.json();
        setDocuments(docsData.documents || docsData || []);
      }
    } catch (error) {
      console.error('Failed to fetch data:', error);
    }
  };

  useEffect(() => {
    fetchData();
  }, [token]);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('classification', 'confidential');

    try {
      setUploadStatus({ status: 'uploading', message: 'Uploading and encrypting...' });
      
      const response = await fetch(`${API_URL}/documents/upload`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });

      if (response.ok) {
        const data = await response.json();
        setUploadStatus({ 
          status: 'success', 
          message: `${file.name} uploaded successfully`
        });
        setTimeout(() => {
          setUploadStatus({ status: 'idle', message: '' });
          fetchData();
        }, 3000);
      } else {
        throw new Error('Upload failed');
      }
    } catch (error) {
      setUploadStatus({ status: 'error', message: 'Upload failed. Please try again.' });
      setTimeout(() => setUploadStatus({ status: 'idle', message: '' }), 3000);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const filteredDocuments = documents.filter(doc => 
    doc.filename.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-indigo-600 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-gray-900">SecureVault</h1>
                <p className="text-xs text-gray-500">Document Security Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="text-sm font-medium text-gray-900">{user.name}</p>
                <p className="text-xs text-gray-500">{user.email}</p>
              </div>
              <button
                onClick={onLogout}
                className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
                title="Logout"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <div className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-6">
          <nav className="flex gap-1">
            {[
              { id: 'documents', label: 'Documents', icon: FileText },
              { id: 'upload', label: 'Upload', icon: Upload },
              { id: 'audit', label: 'Audit Log', icon: Activity }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-indigo-600 text-indigo-600'
                    : 'border-transparent text-gray-600 hover:text-gray-900'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {activeTab === 'documents' && (
          <div className="space-y-6">
            {/* Search */}
            <div className="flex items-center justify-between">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search documents..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
              <button className="flex items-center gap-2 px-4 py-2 text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
                <Filter className="w-4 h-4" />
                Filter
              </button>
            </div>

            {/* Documents List */}
            <div className="bg-white rounded-lg shadow-sm border">
              {filteredDocuments.length === 0 ? (
                <div className="p-12 text-center">
                  <FileText className="w-12 h-12 text-gray-300 mx-auto mb-3" />
                  <p className="text-gray-500 mb-1">No documents found</p>
                  <p className="text-sm text-gray-400">Upload your first document to get started</p>
                </div>
              ) : (
                <div className="divide-y">
                  {filteredDocuments.map((doc) => (
                    <div key={doc.id} className="p-4 hover:bg-gray-50 transition-colors">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 flex-1">
                          <FileText className="w-5 h-5 text-gray-400" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-gray-900 truncate">{doc.filename}</p>
                            <p className="text-xs text-gray-500">
                              {formatFileSize(doc.size_bytes)} • {formatDate(doc.uploaded_at)} • 
                              <span className={`ml-1 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                                doc.classification === 'confidential' ? 'bg-red-100 text-red-800' :
                                doc.classification === 'internal' ? 'bg-yellow-100 text-yellow-800' :
                                'bg-green-100 text-green-800'
                              }`}>
                                {doc.classification}
                              </span>
                              {doc.encrypted && (
                                <span className="ml-1 inline-flex items-center">
                                  <Lock className="w-3 h-3 text-green-600" />
                                </span>
                              )}
                            </p>
                          </div>
                        </div>
                        <button className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded">
                          <Download className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'upload' && (
          <div className="max-w-2xl mx-auto">
            <div className="bg-white rounded-lg shadow-sm border p-8">
              <div className="mb-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-1">Upload Document</h2>
                <p className="text-sm text-gray-600">Files are encrypted with AES-256-GCM before storage</p>
              </div>

              <label className="block cursor-pointer">
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center hover:border-indigo-400 hover:bg-indigo-50/50 transition-all">
                  <Upload className="w-10 h-10 text-gray-400 mx-auto mb-3" />
                  <p className="text-sm text-gray-600 mb-1">Click to upload or drag and drop</p>
                  <p className="text-xs text-gray-500">Maximum file size: 100 MB</p>
                  <input
                    type="file"
                    className="hidden"
                    onChange={handleFileSelect}
                    disabled={uploadStatus.status === 'uploading'}
                  />
                </div>
              </label>

              {uploadStatus.status !== 'idle' && (
                <div className={`mt-4 p-4 rounded-lg flex items-center gap-3 ${
                  uploadStatus.status === 'success' ? 'bg-green-50 text-green-900' :
                  uploadStatus.status === 'error' ? 'bg-red-50 text-red-900' :
                  'bg-blue-50 text-blue-900'
                }`}>
                  {uploadStatus.status === 'success' && <CheckCircle className="w-5 h-5 text-green-600" />}
                  {uploadStatus.status === 'error' && <AlertTriangle className="w-5 h-5 text-red-600" />}
                  {uploadStatus.status === 'uploading' && <Activity className="w-5 h-5 text-blue-600 animate-spin" />}
                  <span className="text-sm font-medium">{uploadStatus.message}</span>
                </div>
              )}

              <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                <h3 className="text-sm font-medium text-gray-900 mb-2">Security Features</h3>
                <ul className="text-xs text-gray-600 space-y-1">
                  <li>• AES-256-GCM encryption with unique document keys</li>
                  <li>• SHA-256 integrity verification</li>
                  <li>• Automatic classification and access control</li>
                  <li>• Full audit trail for all operations</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h2 className="text-lg font-semibold text-gray-900">Security Audit Log</h2>
              <p className="text-sm text-gray-600 mt-1">Complete record of system events and user actions</p>
            </div>
            {auditLogs.length === 0 ? (
              <div className="p-12 text-center">
                <Activity className="w-12 h-12 text-gray-300 mx-auto mb-3" />
                <p className="text-gray-500">No audit logs available</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50 border-b">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Event</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {auditLogs.slice(0, 50).map((log, idx) => (
                      <tr key={log.id || idx} className="hover:bg-gray-50">
                        <td className="px-6 py-3 text-sm text-gray-900 whitespace-nowrap">
                          {formatDate(log.timestamp)}
                        </td>
                        <td className="px-6 py-3 text-sm">
                          <span className={`inline-flex px-2 py-1 rounded text-xs font-medium ${
                            log.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                            log.severity === 'WARNING' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-blue-100 text-blue-800'
                          }`}>
                            {log.event_type}
                          </span>
                        </td>
                        <td className="px-6 py-3 text-sm text-gray-900">{log.action}</td>
                        <td className="px-6 py-3 text-sm text-gray-600">{log.user_id?.substring(0, 8) || 'System'}</td>
                        <td className="px-6 py-3 text-sm">
                          <span className={`inline-flex px-2 py-1 rounded text-xs font-medium ${
                            log.outcome === 'SUCCESS' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}>
                            {log.outcome}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
};

// Main App
export default function App() {
  const { token, user, login, logout, isAuthenticated } = useAuth();

  return isAuthenticated && user && token ? (
    <Dashboard user={user} token={token} onLogout={logout} />
  ) : (
    <LoginPage onLogin={login} />
  );
}