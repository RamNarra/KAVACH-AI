'use client';

import { useState, useEffect, useRef } from 'react';
import { 
  signInWithPopup, 
  signOut, 
  onAuthStateChanged, 
  User 
} from 'firebase/auth';
import { 
  ref, 
  uploadBytesResumable, 
  getDownloadURL 
} from 'firebase/storage';
import { 
  collection, 
  doc, 
  onSnapshot,
  query,
  where,
  orderBy
} from 'firebase/firestore';
import { auth, googleProvider, storage, db } from '../lib/firebase';
import { 
  Shield, 
  Upload, 
  LogOut, 
  Terminal, 
  AlertTriangle, 
  CheckCircle, 
  Activity, 
  FileCode, 
  Lock, 
  ChevronRight, 
  RefreshCw,
  FolderOpen,
  Cpu,
  User as UserIcon,
  Play,
  FileCheck,
  History,
  Clock
} from 'lucide-react';

interface PermissionAnalysis {
  permission: string;
  status: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  description: string;
}

interface SuspiciousActivity {
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  file?: string;
}

interface CodeVulnerability {
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  file?: string;
}

interface InvestigationReport {
  summary: string;
  permissions_analysis: PermissionAnalysis[];
  suspicious_activities: SuspiciousActivity[];
  code_vulnerabilities: CodeVulnerability[];
  recommendations?: string[];
}

interface AnalysisResult {
  id: string;
  apk_url?: string;
  package_name?: string;
  filename?: string;
  status: 'PROCESSING' | 'COMPLETED' | 'FAILED';
  risk_score?: number;
  threat_level?: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  investigation_report?: InvestigationReport;
  error_message?: string;
  created_at?: string;
  progress?: Record<string, string>;
  logs?: string[];
}

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  
  // History state
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  // Current view state
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(null);
  const [activeResult, setActiveResult] = useState<AnalysisResult | null>(null);
  const [fakeLogStep, setFakeLogStep] = useState<number>(0);

  const [error, setError] = useState<string | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setAuthLoading(false);
    });
    return () => unsubscribe();
  }, []);

  // Listen to user's history
  useEffect(() => {
    if (!user) {
      setHistory([]);
      return;
    }
    const q = query(
      collection(db, "apkanalysisresults"),
      where("uid", "==", user.uid),
      orderBy("created_at", "desc")
    );
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const records = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as AnalysisResult));
      setHistory(records);
    });
    return () => unsubscribe();
  }, [user]);

  // Listen to active analysis updates
  useEffect(() => {
    if (!activeAnalysisId) {
      setActiveResult(null);
      setFakeLogStep(0);
      return;
    }
    const docRef = doc(db, "apkanalysisresults", activeAnalysisId);
    const unsubscribe = onSnapshot(docRef, (snap) => {
      if (snap.exists()) {
        const data = { id: snap.id, ...snap.data() } as AnalysisResult;
        setActiveResult(data);
      }
    });
    return () => unsubscribe();
  }, [activeAnalysisId]);

  // Simulated progress terminal
  useEffect(() => {
    if (activeResult?.status === 'PROCESSING') {
      const interval = setInterval(() => {
        setFakeLogStep(prev => prev + 1);
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [activeResult?.status]);

  // Auto-scroll terminal
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeResult?.logs]);

  const handleLogin = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      setFile(null);
      setActiveAnalysisId(null);
      setUploadProgress(0);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      if (!selectedFile.name.endsWith('.apk')) {
        setError('Invalid file format. Kavach AI only accepts .apk files.');
        setFile(null);
        return;
      }
      setFile(selectedFile);
      setError(null);
      setActiveAnalysisId(null); // Reset to upload view
    }
  };

  const executeAnalysis = async () => {
    if (!file || !user) return;
    setError(null);
    setUploadProgress(0);
    setActiveAnalysisId(null);

    try {
      const storageRef = ref(storage, `apks/${user.uid}/${Date.now()}_${file.name}`);
      const uploadTask = uploadBytesResumable(storageRef, file);

      const uploadUrl = await new Promise<string>((resolve, reject) => {
        uploadTask.on(
          'state_changed',
          (snapshot) => {
            const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
            setUploadProgress(Math.round(progress));
          },
          (err) => reject(err),
          async () => resolve(await getDownloadURL(uploadTask.snapshot.ref))
        );
      });

      const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || '';
      const apiEndpoint = `${apiBaseUrl.replace(/\/$/, '')}/api/analyze`;

      const apiResponse = await fetch(apiEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          apk_url: uploadUrl,
          email: user.email,
          uid: user.uid
        }),
      });

      const contentType = apiResponse.headers.get('content-type') || '';
      let rawResult: any = null;
      if (contentType.includes('application/json')) {
        rawResult = await apiResponse.json();
      } else {
        throw new Error(`Server returned non-JSON response (Status ${apiResponse.status})`);
      }

      if (!apiResponse.ok) {
        throw new Error(rawResult.detail || rawResult.error_message || `HTTP ${apiResponse.status} error.`);
      }

      // Backend returns {"id": doc_id, "status": "PROCESSING"}
      setActiveAnalysisId(rawResult.id);

    } catch (err: any) {
      setError(err.message);
      setUploadProgress(0);
    }
  };

  const getThreatColor = (level?: string) => {
    switch (level) {
      case 'SAFE':
        return { text: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/10', glow: 'shadow-emerald-500/20' };
      case 'LOW':
        return { text: 'text-green-400', border: 'border-green-500/30', bg: 'bg-green-500/10', glow: 'shadow-green-500/20' };
      case 'MEDIUM':
        return { text: 'text-amber-400', border: 'border-amber-500/30', bg: 'bg-amber-500/10', glow: 'shadow-amber-500/20' };
      case 'HIGH':
        return { text: 'text-rose-400', border: 'border-rose-500/30', bg: 'bg-rose-500/10', glow: 'shadow-rose-500/20' };
      case 'CRITICAL':
        return { text: 'text-red-500', border: 'border-red-600/40', bg: 'bg-red-950/20', glow: 'shadow-red-600/35' };
      default:
        return { text: 'text-zinc-400', border: 'border-zinc-500/30', bg: 'bg-zinc-500/10', glow: 'shadow-zinc-500/20' };
    }
  };

  const renderSidebar = () => (
    <div className={`flex flex-col w-80 bg-zinc-950 border-r border-zinc-800 transition-transform ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full fixed z-20 h-full'}`}>
      <div className="p-6 border-b border-zinc-800 flex items-center justify-between">
        <h2 className="text-2xl font-bold text-emerald-400 tracking-wider">KAVACH AI</h2>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        <div className="text-sm font-semibold text-zinc-500 uppercase tracking-wider mb-4 flex items-center gap-2">
          <History className="w-4 h-4" /> Past Sessions
        </div>
        {history.length === 0 ? (
          <div className="text-zinc-500 text-base p-4 bg-zinc-900/50 rounded-lg border border-zinc-800 text-center">No analysis history found.</div>
        ) : (
          history.map(item => {
            const tColor = getThreatColor(item.threat_level);
            return (
              <button 
                key={item.id} 
                onClick={() => setActiveAnalysisId(item.id)}
                className={`w-full text-left p-4 rounded-xl border transition-all ${activeAnalysisId === item.id ? `bg-zinc-900 ${tColor.border} shadow-[0_0_15px_rgba(0,0,0,0.5)]` : 'border-zinc-800 hover:bg-zinc-900/80 hover:border-zinc-700'}`}
              >
                <div className="font-mono text-base font-bold truncate text-zinc-200">{item.filename || 'Unknown APK'}</div>
                {item.package_name && <div className="text-sm text-zinc-500 truncate mt-1">{item.package_name}</div>}
                <div className="flex items-center justify-between mt-3">
                  <span className={`text-xs px-2.5 py-1 rounded-sm uppercase font-bold tracking-widest ${tColor.bg} ${tColor.text}`}>
                    {item.threat_level || item.status}
                  </span>
                  <span className="text-xs text-zinc-500 flex items-center gap-1 font-mono">
                    <Clock className="w-3.5 h-3.5"/>
                    {item.created_at ? new Date(item.created_at).toLocaleDateString() : 'Just now'}
                  </span>
                </div>
              </button>
            )
          })
        )}
      </div>
    </div>
  );

  const renderProgressState = () => {
    if (!activeResult || activeResult.status === 'FAILED') return null;
    if (activeResult.status === 'COMPLETED') return null;

    const fakeLogs = [
      "Upload complete. Handing payload to pipeline...",
      "Extracting AndroidManifest.xml and assets...",
      "Decompiling classes with JADX...",
      "Mapping application attack surface via Quark-Engine...",
      "Filtering highest-risk Java sources...",
      "Submitting artifact trace to Gemini 3.5 Flash for synthesis...",
      "Awaiting AI static analysis completion...",
      "Running security heuristics...",
      "Validating permissions against Android specifications...",
      "Compiling final threat report..."
    ];

    const currentLog = fakeLogs[Math.min(fakeLogStep, fakeLogs.length - 1)];

    return (
      <div className="w-full bg-zinc-900 border border-zinc-800 rounded-xl p-8 mb-8 animate-fade-in text-lg shadow-2xl">
        <div className="flex items-center gap-4 text-emerald-400 mb-6 border-b border-zinc-800 pb-4">
          <RefreshCw className="w-8 h-8 animate-spin" />
          <span className="font-mono text-2xl font-bold uppercase tracking-widest">Active Analysis Progress</span>
        </div>
        <div className="flex items-center gap-4 bg-black/50 p-6 rounded-lg border border-zinc-800/50">
          <Activity className="w-6 h-6 text-amber-400 animate-pulse" />
          <span className="font-mono text-xl text-zinc-300">
            {currentLog}
          </span>
        </div>
      </div>
    );
  };

  const renderResult = () => {
    if (!activeResult) return null;
    if (activeResult.status === 'FAILED') {
      return (
        <div className="p-6 bg-red-950/20 border border-red-900/50 rounded-xl text-red-400 text-lg">
          <AlertTriangle className="w-8 h-8 mb-4" />
          <h3 className="font-bold mb-2">Analysis Failed</h3>
          <p>{activeResult.error_message || 'An unknown error occurred during execution.'}</p>
        </div>
      );
    }
    
    if (activeResult.status !== 'COMPLETED') {
      // Return null here, let progress state handle the waiting view
      return null;
    }

    const { risk_score, threat_level, investigation_report, package_name, filename } = activeResult;
    const threatColors = getThreatColor(threat_level);

    return (
      <div className="space-y-8 animate-fade-in text-lg">
        {/* Top Score Card */}
        <div className={`p-8 rounded-xl border ${threatColors.border} ${threatColors.bg} flex flex-col md:flex-row items-center md:items-start gap-8 ${threatColors.glow} mb-8`}>
          <div className="flex flex-col items-center justify-center min-w-[200px] border-b md:border-b-0 md:border-r border-current/20 pb-8 md:pb-0 md:pr-8">
             <div className={`text-8xl font-bold font-mono tracking-tighter ${threatColors.text}`}>
               {risk_score}
             </div>
             <div className={`mt-2 text-xl font-semibold tracking-widest uppercase opacity-80 ${threatColors.text}`}>
                RISK SCORE
             </div>
          </div>
          <div className="flex-1 space-y-4 pt-2">
             <div className="flex flex-wrap items-center gap-4">
                <span className={`text-3xl font-bold uppercase tracking-widest px-4 py-2 border rounded bg-black/40 ${threatColors.border} ${threatColors.text}`}>
                  {threat_level}
                </span>
                <span className="font-mono text-zinc-400 tracking-wider text-xl break-all">TARGET :: {filename}</span>
             </div>
             <p className="text-zinc-300 leading-relaxed font-mono text-xl mt-4">
               PKG_ID: {package_name || 'unknown'}
             </p>
          </div>
        </div>

        {/* AI Synthesis */}
        <div className="p-8 bg-zinc-900 border border-zinc-800 rounded-xl">
           <h3 className="text-2xl font-bold text-zinc-100 flex gap-3 items-center mb-6 uppercase tracking-widest border-b border-zinc-800 pb-4">
             <Cpu className="w-8 h-8 text-emerald-400" /> Synthesis Report
           </h3>
           <p className="text-zinc-300 leading-relaxed text-xl">{investigation_report?.summary}</p>
        </div>

        {/* Findings Grid */}
        <div className="grid lg:grid-cols-2 gap-8">
          {(investigation_report?.suspicious_activities?.length ?? 0) > 0 && (
            <div className="p-8 bg-zinc-900 border border-zinc-800 rounded-xl">
               <h4 className="text-xl font-bold text-zinc-100 mb-6 uppercase flex gap-3 items-center">
                 <AlertTriangle className="w-6 h-6 text-amber-500" /> Anomalies
               </h4>
               <ul className="space-y-6">
                 {investigation_report?.suspicious_activities?.map((act, i) => (
                   <li key={i} className="bg-black/40 p-5 border border-zinc-800 rounded-lg">
                     <div className="font-bold text-amber-400 mb-2 text-xl">{act.title}</div>
                     <div className="text-base text-zinc-400 leading-relaxed">{act.description}</div>
                     {act.file && <div className="text-sm font-mono text-zinc-500 mt-3 truncate break-all">File: {act.file}</div>}
                   </li>
                 ))}
               </ul>
            </div>
          )}

          {(investigation_report?.code_vulnerabilities?.length ?? 0) > 0 && (
            <div className="p-8 bg-zinc-900 border border-zinc-800 rounded-xl">
               <h4 className="text-xl font-bold text-zinc-100 mb-6 uppercase flex gap-3 items-center">
                 <FileCode className="w-6 h-6 text-red-400" /> Vulnerabilities
               </h4>
               <ul className="space-y-6">
                 {investigation_report?.code_vulnerabilities?.map((vuln, i) => (
                   <li key={i} className="bg-black/40 p-5 border border-zinc-800 rounded-lg">
                     <div className="font-bold text-red-400 mb-2 text-xl">{vuln.title}</div>
                     <div className="text-base text-zinc-400 leading-relaxed">{vuln.description}</div>
                     {vuln.file && <div className="text-sm font-mono text-zinc-500 mt-3 truncate break-all">File: {vuln.file}</div>}
                   </li>
                 ))}
               </ul>
            </div>
          )}
        </div>
        
        {/* Recommendations */}
        {investigation_report?.recommendations && investigation_report.recommendations.length > 0 && (
          <div className="p-8 bg-emerald-950/20 border border-emerald-900/50 rounded-xl">
             <h3 className="text-2xl font-bold text-emerald-400 flex gap-3 items-center mb-6 uppercase tracking-widest border-b border-emerald-900/50 pb-4">
               <Shield className="w-8 h-8" /> Recommendations
             </h3>
             <ul className="space-y-4 list-disc list-inside px-4 text-emerald-200/80 text-xl">
               {investigation_report?.recommendations?.map((rec, idx) => (
                 <li key={idx} className="leading-relaxed">{rec}</li>
               ))}
             </ul>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      {user && renderSidebar()}

      {/* Main Content */}
      <div className="flex-1 flex flex-col h-full overflow-y-auto bg-zinc-950 text-zinc-100">
        <header className="flex items-center justify-between p-6 md:p-8 border-b border-zinc-800 sticky top-0 bg-zinc-950/80 backdrop-blur z-10">
          <div className="flex items-center gap-4">
            <button className="md:hidden" onClick={() => setIsSidebarOpen(!isSidebarOpen)}>
              <FileCheck className="w-8 h-8 text-emerald-400" />
            </button>
            <h1 className="text-3xl font-bold font-mono tracking-widest uppercase text-emerald-400 truncate">
              {activeResult ? 'Investigation Report' : 'New Analysis'}
            </h1>
          </div>
          <div>
            {!user ? (
              <button onClick={handleLogin} className="flex items-center gap-3 bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-3 rounded-lg text-lg font-bold uppercase tracking-wider transition-colors shadow-[0_0_20px_rgba(16,185,129,0.3)]">
                <Lock className="w-6 h-6" /> Operator Login
              </button>
            ) : (
              <div className="flex items-center gap-4">
                <div className="hidden sm:flex items-center gap-3 px-5 py-3 bg-zinc-900 rounded-lg border border-zinc-800">
                  <UserIcon className="w-6 h-6 text-emerald-400" />
                  <span className="text-base font-mono text-zinc-300">{user.email}</span>
                </div>
                <button onClick={() => { setActiveAnalysisId(null); setFile(null); }} className="text-zinc-300 hover:text-emerald-400 hover:bg-zinc-900 px-5 py-3 border border-zinc-800 rounded-lg font-bold uppercase text-base hidden md:block">
                  New Scan
                </button>
                <button onClick={handleLogout} className="text-zinc-500 hover:text-red-400 p-3 bg-zinc-900 rounded-lg border border-zinc-800 transition-colors" title="Disconnect">
                  <LogOut className="w-6 h-6" />
                </button>
              </div>
            )}
          </div>
        </header>

        <main className="flex-1 p-6 md:p-12 max-w-7xl mx-auto w-full">
          {error && (
            <div className="mb-8 p-4 bg-red-950/30 border border-red-900/50 rounded-lg text-red-200 flex items-start gap-3">
              <AlertTriangle className="w-6 h-6 text-red-500 shrink-0" />
              <div className="text-lg">{error}</div>
            </div>
          )}

          {!user ? (
            <div className="flex flex-col items-center justify-center p-12 md:p-24 border border-zinc-800 rounded-2xl bg-zinc-900/50 shadow-2xl h-[60vh]">
              <Shield className="w-24 h-24 text-emerald-500/20 mb-6" />
              <h2 className="text-3xl font-bold uppercase tracking-widest text-zinc-200 mb-4 text-center">Authentication Required</h2>
              <p className="text-zinc-400 max-w-xl text-center text-lg leading-relaxed">
                Connect your operator identity to access the proprietary static analysis pipeline 
                powered by Kavach AI engine.
              </p>
            </div>
          ) : (
            <div className="space-y-8">
              {!activeAnalysisId ? (
                // Upload View
                <div className="animate-fade-in text-lg">
                   <h2 className="text-2xl font-bold uppercase tracking-wider mb-6 text-zinc-300">Submit Target Binary</h2>
                   <div className="flex flex-col md:flex-row gap-6">
                      <div className="relative flex-1 group">
                        <input
                          type="file"
                          accept=".apk"
                          onChange={handleFileChange}
                          disabled={uploadProgress > 0}
                          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer disabled:cursor-not-allowed z-10"
                        />
                        <div className={`p-10 border-2 border-dashed rounded-xl flex flex-col items-center justify-center transition-all h-64
                          ${file ? 'border-emerald-500/50 bg-emerald-950/10' : 'border-zinc-700 bg-zinc-900/50 group-hover:border-emerald-600/50 group-hover:bg-zinc-900'}
                          ${uploadProgress > 0 ? 'opacity-50' : ''}
                        `}>
                          <FolderOpen className={`w-16 h-16 mb-4 ${file ? 'text-emerald-400' : 'text-zinc-600'}`} />
                          <h3 className="text-xl font-bold mb-2">
                            {file ? file.name : 'Select or drop .apk payload'}
                          </h3>
                          <p className="text-zinc-500">
                            {file ? `${(file.size / (1024 * 1024)).toFixed(2)} MB binary ready for injection` : 'Max payload: 50MB (Standard APK format)'}
                          </p>
                        </div>
                      </div>

                      <div className="flex flex-col justify-center min-w-[300px]">
                        <button
                          onClick={executeAnalysis}
                          disabled={!file || uploadProgress > 0}
                          className={`w-full py-6 rounded-xl font-mono text-xl font-bold uppercase tracking-widest flex items-center justify-center gap-3 transition-all
                            ${!file 
                              ? 'bg-zinc-900 text-zinc-600 border border-zinc-800' 
                              : uploadProgress > 0
                                ? 'bg-zinc-800 text-zinc-400 border border-zinc-700'
                                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_20px_rgba(16,185,129,0.4)]'
                            }
                          `}
                        >
                          {uploadProgress > 0 ? (
                            <>
                              <RefreshCw className="w-6 h-6 animate-spin" />
                              UPLOADING {uploadProgress}%
                            </>
                          ) : (
                            <>
                              <Play className="w-6 h-6" />
                              INITIATE SCAN
                            </>
                          )}
                        </button>
                      </div>
                   </div>
                </div>
              ) : (
                // Analysis View
                <>
                  {renderProgressState()}
                  {renderResult()}
                </>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
