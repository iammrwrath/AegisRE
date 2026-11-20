import React, { useState, useEffect } from 'react';
import {
  Shield,
  UploadCloud,
  Search,
  Copy,
  Check,
  FolderOpen,
  RefreshCw,
  AlertCircle,
  Key,
  X,
  CheckCircle2,
  Sparkles,
  Sun,
  Moon,
  Cpu,
  Terminal,
  Compass,
  Layers,
  Code2,
  ArrowRight,
} from 'lucide-react';

type ThemeMode = 'dark' | 'light';

const PALETTES = {
  dark: {
    bgPrimary: '#020617',
    bgSecondary: '#0f172a',
    bgTertiary: 'rgba(15, 23, 42, 0.65)',
    bgCode: '#070b14',
    bgHover: 'rgba(30, 41, 59, 0.5)',
    bgSelected: 'rgba(8, 145, 178, 0.18)',
    border: '#1e293b',
    borderStrong: '#334155',
    textPrimary: '#f8fafc',
    textSecondary: '#cbd5e1',
    textMuted: '#94a3b8',
    textDim: '#64748b',
    accent: '#22d3ee',
    accentText: '#38bdf8',
    accentBg: '#0891b2',
    accentSoft: 'rgba(6, 182, 212, 0.14)',
    success: '#4ade80',
    warning: '#fbbf24',
    danger: '#f87171',
    welcomeGradient: 'radial-gradient(circle at center, #0f172a 0%, #020617 100%)',
  },
  light: {
    bgPrimary: '#f8fafc',
    bgSecondary: '#ffffff',
    bgTertiary: '#f1f5f9',
    bgCode: '#0f172a', // keep code/asm dark-slate or crisp readable contrast
    bgHover: '#e2e8f0',
    bgSelected: 'rgba(8, 145, 178, 0.12)',
    border: '#e2e8f0',
    borderStrong: '#cbd5e1',
    textPrimary: '#0f172a',
    textSecondary: '#334155',
    textMuted: '#475569',
    textDim: '#64748b',
    accent: '#0891b2',
    accentText: '#0284c7',
    accentBg: '#0891b2',
    accentSoft: 'rgba(8, 145, 178, 0.1)',
    success: '#16a34a',
    warning: '#d97706',
    danger: '#dc2626',
    welcomeGradient: 'radial-gradient(circle at center, #ffffff 0%, #e2e8f0 100%)',
  },
};

export default function App() {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('aegis_theme');
    return saved === 'light' ? 'light' : 'dark';
  });
  const colors = PALETTES[theme];

  const [target, setTarget] = useState<any>(null);
  const [functions, setFunctions] = useState<any[]>([]);
  const [strings, setStrings] = useState<any[]>([]);
  const [imports, setImports] = useState<any[]>([]);
  const [selectedFunc, setSelectedFunc] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<
    'overview' | 'decompile' | 'disassembly' | 'strings' | 'imports' | 'sections' | 'hex'
  >('overview');

  const [stringCategoryFilter, setStringCategoryFilter] = useState<string>('ALL');
  const [importCategoryFilter, setImportCategoryFilter] = useState<string>('ALL');
  const [filterQuery, setFilterQuery] = useState('');
  const [stringSearch, setStringSearch] = useState('');
  const [importSearch, setImportSearch] = useState('');
  const [customAddressInput, setCustomAddressInput] = useState('');
  const [copied, setCopied] = useState(false);
  const [appVersion, setAppVersion] = useState('1.1.0');
  const [analysisError, setAnalysisError] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);

  // Update check states
  const [showUpdateModal, setShowUpdateModal] = useState(false);
  const [hasConfiguredToken, setHasConfiguredToken] = useState(false);
  const [ghToken, setGhToken] = useState(() => localStorage.getItem('aegis_gh_token') || '');
  const [updateState, setUpdateState] = useState<
    'idle' | 'checking' | 'available' | 'not-available' | 'downloading' | 'downloaded' | 'error'
  >('idle');
  const [updateInfo, setUpdateInfo] = useState<any>(null);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    if (window.aegis?.getVersion) {
      window.aegis.getVersion().then(setAppVersion);
    }

    if (window.aegis?.getTheme) {
      window.aegis.getTheme().then((t: ThemeMode) => {
        if (t === 'light' || t === 'dark') {
          setTheme(t);
          localStorage.setItem('aegis_theme', t);
        }
      });
    }

    if (window.aegis?.hasConfiguredToken) {
      window.aegis.hasConfiguredToken().then((has: boolean) => {
        setHasConfiguredToken(has);
      });
    }

    if (window.aegis?.onUpdaterStatus) {
      return window.aegis.onUpdaterStatus(({ status, data }: any) => {
        if (status === 'checking') setUpdateState('checking');
        else if (status === 'available') {
          setUpdateState('available');
          setUpdateInfo(data);
        } else if (status === 'not-available') {
          setUpdateState('not-available');
        } else if (status === 'downloading') {
          setUpdateState('downloading');
          setDownloadProgress(Math.round(data?.percent || 0));
        } else if (status === 'downloaded') {
          setUpdateState('downloaded');
        } else if (status === 'error') {
          setUpdateState('error');
          setErrorMessage(typeof data === 'string' ? data : JSON.stringify(data));
        }
      });
    }
  }, []);

  const toggleTheme = () => {
    const next: ThemeMode = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('aegis_theme', next);
    if (window.aegis?.setTheme) {
      window.aegis.setTheme(next);
    }
  };

  const handleOpenFile = async () => {
    try {
      setAnalysisError('');
      if (window.aegis?.openFile) {
        const file = await window.aegis.openFile();
        if (file && file.path) {
          await analyze(file.path);
        }
      } else {
        await analyze('C:\\Windows\\System32\\notepad.exe');
      }
    } catch (err: any) {
      setAnalysisError(err?.message || 'Could not open file');
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      const droppedFile: any = files[0];
      if (droppedFile.path) {
        await analyze(droppedFile.path);
      }
    }
  };

  const analyze = async (filePath: string) => {
    try {
      setIsAnalyzing(true);
      setAnalysisError('');
      let res: any;
      if (window.aegis?.analyzeTarget) {
        res = await window.aegis.analyzeTarget(filePath);
      }

      if (res && res.success && res.target) {
        setTarget(res.target);
        setFunctions(res.functions || []);
        setStrings(res.strings || []);
        setImports(res.imports || []);
        setActiveTab('overview');
        // Default select WinMain if discovered, otherwise entry
        const winMainFn = (res.functions || []).find((f: any) => f.name === 'WinMain');
        setSelectedFunc(winMainFn || (res.functions && res.functions[0]) || null);
      } else {
        setAnalysisError(res?.error || 'Could not inspect this file.');
      }
    } catch (err: any) {
      setAnalysisError(err?.message || 'Unexpected error while analyzing file.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleDisassembleAddress = async (addrInput?: string) => {
    const addr = (addrInput || customAddressInput).trim();
    if (!addr || !target?.path) return;

    // First check if already in functions list
    const norm = addr.toLowerCase().replace(/^0x/, '');
    const existing = functions.find(
      (f) => f.address.toLowerCase().replace(/^0x/, '') === norm || f.name.toLowerCase() === addr.toLowerCase()
    );
    if (existing) {
      setSelectedFunc(existing);
      if (activeTab !== 'disassembly' && activeTab !== 'decompile') {
        setActiveTab('decompile');
      }
      return;
    }

    if (window.aegis?.disassembleAt) {
      const res = await window.aegis.disassembleAt(target.path, addr, 512);
      if (res && res.success && res.function) {
        setFunctions((prev) => [res.function, ...prev]);
        setSelectedFunc(res.function);
        if (activeTab !== 'disassembly' && activeTab !== 'decompile') {
          setActiveTab('decompile');
        }
        setCustomAddressInput('');
      } else {
        setAnalysisError(res?.error || `Could not disassemble at ${addr}`);
      }
    }
  };

  const checkForUpdates = async () => {
    setUpdateState('checking');
    setErrorMessage('');
    if (ghToken) {
      localStorage.setItem('aegis_gh_token', ghToken);
    }
    try {
      if (window.aegis?.checkForUpdates) {
        const res = await window.aegis.checkForUpdates(ghToken || undefined);
        if (window.aegis.hasConfiguredToken) {
          setHasConfiguredToken(Boolean(await window.aegis.hasConfiguredToken()));
        }
        if (res.success) {
          if (res.status === 'available') {
            setUpdateState('available');
            setUpdateInfo(res.updateInfo);
          } else if (res.status === 'not-available') {
            setUpdateState('not-available');
            setUpdateInfo(res.updateInfo || null);
          }
        } else {
          setUpdateState('error');
          setErrorMessage(res.error || 'Failed to query GitHub repository releases');
        }
      } else {
        setUpdateState('not-available');
      }
    } catch (err: any) {
      setUpdateState('error');
      setErrorMessage(err?.message || 'Failed to query GitHub repository releases');
    }
  };

  const downloadUpdate = async () => {
    setUpdateState('downloading');
    setDownloadProgress(0);
    setErrorMessage('');
    try {
      if (window.aegis?.downloadUpdate) {
        const res = await window.aegis.downloadUpdate();
        if (res.success) {
          setUpdateState('downloaded');
          setDownloadProgress(100);
        } else {
          setUpdateState('error');
          setErrorMessage(res.error || 'Failed to download and apply update');
        }
      }
    } catch (err: any) {
      setUpdateState('error');
      setErrorMessage(err?.message || 'Failed to download and apply update');
    }
  };

  const installUpdate = () => {
    if (window.aegis?.installUpdate) {
      window.aegis.installUpdate();
    }
  };

  const filteredFunctions = functions.filter(
    (f) =>
      f.name.toLowerCase().includes(filterQuery.toLowerCase()) ||
      (f.plainTitle && f.plainTitle.toLowerCase().includes(filterQuery.toLowerCase())) ||
      f.address.toLowerCase().includes(filterQuery.toLowerCase()) ||
      (f.category && f.category.toLowerCase().includes(filterQuery.toLowerCase()))
  );

  const filteredStrings = strings.filter((s) => {
    const matchesCat = stringCategoryFilter === 'ALL' || s.section === stringCategoryFilter;
    const matchesSearch =
      !stringSearch ||
      s.value.toLowerCase().includes(stringSearch.toLowerCase()) ||
      s.section.toLowerCase().includes(stringSearch.toLowerCase()) ||
      s.offset.toLowerCase().includes(stringSearch.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const importCategories = ['ALL', ...Array.from(new Set(imports.map((i) => i.category || 'System')))];
  const filteredImports = imports.filter((imp) => {
    const matchesCat = importCategoryFilter === 'ALL' || imp.category === importCategoryFilter;
    const matchesSearch =
      !importSearch ||
      imp.function.toLowerCase().includes(importSearch.toLowerCase()) ||
      imp.dll.toLowerCase().includes(importSearch.toLowerCase()) ||
      (imp.plain && imp.plain.toLowerCase().includes(importSearch.toLowerCase()));
    return matchesCat && matchesSearch;
  });

  const getDecompiledCode = (func: any) => {
    if (!func) return '// Select any function from the left sidebar to decompile it to C';
    if (func.decompiled) return func.decompiled;
    return `// Function ${func.name} (${func.address})\n${func.signature} {\n    return 0;\n}`;
  };

  const copyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const urlCount = strings.filter((s) => s.section === 'Web Link / URL').length;
  const pathCount = strings.filter((s) => s.section === 'File Path / System Setting').length;
  const keywordCount = strings.filter((s) => s.section === 'Notable Keyword / Command').length;
  const engineCount = strings.filter((s) => s.section === 'Audio, GPU & Engine Clues').length;

  return (
    <div
      onDragOver={(e) => e.preventDefault()}
      onDrop={handleDrop}
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        width: '100vw',
        backgroundColor: colors.bgPrimary,
        color: colors.textPrimary,
        fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        transition: 'background-color 0.15s ease, color 0.15s ease',
      }}
    >
      {/* Top Header Bar */}
      <header
        style={{
          height: '46px',
          backgroundColor: colors.bgSecondary,
          borderBottom: `1px solid ${colors.border}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 16px',
          paddingRight: '145px', // space for Windows titleBarOverlay buttons
          WebkitAppRegion: 'drag' as any,
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '28px',
              height: '28px',
              borderRadius: '6px',
              backgroundColor: colors.accentSoft,
              color: colors.accent,
              border: `1px solid ${colors.accent}`,
            }}
          >
            <Shield style={{ width: '16px', height: '16px' }} />
          </div>
          <span style={{ fontWeight: 800, fontSize: '14px', letterSpacing: '0.04em', color: colors.textPrimary }}>
            AEGIS<span style={{ color: colors.accent }}>RE</span> STUDIO
          </span>
          <span
            style={{
              fontSize: '11px',
              backgroundColor: colors.bgTertiary,
              color: colors.accentText,
              border: `1px solid ${colors.border}`,
              padding: '2px 8px',
              borderRadius: '999px',
              fontWeight: 600,
            }}
          >
            Ghidra Decompiler Engine • v{appVersion}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', WebkitAppRegion: 'no-drag' as any }}>
          {/* Light / Dark Mode Toggle */}
          <button
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '12px',
              backgroundColor: colors.bgTertiary,
              color: colors.textSecondary,
              border: `1px solid ${colors.borderStrong}`,
              padding: '6px 11px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            {theme === 'dark' ? (
              <>
                <Sun style={{ width: '14px', height: '14px', color: '#fbbf24' }} />
                <span>Light Mode</span>
              </>
            ) : (
              <>
                <Moon style={{ width: '14px', height: '14px', color: '#0284c7' }} />
                <span>Dark Mode</span>
              </>
            )}
          </button>

          <button
            onClick={() => setShowUpdateModal(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '12px',
              backgroundColor: colors.bgTertiary,
              color: colors.textSecondary,
              border: `1px solid ${colors.borderStrong}`,
              padding: '6px 12px',
              borderRadius: '6px',
              cursor: 'pointer',
            }}
          >
            <RefreshCw style={{ width: '13px', height: '13px', color: colors.accentText }} />
            <span>Updates</span>
          </button>

          <button
            onClick={handleOpenFile}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '12px',
              backgroundColor: colors.accentBg,
              color: '#ffffff',
              border: 'none',
              padding: '6px 14px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontWeight: 600,
              boxShadow: '0 2px 8px rgba(8, 145, 178, 0.3)',
            }}
          >
            <FolderOpen style={{ width: '14px', height: '14px' }} />
            <span>Open Binary / App</span>
          </button>
        </div>
      </header>

      {/* Error Banner */}
      {analysisError && (
        <div
          style={{
            backgroundColor: 'rgba(239, 68, 68, 0.14)',
            borderBottom: '1px solid rgba(239, 68, 68, 0.35)',
            padding: '10px 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            color: colors.danger,
            fontSize: '13px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertCircle style={{ width: '16px', height: '16px' }} />
            <span>{analysisError}</span>
          </div>
          <button
            onClick={() => setAnalysisError('')}
            style={{ background: 'none', border: 'none', color: colors.danger, cursor: 'pointer' }}
          >
            <X style={{ width: '16px', height: '16px' }} />
          </button>
        </div>
      )}

      {/* Welcome / Empty State */}
      {!target ? (
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '32px',
            textAlign: 'center',
            background: colors.welcomeGradient,
          }}
        >
          <div
            onClick={handleOpenFile}
            style={{
              cursor: 'pointer',
              maxWidth: '660px',
              width: '100%',
              border: `2px dashed ${colors.accentText}`,
              backgroundColor: colors.bgSecondary,
              borderRadius: '18px',
              padding: '44px 36px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              boxShadow: theme === 'dark' ? '0 20px 50px rgba(0,0,0,0.45)' : '0 16px 40px rgba(15,23,42,0.08)',
            }}
          >
            <div
              style={{
                width: '68px',
                height: '68px',
                borderRadius: '50%',
                backgroundColor: colors.accentSoft,
                color: colors.accent,
                border: `1px solid ${colors.accent}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: '18px',
              }}
            >
              <UploadCloud style={{ width: '34px', height: '34px' }} />
            </div>

            <h2 style={{ fontSize: '22px', fontWeight: 700, color: colors.textPrimary, margin: '0 0 10px 0' }}>
              Drop any executable or binary here to decompile & inspect
            </h2>

            <p style={{ fontSize: '14px', color: colors.textMuted, maxWidth: '520px', lineHeight: 1.6, margin: '0 0 24px 0' }}>
              Powered by AegisRE’s built-in <strong>x86_64 Disassembler, Ghidra-style C Decompiler, and PE/ELF Inspector</strong>.
              Automatically discovers <code>WinMain</code>, <code>.pdata</code> functions, full DLL Import tables, and plain-English capabilities.
            </p>

            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center' }}>
              <button
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: colors.accentBg,
                  color: '#ffffff',
                  fontSize: '14px',
                  fontWeight: 600,
                  padding: '12px 24px',
                  borderRadius: '10px',
                  border: 'none',
                  cursor: 'pointer',
                  boxShadow: '0 4px 14px rgba(8, 145, 178, 0.35)',
                }}
              >
                <FolderOpen style={{ width: '18px', height: '18px' }} />
                {isAnalyzing ? 'Decompiling Binary...' : 'Choose an App or Binary (.exe, .dll)'}
              </button>

              <button
                onClick={(e) => {
                  e.stopPropagation();
                  analyze('C:\\Program Files\\VirtualDJ\\virtualdj.exe');
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: colors.bgTertiary,
                  color: colors.accentText,
                  fontSize: '13px',
                  fontWeight: 600,
                  padding: '12px 18px',
                  borderRadius: '10px',
                  border: `1px solid ${colors.borderStrong}`,
                  cursor: 'pointer',
                }}
              >
                <Cpu style={{ width: '16px', height: '16px' }} />
                Inspect VirtualDJ.exe
              </button>

              <button
                onClick={(e) => {
                  e.stopPropagation();
                  analyze('C:\\Windows\\System32\\notepad.exe');
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: colors.bgTertiary,
                  color: colors.textSecondary,
                  fontSize: '13px',
                  fontWeight: 600,
                  padding: '12px 18px',
                  borderRadius: '10px',
                  border: `1px solid ${colors.borderStrong}`,
                  cursor: 'pointer',
                }}
              >
                <Sparkles style={{ width: '16px', height: '16px' }} />
                Inspect Notepad.exe
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
          {/* Left Sidebar: Ghidra Symbol Tree & Functions */}
          <aside
            style={{
              width: '320px',
              borderRight: `1px solid ${colors.border}`,
              backgroundColor: colors.bgSecondary,
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            {/* Target Summary Header */}
            <div style={{ padding: '12px', borderBottom: `1px solid ${colors.border}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ fontSize: '10px', fontWeight: 700, color: colors.accentText, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Active Target
                </span>
                <span style={{ fontSize: '11px', color: colors.textMuted, fontFamily: 'monospace' }}>
                  Base: {target.imageBase || '0x140000000'}
                </span>
              </div>
              <div style={{ fontSize: '14px', fontWeight: 700, color: colors.textPrimary, wordBreak: 'break-all' }}>
                {target.name}
              </div>
              <div style={{ fontSize: '12px', color: colors.textMuted, marginTop: '3px' }}>
                {target.format} • {target.sizeFormatted}
              </div>
            </div>

            {/* Jump to Any Address (On-Demand Disassembler) */}
            <div style={{ padding: '8px 12px', borderBottom: `1px solid ${colors.border}`, backgroundColor: colors.bgTertiary }}>
              <div style={{ fontSize: '10px', fontWeight: 700, color: colors.textMuted, textTransform: 'uppercase', marginBottom: '5px' }}>
                Go To / Disassemble Address (VA or RVA)
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <input
                  type="text"
                  placeholder="e.g. 0x14151A390"
                  value={customAddressInput}
                  onChange={(e) => setCustomAddressInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleDisassembleAddress()}
                  style={{
                    flex: 1,
                    backgroundColor: colors.bgPrimary,
                    border: `1px solid ${colors.borderStrong}`,
                    borderRadius: '6px',
                    padding: '5px 8px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    color: colors.textPrimary,
                    outline: 'none',
                  }}
                />
                <button
                  onClick={() => handleDisassembleAddress()}
                  style={{
                    backgroundColor: colors.accentBg,
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '0 10px',
                    fontSize: '11px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Decode
                </button>
              </div>
            </div>

            {/* Filter Functions */}
            <div style={{ padding: '8px 12px', borderBottom: `1px solid ${colors.border}` }}>
              <div style={{ position: 'relative' }}>
                <Search style={{ width: '14px', height: '14px', position: 'absolute', left: '10px', top: '8px', color: colors.textDim }} />
                <input
                  type="text"
                  placeholder="Filter functions or addresses..."
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  style={{
                    width: '100%',
                    boxSizing: 'border-box',
                    backgroundColor: colors.bgPrimary,
                    border: `1px solid ${colors.borderStrong}`,
                    borderRadius: '6px',
                    padding: '6px 10px 6px 30px',
                    fontSize: '12px',
                    color: colors.textPrimary,
                    outline: 'none',
                  }}
                />
              </div>
            </div>

            <div
              style={{
                padding: '8px 12px',
                fontSize: '11px',
                fontWeight: 700,
                color: colors.textMuted,
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
                borderBottom: `1px solid ${colors.border}`,
                display: 'flex',
                justifyContent: 'space-between',
              }}
            >
              <span>Symbol Tree ({filteredFunctions.length})</span>
              {target.totalFunctionsDiscovered > functions.length && (
                <span style={{ color: colors.accentText, fontSize: '10px' }}>
                  {target.totalFunctionsDiscovered.toLocaleString()} in .pdata
                </span>
              )}
            </div>

            {/* Function List */}
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {filteredFunctions.map((fn) => {
                const isSelected = selectedFunc?.address === fn.address;
                return (
                  <div
                    key={fn.address}
                    onClick={() => {
                      setSelectedFunc(fn);
                      if (activeTab !== 'disassembly' && activeTab !== 'decompile') {
                        setActiveTab('decompile');
                      }
                    }}
                    style={{
                      padding: '9px 12px',
                      cursor: 'pointer',
                      borderBottom: `1px solid ${colors.border}`,
                      backgroundColor: isSelected ? colors.bgSelected : 'transparent',
                      borderLeft: isSelected ? `3px solid ${colors.accent}` : '3px solid transparent',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span
                        style={{
                          fontSize: '12.5px',
                          fontWeight: 700,
                          fontFamily: 'monospace',
                          color: isSelected ? colors.accentText : colors.textPrimary,
                        }}
                      >
                        {fn.name}
                      </span>
                      <span
                        style={{
                          fontSize: '10px',
                          padding: '1px 6px',
                          borderRadius: '4px',
                          backgroundColor: colors.bgTertiary,
                          color: colors.textMuted,
                          fontFamily: 'monospace',
                        }}
                      >
                        {fn.address}
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: colors.textMuted, marginTop: '3px', display: 'flex', justifyContent: 'space-between' }}>
                      <span>{fn.plainTitle || fn.category || 'Function'}</span>
                      <span>{fn.size} B</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </aside>

          {/* Main Workspace Area */}
          <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', backgroundColor: colors.bgPrimary }}>
            {/* Navigation Tabs */}
            <div
              style={{
                minHeight: '48px',
                borderBottom: `1px solid ${colors.border}`,
                backgroundColor: colors.bgSecondary,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0 16px',
                gap: '8px',
                flexWrap: 'wrap',
              }}
            >
              <div style={{ display: 'flex', gap: '6px', padding: '4px 0', flexWrap: 'wrap' }}>
                {[
                  { id: 'overview', label: '✨ 1. Plain-English Overview' },
                  { id: 'decompile', label: '⚙️ 2. Ghidra C Decompiler' },
                  { id: 'disassembly', label: `🔬 3. x86_64 Disassembly (${selectedFunc?.disassembly?.length || 0} insns)` },
                  { id: 'imports', label: `🔌 4. Imported APIs (${imports.length})` },
                  { id: 'strings', label: `🔍 5. Strings (${strings.length})` },
                  { id: 'sections', label: `📦 6. PE Sections & Exports (${target.sectionDetails?.length || 0})` },
                  { id: 'hex', label: '🔢 7. Raw Hex' },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    style={{
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      border: activeTab === tab.id ? `1px solid ${colors.accent}` : `1px solid ${colors.borderStrong}`,
                      cursor: 'pointer',
                      backgroundColor: activeTab === tab.id ? colors.accentBg : colors.bgTertiary,
                      color: activeTab === tab.id ? '#ffffff' : colors.textSecondary,
                    }}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Active Tab Body */}
            <div style={{ flex: 1, overflow: 'auto', padding: '20px', boxSizing: 'border-box' }}>
              {/* TAB 1: PLAIN-ENGLISH OVERVIEW */}
              {activeTab === 'overview' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', maxWidth: '1120px' }}>
                  {/* Executive Summary Card */}
                  <div
                    style={{
                      backgroundColor: colors.bgSecondary,
                      border: `1px solid ${colors.accent}`,
                      borderRadius: '12px',
                      padding: '20px',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        marginBottom: '8px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: colors.accentText, fontSize: '12px', fontWeight: 700, textTransform: 'uppercase' }}>
                        <Sparkles style={{ width: '15px', height: '15px' }} />
                        Executive Binary Triage & Architecture Summary
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          onClick={() => {
                            const wm = functions.find((f) => f.name === 'WinMain') || functions[0];
                            if (wm) setSelectedFunc(wm);
                            setActiveTab('decompile');
                          }}
                          style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '4px 10px',
                            borderRadius: '6px',
                            backgroundColor: colors.accentBg,
                            color: '#ffffff',
                            border: 'none',
                            cursor: 'pointer',
                          }}
                        >
                          Open WinMain in Decompiler →
                        </button>
                      </div>
                    </div>

                    <h3 style={{ margin: '0 0 8px 0', fontSize: '18px', color: colors.textPrimary }}>
                      {target.name} — {target.plainFormat || target.format}
                    </h3>
                    <p style={{ margin: 0, fontSize: '14px', color: colors.textSecondary, lineHeight: 1.6 }}>
                      {target.summary}
                    </p>

                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
                        gap: '12px',
                        marginTop: '16px',
                        paddingTop: '16px',
                        borderTop: `1px solid ${colors.border}`,
                      }}
                    >
                      <div>
                        <div style={{ fontSize: '11px', color: colors.textMuted }}>Entry Point / WinMain</div>
                        <div style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'monospace', color: colors.accentText, marginTop: '2px' }}>
                          {target.entryPoint || '0x140001000'}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: colors.textMuted }}>Functions in .pdata</div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: colors.textPrimary, marginTop: '2px' }}>
                          {(target.totalFunctionsDiscovered || functions.length).toLocaleString()} subroutines
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: colors.textMuted }}>Imported Windows APIs</div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: colors.textPrimary, marginTop: '2px' }}>
                          {imports.length.toLocaleString()} APIs ({target.totalDllsImported || 0} DLLs)
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: colors.textMuted }}>File Size & Build Date</div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: colors.textPrimary, marginTop: '2px' }}>
                          {target.sizeFormatted} ({target.compileDate})
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: colors.textMuted }}>Obfuscation / Packing</div>
                        <div
                          style={{
                            fontSize: '13px',
                            fontWeight: 700,
                            color: target.isPacked ? colors.warning : colors.success,
                            marginTop: '2px',
                          }}
                        >
                          {target.isPacked ? '⚠️ Packed / Compressed' : `✅ Unpacked (Entropy ${target.entropy})`}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Quick Clues Summary Cards */}
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                      gap: '12px',
                    }}
                  >
                    <div
                      onClick={() => {
                        setStringCategoryFilter('Audio, GPU & Engine Clues');
                        setActiveTab('strings');
                      }}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.border}`,
                        borderRadius: '10px',
                        padding: '14px',
                      }}
                    >
                      <div style={{ fontSize: '12px', color: colors.textMuted }}>🎛️ Audio, GPU & Engine Clues</div>
                      <div style={{ fontSize: '22px', fontWeight: 800, color: colors.accentText, margin: '4px 0' }}>
                        {engineCount}
                      </div>
                      <div style={{ fontSize: '11px', color: colors.textDim }}>Inspect ASIO, CUDA, Direct3D, Codec strings →</div>
                    </div>

                    <div
                      onClick={() => {
                        setStringCategoryFilter('Web Link / URL');
                        setActiveTab('strings');
                      }}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.border}`,
                        borderRadius: '10px',
                        padding: '14px',
                      }}
                    >
                      <div style={{ fontSize: '12px', color: colors.textMuted }}>🌐 Website Links & Endpoints</div>
                      <div style={{ fontSize: '22px', fontWeight: 800, color: colors.accent, margin: '4px 0' }}>
                        {urlCount}
                      </div>
                      <div style={{ fontSize: '11px', color: colors.textDim }}>Click to view embedded URLs →</div>
                    </div>

                    <div
                      onClick={() => {
                        setStringCategoryFilter('File Path / System Setting');
                        setActiveTab('strings');
                      }}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.border}`,
                        borderRadius: '10px',
                        padding: '14px',
                      }}
                    >
                      <div style={{ fontSize: '12px', color: colors.textMuted }}>📁 File Paths, Registry & DLLs</div>
                      <div style={{ fontSize: '22px', fontWeight: 800, color: colors.success, margin: '4px 0' }}>
                        {pathCount}
                      </div>
                      <div style={{ fontSize: '11px', color: colors.textDim }}>Click to view file & Registry paths →</div>
                    </div>

                    <div
                      onClick={() => {
                        setStringCategoryFilter('Notable Keyword / Command');
                        setActiveTab('strings');
                      }}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.border}`,
                        borderRadius: '10px',
                        padding: '14px',
                      }}
                    >
                      <div style={{ fontSize: '12px', color: colors.textMuted }}>🔑 License, Security & Error Clues</div>
                      <div style={{ fontSize: '22px', fontWeight: 800, color: colors.warning, margin: '4px 0' }}>
                        {keywordCount}
                      </div>
                      <div style={{ fontSize: '11px', color: colors.textDim }}>Click to inspect security & license strings →</div>
                    </div>
                  </div>

                  {/* Capabilities Grid */}
                  <div>
                    <h4 style={{ margin: '0 0 10px 0', fontSize: '15px', color: colors.textPrimary }}>
                      Detected System Capabilities (Derived from {imports.length} Real PE Imports & Sections)
                    </h4>
                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                        gap: '12px',
                      }}
                    >
                      {(target.capabilities || []).map((cap: any, i: number) => (
                        <div
                          key={i}
                          style={{
                            backgroundColor: colors.bgSecondary,
                            border: `1px solid ${colors.border}`,
                            borderRadius: '10px',
                            padding: '14px',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                            <span style={{ fontWeight: 700, fontSize: '13.5px', color: colors.accentText }}>
                              {cap.title}
                            </span>
                            <span
                              style={{
                                fontSize: '11px',
                                backgroundColor: colors.bgTertiary,
                                color: colors.textSecondary,
                                padding: '2px 8px',
                                borderRadius: '999px',
                                fontWeight: 600,
                              }}
                            >
                              {cap.count} API(s)
                            </span>
                          </div>
                          <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: colors.textSecondary, lineHeight: 1.55 }}>
                            {cap.examples.map((ex: string, j: number) => (
                              <li key={j}>{ex}</li>
                            ))}
                          </ul>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: GHIDRA C DECOMPILER */}
              {activeTab === 'decompile' && (
                <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '12px' }}>
                  {selectedFunc && (
                    <div
                      style={{
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.border}`,
                        borderRadius: '10px',
                        padding: '12px 16px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: '10px',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: '14px', fontWeight: 700, color: colors.accentText, marginBottom: '3px' }}>
                          {selectedFunc.name} — {selectedFunc.plainTitle || 'Decompiled Function'}
                        </div>
                        <div style={{ fontSize: '12.5px', color: colors.textSecondary }}>
                          {selectedFunc.plainExplanation}
                        </div>
                      </div>
                      <button
                        onClick={() => setActiveTab('disassembly')}
                        style={{
                          padding: '6px 12px',
                          borderRadius: '6px',
                          fontSize: '12px',
                          fontWeight: 600,
                          backgroundColor: colors.bgTertiary,
                          color: colors.accentText,
                          border: `1px solid ${colors.borderStrong}`,
                          cursor: 'pointer',
                        }}
                      >
                        View x86_64 Assembly →
                      </button>
                    </div>
                  )}

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '12px', fontFamily: 'monospace', color: colors.textMuted }}>
                      {selectedFunc?.signature || 'Select a function from the Symbol Tree'}
                    </span>
                    <button
                      onClick={() => copyCode(getDecompiledCode(selectedFunc))}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        fontSize: '11px',
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.borderStrong}`,
                        color: colors.textSecondary,
                        padding: '5px 10px',
                        borderRadius: '6px',
                        cursor: 'pointer',
                      }}
                    >
                      {copied ? (
                        <Check style={{ width: '12px', height: '12px', color: colors.success }} />
                      ) : (
                        <Copy style={{ width: '12px', height: '12px' }} />
                      )}
                      <span>{copied ? 'Copied C Code' : 'Copy Decompiled C'}</span>
                    </button>
                  </div>

                  <pre
                    style={{
                      flex: 1,
                      margin: 0,
                      padding: '18px',
                      backgroundColor: '#090d16',
                      border: `1px solid ${colors.borderStrong}`,
                      borderRadius: '8px',
                      color: '#e2e8f0',
                      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
                      fontSize: '12.5px',
                      lineHeight: 1.65,
                      overflow: 'auto',
                    }}
                  >
                    <code>{getDecompiledCode(selectedFunc)}</code>
                  </pre>
                </div>
              )}

              {/* TAB 3: x86_64 DISASSEMBLY LISTING */}
              {activeTab === 'disassembly' && (
                <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <span style={{ fontSize: '14px', fontWeight: 700, color: colors.textPrimary }}>
                        x86_64 Disassembly Listing:{' '}
                        <span style={{ color: colors.accentText, fontFamily: 'monospace' }}>
                          {selectedFunc?.name} ({selectedFunc?.address})
                        </span>
                      </span>
                      <span style={{ fontSize: '12px', color: colors.textMuted, marginLeft: '12px' }}>
                        Click any <code>call</code> or <code>jmp</code> target address to follow execution flow
                      </span>
                    </div>
                    <button
                      onClick={() => setActiveTab('decompile')}
                      style={{
                        padding: '5px 12px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: 600,
                        backgroundColor: colors.accentBg,
                        color: '#ffffff',
                        border: 'none',
                        cursor: 'pointer',
                      }}
                    >
                      Switch to Decompiled C
                    </button>
                  </div>

                  <div style={{ flex: 1, overflow: 'auto', border: `1px solid ${colors.border}`, borderRadius: '8px', backgroundColor: colors.bgSecondary }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px', fontFamily: 'monospace' }}>
                      <thead style={{ backgroundColor: colors.bgTertiary, position: 'sticky', top: 0, borderBottom: `1px solid ${colors.border}`, color: colors.textMuted }}>
                        <tr>
                          <th style={{ padding: '9px 12px', width: '130px' }}>Address (VA)</th>
                          <th style={{ padding: '9px 12px', width: '190px' }}>Instruction Bytes</th>
                          <th style={{ padding: '9px 12px', width: '90px' }}>Mnemonic</th>
                          <th style={{ padding: '9px 12px' }}>Operands</th>
                          <th style={{ padding: '9px 12px' }}>Cross-Reference / Symbol Comment</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(selectedFunc?.disassembly || []).map((insn: any, idx: number) => {
                          const isBranch = insn.mnemonic.startsWith('j') || insn.mnemonic === 'call' || insn.mnemonic === 'ret';
                          return (
                            <tr key={idx} style={{ borderBottom: `1px solid ${colors.border}` }}>
                              <td style={{ padding: '6px 12px', color: colors.accentText, fontWeight: 600 }}>
                                {insn.address}
                              </td>
                              <td style={{ padding: '6px 12px', color: colors.textDim }}>
                                {insn.bytes}
                              </td>
                              <td
                                style={{
                                  padding: '6px 12px',
                                  fontWeight: 700,
                                  color:
                                    insn.mnemonic === 'call'
                                      ? colors.warning
                                      : insn.mnemonic === 'ret'
                                      ? colors.danger
                                      : isBranch
                                      ? colors.accent
                                      : colors.textPrimary,
                                }}
                              >
                                {insn.mnemonic}
                              </td>
                              <td style={{ padding: '6px 12px', color: colors.textPrimary }}>
                                {insn.flowTarget && insn.flowType === 'call' ? (
                                  <span
                                    onClick={() => handleDisassembleAddress(insn.flowTarget)}
                                    style={{
                                      color: colors.warning,
                                      textDecoration: 'underline',
                                      cursor: 'pointer',
                                      fontWeight: 600,
                                    }}
                                    title={`Click to disassemble ${insn.flowTarget}`}
                                  >
                                    {insn.operands}
                                  </span>
                                ) : (
                                  insn.operands
                                )}
                              </td>
                              <td style={{ padding: '6px 12px', color: colors.success }}>
                                {insn.comment ? `; ${insn.comment}` : ''}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 4: IMPORTED WINDOWS APIS */}
              {activeTab === 'imports' && (
                <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      {importCategories.slice(0, 8).map((cat) => (
                        <button
                          key={cat}
                          onClick={() => setImportCategoryFilter(cat)}
                          style={{
                            padding: '5px 10px',
                            borderRadius: '999px',
                            fontSize: '11.5px',
                            border: `1px solid ${colors.borderStrong}`,
                            cursor: 'pointer',
                            backgroundColor: importCategoryFilter === cat ? colors.accentBg : colors.bgSecondary,
                            color: importCategoryFilter === cat ? '#ffffff' : colors.textSecondary,
                            fontWeight: 600,
                          }}
                        >
                          {cat}
                        </button>
                      ))}
                    </div>

                    <input
                      type="text"
                      placeholder="Search DLL or API name (e.g. D3D11, midi, Crypt)..."
                      value={importSearch}
                      onChange={(e) => setImportSearch(e.target.value)}
                      style={{
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.borderStrong}`,
                        borderRadius: '6px',
                        padding: '6px 12px',
                        fontSize: '12px',
                        color: colors.textPrimary,
                        width: '280px',
                      }}
                    />
                  </div>

                  <div style={{ flex: 1, overflow: 'auto', border: `1px solid ${colors.border}`, borderRadius: '8px', backgroundColor: colors.bgSecondary }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
                      <thead style={{ backgroundColor: colors.bgTertiary, position: 'sticky', top: 0, borderBottom: `1px solid ${colors.border}`, color: colors.textMuted }}>
                        <tr>
                          <th style={{ padding: '10px 12px' }}>IAT Address</th>
                          <th style={{ padding: '10px 12px' }}>DLL Library</th>
                          <th style={{ padding: '10px 12px' }}>Imported Function</th>
                          <th style={{ padding: '10px 12px' }}>Category</th>
                          <th style={{ padding: '10px 12px' }}>Plain-English Behavior</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredImports.map((imp, idx) => (
                          <tr key={idx} style={{ borderBottom: `1px solid ${colors.border}` }}>
                            <td style={{ padding: '7px 12px', color: colors.textMuted, fontFamily: 'monospace' }}>
                              {imp.address}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.success, fontFamily: 'monospace', fontWeight: 600 }}>
                              {imp.dll}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.textPrimary, fontFamily: 'monospace', fontWeight: 700 }}>
                              {imp.function}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.accentText, fontWeight: 600 }}>
                              {imp.category}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.textSecondary }}>
                              {imp.plain}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 5: STRINGS & CLUES */}
              {activeTab === 'strings' && (
                <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      {[
                        { id: 'ALL', label: `All Strings (${strings.length})` },
                        { id: 'Audio, GPU & Engine Clues', label: `🎛️ Audio, GPU & Engine (${engineCount})` },
                        { id: 'Web Link / URL', label: `🌐 Website Links (${urlCount})` },
                        { id: 'File Path / System Setting', label: `📁 File Paths (${pathCount})` },
                        { id: 'Notable Keyword / Command', label: `🔑 Security & Keywords (${keywordCount})` },
                      ].map((pill) => (
                        <button
                          key={pill.id}
                          onClick={() => setStringCategoryFilter(pill.id)}
                          style={{
                            padding: '5px 10px',
                            borderRadius: '999px',
                            fontSize: '12px',
                            border: `1px solid ${colors.borderStrong}`,
                            cursor: 'pointer',
                            backgroundColor: stringCategoryFilter === pill.id ? colors.accentBg : colors.bgSecondary,
                            color: stringCategoryFilter === pill.id ? '#ffffff' : colors.textSecondary,
                            fontWeight: 600,
                          }}
                        >
                          {pill.label}
                        </button>
                      ))}
                    </div>

                    <input
                      type="text"
                      placeholder="Filter strings (e.g. asio, cuda, http, license)..."
                      value={stringSearch}
                      onChange={(e) => setStringSearch(e.target.value)}
                      style={{
                        backgroundColor: colors.bgSecondary,
                        border: `1px solid ${colors.borderStrong}`,
                        borderRadius: '6px',
                        padding: '6px 12px',
                        fontSize: '12px',
                        color: colors.textPrimary,
                        width: '260px',
                      }}
                    />
                  </div>

                  <div style={{ flex: 1, overflow: 'auto', border: `1px solid ${colors.border}`, borderRadius: '8px', backgroundColor: colors.bgSecondary }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
                      <thead style={{ backgroundColor: colors.bgTertiary, position: 'sticky', top: 0, borderBottom: `1px solid ${colors.border}`, color: colors.textMuted }}>
                        <tr>
                          <th style={{ padding: '10px 12px', width: '100px' }}>RVA Offset</th>
                          <th style={{ padding: '10px 12px', width: '90px' }}>Encoding</th>
                          <th style={{ padding: '10px 12px', width: '190px' }}>Category</th>
                          <th style={{ padding: '10px 12px' }}>String Value</th>
                          <th style={{ padding: '10px 12px' }}>Meaning</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredStrings.map((s, idx) => (
                          <tr key={idx} style={{ borderBottom: `1px solid ${colors.border}` }}>
                            <td style={{ padding: '7px 12px', color: colors.textMuted, fontFamily: 'monospace' }}>
                              {s.offset}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.textDim, fontFamily: 'monospace' }}>
                              {s.type}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.accentText, fontWeight: 600, whiteSpace: 'nowrap' }}>
                              {s.section}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.textPrimary, fontFamily: 'monospace', wordBreak: 'break-all' }}>
                              {s.value}
                            </td>
                            <td style={{ padding: '7px 12px', color: colors.textMuted }}>
                              {s.plain}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 6: PE SECTIONS & EXPORTS */}
              {activeTab === 'sections' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '1050px' }}>
                  <div>
                    <h4 style={{ margin: '0 0 10px 0', fontSize: '15px', color: colors.textPrimary }}>
                      PE Memory Sections ({target.sectionDetails?.length || 0})
                    </h4>
                    <div style={{ border: `1px solid ${colors.border}`, borderRadius: '8px', overflow: 'hidden', backgroundColor: colors.bgSecondary }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
                        <thead style={{ backgroundColor: colors.bgTertiary, borderBottom: `1px solid ${colors.border}`, color: colors.textMuted }}>
                          <tr>
                            <th style={{ padding: '10px 12px' }}>Section Name</th>
                            <th style={{ padding: '10px 12px' }}>Virtual Address</th>
                            <th style={{ padding: '10px 12px' }}>Virtual Size</th>
                            <th style={{ padding: '10px 12px' }}>Raw File Offset</th>
                            <th style={{ padding: '10px 12px' }}>Raw Size</th>
                            <th style={{ padding: '10px 12px' }}>Role in Binary</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(target.sectionDetails || []).map((sec: any, idx: number) => (
                            <tr key={idx} style={{ borderBottom: `1px solid ${colors.border}` }}>
                              <td style={{ padding: '8px 12px', fontWeight: 700, fontFamily: 'monospace', color: colors.accentText }}>
                                {sec.name}
                              </td>
                              <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: colors.textPrimary }}>
                                {sec.address}
                              </td>
                              <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: colors.textSecondary }}>
                                {sec.vSize?.toLocaleString()} B
                              </td>
                              <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: colors.textMuted }}>
                                0x{sec.rawPtr?.toString(16).toUpperCase()}
                              </td>
                              <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: colors.textSecondary }}>
                                {sec.rawSize?.toLocaleString()} B
                              </td>
                              <td style={{ padding: '8px 12px', color: colors.textSecondary }}>
                                {sec.name === '.text'
                                  ? 'Executable x86_64 machine code'
                                  : sec.name === '.rdata' || sec.name === '.rodata'
                                  ? 'Read-only constants, strings, and import tables'
                                  : sec.name === '.data'
                                  ? 'Initialized global and static variables'
                                  : sec.name === '.pdata'
                                  ? 'x64 function unwind table (every function boundary)'
                                  : sec.name === '.rsrc'
                                  ? 'Embedded resources (UI skins, graphics, audio, icons)'
                                  : sec.name.toLowerCase().includes('nv')
                                  ? 'NVIDIA CUDA GPU compute kernels (AI / stems DSP)'
                                  : sec.name === '.reloc'
                                  ? 'ASLR base relocation table'
                                  : 'Application data / runtime section'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {target.exports && target.exports.length > 0 && (
                    <div>
                      <h4 style={{ margin: '0 0 10px 0', fontSize: '15px', color: colors.textPrimary }}>
                        Exported Symbols ({target.exports.length})
                      </h4>
                      <div style={{ border: `1px solid ${colors.border}`, borderRadius: '8px', overflow: 'hidden', backgroundColor: colors.bgSecondary }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
                          <thead style={{ backgroundColor: colors.bgTertiary, borderBottom: `1px solid ${colors.border}`, color: colors.textMuted }}>
                            <tr>
                              <th style={{ padding: '10px 12px' }}>Export Name</th>
                              <th style={{ padding: '10px 12px' }}>Virtual Address</th>
                              <th style={{ padding: '10px 12px' }}>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {target.exports.map((exp: any, i: number) => (
                              <tr key={i} style={{ borderBottom: `1px solid ${colors.border}` }}>
                                <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontWeight: 700, color: colors.success }}>
                                  {exp.name}
                                </td>
                                <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: colors.accentText }}>
                                  {exp.address}
                                </td>
                                <td style={{ padding: '8px 12px' }}>
                                  <button
                                    onClick={() => handleDisassembleAddress(exp.address)}
                                    style={{
                                      padding: '4px 10px',
                                      borderRadius: '4px',
                                      fontSize: '11px',
                                      backgroundColor: colors.accentBg,
                                      color: '#ffffff',
                                      border: 'none',
                                      cursor: 'pointer',
                                    }}
                                  >
                                    Decompile Export
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 7: RAW HEX BYTES */}
              {activeTab === 'hex' && (
                <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '10px' }}>
                  <div style={{ fontSize: '13px', color: colors.textMuted }}>
                    First 1,024 raw bytes of <strong>{target.name}</strong> (PE / MZ Header & DOS Stub):
                  </div>
                  <pre
                    style={{
                      flex: 1,
                      margin: 0,
                      padding: '16px',
                      backgroundColor: '#090d16',
                      border: `1px solid ${colors.borderStrong}`,
                      borderRadius: '8px',
                      color: '#67e8f9',
                      fontFamily: 'monospace',
                      fontSize: '12px',
                      lineHeight: 1.6,
                      overflow: 'auto',
                    }}
                  >
                    <code>{target.hexPreview || 'No hex preview available.'}</code>
                  </pre>
                </div>
              )}
            </div>

            {/* Bottom Status Bar */}
            <footer
              style={{
                height: '32px',
                borderTop: `1px solid ${colors.border}`,
                backgroundColor: colors.bgSecondary,
                padding: '0 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '11px',
                color: colors.textMuted,
                fontFamily: 'monospace',
              }}
            >
              <div>
                SHA-256: <span style={{ color: colors.textPrimary }}>{target.hashes?.sha256?.substring(0, 32)}...</span>
                {'  |  '}
                Entry: <span style={{ color: colors.accentText }}>{target.entryPoint}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: colors.success }}></span>
                <span style={{ color: colors.textPrimary, fontFamily: 'sans-serif', fontWeight: 600 }}>
                  Ghidra Static Decompiler Ready • Read-Only Mode
                </span>
              </div>
            </footer>
          </main>
        </div>
      )}

      {/* GitHub Auto-Update Modal */}
      {showUpdateModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
          }}
        >
          <div
            style={{
              width: '480px',
              backgroundColor: colors.bgSecondary,
              border: `1px solid ${colors.borderStrong}`,
              borderRadius: '12px',
              padding: '24px',
              boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: colors.textPrimary,
                  margin: 0,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <RefreshCw style={{ width: '16px', height: '16px', color: colors.accentText }} />
                Built-in Patch Updater
              </h3>
              <button
                onClick={() => setShowUpdateModal(false)}
                style={{ background: 'none', border: 'none', color: colors.textMuted, cursor: 'pointer' }}
              >
                <X style={{ width: '18px', height: '18px' }} />
              </button>
            </div>
            <div style={{ fontSize: '12px', color: colors.textMuted, marginBottom: '14px' }}>
              Installed: <strong style={{ color: colors.textPrimary }}>v{appVersion}</strong> &bull; Repo:{' '}
              <code>iammrwrath/AegisRE</code>
            </div>

            {hasConfiguredToken ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: 'rgba(34, 197, 94, 0.1)',
                  border: '1px solid rgba(34, 197, 94, 0.25)',
                  borderRadius: '8px',
                  padding: '10px 12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: colors.success,
                }}
              >
                <CheckCircle2 style={{ width: '16px', height: '16px', flexShrink: 0 }} />
                <span>
                  GitHub Update Token loaded from <code>%APPDATA%\AegisRE\config.json</code>
                </span>
              </div>
            ) : (
              <div style={{ marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', color: colors.textMuted, marginBottom: '10px', lineHeight: 1.5 }}>
                  Optional: Enter a GitHub token if checking private releases from <code>iammrwrath/AegisRE</code>:
                </div>
                <label
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '11px',
                    fontWeight: 600,
                    color: colors.textSecondary,
                    marginBottom: '6px',
                  }}
                >
                  <Key style={{ width: '12px', height: '12px', color: colors.accentText }} />
                  GitHub Personal Access Token:
                </label>
                <input
                  type="password"
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  value={ghToken}
                  onChange={(e) => setGhToken(e.target.value)}
                  style={{
                    width: '100%',
                    boxSizing: 'border-box',
                    backgroundColor: colors.bgPrimary,
                    border: `1px solid ${colors.borderStrong}`,
                    borderRadius: '6px',
                    padding: '8px 12px',
                    fontSize: '12px',
                    color: colors.textPrimary,
                    outline: 'none',
                  }}
                />
              </div>
            )}

            {updateState === 'checking' && (
              <div
                style={{
                  backgroundColor: colors.accentSoft,
                  border: `1px solid ${colors.accentText}`,
                  borderRadius: '8px',
                  padding: '12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: colors.accentText,
                }}
              >
                Checking <code>iammrwrath/AegisRE</code> on GitHub for new releases and patches...
              </div>
            )}

            {updateState === 'available' && (
              <div
                style={{
                  backgroundColor: colors.accentSoft,
                  border: `1px solid ${colors.accentText}`,
                  borderRadius: '8px',
                  padding: '12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: colors.textPrimary,
                }}
              >
                <div style={{ fontWeight: 700, color: colors.accent, marginBottom: '4px' }}>
                  New Update Available: v{updateInfo?.version || appVersion}
                </div>
                <div style={{ color: colors.textSecondary }}>
                  Current: v{appVersion}
                  {updateInfo?.name ? ` • ${updateInfo.name}` : ''}
                  {updateInfo?.releaseDate ? ` (${new Date(updateInfo.releaseDate).toLocaleDateString()})` : ''}
                </div>
              </div>
            )}

            {updateState === 'downloading' && (
              <div
                style={{
                  backgroundColor: colors.bgTertiary,
                  border: `1px solid ${colors.borderStrong}`,
                  borderRadius: '8px',
                  padding: '12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: colors.textSecondary,
                }}
              >
                <div style={{ marginBottom: '8px' }}>Downloading &amp; applying patch... {downloadProgress}%</div>
                <div
                  style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: colors.bgPrimary,
                    borderRadius: '999px',
                    overflow: 'hidden',
                    border: `1px solid ${colors.border}`,
                  }}
                >
                  <div
                    style={{
                      width: `${Math.min(100, Math.max(0, downloadProgress))}%`,
                      height: '100%',
                      backgroundColor: colors.accentBg,
                      transition: 'width 0.2s ease',
                    }}
                  />
                </div>
              </div>
            )}

            {updateState === 'downloaded' && (
              <div
                style={{
                  backgroundColor: 'rgba(34, 197, 94, 0.12)',
                  border: '1px solid rgba(34, 197, 94, 0.3)',
                  borderRadius: '8px',
                  padding: '12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: colors.success,
                }}
              >
                Update to v{updateInfo?.version || appVersion} applied! Restart to load the new version.
              </div>
            )}

            {updateState === 'not-available' && (
              <div
                style={{
                  backgroundColor: 'rgba(34, 197, 94, 0.1)',
                  border: '1px solid rgba(34, 197, 94, 0.28)',
                  borderRadius: '8px',
                  padding: '12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: colors.success,
                }}
              >
                You are running the latest version of AegisRE Studio (v{appVersion}).
              </div>
            )}

            {updateState === 'error' && (
              <div
                style={{
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '8px',
                  padding: '12px',
                  marginBottom: '16px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                  fontSize: '12px',
                  color: colors.danger,
                }}
              >
                <AlertCircle style={{ width: '16px', height: '16px', flexShrink: 0, marginTop: '2px' }} />
                <span>{errorMessage}</span>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                onClick={() => setShowUpdateModal(false)}
                style={{
                  padding: '7px 14px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  backgroundColor: colors.bgTertiary,
                  border: `1px solid ${colors.borderStrong}`,
                  color: colors.textSecondary,
                  cursor: 'pointer',
                }}
              >
                Close
              </button>
              {updateState === 'available' ? (
                <button
                  onClick={downloadUpdate}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '7px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    backgroundColor: colors.accentBg,
                    border: 'none',
                    color: '#ffffff',
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  Download &amp; Apply Update
                </button>
              ) : updateState === 'downloaded' ? (
                <button
                  onClick={installUpdate}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '7px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    backgroundColor: '#16a34a',
                    border: 'none',
                    color: '#ffffff',
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  Restart to Apply
                </button>
              ) : (
                <button
                  onClick={checkForUpdates}
                  disabled={updateState === 'checking' || updateState === 'downloading'}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '7px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    backgroundColor: colors.accentBg,
                    border: 'none',
                    color: '#ffffff',
                    cursor:
                      updateState === 'checking' || updateState === 'downloading' ? 'not-allowed' : 'pointer',
                    opacity: updateState === 'checking' || updateState === 'downloading' ? 0.65 : 1,
                    fontWeight: 600,
                  }}
                >
                  <RefreshCw style={{ width: '13px', height: '13px' }} />
                  {updateState === 'checking' ? 'Checking...' : 'Check Now'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
