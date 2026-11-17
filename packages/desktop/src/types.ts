export interface TargetAnalysis {
  path: string;
  name: string;
  format: string;
  plainFormat?: string;
  arch: string;
  subsystem: string;
  size?: number;
  sizeFormatted?: string;
  compileDate?: string;
  imageBase?: string;
  entryPoint?: string;
  totalFunctionsDiscovered?: number;
  totalDllsImported?: number;
  entropy?: number;
  isPacked?: boolean;
  packingExplanation?: string;
  securityFeatures?: string[];
  sections: string[];
  sectionDetails?: any[];
  exports?: any[];
  hashes: {
    sha256: string;
    md5: string;
  };
  capabilities?: any[];
  hexPreview?: string;
  summary: string;
}

export interface InstructionItem {
  address: string;
  bytes: string;
  mnemonic: string;
  operands: string;
  comment?: string;
  flowTarget?: string | null;
  flowType?: string | null;
}

export interface FunctionItem {
  address: string;
  rva?: number;
  name: string;
  size: number;
  calls: number;
  category?: string;
  signature: string;
  plainTitle?: string;
  plainExplanation?: string;
  disassembly?: InstructionItem[];
  decompiled?: string;
}

export interface StringItem {
  offset: string;
  section: string;
  value: string;
  type: string;
  plain?: string;
}

export interface ImportItem {
  dll: string;
  function: string;
  address: string;
  category?: string;
  plain?: string;
  signature?: string;
}

export interface AnalysisResult {
  success: boolean;
  target?: TargetAnalysis;
  functions?: FunctionItem[];
  strings?: StringItem[];
  imports?: ImportItem[];
  error?: string;
}

declare global {
  interface Window {
    aegis?: {
      openFile: () => Promise<{ path: string; name: string; size: number; modified: number } | null>;
      analyzeTarget: (filePath: string) => Promise<AnalysisResult>;
      disassembleAt?: (
        filePath: string,
        address: string,
        size?: number
      ) => Promise<{ success: boolean; function?: FunctionItem; error?: string }>;
      getGhidraStatus?: () => Promise<{ installed: boolean; path: string | null; headlessBat: string | null }>;
      getTheme?: () => Promise<'dark' | 'light'>;
      setTheme?: (theme: 'dark' | 'light') => Promise<{ success: boolean; theme: 'dark' | 'light' }>;
      getVersion?: () => Promise<string>;
      checkForUpdates?: (token?: string) => Promise<{ success: boolean; updateInfo?: any; error?: string }>;
      hasConfiguredToken?: () => Promise<boolean>;
      downloadUpdate?: () => Promise<{ success: boolean; error?: string }>;
      installUpdate?: () => void;
      onUpdaterStatus?: (callback: (payload: { status: string; data: any }) => void) => () => void;
      platform: string;
    };
  }
}
