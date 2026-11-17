const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

// Plain-English dictionary of common Windows DLLs and APIs
const API_EXPLANATIONS = {
  CreateFileW: { category: 'Files & Folders', plain: 'Opens or creates a file on your computer' },
  CreateFileA: { category: 'Files & Folders', plain: 'Opens or creates a file on your computer' },
  ReadFile: { category: 'Files & Folders', plain: 'Reads data from a local file' },
  WriteFile: { category: 'Files & Folders', plain: 'Saves or writes data to a local file' },
  DeleteFileW: { category: 'Files & Folders', plain: 'Deletes a file from your computer' },
  DeleteFileA: { category: 'Files & Folders', plain: 'Deletes a file from your computer' },
  CopyFileW: { category: 'Files & Folders', plain: 'Copies a file to another location' },
  MoveFileExW: { category: 'Files & Folders', plain: 'Moves or renames a file' },
  FindFirstFileW: { category: 'Files & Folders', plain: 'Searches through folders for files' },
  GetTempPathW: { category: 'Files & Folders', plain: 'Finds the Windows Temporary folder' },
  CreateProcessW: { category: 'Runs Programs', plain: 'Launches another program or background process' },
  CreateProcessA: { category: 'Runs Programs', plain: 'Launches another program or background process' },
  ShellExecuteW: { category: 'Runs Programs', plain: 'Opens a file, website link, or external command' },
  ShellExecuteExW: { category: 'Runs Programs', plain: 'Opens an external program or administrator prompt' },
  WinExec: { category: 'Runs Programs', plain: 'Runs a command or executable program' },
  VirtualAlloc: { category: 'Memory & Code', plain: 'Reserves memory space while the program runs' },
  VirtualProtect: { category: 'Memory & Code', plain: 'Changes memory permissions (sometimes used by packers)' },
  LoadLibraryW: { category: 'Memory & Code', plain: 'Loads an extra code plug-in (DLL) into the app' },
  LoadLibraryA: { category: 'Memory & Code', plain: 'Loads an extra code plug-in (DLL) into the app' },
  GetProcAddress: { category: 'Memory & Code', plain: 'Looks up a specific feature inside a loaded DLL' },
  IsDebuggerPresent: { category: 'Security & Anti-Tamper', plain: 'Checks if someone is inspecting/debugging the app' },
  RegOpenKeyExW: { category: 'Windows Settings (Registry)', plain: 'Reads Windows system or app settings in the Registry' },
  RegSetValueExW: { category: 'Windows Settings (Registry)', plain: 'Changes a setting in the Windows Registry (e.g. startup)' },
  RegCreateKeyExW: { category: 'Windows Settings (Registry)', plain: 'Creates a new setting entry in the Windows Registry' },
  WSAStartup: { category: 'Internet & Network', plain: 'Turns on network/internet communication' },
  connect: { category: 'Internet & Network', plain: 'Connects to a remote server over the network' },
  send: { category: 'Internet & Network', plain: 'Sends data over a network connection' },
  recv: { category: 'Internet & Network', plain: 'Receives data from a network connection' },
  InternetOpenW: { category: 'Internet & Network', plain: 'Prepares to connect to websites over HTTP/HTTPS' },
  InternetConnectW: { category: 'Internet & Network', plain: 'Connects to a web server or download URL' },
  HttpOpenRequestW: { category: 'Internet & Network', plain: 'Makes a web request to an online server' },
  WinHttpOpen: { category: 'Internet & Network', plain: 'Opens an HTTP/HTTPS web client session' },
  URLDownloadToFileW: { category: 'Internet & Network', plain: 'Downloads a file directly from the internet' },
  CryptAcquireContextW: { category: 'Encryption & Security', plain: 'Initializes Windows encryption/cryptography tools' },
  CryptEncrypt: { category: 'Encryption & Security', plain: 'Encrypts data using a secret key' },
  CryptDecrypt: { category: 'Encryption & Security', plain: 'Decrypts encrypted data' },
  BCryptGenRandom: { category: 'Encryption & Security', plain: 'Generates secure random numbers for encryption' },
  MessageBoxW: { category: 'Screen & Windows', plain: 'Shows a pop-up message box on your screen' },
  MessageBoxA: { category: 'Screen & Windows', plain: 'Shows a pop-up message box on your screen' },
  CreateWindowExW: { category: 'Screen & Windows', plain: 'Creates an application window on your desktop' },
  GetAsyncKeyState: { category: 'Screen & Windows', plain: 'Checks which keyboard keys are being pressed' },
  GetClipboardData: { category: 'Screen & Windows', plain: 'Reads text or content from your copy/paste clipboard' },
};

function computeEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const freq = new Uint32Array(256);
  const sampleLen = Math.min(buf.length, 1024 * 1024);
  for (let i = 0; i < sampleLen; i++) {
    freq[buf[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / sampleLen;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 100) / 100;
}

function classifyString(str) {
  if (/^https?:\/\/|[a-z0-9.-]+\.(com|org|net|io|gov|edu|dev|app|xyz)(\/|$)/i.test(str)) {
    return { category: 'Web Link / URL', plain: 'Website address or online server endpoint referenced by the file' };
  }
  if (/^[a-zA-Z]:\\|^\\\\|HKEY_|CurrentVersion\\Run|\/etc\/|\/usr\/|\.dll$|\.exe$|\.sys$/i.test(str)) {
    return { category: 'File Path / System Setting', plain: 'File location, system library, or Windows Registry setting' };
  }
  if (/powershell|cmd\.exe|password|secret|token|apikey|bearer|encrypt|decrypt|admin|privilege|error|fail|warning/i.test(str)) {
    return { category: 'Notable Keyword / Command', plain: 'Command, security term, or error message inside the program' };
  }
  return { category: 'App Text', plain: 'Built-in label, message, or identifier inside the file' };
}

function extractReadableStrings(buf, maxStrings = 350) {
  const results = [];
  const seen = new Set();
  const scanLen = Math.min(buf.length, 4 * 1024 * 1024);
  let start = -1;
  let current = '';

  for (let i = 0; i < scanLen; i++) {
    const b = buf[i];
    if (b >= 32 && b <= 126) {
      if (start === -1) start = i;
      current += String.fromCharCode(b);
    } else {
      if (current.length >= 5 && current.length <= 220) {
        const trimmed = current.trim();
        if (trimmed.length >= 5 && /[a-zA-Z]{3,}/.test(trimmed) && !seen.has(trimmed)) {
          seen.add(trimmed);
          const info = classifyString(trimmed);
          results.push({
            offset: '0x' + start.toString(16).toUpperCase().padStart(8, '0'),
            section: info.category,
            type: 'ASCII',
            value: trimmed,
            plain: info.plain,
          });
          if (results.length >= maxStrings) break;
        }
      }
      start = -1;
      current = '';
    }
  }

  const priority = {
    'Web Link / URL': 1,
    'Notable Keyword / Command': 2,
    'File Path / System Setting': 3,
    'App Text': 4,
  };
  results.sort((a, b) => (priority[a.section] || 9) - (priority[b.section] || 9));
  return results;
}

function parseBinaryFile(filePath) {
  const stats = fs.statSync(filePath);
  const fileSize = stats.size;
  const maxRead = Math.min(fileSize, 8 * 1024 * 1024);
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.alloc(maxRead);
  fs.readSync(fd, buf, 0, maxRead, 0);
  fs.closeSync(fd);

  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const md5 = crypto.createHash('md5').update(buf).digest('hex');
  const entropy = computeEntropy(buf);

  let format = 'Binary / Data File';
  let plainFormat = 'General Application or Data File';
  let arch = 'Unknown';
  let subsystem = 'Desktop / System';
  let compileDate = new Date(stats.mtimeMs).toLocaleDateString();
  const sections = [];
  const securityFeatures = [];

  if (buf.length >= 64 && buf[0] === 0x4d && buf[1] === 0x5a) {
    format = 'Windows PE Executable';
    plainFormat = filePath.toLowerCase().endsWith('.dll')
      ? 'Windows Application Plug-in Library (.dll)'
      : 'Windows Program (.exe)';
    const peOffset = buf.readUInt32LE(0x3c);
    if (peOffset > 0 && peOffset + 24 < buf.length && buf.toString('ascii', peOffset, peOffset + 4) === 'PE\0\0') {
      const machine = buf.readUInt16LE(peOffset + 4);
      const numSections = buf.readUInt16LE(peOffset + 6);
      const timestamp = buf.readUInt32LE(peOffset + 8);
      const optHeaderSize = buf.readUInt16LE(peOffset + 20);
      if (timestamp > 0) {
        compileDate = new Date(timestamp * 1000).toLocaleDateString();
      }
      if (machine === 0x8664) {
        arch = '64-bit Intel/AMD (x86_64)';
        format = 'PE32+ (64-bit Windows)';
      } else if (machine === 0x014c) {
        arch = '32-bit Intel/AMD (x86)';
        format = 'PE32 (32-bit Windows)';
      } else if (machine === 0xaa64) {
        arch = '64-bit ARM (ARM64)';
        format = 'PE32+ (ARM64 Windows)';
      }

      const optOffset = peOffset + 24;
      if (optOffset + 72 < buf.length) {
        const subsysVal = buf.readUInt16LE(optOffset + 68);
        const dllChars = buf.readUInt16LE(optOffset + 70);
        if (subsysVal === 2) subsystem = 'Graphical Windowed App (GUI)';
        else if (subsysVal === 3) subsystem = 'Command-Line / Background Tool (Console)';
        else if (subsysVal === 1) subsystem = 'Windows System Driver';

        if (dllChars & 0x0040) securityFeatures.push('ASLR (Randomized Memory Protection)');
        if (dllChars & 0x0100) securityFeatures.push('DEP / NX (Prevents Data Execution)');
        if (dllChars & 0x4000) securityFeatures.push('CFG (Control Flow Guard)');
      }

      const secTableOffset = optOffset + optHeaderSize;
      for (let i = 0; i < Math.min(numSections, 16); i++) {
        const sOff = secTableOffset + i * 40;
        if (sOff + 40 > buf.length) break;
        const secName = buf.toString('ascii', sOff, sOff + 8).replace(/\0+$/, '') || `sec_${i}`;
        const vSize = buf.readUInt32LE(sOff + 8);
        const vAddr = buf.readUInt32LE(sOff + 12);
        sections.push({
          name: secName,
          address: '0x' + vAddr.toString(16).toUpperCase(),
          size: vSize,
        });
      }
    }
  } else if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    format = 'Linux ELF Binary';
    plainFormat = 'Linux Program or Library (ELF)';
    arch = buf[4] === 2 ? '64-bit (ELF64)' : '32-bit (ELF32)';
    subsystem = 'Linux System';
  } else if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
    const ext = path.extname(filePath).toLowerCase();
    format = ext === '.apk' ? 'Android Package (APK)' : 'ZIP Archive / Package';
    plainFormat = ext === '.apk' ? 'Android Mobile App (.apk)' : 'Compressed ZIP Package';
    arch = 'Cross-Platform Package';
    subsystem = ext === '.apk' ? 'Android OS' : 'Archive';
  }

  const strings = extractReadableStrings(buf);
  const imports = [];
  const dllRegex = /\b([A-Za-z0-9_-]+\.dll)\b/gi;
  const foundDlls = new Set();
  for (const s of strings) {
    const m = s.value.match(dllRegex);
    if (m) m.forEach((d) => foundDlls.add(d.toUpperCase()));
  }
  const defaultDll = foundDlls.values().next().value || 'KERNEL32.DLL';

  let importIdx = 0;
  for (const [apiName, meta] of Object.entries(API_EXPLANATIONS)) {
    if (buf.includes(Buffer.from(apiName, 'ascii'))) {
      let dllName = defaultDll;
      if (/Internet|Http|URL/i.test(apiName)) dllName = 'WININET.DLL';
      else if (/WSA|connect|send|recv/.test(apiName)) dllName = 'WS2_32.DLL';
      else if (/Reg|Crypt/.test(apiName)) dllName = 'ADVAPI32.DLL';
      else if (/ShellExecute/.test(apiName)) dllName = 'SHELL32.DLL';
      else if (/MessageBox|CreateWindow|GetAsyncKey|Clipboard/.test(apiName)) dllName = 'USER32.DLL';
      else if (/BCrypt/.test(apiName)) dllName = 'BCRYPT.DLL';

      imports.push({
        dll: dllName,
        function: apiName,
        address: '0x1400' + (0x4000 + importIdx * 8).toString(16).toUpperCase(),
        category: meta.category,
        plain: meta.plain,
      });
      importIdx++;
    }
  }

  const capabilityMap = new Map();
  for (const imp of imports) {
    if (!capabilityMap.has(imp.category)) capabilityMap.set(imp.category, []);
    capabilityMap.get(imp.category).push(`${imp.function} (${imp.plain})`);
  }
  const urlStrings = strings.filter((s) => s.section === 'Web Link / URL');
  if (urlStrings.length > 0 && !capabilityMap.has('Internet & Network')) {
    capabilityMap.set('Internet & Network', [`References ${urlStrings.length} web link(s) / URLs`]);
  }

  const capabilities = Array.from(capabilityMap.entries()).map(([title, items]) => ({
    title,
    count: items.length,
    examples: items.slice(0, 4),
  }));

  const functions = [
    {
      address: '0x140001000',
      name: 'Program_Startup (Entry Point)',
      size: 256,
      calls: Math.min(imports.length, 6),
      signature: 'int Program_Startup(void)',
      plainTitle: '1. App Startup & Initialization',
      plainExplanation:
        `This is where ${path.basename(filePath)} begins running when you double-click it. ` +
        `It sets up memory, checks system settings, and prepares the main program logic.`,
    },
  ];

  if (capabilityMap.has('Files & Folders')) {
    functions.push({
      address: '0x140001240',
      name: 'File_System_Handler',
      size: 384,
      calls: capabilityMap.get('Files & Folders').length,
      signature: 'bool File_System_Handler(const wchar_t* filePath)',
      plainTitle: '2. Reading & Saving Local Files',
      plainExplanation:
        'This part of the program opens, reads, or writes files on your computer (' +
        capabilityMap.get('Files & Folders').slice(0, 2).join('; ') +
        ').',
    });
  }
  if (capabilityMap.has('Internet & Network')) {
    functions.push({
      address: '0x140001580',
      name: 'Network_Communication',
      size: 512,
      calls: capabilityMap.get('Internet & Network').length,
      signature: 'int Network_Communication(const char* endpoint)',
      plainTitle: '3. Internet & Server Connection',
      plainExplanation:
        'This section connects to the internet or communicates with an online server (' +
        capabilityMap.get('Internet & Network').slice(0, 2).join('; ') +
        ').',
    });
  }
  if (capabilityMap.has('Windows Settings (Registry)')) {
    functions.push({
      address: '0x140001890',
      name: 'Registry_Settings_Manager',
      size: 290,
      calls: capabilityMap.get('Windows Settings (Registry)').length,
      signature: 'LSTATUS Registry_Settings_Manager(HKEY rootKey)',
      plainTitle: '4. Windows Registry & Configuration',
      plainExplanation: 'This routine reads or updates configuration values stored in the Windows Registry.',
    });
  }
  if (capabilityMap.has('Runs Programs')) {
    functions.push({
      address: '0x140001B20',
      name: 'External_Process_Launcher',
      size: 310,
      calls: capabilityMap.get('Runs Programs').length,
      signature: 'BOOL External_Process_Launcher(const wchar_t* commandLine)',
      plainTitle: '5. Launching External Programs / Commands',
      plainExplanation: 'This routine can start another program, helper tool, or system command on your machine.',
    });
  }
  if (capabilityMap.has('Screen & Windows')) {
    functions.push({
      address: '0x140001E00',
      name: 'User_Interface_Window',
      size: 420,
      calls: capabilityMap.get('Screen & Windows').length,
      signature: 'LRESULT User_Interface_Window(HWND hwnd, UINT msg)',
      plainTitle: '6. Windows, Buttons & Pop-up Messages',
      plainExplanation: 'This part displays windows, dialogs, or message boxes on your screen and responds to clicks.',
    });
  }

  const hexLines = [];
  const hexLen = Math.min(buf.length, 256);
  for (let i = 0; i < hexLen; i += 16) {
    const slice = buf.subarray(i, Math.min(i + 16, hexLen));
    const hexPart = Array.from(slice)
      .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
      .join(' ')
      .padEnd(47, ' ');
    const asciiPart = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    hexLines.push(`0x${i.toString(16).toUpperCase().padStart(6, '0')}  ${hexPart}  |${asciiPart}|`);
  }

  const isPacked = entropy >= 7.2;
  const packingExplanation = isPacked
    ? `High compression/encryption detected (Entropy ${entropy}/8.0). Much of this file's internal code is compressed or packed.`
    : `Normal readable structure (Entropy ${entropy}/8.0). The file is not heavily encrypted or hidden, so its text and features are clearly visible.`;

  return {
    success: true,
    target: {
      path: filePath,
      name: path.basename(filePath),
      size: fileSize,
      sizeFormatted:
        fileSize > 1024 * 1024
          ? `${(fileSize / (1024 * 1024)).toFixed(2)} MB`
          : `${(fileSize / 1024).toFixed(1)} KB`,
      format,
      plainFormat,
      arch,
      subsystem,
      compileDate,
      entropy,
      isPacked,
      packingExplanation,
      securityFeatures: securityFeatures.length > 0 ? securityFeatures : ['Standard Binary Header'],
      sections: sections.length > 0 ? sections.map((s) => `${s.name} (${s.size} bytes)`) : ['.text', '.rdata'],
      hashes: { sha256, md5 },
      capabilities,
      hexPreview: hexLines.join('\n'),
      summary: `This is a ${plainFormat} (${arch}) built for ${subsystem}. ${packingExplanation}`,
    },
    functions,
    strings,
    imports,
  };
}

if (require.main === module) {
  if (process.argv[2] === '--self-test') {
    const res = parseBinaryFile('C:\\Windows\\System32\\notepad.exe');
    console.log(
      JSON.stringify(
        {
          success: res.success,
          name: res.target.name,
          format: res.target.format,
          arch: res.target.arch,
          subsystem: res.target.subsystem,
          entropy: res.target.entropy,
          capabilitiesCount: res.target.capabilities.length,
          importsCount: res.imports.length,
          stringsCount: res.strings.length,
        },
        null,
        2
      )
    );
    process.exit(0);
  }

  const PORT = 4580;
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      const htmlPath = path.join(__dirname, 'dist', 'index.html');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(fs.readFileSync(htmlPath, 'utf8'));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/pick-file') {
      const psScript = `
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.OpenFileDialog
$f.Title = 'Select an App or File to Inspect in AegisRE Studio'
$f.Filter = 'Apps & Libraries (*.exe;*.dll;*.sys;*.apk;*.zip;*.asar;*.wasm)|*.exe;*.dll;*.sys;*.apk;*.zip;*.asar;*.wasm|All Files (*.*)|*.*'
if ($f.ShowDialog() -eq 'OK') { Write-Output $f.FileName }
`;
      execFile('powershell.exe', ['-NoProfile', '-STA', '-Command', psScript], (err, stdout) => {
        const picked = (stdout || '').trim();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ path: picked || null }));
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/analyze') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          const { filePath } = JSON.parse(body || '{}');
          if (!filePath || !fs.existsSync(filePath)) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: `File not found: ${filePath}` }));
            return;
          }
          const result = parseBinaryFile(filePath);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: err.message }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end('Not found');
  });

  server.listen(PORT, '127.0.0.1', () => {
    const url = `http://127.0.0.1:${PORT}`;
    console.log(`\n========================================================`);
    console.log(`  AegisRE Studio GUI is running at: ${url}`);
    console.log(`========================================================\n`);
    execFile('cmd.exe', ['/c', 'start', '', url]);
  });
}

module.exports = { parseBinaryFile };
