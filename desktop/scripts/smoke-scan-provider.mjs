import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

export const SMOKE_MODEL = "hermsec-desktop-smoke-model";
export const SMOKE_API_KEY_ENV = "HERMSEC_DESKTOP_SMOKE_API_KEY";
export const SMOKE_API_KEY = "local-loopback-smoke";
export const SMOKE_MAX_REQUEST_BYTES = 2_000_000;

export const SEVEN_CANONICAL_MODES = Object.freeze([
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
]);

export const EXPECTED_SMOKE_ROLE_COVERAGE = Object.freeze({
  "Dependencies and supply-chain specialist": {
    toolResponses: 4,
    finalResponses: 4,
  },
  "Identity and request security specialist": {
    toolResponses: 4,
    finalResponses: 4,
  },
  "Injection and execution specialist": {
    toolResponses: 4,
    finalResponses: 4,
  },
  "Platform, storage, and deployment specialist": {
    toolResponses: 2,
    finalResponses: 2,
  },
  "Sensitive data and cryptography specialist": {
    toolResponses: 2,
    finalResponses: 2,
  },
  "single bounded investigator": {
    toolResponses: 2,
    finalResponses: 2,
  },
});

const CHAT_PATH = "/v1/chat/completions";
const SEARCH_QUERY = "exec(";
const EXPECTED_REQUEST_COUNT = 44;
const EXPECTED_INSPECTION_ROUNDS = 18;
const EXPECTED_MOA_INSPECTION_ROUNDS = 16;
const EXPECTED_TOOL_CALLS = EXPECTED_INSPECTION_ROUNDS * 2;
const EXPECTED_JUDGE_RESPONSES = 4;
const EXPECTED_AGGREGATOR_RESPONSES = 4;
const EXPECTED_GROUNDED_EMISSIONS = EXPECTED_INSPECTION_ROUNDS;
const QUIESCENCE_TIMEOUT_MS = 5_000;
const PROCESS_QUERY_TIMEOUT_MS = 10_000;
const WINDOWS_JOB_READY_TIMEOUT_MS = 30_000;
const WINDOWS_JOB_CLEANUP_TIMEOUT_MS = 20_000;
const MOA_ROLE_IDS_BY_LABEL = new Map([
  ["Injection and execution specialist", "injection-and-execution"],
  ["Identity and request security specialist", "identity-and-request-security"],
  ["Sensitive data and cryptography specialist", "sensitive-data-and-cryptography"],
  ["Dependencies and supply-chain specialist", "dependencies-and-supply-chain"],
  ["Platform, storage, and deployment specialist", "platform-storage-and-deployment"],
]);
const EXPECTED_MOA_BATCH_ROLE_IDS = Object.freeze([
  Object.freeze([
    "dependencies-and-supply-chain",
    "identity-and-request-security",
    "injection-and-execution",
  ]),
  Object.freeze([
    "dependencies-and-supply-chain",
    "identity-and-request-security",
    "injection-and-execution",
    "platform-storage-and-deployment",
    "sensitive-data-and-cryptography",
  ]),
  Object.freeze([
    "dependencies-and-supply-chain",
    "identity-and-request-security",
    "injection-and-execution",
  ]),
  Object.freeze([
    "dependencies-and-supply-chain",
    "identity-and-request-security",
    "injection-and-execution",
    "platform-storage-and-deployment",
    "sensitive-data-and-cryptography",
  ]),
]);
const INSPECTION_TOOL_NAMES = new Set([
  "inspect_project",
  "list_files",
  "search_code",
  "read_file_snippet",
  "read_manifest",
  "read_dependency_inventory",
]);
const REQUEST_KEYS = new Set([
  "model",
  "messages",
  "temperature",
  "max_tokens",
  "response_format",
  "tools",
  "tool_choice",
  "parallel_tool_calls",
]);
const MODEL_ENVIRONMENT_NAMES = [
  "HERMSEC_MODEL_PROVIDER",
  "HERMSEC_MODEL",
  "HERMSEC_MODEL_BASE_URL",
  "HERMSEC_MODEL_API_KEY_ENV",
  "HERMSEC_ALLOW_REMOTE_PROVIDERS",
  "HERMSEC_AGENT_MODEL_CONFIG",
  "HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT",
  "HERMSEC_PRODUCT_AGENT_PANEL",
  "HERMSEC_CLI_ROOT",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "OPENROUTER_API_KEY",
  "OPENROUTER_BASE_URL",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_BASE_URL",
  "GEMINI_API_KEY",
  "GEMINI_BASE_URL",
  "OPENCODE_GO_API_KEY",
  "OLLAMA_API_KEY",
  "OLLAMA_HOST",
  SMOKE_API_KEY_ENV,
];
const SCANNER_IDS = [
  "hermsec-heuristics",
  "semgrep",
  "gitleaks",
  "trufflehog",
  "osv-scanner",
  "trivy",
  "checkov",
  "bandit",
  "pip-audit",
  "pmg",
  "retire",
  "findsecbugs",
  "dependency-check",
  "psalm",
  "composer-audit",
  "gosec",
  "govulncheck",
  "cargo-audit",
  "brakeman",
  "flawfinder",
  "cppcheck",
  "dotnet-vulnerable",
];

export function createSmokeDesktopSettings({ baseUrl, reportDir }) {
  return {
    general: {
      language: "English",
      autoAcceptPermissions: false,
      terminalShell: "Auto (Default)",
      privacyMode: true,
      scanMode: "scanner-only",
      thinkingLevel: "balanced",
      contextWindow: "standard",
    },
    defaultProjectDir: "",
    defaultReportDir: reportDir,
    activeModelId: SMOKE_MODEL,
    activeProviderId: "desktop-smoke-provider",
    automation: {
      enabled: false,
      frequency: "custom-days",
      intervalDays: 1,
      time: "09:00",
      scanMode: "scanner-only",
    },
    providers: [
      {
        id: "desktop-smoke-provider",
        displayName: "Hermsec desktop smoke provider",
        baseUrl,
        apiFormat: "openai-compatible",
        authKind: "environment",
        apiKeyEnvVar: SMOKE_API_KEY_ENV,
        enabled: true,
        supportsModelDiscovery: false,
        models: [
          {
            id: SMOKE_MODEL,
            label: "Hermsec desktop smoke model",
            enabled: true,
          },
        ],
        modelDiscovery: { status: "idle" },
      },
    ],
    scanners: {
      autoInstallMissing: false,
      allowOnlineUpdates: false,
      labInstallAll: false,
      items: SCANNER_IDS.map((id) => ({
        id,
        enabled: id === "hermsec-heuristics",
        autoInstall: false,
      })),
    },
    agents: {
      singleAgent: {
        providerId: "desktop-smoke-provider",
        modelId: SMOKE_MODEL,
        reasoningDepth: "balanced",
        maxToolRounds: 4,
      },
      moa: {
        presetId: "low-panel",
        panelSize: 5,
        debateRounds: 1,
        consensusThreshold: "majority",
      },
    },
  };
}

export function createSmokeChildEnvironment(
  inheritedEnv,
  { baseUrl, homeDir, reportDir, projectPath, cliRoot },
) {
  const env = { ...inheritedEnv };
  for (const name of MODEL_ENVIRONMENT_NAMES) {
    deleteEnvironmentVariable(env, name);
  }

  Object.assign(env, {
    HERMSEC_HOME: homeDir,
    HERMSEC_SMOKE_SCAN_MODES_RUN: "true",
    HERMSEC_SMOKE_SCAN_MODES_OUT: reportDir,
    HERMSEC_MODEL_PROVIDER: "openai-compatible",
    HERMSEC_MODEL: SMOKE_MODEL,
    HERMSEC_MODEL_BASE_URL: baseUrl,
    HERMSEC_MODEL_API_KEY_ENV: SMOKE_API_KEY_ENV,
    HERMSEC_ALLOW_REMOTE_PROVIDERS: "false",
    HERMSEC_SCANNER_AUTO_INSTALL: "false",
    HERMSEC_SCANNER_ONLINE_UPDATES: "false",
    [SMOKE_API_KEY_ENV]: SMOKE_API_KEY,
    ...(projectPath ? { HERMSEC_SMOKE_PROJECT: projectPath } : {}),
    ...(cliRoot ? { HERMSEC_CLI_ROOT: cliRoot } : {}),
  });

  return env;
}

export function createUniqueSmokeReportRoot(baseParent) {
  const resolvedParent = resolve(baseParent);
  mkdirSync(resolvedParent, { recursive: true });
  return mkdtempSync(resolve(resolvedParent, "run-"));
}

export async function verifyCurrentCliBuild(repositoryRoot, options = {}) {
  const root = resolve(repositoryRoot);
  const sourceFingerprintBefore = cliSourceConfigFingerprint(root);
  const currentDist = resolve(root, "dist");
  let referenceDist = options.referenceDist
    ? resolve(options.referenceDist)
    : undefined;

  if (!referenceDist) {
    const tscPath = resolve(
      options.typescriptPath
        ?? resolve(root, "node_modules", "typescript", "bin", "tsc"),
    );
    if (!existsSync(tscPath)) {
      throw new Error(
        "Cannot prove the root Hermsec CLI build is current because the local TypeScript compiler is unavailable.",
      );
    }
    const referenceParent = resolve(options.referenceParent ?? root);
    mkdirSync(referenceParent, { recursive: true });
    referenceDist = mkdtempSync(resolve(referenceParent, "cli-currentness-"));
    const result = await runCommandCapture(
      process.execPath,
      [
        tscPath,
        "-p",
        resolve(root, "tsconfig.json"),
        "--outDir",
        referenceDist,
        "--pretty",
        "false",
      ],
      boundedPositiveInteger(options.timeoutMs, 180_000),
      root,
    );
    if (result.code !== 0) {
      throw new Error(
        `Cannot prove the root Hermsec CLI build is current because the isolated TypeScript build failed: ${result.stderr.trim() || result.stdout.trim() || `exit ${result.code ?? result.signal ?? "unknown"}`}`,
      );
    }
  }

  const sourceFingerprintAfter = cliSourceConfigFingerprint(root);
  if (sourceFingerprintAfter !== sourceFingerprintBefore) {
    throw new Error("Root Hermsec source/config inputs changed during CLI freshness verification.");
  }
  const currentBuildFingerprint = cliJavaScriptBuildFingerprint(currentDist);
  const referenceBuildFingerprint = cliJavaScriptBuildFingerprint(referenceDist);
  if (currentBuildFingerprint !== referenceBuildFingerprint) {
    throw new Error(
      "The root Hermsec CLI build is stale: dist JavaScript does not match an isolated build of current source/config inputs.",
    );
  }
  return {
    sourceConfigFingerprint: sourceFingerprintAfter,
    javascriptBuildFingerprint: currentBuildFingerprint,
    distFingerprint: contentTreeFingerprint(currentDist),
    referenceDist,
  };
}

export function cliSourceConfigFingerprint(repositoryRoot) {
  const root = resolve(repositoryRoot);
  const inputs = [
    ...walkFiles(resolve(root, "src")).filter((filePath) =>
      /\.(?:[cm]?ts|tsx|json)$/iu.test(filePath)
    ),
    resolve(root, "package.json"),
    resolve(root, "tsconfig.json"),
  ];
  return contentFilesFingerprint(root, inputs);
}

export function cliJavaScriptBuildFingerprint(distRoot) {
  const root = resolve(distRoot);
  const sourceRoot = resolve(root, "src");
  if (!existsSync(resolve(sourceRoot, "bin", "hermsec.js"))) {
    throw new Error(`The root Hermsec CLI build entry is missing from ${sourceRoot}.`);
  }
  return contentFilesFingerprint(
    sourceRoot,
    walkFiles(sourceRoot).filter((filePath) => /\.(?:c|m)?js$/iu.test(filePath)),
  );
}

export function assertFreshSevenModeSummary(summaryPath, startedAt) {
  if (!existsSync(summaryPath)) {
    throw new Error("Hermsec scan modes smoke test exited without writing smoke-summary.json.");
  }
  if (statSync(summaryPath).mtimeMs + 2_000 < startedAt) {
    throw new Error("Hermsec scan modes smoke test left only a stale smoke-summary.json.");
  }
  const summary = JSON.parse(readFileSync(summaryPath, "utf8"));
  const expectedReportDir = resolve(dirname(summaryPath));
  const actualModes = Array.isArray(summary.runs)
    ? summary.runs.map((run) => run?.assistMode)
    : [];
  if (
    summary.ok !== true
    || resolve(String(summary.reportDir ?? "")) !== expectedReportDir
    || actualModes.length !== SEVEN_CANONICAL_MODES.length
    || SEVEN_CANONICAL_MODES.some((mode, index) => actualModes[index] !== mode)
  ) {
    throw new Error(
      "Hermsec scan modes smoke summary did not belong to this run or contain the exact seven canonical modes.",
    );
  }
  for (const run of summary.runs) {
    const runReportDir = resolve(String(run?.reportDir ?? ""));
    if (
      runReportDir === expectedReportDir
      || !runReportDir.startsWith(`${expectedReportDir}\\`)
        && !runReportDir.startsWith(`${expectedReportDir}/`)
    ) {
      throw new Error("Hermsec scan modes smoke summary referenced an artifact outside this run.");
    }
  }
  return summary;
}

const WINDOWS_JOB_HELPER_SOURCE = String.raw`
param(
  [Parameter(Mandatory = $true)]
  [string]$SpecPath
)

$ErrorActionPreference = 'Stop'
$spec = Get-Content -LiteralPath $SpecPath -Raw | ConvertFrom-Json

function Write-AtomicJson {
  param([string]$Path, [object]$Value)
  $temporaryPath = $Path + '.tmp-' + [Guid]::NewGuid().ToString('N')
  $json = $Value | ConvertTo-Json -Compress -Depth 5
  [System.IO.File]::WriteAllText(
    $temporaryPath,
    $json,
    [System.Text.UTF8Encoding]::new($false)
  )
  [System.IO.File]::Move($temporaryPath, $Path)
}

try {
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public sealed class HermsecSmokeJobResult
{
    public int RootPid { get; set; }
    public int RootExitCode { get; set; }
    public string TerminationReason { get; set; }
    public uint ActiveProcessesAfterCleanup { get; set; }
    public bool CleanupVerified { get; set; }
}

public static class HermsecSmokeJob
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private const uint WAIT_FAILED = 0xFFFFFFFF;
    private const uint STILL_ACTIVE = 259;
    private const uint TERMINATE_EXIT_CODE = 0xE0000001;
    private const int JobObjectBasicAccountingInformation = 1;
    private const int JobObjectExtendedLimitInformation = 9;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint informationLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        IntPtr job,
        int informationClass,
        out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information,
        uint informationLength,
        IntPtr returnLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    public static HermsecSmokeJobResult Run(
        string applicationPath,
        string[] arguments,
        string workingDirectory,
        string readyPath
    )
    {
        IntPtr job = IntPtr.Zero;
        PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
        bool processCreated = false;
        bool assigned = false;
        int terminateRequested = 0;

        try
        {
            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                ThrowLastWin32("CreateJobObject");
            }

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ref limits,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))
            ))
            {
                ThrowLastWin32("SetInformationJobObject");
            }

            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            startupInfo.dwFlags = STARTF_USESTDHANDLES;
            startupInfo.hStdInput = InheritableStandardHandle(STD_INPUT_HANDLE);
            startupInfo.hStdOutput = InheritableStandardHandle(STD_OUTPUT_HANDLE);
            startupInfo.hStdError = InheritableStandardHandle(STD_ERROR_HANDLE);

            StringBuilder commandLine = new StringBuilder(
                BuildCommandLine(applicationPath, arguments)
            );
            if (!CreateProcess(
                applicationPath,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                CREATE_SUSPENDED,
                IntPtr.Zero,
                workingDirectory,
                ref startupInfo,
                out processInformation
            ))
            {
                ThrowLastWin32("CreateProcess");
            }
            processCreated = true;

            if (!AssignProcessToJobObject(job, processInformation.hProcess))
            {
                ThrowLastWin32("AssignProcessToJobObject");
            }
            assigned = true;

            Thread inputThread = new Thread(delegate()
            {
                try
                {
                    string line;
                    while ((line = Console.In.ReadLine()) != null)
                    {
                        if (String.Equals(line.Trim(), "terminate", StringComparison.Ordinal))
                        {
                            Interlocked.Exchange(ref terminateRequested, 1);
                            return;
                        }
                    }
                }
                catch
                {
                    // Losing the controller pipe is also a termination request.
                }
                Interlocked.Exchange(ref terminateRequested, 1);
            });
            inputThread.IsBackground = true;
            inputThread.Start();

            WriteReadyFile(readyPath, (int)processInformation.dwProcessId);
            if (ResumeThread(processInformation.hThread) == UInt32.MaxValue)
            {
                ThrowLastWin32("ResumeThread");
            }
            CloseHandle(processInformation.hThread);
            processInformation.hThread = IntPtr.Zero;

            bool terminationSent = false;
            string terminationReason = "root-exit";
            while (true)
            {
                if (Volatile.Read(ref terminateRequested) == 1 && !terminationSent)
                {
                    if (!TerminateJobObject(job, TERMINATE_EXIT_CODE))
                    {
                        ThrowLastWin32("TerminateJobObject");
                    }
                    terminationSent = true;
                    terminationReason = "controller-request";
                }

                uint waitResult = WaitForSingleObject(processInformation.hProcess, 25);
                if (waitResult == WAIT_OBJECT_0)
                {
                    break;
                }
                if (waitResult == WAIT_FAILED)
                {
                    ThrowLastWin32("WaitForSingleObject");
                }
                if (waitResult != WAIT_TIMEOUT)
                {
                    throw new InvalidOperationException(
                        "Unexpected process wait result: " + waitResult.ToString()
                    );
                }
            }

            uint unsignedExitCode;
            if (!GetExitCodeProcess(processInformation.hProcess, out unsignedExitCode))
            {
                ThrowLastWin32("GetExitCodeProcess");
            }
            if (unsignedExitCode == STILL_ACTIVE)
            {
                throw new InvalidOperationException(
                    "Root process remained active after its process handle was signaled."
                );
            }

            if (!terminationSent && !TerminateJobObject(job, TERMINATE_EXIT_CODE))
            {
                ThrowLastWin32("TerminateJobObject");
            }
            uint activeProcesses = WaitForJobEmpty(job, 15000);

            return new HermsecSmokeJobResult
            {
                RootPid = (int)processInformation.dwProcessId,
                RootExitCode = unchecked((int)unsignedExitCode),
                TerminationReason = terminationReason,
                ActiveProcessesAfterCleanup = activeProcesses,
                CleanupVerified = activeProcesses == 0
            };
        }
        finally
        {
            if (assigned && job != IntPtr.Zero)
            {
                TerminateJobObject(job, TERMINATE_EXIT_CODE);
            }
            else if (processCreated && processInformation.hProcess != IntPtr.Zero)
            {
                TerminateProcess(processInformation.hProcess, TERMINATE_EXIT_CODE);
            }
            if (processInformation.hThread != IntPtr.Zero)
            {
                CloseHandle(processInformation.hThread);
            }
            if (processInformation.hProcess != IntPtr.Zero)
            {
                CloseHandle(processInformation.hProcess);
            }
            if (job != IntPtr.Zero)
            {
                CloseHandle(job);
            }
        }
    }

    private static IntPtr InheritableStandardHandle(int identifier)
    {
        IntPtr handle = GetStdHandle(identifier);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            ThrowLastWin32("GetStdHandle");
        }
        if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
        {
            ThrowLastWin32("SetHandleInformation");
        }
        return handle;
    }

    private static uint WaitForJobEmpty(IntPtr job, int timeoutMilliseconds)
    {
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
        while (true)
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
            if (!QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                out accounting,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)),
                IntPtr.Zero
            ))
            {
                ThrowLastWin32("QueryInformationJobObject");
            }
            if (accounting.ActiveProcesses == 0)
            {
                return 0;
            }
            if (DateTime.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    "Windows Job Object still contains "
                    + accounting.ActiveProcesses.ToString()
                    + " active process(es)."
                );
            }
            Thread.Sleep(10);
        }
    }

    private static void WriteReadyFile(string path, int rootPid)
    {
        string json =
            "{\"schemaVersion\":\"1.0\",\"rootPid\":"
            + rootPid.ToString()
            + ",\"assignedBeforeResume\":true,\"killOnJobClose\":true,"
            + "\"breakawayAllowed\":false}";
        string temporaryPath = path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(temporaryPath, json, new UTF8Encoding(false));
        File.Move(temporaryPath, path);
    }

    private static string BuildCommandLine(string applicationPath, string[] arguments)
    {
        StringBuilder builder = new StringBuilder();
        builder.Append(QuoteArgument(applicationPath));
        if (arguments != null)
        {
            foreach (string argument in arguments)
            {
                builder.Append(' ');
                builder.Append(QuoteArgument(argument ?? String.Empty));
            }
        }
        return builder.ToString();
    }

    private static string QuoteArgument(string argument)
    {
        if (
            argument.Length > 0
            && argument.IndexOfAny(new char[] { ' ', '\t', '\r', '\n', '"' }) < 0
        )
        {
            return argument;
        }

        StringBuilder builder = new StringBuilder();
        builder.Append('"');
        int backslashes = 0;
        foreach (char character in argument)
        {
            if (character == '\\')
            {
                backslashes += 1;
                continue;
            }
            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }
            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }

    private static void ThrowLastWin32(string operation)
    {
        int error = Marshal.GetLastWin32Error();
        throw new Win32Exception(error, operation + " failed");
    }
}
'@

  $arguments = @($spec.arguments | ForEach-Object { [string]$_ })
  $result = [HermsecSmokeJob]::Run(
    [string]$spec.applicationPath,
    [string[]]$arguments,
    [string]$spec.workingDirectory,
    [string]$spec.readyPath
  )
  Write-AtomicJson -Path ([string]$spec.statusPath) -Value ([ordered]@{
    schemaVersion = '1.0'
    ok = $true
    rootPid = $result.RootPid
    rootExitCode = $result.RootExitCode
    terminationReason = $result.TerminationReason
    activeProcessesAfterCleanup = $result.ActiveProcessesAfterCleanup
    cleanupVerified = $result.CleanupVerified
    assignedBeforeResume = $true
    killOnJobClose = $true
    breakawayAllowed = $false
  })
  if (-not $result.CleanupVerified) {
    exit 1
  }
  if ($result.RootExitCode -lt 0 -or $result.RootExitCode -gt 255) {
    exit 1
  }
  exit $result.RootExitCode
}
catch {
  try {
    Write-AtomicJson -Path ([string]$spec.statusPath) -Value ([ordered]@{
      schemaVersion = '1.0'
      ok = $false
      error = $_.Exception.Message
      cleanupVerified = $false
      activeProcessesAfterCleanup = $null
      assignedBeforeResume = $false
      killOnJobClose = $true
      breakawayAllowed = $false
    })
  }
  catch {
    # The Node controller will fail closed if the status artifact is absent.
  }
  [Console]::Error.WriteLine($_.Exception.ToString())
  exit 1
}
`;

export function processTreeTerminationPlan(platform, pid) {
  if (!Number.isInteger(pid) || pid < 1) {
    throw new Error(`Invalid process ID for tree termination: ${String(pid)}.`);
  }
  if (platform === "win32") {
    return {
      kind: "windows-job-object",
      killOnJobClose: true,
      breakawayAllowed: false,
      pidTargeting: false,
    };
  }
  return {
    kind: "process-group",
    pid: -pid,
    firstSignal: "SIGTERM",
    finalSignal: "SIGKILL",
  };
}

export function spawnSmokeProcessInContainment(command, args, options = {}) {
  const platform = options.platform ?? process.platform;
  if (platform === "win32") {
    return spawnWindowsJobProcess(command, args, options);
  }
  const processHandle = spawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: options.stdio,
    shell: false,
    detached: true,
  });
  return {
    processHandle,
    tracker: noOpProcessTreeTracker(processHandle.pid),
  };
}

export function startProcessTreeTracker(processHandle, options = {}) {
  const pid = processHandle?.pid;
  if (!Number.isInteger(pid) || pid < 1) {
    throw new Error(`Invalid process ID for lineage tracking: ${String(pid)}.`);
  }
  const platform = options.platform ?? process.platform;
  if (platform === "win32") {
    throw new Error(
      "Windows smoke processes must be created inside a Job Object before they resume.",
    );
  }
  return noOpProcessTreeTracker(pid);
}

export async function terminateProcessTree(processHandle, options = {}) {
  const pid = processHandle?.pid;
  if (!Number.isInteger(pid) || pid < 1) {
    return;
  }
  const platform = options.platform ?? process.platform;
  const graceMs = boundedPositiveInteger(options.graceMs, 2_000);
  const plan = processTreeTerminationPlan(platform, pid);

  if (plan.kind === "windows-job-object") {
    const tracker = options.tracker;
    if (!tracker || tracker.kind !== "windows-job-object") {
      throw new Error(
        "Refusing PID-based Windows cleanup: an assigned Job Object controller is required.",
      );
    }
    const cleanup = await tracker.stop();
    assertWindowsJobCleanup(cleanup);
    if (isProcessRunning(processHandle)) {
      throw new Error("Windows Job Object owner remained active after cleanup.");
    }
    return;
  }

  await options.tracker?.stop();
  signalProcessGroup(plan.pid, plan.firstSignal);
  await waitForProcessExit(processHandle, graceMs);
  signalProcessGroup(plan.pid, plan.finalSignal);
  await waitForProcessExit(processHandle, graceMs);
  await waitForProcessGroupExit(plan.pid, graceMs);
  if (isProcessRunning(processHandle) || isProcessGroupRunning(plan.pid)) {
    throw new Error(`Failed to terminate process group rooted at PID ${pid}.`);
  }
}

function spawnWindowsJobProcess(command, args, options) {
  if (!isAbsolute(command) || !existsSync(command)) {
    throw new Error(`Windows Job Object target must be an existing absolute path: ${command}`);
  }
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== "string")) {
    throw new Error("Windows Job Object target arguments must be an array of strings.");
  }
  const workingDirectory = resolve(options.cwd ?? process.cwd());
  if (!existsSync(workingDirectory)) {
    throw new Error(`Windows Job Object working directory does not exist: ${workingDirectory}`);
  }
  const containmentRoot = resolve(String(options.containmentRoot ?? ""));
  if (!options.containmentRoot || !isAbsolute(containmentRoot)) {
    throw new Error("Windows Job Object containmentRoot must be an absolute path.");
  }
  mkdirSync(containmentRoot, { recursive: true });
  const helperDirectory = mkdtempSync(join(containmentRoot, "windows-job-"));
  const helperPath = resolve(helperDirectory, "job-owner.ps1");
  const specPath = resolve(helperDirectory, "job-spec.json");
  const readyPath = resolve(helperDirectory, "job-ready.json");
  const statusPath = resolve(helperDirectory, "job-status.json");
  writeFileSync(helperPath, WINDOWS_JOB_HELPER_SOURCE, "utf8");
  writeFileSync(
    specPath,
    JSON.stringify(
      {
        schemaVersion: "1.0",
        applicationPath: command,
        arguments: args,
        workingDirectory,
        readyPath,
        statusPath,
      },
      null,
      2,
    ),
    "utf8",
  );

  const processHandle = spawn(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      helperPath,
      "-SpecPath",
      specPath,
    ],
    {
      cwd: workingDirectory,
      env: options.env,
      stdio: windowsJobOwnerStdio(options.stdio),
      shell: false,
      windowsHide: true,
    },
  );
  processHandle.stdin?.on("error", () => {
    // A normal root exit can close the controller pipe before finalization writes to it.
  });
  const tracker = windowsJobController(processHandle, {
    readyPath,
    statusPath,
    helperDirectory,
    onError: options.onError,
  });
  return { processHandle, tracker };
}

function windowsJobController(processHandle, options) {
  const state = {
    ownerPid: processHandle.pid,
    rootPid: undefined,
    ready: undefined,
    status: undefined,
    stopping: false,
    stopped: false,
    error: undefined,
    errorReported: false,
    stopPromise: undefined,
  };
  const ownerOutcome = childProcessOutcome(processHandle);
  const recordError = (error) => {
    state.error ??= error instanceof Error ? error : new Error(String(error));
    if (!state.errorReported) {
      state.errorReported = true;
      options.onError?.(state.error.message);
    }
  };
  const readyPromise = waitForJsonArtifact(
    options.readyPath,
    processHandle,
    WINDOWS_JOB_READY_TIMEOUT_MS,
    "Windows Job Object readiness",
  ).then((ready) => {
    assertWindowsJobReady(ready);
    state.ready = ready;
    state.rootPid = ready.rootPid;
    return ready;
  }).catch((error) => {
    recordError(error);
    throw error;
  });

  return {
    kind: "windows-job-object",
    ready() {
      return readyPromise;
    },
    stop() {
      if (!state.stopPromise) {
        state.stopPromise = (async () => {
          state.stopping = true;
          const cleanupErrors = [];
          try {
            if (isProcessRunning(processHandle)) {
              try {
                processHandle.stdin?.write("terminate\n");
                processHandle.stdin?.end();
              } catch (error) {
                cleanupErrors.push(error);
              }
            }

            let outcome;
            try {
              outcome = await withTimeout(
                ownerOutcome,
                WINDOWS_JOB_CLEANUP_TIMEOUT_MS,
                "Windows Job Object owner did not exit after termination.",
              );
            } catch (error) {
              cleanupErrors.push(error);
            }
            if (outcome?.error) {
              cleanupErrors.push(outcome.error);
            }

            try {
              const status = await waitForJsonArtifact(
                options.statusPath,
                processHandle,
                1_000,
                "Windows Job Object cleanup status",
                true,
              );
              assertWindowsJobCleanup(status);
              if (state.ready && status.rootPid !== state.ready.rootPid) {
                throw new Error("Windows Job Object status did not match its pre-resume root.");
              }
              state.status = status;
              state.rootPid = status.rootPid;
            } catch (error) {
              cleanupErrors.push(error);
            }
          } finally {
            state.stopped = true;
          }

          if (cleanupErrors.length > 0) {
            const error = cleanupErrors.length === 1
              ? cleanupErrors[0]
              : new AggregateError(cleanupErrors, "Windows Job Object cleanup failed.");
            recordError(error);
            throw error;
          }
          return {
            containment: "windows-job-object",
            rootPid: state.status.rootPid,
            rootExitCode: state.status.rootExitCode,
            terminationReason: state.status.terminationReason,
            activeProcessesAfterCleanup: state.status.activeProcessesAfterCleanup,
            cleanupVerified: state.status.cleanupVerified,
            assignedBeforeResume: state.status.assignedBeforeResume,
            killOnJobClose: state.status.killOnJobClose,
            breakawayAllowed: state.status.breakawayAllowed,
          };
        })();
      }
      return state.stopPromise;
    },
    snapshot() {
      return {
        containment: "windows-job-object",
        ownerPid: state.ownerPid,
        rootPid: state.rootPid,
        running: !state.stopping && !state.stopped,
        stopped: state.stopped,
        assignedBeforeResume: state.ready?.assignedBeforeResume,
        killOnJobClose: state.ready?.killOnJobClose ?? true,
        breakawayAllowed: state.ready?.breakawayAllowed ?? false,
        activeProcessesAfterCleanup: state.status?.activeProcessesAfterCleanup,
        cleanupVerified: state.status?.cleanupVerified,
        helperDirectory: options.helperDirectory,
        error: state.error?.message,
      };
    },
  };
}

function noOpProcessTreeTracker(rootPid) {
  let stopped = false;
  return {
    kind: "process-group",
    ready() {
      return Promise.resolve();
    },
    stop() {
      stopped = true;
      return Promise.resolve({ error: undefined });
    },
    snapshot() {
      return {
        containment: "process-group",
        rootPid,
        running: !stopped,
        stopped,
        error: undefined,
      };
    },
  };
}

function windowsJobOwnerStdio(stdio) {
  if (stdio === "inherit") {
    return ["pipe", "inherit", "inherit"];
  }
  if (stdio === "ignore") {
    return ["pipe", "ignore", "ignore"];
  }
  if (Array.isArray(stdio)) {
    return ["pipe", stdio[1] ?? "pipe", stdio[2] ?? "pipe"];
  }
  return ["pipe", "pipe", "pipe"];
}

function childProcessOutcome(processHandle) {
  if (processHandle.exitCode !== null || processHandle.signalCode !== null) {
    return Promise.resolve({
      code: processHandle.exitCode,
      signal: processHandle.signalCode,
    });
  }
  return new Promise((resolvePromise) => {
    let settled = false;
    const settle = (outcome) => {
      if (settled) {
        return;
      }
      settled = true;
      resolvePromise(outcome);
    };
    processHandle.once("error", (error) => {
      settle({ code: null, signal: null, error });
    });
    processHandle.once("exit", (code, signal) => {
      settle({ code, signal });
    });
  });
}

async function waitForJsonArtifact(
  artifactPath,
  processHandle,
  timeoutMs,
  label,
  allowExited = false,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(artifactPath)) {
      return readJsonArtifact(artifactPath, label);
    }
    if (!allowExited && !isProcessRunning(processHandle)) {
      break;
    }
    await sleep(20);
  }
  throw new Error(`${label} artifact was not produced: ${artifactPath}`);
}

function readJsonArtifact(artifactPath, label) {
  let parsed;
  try {
    const source = readFileSync(artifactPath, "utf8").replace(/^\uFEFF/u, "");
    parsed = JSON.parse(source);
  } catch (error) {
    throw new Error(
      `${label} artifact was invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!isRecord(parsed)) {
    throw new Error(`${label} artifact must be a JSON object.`);
  }
  return parsed;
}

function assertWindowsJobReady(ready) {
  if (
    ready.schemaVersion !== "1.0"
    || !Number.isInteger(ready.rootPid)
    || ready.rootPid < 1
    || ready.assignedBeforeResume !== true
    || ready.killOnJobClose !== true
    || ready.breakawayAllowed !== false
  ) {
    throw new Error("Windows Job Object readiness proof was incomplete or unsafe.");
  }
}

function assertWindowsJobCleanup(cleanup) {
  if (
    !isRecord(cleanup)
    || cleanup.ok === false
    || cleanup.cleanupVerified !== true
    || cleanup.activeProcessesAfterCleanup !== 0
    || cleanup.assignedBeforeResume !== true
    || cleanup.killOnJobClose !== true
    || cleanup.breakawayAllowed !== false
  ) {
    const detail = isRecord(cleanup) && typeof cleanup.error === "string"
      ? `: ${cleanup.error}`
      : "";
    throw new Error(`Windows Job Object cleanup proof was incomplete or unsafe${detail}`);
  }
}

function withTimeout(promise, timeoutMs, message) {
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(message));
    }, timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolvePromise(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function sleep(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}

export async function startSmokeScanProvider(options = {}) {
  const state = {
    accepting: true,
    closed: false,
    requests: 0,
    activeRequests: 0,
    maxActiveRequests: 0,
    inspectionToolResponses: 0,
    inspectionFinalResponses: 0,
    singleToolResponses: 0,
    singleFinalResponses: 0,
    moaToolResponses: 0,
    moaFinalResponses: 0,
    issuedToolCalls: 0,
    validatedToolResults: 0,
    judgeResponses: 0,
    aggregatorResponses: 0,
    groundedEmissions: 0,
    groundedMoaBatches: 0,
    judgedMoaBatches: 0,
    aggregatedMoaBatches: 0,
    adjudicationIndex: 0,
    pendingMoaBatch: undefined,
    judgedMoaBatch: undefined,
    roles: new Map(),
    issuedTurns: new Map(),
    violations: [],
  };
  const quiescenceWaiters = new Set();
  const violatingSockets = new WeakSet();
  let closePromise;

  const notifyQuiescence = () => {
    if (state.activeRequests !== 0) {
      return;
    }
    for (const resolveWaiter of quiescenceWaiters) {
      resolveWaiter();
    }
    quiescenceWaiters.clear();
  };
  const recordViolation = (message, socket) => {
    if (socket && violatingSockets.has(socket)) {
      return;
    }
    if (socket) {
      violatingSockets.add(socket);
    }
    state.violations.push(message);
    options.onViolation?.(message);
  };

  const server = createServer(async (request, response) => {
    state.activeRequests += 1;
    state.maxActiveRequests = Math.max(state.maxActiveRequests, state.activeRequests);
    try {
      if (!state.accepting) {
        throw requestError(503, "Smoke provider received a request after shutdown began.");
      }
      const body = await validateRequest(request);
      state.requests += 1;
      const reply = responseForRequest(body, state);
      writeJson(response, 200, reply);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      recordViolation(message, request.socket);
      writeJson(response, statusForError(error), {
        error: {
          type: "invalid_smoke_request",
          message,
        },
      });
    } finally {
      state.activeRequests -= 1;
      notifyQuiescence();
    }
  });

  server.on("clientError", (error, socket) => {
    const message = `client-error:${error.message}`;
    recordViolation(message, socket);
    if (!socket.destroyed) {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    }
  });

  await new Promise((resolvePromise, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolvePromise();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(0, "127.0.0.1");
  });

  const address = server.address();
  if (!address || typeof address === "string" || address.address !== "127.0.0.1") {
    await closeServer(server, () => waitForQuiescence(state, quiescenceWaiters));
    throw new Error("Smoke provider did not bind to the IPv4 loopback interface.");
  }

  return {
    baseUrl: `http://127.0.0.1:${address.port}/v1`,
    snapshot() {
      return snapshotState(state);
    },
    assertCoverage() {
      assertProviderCoverage(state);
    },
    quiesce(timeoutMs = QUIESCENCE_TIMEOUT_MS) {
      return waitForQuiescence(state, quiescenceWaiters, timeoutMs);
    },
    close() {
      if (!closePromise) {
        state.accepting = false;
        closePromise = closeServer(
          server,
          () => waitForQuiescence(state, quiescenceWaiters),
        ).then(() => {
          state.closed = true;
        });
      }
      return closePromise;
    },
  };
}

function responseForRequest(body, state) {
  const system = systemMessage(body.messages);
  const role = inspectionRole(system);
  const digest = requestDigest(body);

  if (system.includes("bounded Hermsec MoA evidence judge")) {
    const batch = consumeGroundedBatchForJudge(body.messages, state);
    const ids = batch.candidates.map((candidate) => candidate.candidateId);
    const responseJudgments = ids.map((candidateId) => ({
      candidateId,
      verdict: "accepted",
      confidence: "high",
      reason: "The candidate is bound to repository tool evidence.",
    }));
    const judgments = responseJudgments.map((judgment) => ({
      ...judgment,
      reviewedBy: body.model,
      source: "judge",
    }));
    state.judgedMoaBatch = {
      ...batch,
      judgments,
      phase: "judged",
    };
    state.judgeResponses += 1;
    state.judgedMoaBatches += 1;
    return completion(body.model, digest, {
      judgments: responseJudgments,
    });
  }

  if (system.includes("bounded Hermsec MoA aggregator")) {
    const batch = consumeJudgedBatchForAggregator(body.messages, state);
    const ids = batch.candidates.map((candidate) => candidate.candidateId);
    state.judgedMoaBatch = undefined;
    state.adjudicationIndex += 1;
    state.aggregatorResponses += 1;
    state.aggregatedMoaBatches += 1;
    return completion(body.model, digest, {
      groups: ids.map((candidateId) => ({
        candidateIds: [candidateId],
        rationale: "Preserve the supplied evidence-bound candidate.",
      })),
    });
  }

  if (!system.includes("bounded Hermsec repository security investigator") || !role) {
    throw requestError(422, "Unexpected model role or system prompt.");
  }
  if (role !== "single bounded investigator" && state.judgedMoaBatch) {
    throw requestError(
      422,
      "MoA specialist request arrived before the aggregator consumed the judged batch.",
    );
  }

  const roleState = state.roles.get(role) ?? { toolResponses: 0, finalResponses: 0 };
  state.roles.set(role, roleState);
  const hasToolEvidence = body.messages.some((message) => message.role === "tool");

  if (!hasToolEvidence) {
    validateInspectionTools(body);
    registerIssuedTurn(state, body, digest);
    roleState.toolResponses += 1;
    state.inspectionToolResponses += 1;
    if (role === "single bounded investigator") {
      state.singleToolResponses += 1;
    } else {
      state.moaToolResponses += 1;
    }
    return toolCompletion(body.model, digest);
  }

  const evidence = validateToolEvidenceTurn(body, state);
  roleState.finalResponses += 1;
  state.inspectionFinalResponses += 1;
  if (role === "single bounded investigator") {
    state.singleFinalResponses += 1;
  } else {
    state.moaFinalResponses += 1;
  }
  const finding = groundedFinding(role, evidence);
  registerGroundedCandidate(state, role, finding);
  return completion(body.model, digest, {
    findings: [finding],
    abstained: false,
  });
}

async function validateRequest(request) {
  if (
    request.socket.remoteAddress !== "127.0.0.1"
    && request.socket.remoteAddress !== "::ffff:127.0.0.1"
  ) {
    throw requestError(403, "Smoke provider accepts loopback clients only.");
  }
  if (request.method !== "POST") {
    throw requestError(405, `Unexpected HTTP method: ${request.method ?? "unknown"}.`);
  }
  if (request.url !== CHAT_PATH) {
    throw requestError(404, `Unexpected request path: ${request.url ?? "unknown"}.`);
  }
  if (!String(request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) {
    throw requestError(415, "Smoke provider requires application/json.");
  }
  if (request.headers.authorization !== `Bearer ${SMOKE_API_KEY}`) {
    throw requestError(401, "Smoke provider authorization did not match the local sentinel.");
  }

  const raw = await readBoundedSmokeRequestBody(request);
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    throw requestError(400, "Smoke provider request body was not valid JSON.");
  }
  if (!isRecord(body)) {
    throw requestError(400, "Smoke provider request body must be an object.");
  }
  const unknownKeys = Object.keys(body).filter((key) => !REQUEST_KEYS.has(key));
  if (unknownKeys.length > 0) {
    throw requestError(422, `Unexpected request field(s): ${unknownKeys.sort().join(", ")}.`);
  }
  if (body.model !== SMOKE_MODEL) {
    throw requestError(422, `Unexpected model: ${String(body.model)}.`);
  }
  if (body.temperature !== 0) {
    throw requestError(422, "Smoke provider requires deterministic temperature 0.");
  }
  if (!Number.isInteger(body.max_tokens) || body.max_tokens < 1 || body.max_tokens > 10_000) {
    throw requestError(422, "Smoke provider requires a bounded max_tokens value.");
  }
  if (
    !isRecord(body.response_format)
    || body.response_format.type !== "json_object"
    || Object.keys(body.response_format).some((key) => key !== "type")
  ) {
    throw requestError(422, "Smoke provider requires JSON-object response format.");
  }
  if (!Array.isArray(body.messages) || body.messages.length < 2) {
    throw requestError(422, "Smoke provider requires at least system and user messages.");
  }
  validateMessages(body.messages);
  return body;
}

function validateMessages(messages) {
  const roles = new Set(["system", "user", "assistant", "tool"]);
  if (messages[0]?.role !== "system") {
    throw requestError(422, "First model message must be the Hermsec system prompt.");
  }
  for (const [index, message] of messages.entries()) {
    if (!isRecord(message) || !roles.has(message.role)) {
      throw requestError(422, `Message ${index} has an unexpected role or shape.`);
    }
    if (typeof message.content !== "string" && message.content !== null) {
      throw requestError(422, `Message ${index} has invalid content.`);
    }
  }
}

function validateInspectionTools(body) {
  if (!Array.isArray(body.tools) || body.tools.length === 0) {
    throw requestError(422, "Initial inspection request did not expose bounded tools.");
  }
  if (body.tool_choice !== "auto" || body.parallel_tool_calls !== false) {
    throw requestError(422, "Initial inspection request has unsafe tool-choice settings.");
  }
  const names = [];
  for (const tool of body.tools) {
    const name = tool?.function?.name;
    if (
      !isRecord(tool)
      || tool.type !== "function"
      || !isRecord(tool.function)
      || typeof name !== "string"
      || !INSPECTION_TOOL_NAMES.has(name)
    ) {
      throw requestError(422, "Initial inspection request exposed an unexpected tool.");
    }
    names.push(name);
  }
  if (new Set(names).size !== names.length) {
    throw requestError(422, "Initial inspection request exposed duplicate tool definitions.");
  }
  for (const requiredName of ["list_files", "search_code"]) {
    if (!names.includes(requiredName)) {
      throw requestError(422, `Initial inspection request did not expose ${requiredName}.`);
    }
  }
}

function registerIssuedTurn(state, body, digest) {
  const calls = expectedToolCalls(digest);
  const existing = state.issuedTurns.get(digest);
  if (existing && !sameToolCalls(existing.calls, calls)) {
    throw requestError(422, "Deterministic tool-call digest collision detected.");
  }
  state.issuedTurns.set(digest, {
    calls,
    pending: (existing?.pending ?? 0) + 1,
  });
  state.issuedToolCalls += calls.length;
}

function validateToolEvidenceTurn(body, state) {
  if (body.tools !== undefined) {
    validateInspectionTools(body);
  } else if (body.tool_choice !== undefined || body.parallel_tool_calls !== undefined) {
    throw requestError(422, "Final inspection request has incomplete tool-choice settings.");
  }

  const assistantTurns = body.messages
    .map((message, index) => ({ message, index }))
    .filter(({ message }) => message.role === "assistant" && Array.isArray(message.tool_calls));
  if (assistantTurns.length !== 1) {
    throw requestError(422, "Final inspection request must contain exactly one assistant tool_calls turn.");
  }
  const assistantTurn = assistantTurns[0];
  const trailingMessages = body.messages.slice(assistantTurn.index + 1);
  if (
    trailingMessages.length === 0
    || trailingMessages.some((message) => message.role !== "tool")
  ) {
    throw requestError(422, "Final inspection request must contain only tool results after tool_calls.");
  }

  const initialBody = {
    ...body,
    messages: body.messages.slice(0, assistantTurn.index),
  };
  const initialDigest = requestDigest(initialBody);
  const issuedTurn = state.issuedTurns.get(initialDigest);
  if (!issuedTurn || issuedTurn.pending < 1) {
    throw requestError(422, "Final inspection request referenced an unissued tool-call turn.");
  }

  const assistantCalls = assistantTurn.message.tool_calls;
  if (!sameToolCalls(assistantCalls, issuedTurn.calls)) {
    throw requestError(422, "Final inspection request tool_calls did not match the exact issued IDs, names, and arguments.");
  }

  const issuedById = new Map(issuedTurn.calls.map((call) => [call.id, call]));
  const resultIds = new Set();
  const evidenceIds = new Set();
  const evidenceByTool = new Map();
  for (const message of trailingMessages) {
    const resultId = message.tool_call_id;
    if (typeof resultId !== "string" || !resultId) {
      throw requestError(422, "Tool result is missing its issued tool_call_id.");
    }
    if (resultIds.has(resultId)) {
      throw requestError(422, `Duplicate tool result for issued call ID ${resultId}.`);
    }
    resultIds.add(resultId);
    const issuedCall = issuedById.get(resultId);
    if (!issuedCall) {
      throw requestError(422, `Tool result referenced unissued call ID ${resultId}.`);
    }
    const evidence = parseFramedToolEvidence(message.content);
    if (evidence.tool !== issuedCall.function.name) {
      throw requestError(
        422,
        `Tool result for ${resultId} claimed ${evidence.tool} instead of ${issuedCall.function.name}.`,
      );
    }
    if (evidenceIds.has(evidence.evidenceId)) {
      throw requestError(422, `Duplicate tool evidence ID ${evidence.evidenceId}.`);
    }
    evidenceIds.add(evidence.evidenceId);
    evidenceByTool.set(evidence.tool, evidence);
  }
  const missingIds = [...issuedById.keys()].filter((id) => !resultIds.has(id));
  if (missingIds.length > 0) {
    throw requestError(422, `Missing tool result(s) for issued call ID(s): ${missingIds.join(", ")}.`);
  }

  validateGroundingEvidence(evidenceByTool);
  issuedTurn.pending -= 1;
  state.validatedToolResults += resultIds.size;
  return evidenceByTool;
}

function parseFramedToolEvidence(content) {
  if (typeof content !== "string") {
    throw requestError(422, "Tool result content must be framed text.");
  }
  const lines = content.split(/\r?\n/u);
  const beginIndexes = indexesOf(lines, "HERMSEC_UNTRUSTED_REPOSITORY_DATA_BEGIN");
  const endIndexes = indexesOf(lines, "HERMSEC_UNTRUSTED_REPOSITORY_DATA_END");
  if (
    beginIndexes.length !== 1
    || endIndexes.length !== 1
    || endIndexes[0] <= beginIndexes[0] + 1
  ) {
    throw requestError(422, "Tool result did not contain exactly one complete evidence frame.");
  }
  const frameLines = lines.slice(beginIndexes[0] + 1, endIndexes[0]);
  const jsonLine = frameLines.at(-1);
  let payload;
  try {
    payload = JSON.parse(jsonLine ?? "");
  } catch {
    throw requestError(422, "Tool result evidence frame did not end with valid JSON.");
  }
  if (
    !isRecord(payload)
    || typeof payload.evidenceId !== "string"
    || !payload.evidenceId
    || typeof payload.tool !== "string"
    || !payload.tool
    || !Object.hasOwn(payload, "data")
  ) {
    throw requestError(422, "Tool result evidence frame had an invalid payload shape.");
  }
  return payload;
}

function validateGroundingEvidence(evidenceByTool) {
  const listEvidence = evidenceByTool.get("list_files");
  if (
    !listEvidence
    || !isRecord(listEvidence.data)
    || !Array.isArray(listEvidence.data.files)
    || listEvidence.data.files.length === 0
  ) {
    throw requestError(422, "list_files evidence did not contain repository files.");
  }
  const searchEvidence = evidenceByTool.get("search_code");
  const matches = isRecord(searchEvidence?.data) && Array.isArray(searchEvidence.data.matches)
    ? searchEvidence.data.matches
    : [];
  if (!matches.some(isGroundedExecMatch)) {
    throw requestError(422, `search_code evidence did not contain a grounded ${SEARCH_QUERY} match.`);
  }
}

function groundedFinding(role, evidenceByTool) {
  const searchEvidence = evidenceByTool.get("search_code");
  const match = searchEvidence.data.matches.find(isGroundedExecMatch);
  return {
    candidateId: `smoke-command-injection-${slug(role)}-${slug(match.file)}-${match.line}`,
    title: "Untrusted input can reach command execution",
    category: "code",
    severity: "high",
    confidence: "high",
    description:
      "A bounded repository search located a process-execution call in application source.",
    evidence: match.preview,
    remediation:
      "Avoid shell execution and pass validated arguments to a fixed executable.",
    ruleId: "hermsec.smoke.command-injection",
    cwe: ["CWE-78"],
    evidenceIds: [searchEvidence.evidenceId],
    sourceLocations: [
      {
        file: match.file,
        startLine: match.line,
        endLine: match.line,
      },
    ],
  };
}

function registerGroundedCandidate(state, roleLabel, finding) {
  const candidate = canonicalCandidateProjection(roleLabel, finding);
  state.groundedEmissions += 1;
  if (roleLabel === "single bounded investigator") {
    return;
  }
  if (state.adjudicationIndex >= EXPECTED_MOA_BATCH_ROLE_IDS.length) {
    throw requestError(422, "Grounded MoA candidate was emitted after all batches were adjudicated.");
  }
  if (state.judgedMoaBatch) {
    throw requestError(422, "Grounded MoA candidate was emitted while a judged batch awaited aggregation.");
  }

  const expectedRoles = EXPECTED_MOA_BATCH_ROLE_IDS[state.adjudicationIndex];
  if (!expectedRoles?.includes(candidate.role)) {
    throw requestError(
      422,
      `Grounded candidate role ${candidate.role} does not belong to MoA batch ${state.adjudicationIndex + 1}.`,
    );
  }
  const batch = state.pendingMoaBatch ?? {
    batchIndex: state.adjudicationIndex,
    phase: "collecting",
    candidatesByRole: new Map(),
  };
  if (batch.batchIndex !== state.adjudicationIndex || batch.phase !== "collecting") {
    throw requestError(422, "Grounded MoA candidate attempted to reuse an adjudication phase.");
  }
  if (batch.candidatesByRole.has(candidate.role)) {
    throw requestError(
      422,
      `Grounded MoA batch contained duplicate role ${candidate.role}.`,
    );
  }
  batch.candidatesByRole.set(candidate.role, candidate);
  state.pendingMoaBatch = batch;

  if (batch.candidatesByRole.size === expectedRoles.length) {
    const actualRoles = [...batch.candidatesByRole.keys()].sort();
    if (JSON.stringify(actualRoles) !== JSON.stringify([...expectedRoles].sort())) {
      throw requestError(422, "Grounded MoA batch role coverage did not match the expected batch.");
    }
    batch.phase = "pending-judge";
    batch.candidates = sortedCandidates(batch.candidatesByRole.values());
    batch.batchId = candidateBatchId(batch.candidates);
    delete batch.candidatesByRole;
    state.groundedMoaBatches += 1;
  }
}

function consumeGroundedBatchForJudge(messages, state) {
  if (state.judgedMoaBatch) {
    throw requestError(422, "MoA judge attempted duplicate or out-of-order phase use.");
  }
  const batch = state.pendingMoaBatch;
  if (!batch || batch.phase !== "pending-judge" || !Array.isArray(batch.candidates)) {
    throw requestError(422, "MoA judge did not have exactly one complete pending grounded batch.");
  }
  const payload = parseFramedCandidatePayload(messages);
  if (!hasOnlyKeys(payload, ["candidates"]) || !Array.isArray(payload.candidates)) {
    throw requestError(422, "MoA judge payload must contain only the pending candidates.");
  }
  validateExactCandidateSet(payload.candidates, batch.candidates, "judge");
  state.pendingMoaBatch = undefined;
  return {
    batchIndex: batch.batchIndex,
    batchId: batch.batchId,
    candidates: batch.candidates,
    phase: "judge-consumed",
  };
}

function consumeJudgedBatchForAggregator(messages, state) {
  if (state.pendingMoaBatch) {
    throw requestError(422, "MoA aggregator arrived before the pending grounded batch was judged.");
  }
  const batch = state.judgedMoaBatch;
  if (!batch || batch.phase !== "judged") {
    throw requestError(422, "MoA aggregator did not have exactly one successful judged batch.");
  }
  const payload = parseFramedCandidatePayload(messages);
  if (
    !hasOnlyKeys(payload, ["candidates", "judgments"])
    || !Array.isArray(payload.candidates)
    || !Array.isArray(payload.judgments)
  ) {
    throw requestError(422, "MoA aggregator payload must contain only candidates and judgments.");
  }
  validateExactCandidateSet(payload.candidates, batch.candidates, "aggregator");
  validateExactJudgments(payload.judgments, batch.judgments);
  return batch;
}

function validateExactCandidateSet(actual, expected, phase) {
  const expectedById = new Map(expected.map((candidate) => [candidate.candidateId, candidate]));
  const seen = new Set();
  for (const candidate of actual) {
    if (!isRecord(candidate) || typeof candidate.candidateId !== "string") {
      throw requestError(422, `MoA ${phase} candidate had an invalid shape.`);
    }
    if (seen.has(candidate.candidateId)) {
      throw requestError(422, `MoA ${phase} replayed candidate ID ${candidate.candidateId}.`);
    }
    seen.add(candidate.candidateId);
    const grounded = expectedById.get(candidate.candidateId);
    if (!grounded) {
      throw requestError(
        422,
        `MoA ${phase} referenced unrelated candidate ID ${candidate.candidateId}.`,
      );
    }
    if (canonicalJson(candidate) !== canonicalJson(grounded)) {
      throw requestError(
        422,
        `MoA ${phase} candidate ${candidate.candidateId} did not match its grounded emission.`,
      );
    }
  }
  const missing = [...expectedById.keys()].filter((candidateId) => !seen.has(candidateId));
  if (missing.length > 0 || actual.length !== expected.length) {
    throw requestError(
      422,
      `MoA ${phase} candidate batch was missing expected ID(s): ${missing.join(", ") || "unknown"}.`,
    );
  }
}

function validateExactJudgments(actual, expected) {
  const expectedById = new Map(expected.map((judgment) => [judgment.candidateId, judgment]));
  const seen = new Set();
  for (const judgment of actual) {
    if (!isRecord(judgment) || typeof judgment.candidateId !== "string") {
      throw requestError(422, "MoA aggregator judgment had an invalid shape.");
    }
    if (seen.has(judgment.candidateId)) {
      throw requestError(
        422,
        `MoA aggregator replayed judgment for ${judgment.candidateId}.`,
      );
    }
    seen.add(judgment.candidateId);
    const issued = expectedById.get(judgment.candidateId);
    if (!issued || canonicalJson(judgment) !== canonicalJson(issued)) {
      throw requestError(
        422,
        `MoA aggregator judgment for ${judgment.candidateId} did not match the successful judge batch.`,
      );
    }
  }
  const missing = [...expectedById.keys()].filter((candidateId) => !seen.has(candidateId));
  if (missing.length > 0 || actual.length !== expected.length) {
    throw requestError(
      422,
      `MoA aggregator judgments were missing expected ID(s): ${missing.join(", ") || "unknown"}.`,
    );
  }
}

function parseFramedCandidatePayload(messages) {
  const userMessages = messages.filter((message) => message.role === "user");
  if (userMessages.length !== 1 || typeof userMessages[0]?.content !== "string") {
    throw requestError(422, "MoA phase requires exactly one framed user payload.");
  }
  const lines = userMessages[0].content.split(/\r?\n/u);
  const beginIndexes = indexesOf(lines, "HERMSEC_UNTRUSTED_CANDIDATE_DATA_BEGIN");
  const endIndexes = indexesOf(lines, "HERMSEC_UNTRUSTED_CANDIDATE_DATA_END");
  if (
    beginIndexes.length !== 1
    || endIndexes.length !== 1
    || endIndexes[0] <= beginIndexes[0] + 1
  ) {
    throw requestError(422, "MoA payload did not contain exactly one complete candidate frame.");
  }
  const jsonLine = lines.slice(beginIndexes[0] + 1, endIndexes[0]).at(-1);
  let payload;
  try {
    payload = JSON.parse(jsonLine ?? "");
  } catch {
    throw requestError(422, "MoA candidate frame did not end with valid JSON.");
  }
  if (!isRecord(payload)) {
    throw requestError(422, "MoA candidate frame payload must be an object.");
  }
  return payload;
}

function canonicalCandidateProjection(roleLabel, finding) {
  const role = roleLabel === "single bounded investigator"
    ? "single-agent-inspector"
    : MOA_ROLE_IDS_BY_LABEL.get(roleLabel);
  if (!role) {
    throw requestError(422, `Could not map grounded role ${roleLabel} to a canonical role.`);
  }
  const sourceLocations = finding.sourceLocations.map((location) => ({
    file: location.file.replaceAll("\\", "/"),
    startLine: location.startLine,
    endLine: location.endLine,
  }));
  const location = {
    path: sourceLocations[0].file,
    startLine: sourceLocations[0].startLine,
    endLine: sourceLocations[0].endLine,
  };
  const vulnerabilityClass = "command-injection";
  const exactAnchors = [
    `fingerprint:${normalizeAnchorText("pending-agent-fingerprint")}`,
    `content:${stableId(JSON.stringify({
      category: finding.category,
      vulnerabilityClass,
      title: normalizeAnchorText(finding.title),
      description: normalizeAnchorText(finding.description),
      evidence: normalizeAnchorText(finding.evidence),
      remediation: normalizeAnchorText(finding.remediation),
      ruleId: normalizeAnchorText(finding.ruleId ?? ""),
      location,
      package: null,
    }), "anchor")}`,
  ].sort();
  const sinkAnchors = findingSinkAnchors(finding.evidence);
  const mergeAnchor = sinkAnchors[0] ?? exactAnchors.find((anchor) =>
    anchor.startsWith("content:")
  ) ?? exactAnchors[0];
  const groupAnchor = [
    "repository",
    finding.category,
    vulnerabilityClass,
    `${location.path}:${location.startLine}-${location.endLine}`,
    mergeAnchor,
  ].join("|");
  const identityKey = [
    groupAnchor,
    `cwes:${finding.cwe.join(",")}`,
    `exact:${exactAnchors.join(",")}`,
    `sink:${sinkAnchors.join(",")}`,
  ].join("|");
  const candidateId = stableId([
    role,
    "initial",
    finding.candidateId,
    identityKey,
    finding.evidenceIds.join("|"),
  ].join("\0"), "candidate");
  return {
    candidateId,
    role,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    description: finding.description,
    evidence: finding.evidence,
    cwe: [...finding.cwe],
    evidenceIds: [...finding.evidenceIds],
    sourceLocations,
  };
}

function findingSinkAnchors(evidence) {
  const anchors = [];
  const callPattern = /[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*){0,4}\s*\([^;\r\n]{0,180}\)/gu;
  for (const match of evidence.normalize("NFKC").matchAll(callPattern)) {
    const normalized = normalizeAnchorText(match[0]);
    if (normalized) {
      anchors.push(`sink-code:${stableId(normalized, "anchor")}`);
    }
  }
  const assignmentPattern = /[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*){1,4}\s*=\s*[^;\r\n]{1,160}/gu;
  for (const match of evidence.normalize("NFKC").matchAll(assignmentPattern)) {
    const normalized = normalizeAnchorText(match[0]);
    if (normalized) {
      anchors.push(`sink-code:${stableId(normalized, "anchor")}`);
    }
  }
  const quotedCodePattern = /`([^`\r\n]{3,180})`/gu;
  for (const match of evidence.normalize("NFKC").matchAll(quotedCodePattern)) {
    const normalized = normalizeAnchorText(match[1] ?? "");
    if (normalized) {
      anchors.push(`sink-code:${stableId(normalized, "anchor")}`);
    }
  }
  return [...new Set(anchors)].sort();
}

function normalizeAnchorText(value) {
  return String(value)
    .normalize("NFKC")
    .toLowerCase()
    .replace(/\s+/gu, " ")
    .replace(/\s*([()[\]{},.;:=+\-*/])\s*/gu, "$1")
    .trim();
}

function stableId(value, prefix) {
  return `${prefix}-${createHash("sha256").update(value).digest("hex").slice(0, 16)}`;
}

function sortedCandidates(candidates) {
  return [...candidates].sort((left, right) =>
    left.candidateId.localeCompare(right.candidateId)
  );
}

function candidateBatchId(candidates) {
  return stableId(candidates.map((candidate) => candidate.candidateId).sort().join("\0"), "batch");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hasOnlyKeys(value, expectedKeys) {
  const actual = Object.keys(value).sort();
  return JSON.stringify(actual) === JSON.stringify([...expectedKeys].sort());
}

function isGroundedExecMatch(value) {
  return (
    isRecord(value)
    && typeof value.file === "string"
    && value.file.length > 0
    && Number.isInteger(value.line)
    && value.line > 0
    && typeof value.preview === "string"
    && value.preview.includes(SEARCH_QUERY)
  );
}

function toolCompletion(model, digest) {
  return {
    id: `chatcmpl-smoke-${digest}`,
    object: "chat.completion",
    model,
    choices: [
      {
        index: 0,
        finish_reason: "tool_calls",
        message: {
          role: "assistant",
          content: null,
          tool_calls: expectedToolCalls(digest),
        },
      },
    ],
    usage: tokenUsage(64),
  };
}

function expectedToolCalls(digest) {
  return [
    {
      id: `smoke-list-files-${digest}`,
      type: "function",
      function: {
        name: "list_files",
        arguments: JSON.stringify({ limit: 500 }),
      },
    },
    {
      id: `smoke-search-code-${digest}`,
      type: "function",
      function: {
        name: "search_code",
        arguments: JSON.stringify({ query: SEARCH_QUERY, limit: 20 }),
      },
    },
  ];
}

function sameToolCalls(actual, expected) {
  if (!Array.isArray(actual) || actual.length !== expected.length) {
    return false;
  }
  return actual.every((call, index) => {
    const expectedCall = expected[index];
    return (
      isRecord(call)
      && call.id === expectedCall.id
      && call.type === expectedCall.type
      && isRecord(call.function)
      && call.function.name === expectedCall.function.name
      && call.function.arguments === expectedCall.function.arguments
      && Object.keys(call).every((key) => ["id", "type", "function"].includes(key))
      && Object.keys(call.function).every((key) => ["name", "arguments"].includes(key))
    );
  });
}

function completion(model, digest, content) {
  return {
    id: `chatcmpl-smoke-${digest}`,
    object: "chat.completion",
    model,
    choices: [
      {
        index: 0,
        finish_reason: "stop",
        message: {
          role: "assistant",
          content: JSON.stringify(content),
        },
      },
    ],
    usage: tokenUsage(96),
  };
}

function tokenUsage(completionTokens) {
  return {
    prompt_tokens: 160,
    completion_tokens: completionTokens,
    total_tokens: 160 + completionTokens,
  };
}

function systemMessage(messages) {
  const message = messages.find((candidate) => candidate.role === "system");
  return typeof message?.content === "string" ? message.content : "";
}

function inspectionRole(system) {
  return /^Assigned security role:\s*(.+)$/mu.exec(system)?.[1]?.trim();
}

function requestDigest(body) {
  return createHash("sha256").update(JSON.stringify(body)).digest("hex").slice(0, 16);
}

export function readBoundedSmokeRequestBody(request) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    let bytes = 0;
    let settled = false;

    const cleanup = () => {
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("aborted", onAborted);
      request.off("error", onError);
      request.off("close", onClose);
    };
    const settle = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback(value);
    };
    const onData = (chunk) => {
      if (settled) {
        return;
      }
      bytes += chunk.length;
      if (bytes > SMOKE_MAX_REQUEST_BYTES) {
        settle(
          reject,
          requestError(413, "Smoke provider request exceeded the body limit."),
        );
        request.resume();
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => {
      settle(resolvePromise, Buffer.concat(chunks).toString("utf8"));
    };
    const onAborted = () => {
      settle(reject, requestError(400, "Smoke provider request body was aborted."));
    };
    const onError = (error) => {
      settle(reject, error);
    };
    const onClose = () => {
      if (!request.complete) {
        settle(reject, requestError(400, "Smoke provider request closed before completion."));
      }
    };

    request.on("data", onData);
    request.once("end", onEnd);
    request.once("aborted", onAborted);
    request.once("error", onError);
    request.once("close", onClose);
  });
}

function writeJson(response, status, payload) {
  if (response.writableEnded || response.destroyed) {
    return;
  }
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    connection: "close",
  });
  response.end(body);
}

function statusForError(error) {
  return Number.isInteger(error?.statusCode) ? error.statusCode : 400;
}

function requestError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function assertProviderCoverage(state) {
  if (state.accepting || !state.closed || state.activeRequests !== 0) {
    throw new Error(
      "Smoke provider coverage can be finalized only after it is closed with zero in-flight requests.",
    );
  }
  if (state.violations.length > 0) {
    throw new Error(`Smoke provider rejected request(s): ${state.violations.join(" | ")}`);
  }
  const snapshot = snapshotState(state);
  assertExactCount("canonical harness request", snapshot.requests, EXPECTED_REQUEST_COUNT);
  assertExactCount(
    "inspection tool response",
    snapshot.inspectionToolResponses,
    EXPECTED_INSPECTION_ROUNDS,
  );
  assertExactCount(
    "inspection final response",
    snapshot.inspectionFinalResponses,
    EXPECTED_INSPECTION_ROUNDS,
  );
  assertExactCount("Single tool response", snapshot.singleToolResponses, 2);
  assertExactCount("Single final response", snapshot.singleFinalResponses, 2);
  assertExactCount(
    "MoA specialist tool response",
    snapshot.moaToolResponses,
    EXPECTED_MOA_INSPECTION_ROUNDS,
  );
  assertExactCount(
    "MoA specialist final response",
    snapshot.moaFinalResponses,
    EXPECTED_MOA_INSPECTION_ROUNDS,
  );
  assertExactCount("issued tool call", snapshot.issuedToolCalls, EXPECTED_TOOL_CALLS);
  assertExactCount(
    "validated tool result",
    snapshot.validatedToolResults,
    EXPECTED_TOOL_CALLS,
  );
  assertExactCount(
    "MoA judge response",
    snapshot.judgeResponses,
    EXPECTED_JUDGE_RESPONSES,
  );
  assertExactCount(
    "MoA aggregator response",
    snapshot.aggregatorResponses,
    EXPECTED_AGGREGATOR_RESPONSES,
  );
  assertExactCount(
    "grounded candidate emission",
    snapshot.groundedEmissions,
    EXPECTED_GROUNDED_EMISSIONS,
  );
  assertExactCount(
    "registered grounded MoA batch",
    snapshot.groundedMoaBatches,
    EXPECTED_JUDGE_RESPONSES,
  );
  assertExactCount(
    "successfully judged MoA batch",
    snapshot.judgedMoaBatches,
    EXPECTED_JUDGE_RESPONSES,
  );
  assertExactCount(
    "successfully aggregated MoA batch",
    snapshot.aggregatedMoaBatches,
    EXPECTED_AGGREGATOR_RESPONSES,
  );
  assertExactCount(
    "completed MoA adjudication sequence",
    snapshot.adjudicationIndex,
    EXPECTED_AGGREGATOR_RESPONSES,
  );
  if (JSON.stringify(snapshot.roles) !== JSON.stringify(EXPECTED_SMOKE_ROLE_COVERAGE)) {
    throw new Error(
      `Smoke provider role coverage mismatch. Expected ${JSON.stringify(EXPECTED_SMOKE_ROLE_COVERAGE)}, received ${JSON.stringify(snapshot.roles)}.`,
    );
  }
  if (snapshot.pendingIssuedTurns !== 0) {
    throw new Error(
      `Smoke provider finished with ${snapshot.pendingIssuedTurns} unconsumed issued tool-call turn(s).`,
    );
  }
  if (snapshot.pendingMoaBatch || snapshot.judgedMoaBatch) {
    throw new Error("Smoke provider finished with an unconsumed MoA adjudication batch.");
  }
}

function assertExactCount(label, actual, expected) {
  if (actual !== expected) {
    throw new Error(`Smoke provider expected exactly ${expected} ${label}(s), received ${actual}.`);
  }
}

function snapshotState(state) {
  return {
    accepting: state.accepting,
    closed: state.closed,
    requests: state.requests,
    activeRequests: state.activeRequests,
    maxActiveRequests: state.maxActiveRequests,
    inspectionToolResponses: state.inspectionToolResponses,
    inspectionFinalResponses: state.inspectionFinalResponses,
    singleToolResponses: state.singleToolResponses,
    singleFinalResponses: state.singleFinalResponses,
    moaToolResponses: state.moaToolResponses,
    moaFinalResponses: state.moaFinalResponses,
    issuedToolCalls: state.issuedToolCalls,
    validatedToolResults: state.validatedToolResults,
    judgeResponses: state.judgeResponses,
    aggregatorResponses: state.aggregatorResponses,
    groundedEmissions: state.groundedEmissions,
    groundedMoaBatches: state.groundedMoaBatches,
    judgedMoaBatches: state.judgedMoaBatches,
    aggregatedMoaBatches: state.aggregatedMoaBatches,
    adjudicationIndex: state.adjudicationIndex,
    pendingMoaBatch: snapshotMoaBatch(state.pendingMoaBatch),
    judgedMoaBatch: snapshotMoaBatch(state.judgedMoaBatch),
    pendingIssuedTurns: [...state.issuedTurns.values()]
      .reduce((total, turn) => total + turn.pending, 0),
    roles: Object.fromEntries(
      [...state.roles.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([role, counts]) => [role, { ...counts }]),
    ),
    violations: [...state.violations],
  };
}

function snapshotMoaBatch(batch) {
  if (!batch) {
    return undefined;
  }
  return {
    batchIndex: batch.batchIndex,
    batchId: batch.batchId,
    phase: batch.phase,
    candidates: Array.isArray(batch.candidates)
      ? structuredClone(batch.candidates)
      : sortedCandidates(batch.candidatesByRole?.values() ?? []),
    ...(Array.isArray(batch.judgments)
      ? { judgments: structuredClone(batch.judgments) }
      : {}),
  };
}

function deleteEnvironmentVariable(env, name) {
  const normalized = process.platform === "win32" ? name.toUpperCase() : name;
  for (const key of Object.keys(env)) {
    if ((process.platform === "win32" ? key.toUpperCase() : key) === normalized) {
      delete env[key];
    }
  }
}

async function waitForQuiescence(
  state,
  quiescenceWaiters,
  timeoutMs = QUIESCENCE_TIMEOUT_MS,
) {
  if (state.activeRequests === 0) {
    return;
  }
  await new Promise((resolvePromise, reject) => {
    let timer;
    const resolveWaiter = () => {
      clearTimeout(timer);
      resolvePromise();
    };
    timer = setTimeout(() => {
      quiescenceWaiters.delete(resolveWaiter);
      reject(
        new Error(
          `Smoke provider still had ${state.activeRequests} in-flight request(s) after ${timeoutMs} ms.`,
        ),
      );
    }, timeoutMs);
    quiescenceWaiters.add(resolveWaiter);
  });
}

async function closeServer(server, waitForProviderQuiescence) {
  const closeResult = server.listening
    ? new Promise((resolvePromise, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolvePromise();
          }
        });
      })
    : Promise.resolve();
  server.closeIdleConnections?.();
  await waitForProviderQuiescence();
  server.closeIdleConnections?.();
  server.closeAllConnections?.();
  await closeResult;
}

function runCommandCapture(command, args, timeoutMs, cwd, env) {
  return new Promise((resolvePromise, reject) => {
    const commandProcess = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      commandProcess.kill("SIGKILL");
      reject(new Error(`${command} timed out after ${timeoutMs} ms.`));
    }, timeoutMs);
    commandProcess.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    commandProcess.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    commandProcess.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    commandProcess.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolvePromise({ code, signal, stdout, stderr });
    });
  });
}

function contentTreeFingerprint(root) {
  const resolvedRoot = resolve(root);
  return contentFilesFingerprint(resolvedRoot, walkFiles(resolvedRoot));
}

function contentFilesFingerprint(root, files) {
  const resolvedRoot = resolve(root);
  const normalizedFiles = [...new Set(files.map((filePath) => resolve(filePath)))]
    .sort((left, right) => left.localeCompare(right));
  if (normalizedFiles.length === 0) {
    throw new Error(`Cannot fingerprint an empty file set under ${resolvedRoot}.`);
  }
  const digest = createHash("sha256");
  let bytes = 0;
  for (const filePath of normalizedFiles) {
    if (!existsSync(filePath) || !statSync(filePath).isFile()) {
      throw new Error(`CLI freshness input is missing: ${filePath}.`);
    }
    const content = readFileSync(filePath);
    bytes += content.byteLength;
    digest.update(relative(resolvedRoot, filePath).replaceAll("\\", "/"));
    digest.update("\0");
    digest.update(content);
    digest.update("\0");
  }
  return `${normalizedFiles.length}:${bytes}:${digest.digest("hex")}`;
}

function walkFiles(root) {
  const resolvedRoot = resolve(root);
  if (!existsSync(resolvedRoot)) {
    return [];
  }
  const pending = [resolvedRoot];
  const files = [];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((left, right) =>
      left.name.localeCompare(right.name)
    )) {
      const entryPath = resolve(current, entry.name);
      if (entry.isDirectory()) {
        pending.push(entryPath);
      } else if (entry.isFile()) {
        files.push(entryPath);
      }
    }
  }
  return files.sort((left, right) => left.localeCompare(right));
}

function signalProcessGroup(groupPid, signal) {
  try {
    process.kill(groupPid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") {
      throw error;
    }
  }
}

function waitForProcessExit(processHandle, timeoutMs) {
  if (!isProcessRunning(processHandle)) {
    return Promise.resolve(true);
  }
  return new Promise((resolvePromise) => {
    let settled = false;
    const finish = (exited) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      processHandle.off("exit", onExit);
      resolvePromise(exited);
    };
    const onExit = () => finish(true);
    const timer = setTimeout(() => finish(false), timeoutMs);
    processHandle.once("exit", onExit);
  });
}

function isProcessRunning(processHandle) {
  return processHandle.exitCode === null && processHandle.signalCode === null;
}

function waitForProcessGroupExit(groupPid, timeoutMs) {
  if (!isProcessGroupRunning(groupPid)) {
    return Promise.resolve(true);
  }
  return new Promise((resolvePromise) => {
    const deadline = Date.now() + timeoutMs;
    const check = () => {
      if (!isProcessGroupRunning(groupPid)) {
        resolvePromise(true);
      } else if (Date.now() >= deadline) {
        resolvePromise(false);
      } else {
        setTimeout(check, 25);
      }
    };
    check();
  });
}

export function isProcessGroupRunning(groupPid, kill = process.kill) {
  try {
    kill(groupPid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") {
      return false;
    }
    if (error?.code === "EPERM") {
      return true;
    }
    throw error;
  }
}

function boundedPositiveInteger(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function indexesOf(values, expected) {
  const indexes = [];
  for (const [index, value] of values.entries()) {
    if (value === expected) {
      indexes.push(index);
    }
  }
  return indexes;
}

function slug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-|-$/gu, "");
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
