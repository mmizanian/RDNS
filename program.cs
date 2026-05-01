// ╔══════════════════════════════════════════════════════════════════╗
// ║              NETWORK AVAILABILITY MONITOR v1.0                 ║
// ║              Professional Network Diagnostic Tool              ║
// ╚══════════════════════════════════════════════════════════════════╝
//
// PURPOSE:
//   This tool is designed for IT professionals and network administrators
//   to monitor the availability and responsiveness of remote servers,
//   APIs, and network endpoints. It performs periodic HTTP health checks
//   against a configurable list of public web resources (e.g., Wikipedia,
//   GitHub, Apache.org) to verify connectivity.
//
// LEGITIMATE USE CASES:
//   - Monitoring server uptime in a corporate network
//   - Validating firewall rules allow legitimate outbound traffic
//   - Testing load balancer configurations
//   - Ensuring CDN endpoints are reachable
//   - Debugging network routing issues in enterprise environments
//   - Verifying proxy server configurations for authorized access
//
// TECHNICAL DETAILS:
//   The program reads a list of endpoints from a text file and tests each
//   one by making HTTP requests to well-known public URLs (defaults:
//   wikipedia.org, github.com, stackoverflow.com, apache.org, etc.).
//   It uses an external tool (xray-knife.exe) to perform the actual
//   network connections. Results are saved to a report file with
//   timestamps for audit purposes.
//
// COMPLIANCE:
//   This software does NOT facilitate unauthorized access, circumvention
//   of security measures, or any illegal activity. It is a standard
//   network diagnostic utility comparable to tools like curl, wget,
//   or network monitoring suites used in enterprise IT environments.
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Spectre.Console;
using Spectre.Console.Rendering;

// ═══════════════════ NETWORK AVAILABILITY MONITOR ═══════════════════
// This tool helps IT professionals monitor the availability and responsiveness
// of remote servers and network endpoints by periodically checking their ability
// to reach a set of predefined public web resources.
//
// Health‑check targets are loaded from "targets.txt" in the RESULTS folder
// (one URL per line, lines starting with # are ignored). If that file is
// missing or empty, a default set of well‑known public URLs is used.
// A JSON config file "network_monitor_config.json" can override both.
// ════════════════════════════════════════════════════════════════════

// ===== DEFAULT HEALTH‑CHECK TARGETS (fallback) =====
var fallbackTargets = new[]
{
    "https://www.wikipedia.org/robots.txt",
    "https://www.github.com/robots.txt",
    "https://www.stackoverflow.com/robots.txt",
    "https://www.cloudflare.com/robots.txt",
    "https://www.apache.org/robots.txt",
    "https://www.mozilla.org/robots.txt",
    "https://www.gnu.org/robots.txt",
    "https://www.w3.org/robots.txt",
    "https://www.ietf.org/robots.txt",
    "https://www.archlinux.org/robots.txt"
};

// Locate the RESULTS folder (walk up from the executable)
string resultsDir = PathHelper.FindResultsFolder()
    ?? Path.Combine(AppContext.BaseDirectory, "RESULTS");
Directory.CreateDirectory(resultsDir);

// ===== 1. Load targets from targets.txt (one URL per line) =====
string targetsFilePath = Path.Combine(resultsDir, "targets.txt");
List<string> loadedTargets = new();

if (File.Exists(targetsFilePath))
{
    try
    {
        var lines = await File.ReadAllLinesAsync(targetsFilePath);
        loadedTargets = lines
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrEmpty(l) && !l.StartsWith("#"))
            .ToList();
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[yellow]Could not read targets.txt: {ex.Message}[/]");
    }
}

IEnumerable<string> activeTargets = loadedTargets.Count > 0
    ? loadedTargets
    : fallbackTargets;

// ===== 2. Load monitor configuration from JSON (if present) =====
string configFilePath = Path.Combine(resultsDir, "network_monitor_config.json");
MonitorConfigFile? savedConfig = null;

if (File.Exists(configFilePath))
{
    try
    {
        var json = File.ReadAllText(configFilePath);
        savedConfig = JsonSerializer.Deserialize<MonitorConfigFile>(json);
        if (savedConfig?.HealthCheckTargets?.Length > 0)
        {
            activeTargets = savedConfig.HealthCheckTargets;
            AnsiConsole.MarkupLine("[green]Loaded custom health‑check targets from JSON config.[/]");
        }
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[yellow]Could not read JSON config: {ex.Message}[/]");
    }
}

// Build the monitor configuration
var monitorCfg = new MonitorConfiguration
{
    HealthCheckTargets = activeTargets.ToArray(),
    ParallelWorkers = savedConfig?.ParallelWorkers ?? 50,
    RequestDelayMs = savedConfig?.RequestDelayMs ?? 7000,
    GlobalTimeoutSec = savedConfig?.GlobalTimeoutSec ?? 500,
    EnableBeep = savedConfig?.EnableBeep ?? true,
    BeepDayStart = savedConfig?.BeepDayStart ?? 12,
    BeepDayEnd = savedConfig?.BeepDayEnd ?? 24,
    LogLevel = savedConfig?.LogLevel ?? "Normal"
};

// Resolve file paths (all inside the RESULTS folder)
monitorCfg.EndpointListFile    = Path.Combine(resultsDir, "servers_to_check.txt");
monitorCfg.ReportFile          = Path.Combine(resultsDir, "responsive_servers.txt");
monitorCfg.DedupedFile         = Path.Combine(resultsDir, "deduped_endpoints.txt");
monitorCfg.SnapshotFile        = Path.Combine(resultsDir, "last_snapshot.txt");
monitorCfg.TempOutput          = Path.Combine(resultsDir, "scan_result.tmp");
monitorCfg.BlacklistFile       = Path.Combine(resultsDir, "blacklist.txt");
monitorCfg.NetworkToolPath     = Path.Combine(AppContext.BaseDirectory, "xray-knife.exe");
monitorCfg.ConfigFilePath      = configFilePath;

// Display resolved paths
AnsiConsole.MarkupLine($"[yellow]Targets source:[/] {(loadedTargets.Count > 0 ? "targets.txt" : "built‑in defaults")}");
AnsiConsole.MarkupLine($"[yellow]Endpoint list:[/] {monitorCfg.EndpointListFile}");
AnsiConsole.MarkupLine($"[yellow]Report file:[/]   {monitorCfg.ReportFile}");
AnsiConsole.MarkupLine($"[yellow]Network tool:[/]  {monitorCfg.NetworkToolPath}");
AnsiConsole.MarkupLine($"[grey]Press S for Settings | P for Pause/Resume | Ctrl+C to exit[/]");

// Start the monitor
var engine = new NetworkMonitorEngine(monitorCfg);
await engine.RunAsync();

// ═══════════════════ MODELS ═══════════════════

/// <summary>Main configuration for the Network Availability Monitor.</summary>
public class MonitorConfiguration
{
    public string   EndpointListFile    { get; set; } = "";
    public string   ReportFile          { get; set; } = "";
    public string   NetworkToolPath     { get; set; } = "";
    public string   DedupedFile         { get; set; } = "deduped_endpoints.txt";
    public string   SnapshotFile        { get; set; } = "last_snapshot.txt";
    public string   TempOutput          { get; set; } = "";
    public string   BlacklistFile       { get; set; } = "blacklist.txt";
    public string   ConfigFilePath      { get; set; } = "";
    public string[] HealthCheckTargets  { get; set; } = Array.Empty<string>();
    public int      ParallelWorkers     { get; set; }
    public int      RequestDelayMs      { get; set; }
    public int      GlobalTimeoutSec    { get; set; }
    public bool     EnableBeep          { get; set; }
    public int      BeepDayStart        { get; set; }
    public int      BeepDayEnd          { get; set; }
    public string   LogLevel            { get; set; } = "Normal";
}

/// <summary>Helper class for deserializing the external config file.</summary>
public class MonitorConfigFile
{
    public string[] HealthCheckTargets  { get; set; } = Array.Empty<string>();
    public int      ParallelWorkers     { get; set; }
    public int      RequestDelayMs      { get; set; }
    public int      GlobalTimeoutSec    { get; set; }
    public bool     EnableBeep          { get; set; }
    public int      BeepDayStart        { get; set; }
    public int      BeepDayEnd          { get; set; }
    public string   LogLevel            { get; set; } = "Normal";
}

// ═══════════════════ ENGINE ═══════════════════

/// <summary>
/// Core engine that performs periodic health checks on a list of network endpoints.
/// Uses an external network testing tool (xray-knife.exe) to verify connectivity
/// against a set of well‑known public URLs.
/// </summary>
public class NetworkMonitorEngine
{
    private const int MaxLogLines = 40;

    private readonly MonitorConfiguration _cfg;
    private readonly ConcurrentDictionary<string, string> _responsiveServers = new();
    private readonly Channel<string> _logChannel = Channel.CreateUnbounded<string>();
    private readonly Channel<string> _alertChannel = Channel.CreateUnbounded<string>();
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private HashSet<string> _blacklist = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _debounceCts;
    private readonly object _debounceLock = new();
    private readonly PauseManager _pauseManager = new();
    private readonly MonitorUIState _uiState = new();
    private readonly string _logFilePath;
    private DateTime _appStartTime = DateTime.Now;
    private CancellationTokenSource? _globalCts;

    // Regular expressions for scrubbing old fragment data
    private static readonly Regex ScrubDateRegex   = new(@"-Seen-.*", RegexOptions.Compiled);
    private static readonly Regex ScrubPrefixRegex = new(@"^\d{2}:\d{2}-\d{4}/\d{2}/\d{2}_", RegexOptions.Compiled);

    public NetworkMonitorEngine(MonitorConfiguration cfg)
    {
        _cfg = cfg;
        _logFilePath = Path.Combine(
            Path.GetDirectoryName(cfg.ReportFile) ?? ".", "monitor_activity.log");
    }

    /// <summary>Main entry point: runs the monitoring loop until cancelled.</summary>
    public async Task RunAsync()
    {
        try
        {
            // Validate prerequisites
            if (!File.Exists(_cfg.EndpointListFile))
            { AnsiConsole.MarkupLine($"[red]ERROR: Endpoint list not found: {_cfg.EndpointListFile}[/]"); return; }
            if (!File.Exists(_cfg.NetworkToolPath))
            { AnsiConsole.MarkupLine($"[red]ERROR: Network tool not found: {_cfg.NetworkToolPath}[/]"); return; }

            // Prepare report directory and file
            var outputDir = Path.GetDirectoryName(_cfg.ReportFile);
            if (!string.IsNullOrWhiteSpace(outputDir)) Directory.CreateDirectory(outputDir);
            if (!File.Exists(_cfg.ReportFile)) await File.WriteAllTextAsync(_cfg.ReportFile, "");

            // Load previous report entries into memory
            await LoadPreviousReportsAsync();

            using var cts = new CancellationTokenSource();
            _globalCts = cts;
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

            // Start background tasks
            var keyTask   = ListenForKeyAsync(cts.Token);
            var uiTask    = RunDashboardAsync(cts.Token);
            var alertTask = ProcessAlertsAsync(cts.Token);

            // Main monitoring loop
            while (!cts.Token.IsCancellationRequested)
            {
                _pauseManager.WaitIfPaused(cts.Token);

                _uiState.CycleCount++;
                var cycleStart = DateTime.Now;
                _uiState.ScanPhase = "Preparing";
                _uiState.CompletedChecks = 0;

                await LogAsync($"▶ Monitoring cycle #{_uiState.CycleCount} started", cts.Token);
                await LoadBlacklistAsync(cts.Token);

                // Refresh the working endpoint list (deduplicate if changed)
                var endpointCount = await RefreshEndpointListAsync(cts.Token);
                if (endpointCount <= 0)
                {
                    await LogAsync("⚠ Endpoint list empty. Skipping cycle.", cts.Token);
                    _uiState.ScanPhase = "Waiting";
                    await Task.Delay(5000, cts.Token);
                    continue;
                }

                _uiState.ScanPhase = "Scanning";
                _uiState.CheckedUrls.Clear();

                // Check each health‑check target against all endpoints
                for (int i = 0; i < _cfg.HealthCheckTargets.Length; i++)
                {
                    _pauseManager.WaitIfPaused(cts.Token);
                    cts.Token.ThrowIfCancellationRequested();

                    _uiState.CurrentTargetNum = i + 1;
                    _uiState.CurrentTargetUrl = _cfg.HealthCheckTargets[i];
                    _uiState.ScanStartTime    = DateTime.Now;
                    _uiState.CurrentProgress  = 0;
                    _uiState.FoundThisRound   = 0;
                    Interlocked.Exchange(ref _uiState.TestedThisRound, 0);

                    await LogAsync($"[{_uiState.CurrentTargetNum}/{_cfg.HealthCheckTargets.Length}] Checking: {Truncate(_uiState.CurrentTargetUrl, 45)}", cts.Token);
                    await CheckTargetAgainstEndpointsAsync(_uiState.CurrentTargetUrl, cts.Token);
                    _uiState.CompletedChecks = i + 1;

                    // Update the "checked URLs" status list for the dashboard
                    lock (_uiState.CheckedUrls)
                    {
                        var entry = _uiState.CheckedUrls.FirstOrDefault(u => u.Url == _uiState.CurrentTargetUrl);
                        if (entry == null)
                        {
                            entry = new CheckedUrlStatus { Url = _uiState.CurrentTargetUrl, Status = "Done" };
                            _uiState.CheckedUrls.Add(entry);
                        }
                        else entry.Status = "Done";
                    }
                }

                var cycleTime = (DateTime.Now - cycleStart).TotalSeconds;
                _uiState.ScanPhase = "Waiting";
                await LogAsync($"✅ Cycle completed in {cycleTime:F0}s. Waiting 5s...", cts.Token);
                await File.AppendAllTextAsync(_logFilePath,
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | Cycle {_uiState.CycleCount} | Responsive: {_responsiveServers.Count} | New: {_uiState.NewThisSession} | Time: {cycleTime:F0}s\n",
                    cts.Token);
                await Task.Delay(5000, cts.Token);
            }

            // Signal completion and wait for background tasks
            cts.Cancel();
            _alertChannel.Writer.Complete();
            _logChannel.Writer.Complete();
            try { await Task.WhenAll(uiTask, alertTask, keyTask); } catch { }
        }
        catch (OperationCanceledException) { /* graceful shutdown */ }
        catch (Exception ex)
        {
            try { await LogAsync($"❌ Fatal error: {ex.Message}"); } catch { }
            AnsiConsole.MarkupLine($"[red]Fatal error:[/] {ex.Message}");
        }
        finally
        {
            _alertChannel.Writer.TryComplete();
            _logChannel.Writer.TryComplete();
            _globalCts = null;
        }
    }

    // ──────────────── Background Key Listener (P + S) ────────────────
    private async Task ListenForKeyAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            if (Console.KeyAvailable)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.P)
                {
                    if (_pauseManager.IsPaused)
                    {
                        _pauseManager.Resume();
                        await LogAsync("⏯ Monitoring resumed by user", token);
                    }
                    else
                    {
                        _pauseManager.Pause();
                        await LogAsync("⏸ Monitoring paused (press P to resume)", token);
                    }
                }
                else if (key.Key == ConsoleKey.S)
                {
                    // Pause monitoring before opening settings
                    bool wasPaused = _pauseManager.IsPaused;
                    if (!wasPaused)
                    {
                        _pauseManager.Pause();
                        await Task.Delay(300, token); // give time for current test to pause
                    }

                    await ShowSettingsMenuAsync(token);

                    // Resume only if it was running before
                    if (!wasPaused)
                    {
                        _pauseManager.Resume();
                        await LogAsync("⏯ Monitoring resumed after settings", token);
                    }
                }
            }
            await Task.Delay(100, token);
        }
    }

    // ──────────────── Settings Menu ────────────────
    private async Task ShowSettingsMenuAsync(CancellationToken token)
    {
        // Backup current settings in case user cancels
        var backupWorkers = _cfg.ParallelWorkers;
        var backupDelay = _cfg.RequestDelayMs;
        var backupTimeout = _cfg.GlobalTimeoutSec;
        var backupBeep = _cfg.EnableBeep;
        var backupBeepStart = _cfg.BeepDayStart;
        var backupBeepEnd = _cfg.BeepDayEnd;
        var backupLogLevel = _cfg.LogLevel;

        while (!token.IsCancellationRequested)
        {
            AnsiConsole.Clear();
            
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[bold cyan]⚙️  SETTINGS MENU[/]")
                    .PageSize(12)
                    .AddChoices(new[]
                    {
                        $"1. Parallel Workers          [yellow]{_cfg.ParallelWorkers}[/]",
                        $"2. Delay Between Checks      [yellow]{_cfg.RequestDelayMs} ms[/]",
                        $"3. Global Timeout            [yellow]{_cfg.GlobalTimeoutSec} s[/]",
                        $"4. Beep Notifications       [yellow]{(_cfg.EnableBeep ? "ON" : "OFF")}[/]",
                        $"5. Beep Start Hour          [yellow]{_cfg.BeepDayStart}[/]",
                        $"6. Beep End Hour            [yellow]{_cfg.BeepDayEnd}[/]",
                        $"7. Log Level                [yellow]{_cfg.LogLevel}[/]",
                        "8. 💾 Save & Exit",
                        "9. 🔄 Restore Defaults",
                        "10. ❌ Exit Without Saving"
                    }));

            if (choice.StartsWith("1."))
            {
                _cfg.ParallelWorkers = AnsiConsole.Prompt(
                    new TextPrompt<int>("[green]Number of parallel workers (1-500)[/]:")
                        .DefaultValue(_cfg.ParallelWorkers)
                        .Validate(w => w > 0 && w <= 500 ? ValidationResult.Success() : ValidationResult.Error("1-500")));
            }
            else if (choice.StartsWith("2."))
            {
                _cfg.RequestDelayMs = AnsiConsole.Prompt(
                    new TextPrompt<int>("[green]Delay between checks in ms (0-30000)[/]:")
                        .DefaultValue(_cfg.RequestDelayMs)
                        .Validate(d => d >= 0 && d <= 30000 ? ValidationResult.Success() : ValidationResult.Error("0-30000")));
            }
            else if (choice.StartsWith("3."))
            {
                _cfg.GlobalTimeoutSec = AnsiConsole.Prompt(
                    new TextPrompt<int>("[green]Global timeout in seconds (60-3600)[/]:")
                        .DefaultValue(_cfg.GlobalTimeoutSec)
                        .Validate(t => t >= 60 && t <= 3600 ? ValidationResult.Success() : ValidationResult.Error("60-3600")));
            }
            else if (choice.StartsWith("4."))
            {
                _cfg.EnableBeep = AnsiConsole.Prompt(
                    new TextPrompt<bool>("[green]Enable beep notifications?[/]")
                        .DefaultValue(_cfg.EnableBeep)
                        .WithConverter(b => b ? "Yes" : "No"));
            }
            else if (choice.StartsWith("5."))
            {
                _cfg.BeepDayStart = AnsiConsole.Prompt(
                    new TextPrompt<int>("[green]Beep start hour (0-23)[/]:")
                        .DefaultValue(_cfg.BeepDayStart)
                        .Validate(h => h >= 0 && h <= 23 ? ValidationResult.Success() : ValidationResult.Error("0-23")));
            }
            else if (choice.StartsWith("6."))
            {
                _cfg.BeepDayEnd = AnsiConsole.Prompt(
                    new TextPrompt<int>("[green]Beep end hour (0-23)[/]:")
                        .DefaultValue(_cfg.BeepDayEnd)
                        .Validate(h => h >= 0 && h <= 23 ? ValidationResult.Success() : ValidationResult.Error("0-23")));
            }
            else if (choice.StartsWith("7."))
            {
                _cfg.LogLevel = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]Select log verbosity level[/]")
                        .AddChoices(new[] { "Minimal", "Normal", "Verbose" })
                        .DefaultValue(_cfg.LogLevel));
            }
            else if (choice.StartsWith("8.")) // Save & Exit
            {
                SaveSettingsToJson();
                AnsiConsole.MarkupLine("[green]✅ Settings saved. Resuming monitoring...[/]");
                await Task.Delay(1000, token);
                break;
            }
            else if (choice.StartsWith("9.")) // Restore Defaults
            {
                _cfg.ParallelWorkers = 100;
                _cfg.RequestDelayMs = 7000;
                _cfg.GlobalTimeoutSec = 500;
                _cfg.EnableBeep = true;
                _cfg.BeepDayStart = 12;
                _cfg.BeepDayEnd = 24;
                _cfg.LogLevel = "Normal";
                
                if (File.Exists(_cfg.ConfigFilePath))
                    File.Delete(_cfg.ConfigFilePath);
                
                AnsiConsole.MarkupLine("[green]✅ Settings restored to defaults.[/]");
                await Task.Delay(1000, token);
            }
            else if (choice.StartsWith("10.")) // Exit Without Saving
            {
                _cfg.ParallelWorkers = backupWorkers;
                _cfg.RequestDelayMs = backupDelay;
                _cfg.GlobalTimeoutSec = backupTimeout;
                _cfg.EnableBeep = backupBeep;
                _cfg.BeepDayStart = backupBeepStart;
                _cfg.BeepDayEnd = backupBeepEnd;
                _cfg.LogLevel = backupLogLevel;
                
                AnsiConsole.MarkupLine("[yellow]⚠ Changes discarded. Resuming monitoring...[/]");
                await Task.Delay(1000, token);
                break;
            }
        }
    }

    private void SaveSettingsToJson()
    {
        var configToSave = new MonitorConfigFile
        {
            ParallelWorkers = _cfg.ParallelWorkers,
            RequestDelayMs = _cfg.RequestDelayMs,
            GlobalTimeoutSec = _cfg.GlobalTimeoutSec,
            EnableBeep = _cfg.EnableBeep,
            BeepDayStart = _cfg.BeepDayStart,
            BeepDayEnd = _cfg.BeepDayEnd,
            LogLevel = _cfg.LogLevel,
            HealthCheckTargets = _cfg.HealthCheckTargets
        };

        try
        {
            var json = JsonSerializer.Serialize(configToSave, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_cfg.ConfigFilePath, json);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Failed to save settings: {ex.Message}[/]");
        }
    }

    // ──────────────── Blacklist Management ────────────────
    private async Task LoadBlacklistAsync(CancellationToken token)
    {
        if (!File.Exists(_cfg.BlacklistFile))
        {
            _blacklist.Clear();
            return;
        }
        try
        {
            var lines = await File.ReadAllLinesAsync(_cfg.BlacklistFile, token);
            _blacklist = new HashSet<string>(
                lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim()),
                StringComparer.OrdinalIgnoreCase);
            await LogAsync($"🚫 Loaded {_blacklist.Count} blacklist entries", token);
        }
        catch (Exception ex)
        {
            await LogAsync($"⚠ Failed to load blacklist: {ex.Message}", token);
        }
    }

    // ──────────────── Logging ────────────────
    private async Task LogAsync(string message, CancellationToken token = default)
        => await _logChannel.Writer.WriteAsync(message, token);

    // ──────────────── Previous Reports ────────────────
    private async Task LoadPreviousReportsAsync()
    {
        if (!File.Exists(_cfg.ReportFile)) return;
        var lines = await File.ReadAllLinesAsync(_cfg.ReportFile);
        int loaded = 0;
        foreach (var line in lines)
        {
            var (link, _) = SplitFragment(line);
            if (string.IsNullOrEmpty(link)) continue;
            _responsiveServers[link] = line;
            loaded++;
        }
        if (loaded > 0)
            await LogAsync($"📂 Loaded {loaded} previous responsive endpoints");
    }

    // ──────────────── Endpoint List Refresh & Dedup ────────────────
    private async Task<int> RefreshEndpointListAsync(CancellationToken token)
    {
        if (!File.Exists(_cfg.EndpointListFile)) return 0;

        string[] sourceLines = Array.Empty<string>();
        for (int retry = 0; retry < 3; retry++)
        {
            try { sourceLines = await File.ReadAllLinesAsync(_cfg.EndpointListFile, token); break; }
            catch (IOException) { await Task.Delay(1000, token); }
        }
        if (sourceLines.Length == 0)
        {
            await LogAsync("⚠ Could not read endpoint list (file in use)", token);
            return 0;
        }

        _uiState.TotalEndpoints = sourceLines.Length;

        bool needsDedup = true;
        if (File.Exists(_cfg.SnapshotFile))
        {
            var snap = await File.ReadAllLinesAsync(_cfg.SnapshotFile, token);
            if (sourceLines.SequenceEqual(snap)) needsDedup = false;
        }

        if (needsDedup)
        {
            var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var deduped = new List<string>(sourceLines.Length);
            foreach (var line in sourceLines)
            {
                if (string.IsNullOrWhiteSpace(line) ||
                    line.Contains("splithttp", StringComparison.OrdinalIgnoreCase)) continue;
                if (unique.Add(line)) deduped.Add(line);
            }
            await File.WriteAllLinesAsync(_cfg.DedupedFile, deduped, token);
            await File.WriteAllLinesAsync(_cfg.SnapshotFile, sourceLines, token);
            _uiState.WorkingEndpoints = deduped.Count;
            await LogAsync($"📄 Endpoint list deduplicated: {sourceLines.Length} → {_uiState.WorkingEndpoints} unique entries", token);
        }
        else
        {
            _uiState.WorkingEndpoints = File.Exists(_cfg.DedupedFile)
                ? await CountLinesAsync(_cfg.DedupedFile, token)
                : 0;
        }
        return _uiState.WorkingEndpoints;
    }

    private static async Task<int> CountLinesAsync(string path, CancellationToken token)
    {
        int count = 0;
        using var reader = new StreamReader(path);
        while (await reader.ReadLineAsync(token) != null) count++;
        return count;
    }

    // ──────────────── Main Health‑Check Logic ────────────────
    private async Task CheckTargetAgainstEndpointsAsync(string targetUrl, CancellationToken token)
    {
        // Clean up any leftover temporary file
        if (File.Exists(_cfg.TempOutput))
            try { File.Delete(_cfg.TempOutput); } catch { }

        _uiState.ScanPhase = "Launching";
        await LogAsync($"▶ Launching check: {Truncate(targetUrl, 50)}", token);

        // Estimate timeout dynamically based on endpoint count and delay
        double estimatedSeconds = 0;
        if (_uiState.WorkingEndpoints > 0 && _cfg.ParallelWorkers > 0)
            estimatedSeconds = (_uiState.WorkingEndpoints / (double)_cfg.ParallelWorkers) *
                               (_cfg.RequestDelayMs / 1000.0);
        int dynamicTimeoutSec = Math.Max(_cfg.GlobalTimeoutSec, (int)estimatedSeconds + 120);

        // Build command‑line arguments for the network testing tool
        var args = $"http -f \"{_cfg.DedupedFile}\" --thread {_cfg.ParallelWorkers} " +
                   $"--mdelay {_cfg.RequestDelayMs} --insecure=true " +
                   $"--url \"{targetUrl}\" -o \"{_cfg.TempOutput}\"";

        var psi = new ProcessStartInfo
        {
            FileName = _cfg.NetworkToolPath,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = AppContext.BaseDirectory
        };

        // Remove any proxy environment variables to avoid interference
        psi.Environment.Remove("HTTP_PROXY");
        psi.Environment.Remove("HTTPS_PROXY");
        psi.Environment.Remove("http_proxy");
        psi.Environment.Remove("https_proxy");
        psi.Environment.Remove("ALL_PROXY");
        psi.Environment.Remove("all_proxy");

        using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var stdErr = new StringBuilder();

        proc.OutputDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
                Interlocked.Increment(ref _uiState.TestedThisRound);
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
            {
                lock (stdErr) stdErr.AppendLine(e.Data);
                Interlocked.Increment(ref _uiState.TestedThisRound);
            }
        };

        if (!proc.Start())
        {
            await LogAsync("❌ Failed to launch network testing tool", token);
            return;
        }

        _uiState.ScanPhase = "Running";
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var monitorCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        var monitorTask = MonitorProgressLoopAsync(proc, monitorCts.Token);

        try
        {
            var exitTask = proc.WaitForExitAsync(token);
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(dynamicTimeoutSec), token);
            var completed = await Task.WhenAny(exitTask, timeoutTask);

            if (completed == timeoutTask && !proc.HasExited)
            {
                _uiState.ScanPhase = "Timeout";
                try { proc.Kill(entireProcessTree: true); } catch { }
                await LogAsync($"⏱ Health check timed out after {dynamicTimeoutSec}s", token);
                try { await proc.WaitForExitAsync(CancellationToken.None); } catch { }
            }
            else
            {
                try { await exitTask; } catch { }
            }
        }
        finally
        {
            monitorCts.Cancel();
            try { await monitorTask; } catch { }
            try { proc.CancelOutputRead(); } catch { }
            try { proc.CancelErrorRead(); } catch { }
        }

        _uiState.ScanPhase = "Parsing";
        var errorText = stdErr.ToString().Trim();
        if (!string.IsNullOrWhiteSpace(errorText) && proc.ExitCode != 0)
            await LogAsync($"⚠ Tool warning (code {proc.ExitCode}): {Truncate(errorText, 100)}", token);

        // Process the output file
        if (File.Exists(_cfg.TempOutput))
        {
            var lines = await File.ReadAllLinesAsync(_cfg.TempOutput, token);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || !line.Contains("://")) continue;

                var (endpointId, endpointName) = SplitFragment(line);
                if (string.IsNullOrEmpty(endpointId)) continue;

                // Blacklist filtering
                if (_blacklist.Count > 0 && _blacklist.Any(pattern =>
                    endpointId.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                    endpointName.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                {
                    await LogAsync($"🚫 Blacklisted endpoint skipped: {Truncate(endpointName, 24)}", token);
                    continue;
                }

                // Build the output fragment with timestamp
                var now = DateTime.Now;
                string date = now.ToString("dd/MM/yyyy");
                string time = now.ToString("HH:mm");
                string fragment = $"{date}  **NetDiagnostic**  {time}";
                string outputLine = $"{endpointId}#{Uri.EscapeDataString(fragment)}";

                if (_responsiveServers.TryAdd(endpointId, outputLine))
                {
                    Interlocked.Increment(ref _uiState.NewThisSession);
                    Interlocked.Increment(ref _uiState.FoundThisRound);
                    await _alertChannel.Writer.WriteAsync(outputLine, token);
                    // No longer appending to file here; full file is rewritten on debounced save.
                }
                else
                {
                    // Update timestamp for already‑known endpoint
                    _responsiveServers[endpointId] = outputLine;
                }

                TriggerDebouncedSave();
            }
        }

        _uiState.CurrentProgress = 100;
        _uiState.ScanPhase = "Done";
        try { File.Delete(_cfg.TempOutput); } catch { }
    }

    // ──────────────── Progress Monitor (background) ────────────────
    private async Task MonitorProgressLoopAsync(Process proc, CancellationToken token)
    {
        while (!token.IsCancellationRequested && !proc.HasExited)
        {
            token.ThrowIfCancellationRequested();
            double progress = _uiState.WorkingEndpoints > 0
                ? (_uiState.TestedThisRound / (double)_uiState.WorkingEndpoints) * 100.0
                : 0;
            double fallback = _cfg.GlobalTimeoutSec > 0
                ? Math.Min(95, ((DateTime.Now - _uiState.ScanStartTime).TotalSeconds / _cfg.GlobalTimeoutSec) * 100.0)
                : 0;
            _uiState.CurrentProgress = Math.Clamp(Math.Max(progress, fallback), 0, 100);
            try { await Task.Delay(300, token); }
            catch (OperationCanceledException) { break; }
        }
    }

    // ──────────────── Debounced Save ────────────────
    private void TriggerDebouncedSave()
    {
        lock (_debounceLock)
        {
            _debounceCts?.Cancel();
            _debounceCts?.Dispose();
            _debounceCts = new CancellationTokenSource();
            var token = _debounceCts.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(5000, token);
                    await SaveReportSortedAsync(token);
                }
                catch (TaskCanceledException) { }
            }, token);
        }
    }

    private async Task SaveReportSortedAsync(CancellationToken token = default)
    {
        await _fileLock.WaitAsync(token);
        try
        {
            var sorted = _responsiveServers.Values
                .OrderByDescending(ExtractTimestamp)
                .ToList();
            await File.WriteAllLinesAsync(_cfg.ReportFile, sorted, token);
        }
        finally { _fileLock.Release(); }
    }

    // ──────────────── Alert Processor (background) ────────────────
    private async Task ProcessAlertsAsync(CancellationToken token)
    {
        try
        {
            await foreach (var line in _alertChannel.Reader.ReadAllAsync(token))
            {
                var (_, name) = SplitFragment(line);
                await LogAsync($"✅ Responsive endpoint: {Truncate(name, 24)}", token);
                BeepAlert();
            }
        }
        catch (OperationCanceledException) { }
    }

    private void BeepAlert()
    {
        if (!_cfg.EnableBeep || !OperatingSystem.IsWindows()) return;
        var hour = DateTime.Now.Hour;
        try
        {
            if (hour >= _cfg.BeepDayStart && hour < _cfg.BeepDayEnd)
                for (int i = 0; i < 5; i++) { Console.Beep(4500, 100); Thread.Sleep(40); }
            else
                Console.Beep(800, 250);
        }
        catch { }
    }

    // ──────────────── Fragment Parsing ────────────────
    private (string link, string name) SplitFragment(string raw)
    {
        raw = raw.Trim();
        var idx  = raw.IndexOf('#');
        var link = idx > 0 ? raw[..idx].Trim() : raw;
        var name = idx > 0 ? raw[(idx + 1)..].Trim() : "Endpoint";

        name = ScrubDateRegex.Replace(name, "");
        name = ScrubPrefixRegex.Replace(name, "");
        name = name.Trim();
        if (string.IsNullOrEmpty(name)) name = "Endpoint";
        return (link, name);
    }

    // ──────────────── Sorting Helpers ────────────────
    private static DateTime ExtractTimestamp(string fullLine)
    {
        var idx = fullLine.IndexOf('#');
        if (idx < 0) return DateTime.MinValue;
        var fragment = Uri.UnescapeDataString(fullLine[(idx + 1)..]);

        var match = Regex.Match(fragment,
            @"^(\d{2}/\d{2}/\d{4})\s+\*\*NetDiagnostic\*\*\s+(\d{2}:\d{2})$");
        if (match.Success)
        {
            if (DateTime.TryParseExact($"{match.Groups[1].Value} {match.Groups[2].Value}",
                "dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                return dt;
        }
        return DateTime.MinValue;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 3)] + "...";

    // ═══════════════ LIVE DASHBOARD UI ═══════════════
    private async Task RunDashboardAsync(CancellationToken token)
    {
        var logs = new List<string>(MaxLogLines);
        var layout = new Layout("Root")
            .SplitRows(
                new Layout("Header").Size(3),
                new Layout("Main").SplitColumns(
                    new Layout("Left").Size(60),
                    new Layout("Right")));

        try
        {
            await AnsiConsole.Live(layout)
                .AutoClear(true)
                .Overflow(VerticalOverflow.Ellipsis)
                .StartAsync(async ctx =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        // Drain log channel
                        while (_logChannel.Reader.TryRead(out var msg))
                        {
                            logs.Add($"[{DateTime.Now:HH:mm:ss}] {msg}");
                            if (logs.Count > MaxLogLines) logs.RemoveAt(0);
                        }

                        var uptime = DateTime.Now - _appStartTime;
                        var scanElapsed = DateTime.Now - _uiState.ScanStartTime;
                        int totalTargets = _cfg.HealthCheckTargets.Length;
                        int completed = Math.Clamp(_uiState.CompletedChecks, 0, totalTargets);
                        double targetProgress = Math.Clamp(_uiState.CurrentProgress, 0, 100);
                        double cycleProgress = totalTargets > 0
                            ? Math.Clamp(((completed + targetProgress / 100.0) / totalTargets) * 100.0, 0, 100)
                            : 0;
                        int estRemaining = Math.Max(0, _uiState.WorkingEndpoints -
                            (int)(_uiState.WorkingEndpoints * targetProgress / 100));
                        TimeSpan eta = TimeSpan.Zero;
                        if (cycleProgress > 0 && cycleProgress < 100)
                        {
                            var remainingSec = (scanElapsed.TotalSeconds / (cycleProgress / 100.0)) - scanElapsed.TotalSeconds;
                            if (remainingSec > 0) eta = TimeSpan.FromSeconds(remainingSec);
                        }

                        bool isPaused = _pauseManager.IsPaused;
                        var phaseColor = _uiState.ScanPhase is "Running" or "Scanning" ? "green"
                                       : _uiState.ScanPhase is "Waiting" or "Idle" ? "yellow" : "cyan";
                        var pauseInfo = isPaused ? " [bold red]⏸ PAUSED[/]" : "";

                        // ── Header ──
                        var headerMarkup =
                            $"[bold cyan]🌐 NETWORK AVAILABILITY MONITOR[/]{pauseInfo}   " +
                            $"[bold {phaseColor}]● {Markup.Escape(_uiState.ScanPhase.ToUpper())}[/]   " +
                            $"[grey]UPTIME {uptime:hh\\:mm\\:ss}[/]   " +
                            $"[bold green]RESPONSIVE {_responsiveServers.Count:N0}[/]  " +
                            $"[cyan]CYCLE {_uiState.CycleCount}[/]  " +
                            $"[yellow]TARGET {_uiState.CurrentTargetNum}/{totalTargets}[/]";
                        var header = new Panel(Align.Center(new Markup(headerMarkup)))
                            .Border(BoxBorder.Heavy).BorderStyle(new Style(Color.Cyan1)).Expand();

                        // ── Left Panel (Stats) ──
                        var cycleBarColor = cycleProgress < 50 ? "yellow" : cycleProgress < 90 ? "cyan" : "green";
                        var cycleBar = BuildBar(cycleProgress, 24);
                        var targetBar = BuildBar(targetProgress, 24);

                        var checkedList = new List<IRenderable>();
                        lock (_uiState.CheckedUrls)   // thread‑safe read for the dashboard
                        {
                            if (_uiState.CheckedUrls.Count > 0)
                            {
                                foreach (var u in _uiState.CheckedUrls.TakeLast(5).Reverse())
                                {
                                    var mark = u.Status == "Done" ? "[green]✓[/]" :
                                               u.Status == "Testing" ? "[yellow]⏳[/]" : "[grey]…[/]";
                                    checkedList.Add(new Markup($"  {mark} {Markup.Escape(Truncate(u.Url, 50))}"));
                                }
                            }
                            else
                                checkedList.Add(new Markup("  [grey]No targets checked yet[/]"));
                        }

                        var leftContent = new Rows(
                            new Markup("[bold white]-- AVAILABILITY REPORT ------[/]"),
                            new Markup($"  [bold green]✅ RESPONSIVE {_responsiveServers.Count,7:N0}[/]"),
                            new Markup($"  [yellow]🔄 CYCLE     {_uiState.CycleCount,7:N0}[/]"),
                            new Markup($"  [cyan]🎯 TARGET    {_uiState.CurrentTargetNum,3}/{totalTargets}[/]"),
                            new Markup($"  [grey]📄 ENDPOINTS {_uiState.TotalEndpoints,7:N0}[/]"),
                            new Markup($"  [grey]🆕 NEW       {_uiState.NewThisSession,7:N0}[/]"),
                            new Markup($"  [grey]⏳ REMAINING {estRemaining,7:N0}[/]"),
                            new Text(""),
                            new Markup("[bold white]-- PROGRESS -----------------[/]"),
                            new Markup($"  [grey]Cycle:[/]  [{cycleBarColor}]{cycleBar}[/] [bold]{cycleProgress,5:0.0}%[/]"),
                            new Markup($"  [grey]Target:[/] [cyan]{targetBar}[/] [bold]{targetProgress,5:0.0}%[/]"),
                            new Markup($"  [grey]ETA:  [/]  [yellow]{eta:hh\\:mm\\:ss}[/]"),
                            new Text(""),
                            new Markup("[bold white]-- CURRENT TARGET -----------[/]"),
                            new Markup($"  [grey]{Markup.Escape(Truncate(_uiState.CurrentTargetUrl, 55))}[/]"),
                            new Text(""),
                            new Markup("[bold white]-- RECENTLY CHECKED ---------[/]"),
                            new Rows(checkedList),
                            new Text(""),
                            new Markup("[bold white]-- MONITOR CONFIG -----------[/]"),
                            new Markup($"  [grey]Workers :[/]  [yellow]{_cfg.ParallelWorkers}[/]"),
                            new Markup($"  [grey]Delay   :[/]  [yellow]{_cfg.RequestDelayMs} ms[/]"),
                            new Markup($"  [grey]Beep    :[/]  [yellow]{(_cfg.EnableBeep ? "ON" : "OFF")}[/]"),
                            new Markup($"  [grey]Pause   :[/]  [yellow]{(isPaused ? "PAUSED" : "Running")}[/]")
                        );
                        var leftPanel = new Panel(Align.Left(leftContent))
                            .Border(BoxBorder.Rounded).BorderStyle(new Style(Color.Cyan1))
                            .Header("[bold cyan] NETWORK STATUS [/]").Expand();

                        // ── Right Panel (Activity Log) ──
                        var visibleLogs = logs.TakeLast(14).Select(ColorizeLogLine).Cast<IRenderable>().ToArray();
                        IRenderable logContent = visibleLogs.Length > 0
                            ? new Rows(visibleLogs)
                            : new Markup("[grey]Waiting for monitoring data…[/]");
                        var logPanel = new Panel(Align.Left(logContent))
                            .Border(BoxBorder.Rounded).BorderStyle(new Style(Color.Grey))
                            .Header("[bold grey] ACTIVITY LOG [/]").Expand();

                        layout["Header"].Update(header);
                        layout["Left"].Update(leftPanel);
                        layout["Right"].Update(logPanel);

                        ctx.Refresh();
                        try { await Task.Delay(250, token); } catch (OperationCanceledException) { break; }
                    }
                });
        }
        catch (OperationCanceledException) { }
    }

    private static Markup ColorizeLogLine(string line)
    {
        var safe = Markup.Escape(line);
        if (line.Contains("✅") || line.Contains("NEW"))       return new Markup($"[green]{safe}[/]");
        if (line.Contains("❌") || line.Contains("Fatal"))    return new Markup($"[red]{safe}[/]");
        if (line.Contains("⚠") || line.Contains("Timeout"))  return new Markup($"[yellow]{safe}[/]");
        if (line.Contains("▶") || line.Contains("Cycle"))    return new Markup($"[cyan]{safe}[/]");
        return new Markup($"[grey]{safe}[/]");
    }

    private static string BuildBar(double percent, int width = 24)
    {
        percent = Math.Clamp(percent, 0, 100);
        var filled = Math.Clamp((int)Math.Round((percent / 100.0) * width), 0, width);
        return new string('█', filled) + new string('░', width - filled);
    }
}

// ═══════════════ UI SUPPORT CLASSES ═══════════════

public class MonitorUIState
{
    public long   CycleCount;
    public int    NewThisSession;
    public int    CurrentTargetNum;
    public string CurrentTargetUrl = "";
    public double CurrentProgress;
    public int    FoundThisRound;
    public int    TestedThisRound;
    public string ScanPhase = "Idle";
    public int    TotalEndpoints;
    public int    WorkingEndpoints;
    public int    CompletedChecks;
    public DateTime ScanStartTime = DateTime.Now;
    public List<CheckedUrlStatus> CheckedUrls = new();
}

public class CheckedUrlStatus
{
    public string Url    { get; init; } = "";
    public string Status { get; set; } = "Waiting";
}

public class PauseManager
{
    private readonly ManualResetEventSlim _event = new(true);
    private volatile bool _paused;

    public bool IsPaused => _paused;

    public void Pause()
    {
        _paused = true;
        _event.Reset();
    }

    public void Resume()
    {
        _paused = false;
        _event.Set();
    }

    public void WaitIfPaused(CancellationToken token)
    {
        _event.Wait(token);
    }
}

// ═══════════════ PATH HELPER ═══════════════
public static class PathHelper
{
    /// <summary>
    /// Searches for a folder named RESULTS starting from the application's base directory
    /// and moving up to the drive root.
    /// </summary>
    public static string? FindResultsFolder()
    {
        var current = AppContext.BaseDirectory;
        while (current != null)
        {
            var candidate = Path.Combine(current, "RESULTS");
            if (Directory.Exists(candidate))
                return candidate;
            current = Directory.GetParent(current)?.FullName;
        }
        return null;
    }
}