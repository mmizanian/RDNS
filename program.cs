// ╔══════════════════════════════════════════════════════════════════╗
// ║   NETWORK AVAILABILITY MONITOR v1.6 – Self‑Contained Edition  ║
// ║              (Embedded Resources Fixed)                       ║
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
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Spectre.Console;
using Spectre.Console.Rendering;

// ===================== TOP‑LEVEL STATEMENTS =====================

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

// Locate RESULTS folder (walk up from exe)
string resultsDir = PathHelper.FindResultsFolder()
    ?? Path.Combine(AppContext.BaseDirectory, "RESULTS");
Directory.CreateDirectory(resultsDir);

// ----------------------------------------------------------------
// Helper: extract embedded resource to disk (matches by suffix)
// ----------------------------------------------------------------
static async Task EnsureEmbeddedFileExists(string resourceName, string diskPath)
{
    if (File.Exists(diskPath)) return;

    try
    {
        var assembly = Assembly.GetExecutingAssembly();
        // Find any embedded resource whose name ends with the given resourceName (e.g., "servers_to_check.txt")
        string? fullName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("." + resourceName, StringComparison.OrdinalIgnoreCase)
                                 || n.Equals(resourceName, StringComparison.OrdinalIgnoreCase));

        if (fullName == null) return; // not embedded for this platform

        using var stream = assembly.GetManifestResourceStream(fullName);
        if (stream == null) return;

        string? dir = Path.GetDirectoryName(diskPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        using (var fileStream = File.Create(diskPath))
        {
            await stream.CopyToAsync(fileStream);
        }

        // Make executable on Unix-like systems
        if ((OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) &&
            resourceName.Contains("xray-knife", StringComparison.OrdinalIgnoreCase))
        {
            try { Process.Start("chmod", $"+x \"{diskPath}\""); } catch { }
        }

        ConsoleHelper.WriteLine($"✓ Extracted embedded '{resourceName}'", ConsoleColor.DarkGray);
    }
    catch (Exception ex)
    {
        ConsoleHelper.WriteLine($"⚠ Could not extract '{resourceName}': {ex.Message}", ConsoleColor.Yellow);
    }
}

// Extract required files from embedded resources
await EnsureEmbeddedFileExists("servers_to_check.txt", Path.Combine(resultsDir, "servers_to_check.txt"));
await EnsureEmbeddedFileExists("targets.txt", Path.Combine(resultsDir, "targets.txt"));
await EnsureEmbeddedFileExists("blacklist.txt", Path.Combine(resultsDir, "blacklist.txt"));

// Determine correct tool name based on OS
string toolResourceName, toolFileName;
if (OperatingSystem.IsWindows())
{
    toolResourceName = "xray-knife.exe";
    toolFileName     = "xray-knife.exe";
}
else if (OperatingSystem.IsLinux())
{
    toolResourceName = "xray-knife-linux";
    toolFileName     = "xray-knife";
}
else // macOS
{
    toolResourceName = "xray-knife-macos";
    toolFileName     = "xray-knife";
}
string toolPath = Path.Combine(AppContext.BaseDirectory, toolFileName);
await EnsureEmbeddedFileExists(toolResourceName, toolPath);
if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
{
    try { Process.Start("chmod", $"+x \"{toolPath}\""); } catch { }
}

// ===== 1. Load targets from targets.txt =====
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

// ===== 2. Override with JSON config if present =====
string configFilePath = Path.Combine(resultsDir, "network_monitor_config.json");
MonitorSettingsDto? savedSettings = null;
if (File.Exists(configFilePath))
{
    try
    {
        string json = await File.ReadAllTextAsync(configFilePath);
        savedSettings = JsonSerializer.Deserialize<MonitorSettingsDto>(json);
        AnsiConsole.MarkupLine("[green]✓ Loaded custom settings from network_monitor_config.json[/]");
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[yellow]⚠ Could not read JSON config: {ex.Message}[/]");
    }
}

// Build effective configuration, falling back to defaults
var monitorCfg = new MonitorConfiguration
{
    HealthCheckTargets = (savedSettings?.HealthCheckTargets?.Length > 0
                          ? savedSettings.HealthCheckTargets
                          : activeTargets.ToArray()),
    ParallelWorkers    = savedSettings?.ParallelWorkers    ?? 150,
    RequestDelayMs     = savedSettings?.RequestDelayMs     ?? 15000,
    GlobalTimeoutSec   = savedSettings?.GlobalTimeoutSec   ?? 500,
    EnableBeep         = savedSettings?.EnableBeep         ?? true,
    BeepDayStart       = savedSettings?.BeepDayStart       ?? 12,
    LogVerbosityLevel  = savedSettings?.LogVerbosityLevel  ?? "Normal",
    AggregationKeyPattern = savedSettings?.AggregationKeyPattern ?? @"^(?:.*?@)?([^?/]+)",
    FragmentFormat        = savedSettings?.FragmentFormat        ?? "{date}  **MIZI**  {time}",
    EndpointSourceFilePath = savedSettings?.EndpointSourceFilePath ?? "",
    DayFrequency          = savedSettings?.DayFrequency          ?? 4500,
    NightFrequency        = savedSettings?.NightFrequency        ?? 800,
    DayCount              = savedSettings?.DayCount              ?? 5,
    NightCount            = savedSettings?.NightCount            ?? 1,
    NightStartHour        = savedSettings?.NightStartHour        ?? 0
};

// Resolve file paths
monitorCfg.EndpointListFile = !string.IsNullOrWhiteSpace(savedSettings?.EndpointSourceFilePath)
    ? savedSettings.EndpointSourceFilePath
    : Path.Combine(resultsDir, "servers_to_check.txt");
monitorCfg.ReportFile          = Path.Combine(resultsDir, "responsive_servers.txt");
monitorCfg.DedupedFile         = Path.Combine(resultsDir, "deduped_endpoints.txt");
monitorCfg.SnapshotFile        = Path.Combine(resultsDir, "last_snapshot.txt");
monitorCfg.TempOutput          = Path.Combine(resultsDir, "scan_result.tmp");
monitorCfg.BlacklistFile       = Path.Combine(resultsDir, "blacklist.txt");
monitorCfg.NetworkToolPath     = toolPath;
monitorCfg.ResultsDir          = resultsDir;

AnsiConsole.MarkupLine($"[yellow]Targets source:[/] {(loadedTargets.Count > 0 ? "targets.txt" : "built‑in defaults")}");
AnsiConsole.MarkupLine($"[yellow]Endpoint list:[/] {monitorCfg.EndpointListFile}");
AnsiConsole.MarkupLine($"[yellow]Report file:[/]   {monitorCfg.ReportFile}");
AnsiConsole.MarkupLine($"[yellow]Network tool:[/]  {monitorCfg.NetworkToolPath}");
AnsiConsole.MarkupLine($"[grey]Monitoring will start with {monitorCfg.ParallelWorkers} workers, {monitorCfg.RequestDelayMs}ms delay.[/]");

var engine = new NetworkMonitorEngine(monitorCfg);
await engine.RunAsync();

// ===================== TYPE DECLARATIONS =====================

public class MonitorConfiguration
{
    public string   EndpointListFile    { get; set; } = "";
    public string   ReportFile          { get; set; } = "";
    public string   NetworkToolPath     { get; set; } = "";
    public string   DedupedFile         { get; set; } = "deduped_endpoints.txt";
    public string   SnapshotFile        { get; set; } = "last_snapshot.txt";
    public string   TempOutput          { get; set; } = "";
    public string   BlacklistFile       { get; set; } = "blacklist.txt";
    public string   ResultsDir          { get; set; } = "";
    public string[] HealthCheckTargets  { get; set; } = Array.Empty<string>();
    public int      ParallelWorkers     { get; set; } = 150;
    public int      RequestDelayMs      { get; set; } = 15000;
    public int      GlobalTimeoutSec    { get; set; } = 500;
    public bool     EnableBeep          { get; set; } = true;
    public int      BeepDayStart        { get; set; } = 12;
    public string   LogVerbosityLevel   { get; set; } = "Normal";
    public string   AggregationKeyPattern   { get; set; } = @"^(?:.*?@)?([^?/]+)";
    public string   FragmentFormat          { get; set; } = "{date}  **MIZI**  {time}";
    public string   EndpointSourceFilePath  { get; set; } = "";
    public int      DayFrequency            { get; set; } = 4500;
    public int      NightFrequency          { get; set; } = 800;
    public int      DayCount                { get; set; } = 5;
    public int      NightCount              { get; set; } = 1;
    public int      NightStartHour          { get; set; } = 0;
}

public class MonitorSettingsDto
{
    public string[] HealthCheckTargets  { get; set; } = Array.Empty<string>();
    public int      ParallelWorkers     { get; set; } = 150;
    public int      RequestDelayMs      { get; set; } = 15000;
    public int      GlobalTimeoutSec    { get; set; } = 500;
    public bool     EnableBeep          { get; set; } = true;
    public int      BeepDayStart        { get; set; } = 12;
    public string   LogVerbosityLevel   { get; set; } = "Normal";
    public string   AggregationKeyPattern   { get; set; } = @"^(?:.*?@)?([^?/]+)";
    public string   FragmentFormat          { get; set; } = "{date}  **MIZI**  {time}";
    public string   EndpointSourceFilePath  { get; set; } = "";
    public int      DayFrequency            { get; set; } = 4500;
    public int      NightFrequency          { get; set; } = 800;
    public int      DayCount                { get; set; } = 5;
    public int      NightCount              { get; set; } = 1;
    public int      NightStartHour          { get; set; } = 0;
}

// ---------------------- Engine --------------------------
public class NetworkMonitorEngine
{
    private const int MaxLogLines = 40;

    private readonly MonitorConfiguration _cfg;
    private readonly ConcurrentDictionary<string, (string EndpointId, string Fragment)> _responsiveServers = new();
    private Channel<string> _logChannel = Channel.CreateUnbounded<string>();
    private readonly Channel<string> _alertChannel = Channel.CreateUnbounded<string>();
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private HashSet<string> _blacklist = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _debounceCts;
    private readonly object _debounceLock = new();
    private readonly PauseManager _pauseManager = new();
    private readonly MonitorUIState _uiState = new();
    private readonly string _logFilePath;
    private DateTime _appStartTime = DateTime.Now;

    private Task? _dashboardTask;
    private CancellationTokenSource? _dashboardCts;

    private static readonly Regex ScrubDateRegex   = new(@"-Seen-.*", RegexOptions.Compiled);
    private static readonly Regex ScrubPrefixRegex = new(@"^\d{2}:\d{2}-\d{4}/\d{2}/\d{2}_", RegexOptions.Compiled);

    public NetworkMonitorEngine(MonitorConfiguration cfg)
    {
        _cfg = cfg;
        _logFilePath = Path.Combine(
            Path.GetDirectoryName(cfg.ReportFile) ?? ".", "monitor_activity.log");
    }

    public async Task RunAsync()
    {
        try
        {
            if (!File.Exists(_cfg.EndpointListFile))
            { AnsiConsole.MarkupLine($"[red]ERROR: Endpoint list not found: {_cfg.EndpointListFile}[/]"); return; }
            if (!File.Exists(_cfg.NetworkToolPath))
            { AnsiConsole.MarkupLine($"[red]ERROR: Network tool not found: {_cfg.NetworkToolPath}[/]"); return; }

            var outputDir = Path.GetDirectoryName(_cfg.ReportFile);
            if (!string.IsNullOrWhiteSpace(outputDir)) Directory.CreateDirectory(outputDir);
            if (!File.Exists(_cfg.ReportFile)) await File.WriteAllTextAsync(_cfg.ReportFile, "");

            await LoadPreviousReportsAsync();

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

            _dashboardCts = new CancellationTokenSource();
            _dashboardTask = RunDashboardAsync(_dashboardCts.Token);

            var keyTask   = ListenForKeyPressesAsync(cts.Token);
            var alertTask = ProcessAlertsAsync(cts.Token);

            while (!cts.Token.IsCancellationRequested)
            {
                _pauseManager.WaitIfPaused(cts.Token);
                _uiState.CycleCount++;
                var cycleStart = DateTime.Now;
                _uiState.ScanPhase = "Preparing";
                _uiState.CompletedChecks = 0;

                await LogAsync($"▶ Monitoring cycle #{_uiState.CycleCount} started", cts.Token);
                await LoadBlacklistAsync(cts.Token);

                var endpointCount = await RefreshEndpointListAsync(cts.Token);
                if (endpointCount <= 0)
                {
                    await LogAsync("⚠ Endpoint list empty. Skipping cycle.", cts.Token);
                    _uiState.ScanPhase = "Waiting";
                    await Task.Delay(5000, cts.Token);
                    continue;
                }

                _uiState.ScanPhase = "Scanning";
                lock (_uiState.CheckedUrls) { _uiState.CheckedUrls.Clear(); }

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

            cts.Cancel();
            _alertChannel.Writer.Complete();
            _logChannel.Writer.Complete();
            try { await Task.WhenAll(_dashboardTask ?? Task.CompletedTask, alertTask, keyTask); } catch { }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            try { await LogAsync($"❌ Fatal error: {ex.Message}"); } catch { }
            AnsiConsole.MarkupLine($"[red]Fatal error:[/] {ex.Message}");
        }
        finally
        {
            _alertChannel.Writer.TryComplete();
            _logChannel.Writer.TryComplete();
            _dashboardCts?.Cancel();
            if (_dashboardTask != null) { try { await _dashboardTask; } catch { } }
        }
    }

    private async Task ListenForKeyPressesAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            if (Console.KeyAvailable)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.P)
                {
                    if (_pauseManager.IsPaused) { _pauseManager.Resume(); await LogAsync("⏯ Resumed", token); }
                    else { _pauseManager.Pause(); await LogAsync("⏸ Paused (P to resume)", token); }
                }
                else if (key.Key == ConsoleKey.S)
                {
                    await RunSettingsMenuAsync(token);
                }
            }
            await Task.Delay(100, token);
        }
    }

    // ---- Settings menu (unchanged graphical part from v1.5) ----
    private async Task RunSettingsMenuAsync(CancellationToken mainToken)
    {
        bool wasPaused = _pauseManager.IsPaused;
        if (!wasPaused) _pauseManager.Pause();
        MonitorConfiguration originalCfg = CloneConfiguration(_cfg);
        var oldDashboardCts = _dashboardCts;
        oldDashboardCts?.Cancel();
        if (_dashboardTask != null) { try { await _dashboardTask; } catch (OperationCanceledException) { } }
        oldDashboardCts?.Dispose();
        AnsiConsole.Reset();
        Console.Clear();
        AnsiConsole.Clear();
        await Task.Delay(50);
        _logChannel.Writer.TryComplete();
        _logChannel = Channel.CreateUnbounded<string>();

        try
        {
            var editCfg = CloneConfiguration(_cfg);
            bool exit = false;
            while (!exit && !mainToken.IsCancellationRequested)
            {
                var choices = new List<string>
                {
                    $"📊 Parallel Workers         : {editCfg.ParallelWorkers}",
                    $"⏱  Delay Between Checks ms  : {editCfg.RequestDelayMs}",
                    $"⏰ Global Timeout sec       : {editCfg.GlobalTimeoutSec}",
                    $"🔔 Beep Notifications       : {(editCfg.EnableBeep ? "ON" : "OFF")}",
                    $"⚙  Configure Beep Details",
                    $"📝 Log Verbosity            : {editCfg.LogVerbosityLevel}",
                    $"📋 Manage Test Targets      : ({editCfg.HealthCheckTargets.Length} URLs)",
                    $"🔗 Aggregation Pattern      : {Truncate(editCfg.AggregationKeyPattern, 20)}",
                    $"🖊  Fragment Format         : {Truncate(editCfg.FragmentFormat, 20)}",
                    $"📁 Endpoint Source File     : {Truncate(editCfg.EndpointSourceFilePath, 30)}",
                    $"[green]💾 Save & Exit[/]",
                    $"[yellow]🔄 Restore Defaults[/]",
                    $"[red]❌ Exit Without Saving[/]"
                };
                int selectedIndex = SimpleMenu.Show("⚙ SETTINGS MENU", choices, 0, allowBack: true);
                if (selectedIndex < 0)
                {
                    ApplyConfiguration(originalCfg, _cfg);
                    ConsoleHelper.WriteLine("✓ Changes discarded. Settings unchanged.", ConsoleColor.Yellow);
                    exit = true; break;
                }
                string selected = choices[selectedIndex];
                if (selected.StartsWith("📊")) editCfg.ParallelWorkers = ReadInt("Parallel Workers (1-500)", editCfg.ParallelWorkers, 1, 500);
                else if (selected.StartsWith("⏱")) editCfg.RequestDelayMs = ReadInt("Delay Between Checks ms (0-30000)", editCfg.RequestDelayMs, 0, 30000);
                else if (selected.StartsWith("⏰")) editCfg.GlobalTimeoutSec = ReadInt("Global Timeout sec (60-3600)", editCfg.GlobalTimeoutSec, 60, 3600);
                else if (selected.StartsWith("🔔"))
                {
                    editCfg.EnableBeep = !editCfg.EnableBeep;
                    ConsoleHelper.WriteLine($"Beep toggled to {(editCfg.EnableBeep ? "ON" : "OFF")}", ConsoleColor.Green);
                    await Task.Delay(500);
                }
                else if (selected.StartsWith("⚙")) await ConfigureBeepDetailsAsync(editCfg);
                else if (selected.StartsWith("📝")) editCfg.LogVerbosityLevel = ReadOption("Log Verbosity Level", new[] { "Minimal", "Normal", "Verbose" }, editCfg.LogVerbosityLevel);
                else if (selected.StartsWith("📋")) await ManageTargetsAsync(editCfg);
                else if (selected.StartsWith("🔗")) editCfg.AggregationKeyPattern = ReadString("Regex pattern (empty = use full endpoint)", editCfg.AggregationKeyPattern);
                else if (selected.StartsWith("🖊")) editCfg.FragmentFormat = ReadString("Fragment format (use {date} and {time})", editCfg.FragmentFormat);
                else if (selected.StartsWith("📁")) await ChangeEndpointSourceFileAsync(editCfg);
                else if (selected.Contains("Save"))
                {
                    ApplyConfiguration(editCfg, _cfg);
                    await SaveSettingsToFileAsync(_cfg);
                    ConsoleHelper.WriteLine("✅ Settings saved successfully!", ConsoleColor.Green);
                    exit = true;
                }
                else if (selected.Contains("Restore"))
                {
                    if (ConsoleHelper.Confirm("Reset all settings to defaults?"))
                    {
                        var defaults = CreateDefaultConfiguration();
                        ApplyConfiguration(defaults, editCfg);
                        ApplyConfiguration(defaults, _cfg);
                        try { File.Delete(Path.Combine(_cfg.ResultsDir, "network_monitor_config.json")); } catch { }
                        ConsoleHelper.WriteLine("✅ All settings reset to defaults!", ConsoleColor.Green);
                        exit = true;
                    }
                }
                else if (selected.Contains("Exit"))
                {
                    ApplyConfiguration(originalCfg, _cfg);
                    ConsoleHelper.WriteLine("✓ Changes discarded. Settings unchanged.", ConsoleColor.Yellow);
                    exit = true;
                }
            }
        }
        finally
        {
            Console.Clear();
            AnsiConsole.Reset();
            AnsiConsole.Clear();
            await Task.Delay(50);
            _dashboardCts = new CancellationTokenSource();
            _dashboardTask = RunDashboardAsync(_dashboardCts.Token);
            if (!wasPaused) _pauseManager.Resume();
        }
    }

    // ---- Input helpers (plain console) ----
    private static int ReadInt(string title, int current, int min, int max)
    {
        while (true)
        {
            ConsoleHelper.Write($"{title} [{min}-{max}] (current: {current}): ", ConsoleColor.Cyan);
            string? input = Console.ReadLine();
            if (int.TryParse(input, out int val) && val >= min && val <= max) return val;
            ConsoleHelper.WriteLine("Invalid input.", ConsoleColor.Red);
        }
    }

    private static string ReadString(string title, string current)
    {
        ConsoleHelper.Write($"{title} (current: {current}): ", ConsoleColor.Cyan);
        string? input = Console.ReadLine();
        return string.IsNullOrWhiteSpace(input) ? current : input.Trim();
    }

    private static string ReadOption(string title, string[] options, string current)
    {
        var idx = SimpleMenu.Show(title, new List<string>(options), options.ToList().IndexOf(current));
        return idx >= 0 ? options[idx] : current;
    }

    private async Task ChangeEndpointSourceFileAsync(MonitorConfiguration editCfg)
    {
        ConsoleHelper.Write("Full path to endpoint source file (current: " + editCfg.EndpointSourceFilePath + "): ", ConsoleColor.Cyan);
        string path = Console.ReadLine()?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(path)) { ConsoleHelper.WriteLine("No change (empty path)", ConsoleColor.Yellow); return; }
        if (!File.Exists(path)) { ConsoleHelper.WriteLine("Error: file does not exist. Keeping previous path.", ConsoleColor.Red); await Task.Delay(1500); return; }
        editCfg.EndpointSourceFilePath = path;
        editCfg.EndpointListFile = path;
        ConsoleHelper.WriteLine("✓ Endpoint source file updated.", ConsoleColor.Green);
        await Task.Delay(1000);
    }

    private async Task ConfigureBeepDetailsAsync(MonitorConfiguration editCfg)
    {
        bool back = false;
        while (!back)
        {
            var choices = new List<string>
            {
                $"🔊 Daytime Frequency (Hz)  : {editCfg.DayFrequency}",
                $"🔉 Nighttime Frequency (Hz): {editCfg.NightFrequency}",
                $"🔢 Daytime Beep Count      : {editCfg.DayCount}",
                $"🔢 Nighttime Beep Count    : {editCfg.NightCount}",
                $"🌅 Daytime Start Hour      : {editCfg.BeepDayStart}",
                $"🌌 Nighttime Start Hour    : {editCfg.NightStartHour}",
                $"[yellow]↩ Back[/]"
            };
            int sel = SimpleMenu.Show("BEEP CONFIGURATION", choices);
            if (sel < 0 || choices[sel].Contains("Back")) { back = true; continue; }
            string choice = choices[sel];
            if (choice.StartsWith("🔊")) editCfg.DayFrequency = ReadInt("Daytime Frequency (Hz)", editCfg.DayFrequency, 100, 20000);
            else if (choice.StartsWith("🔉")) editCfg.NightFrequency = ReadInt("Nighttime Frequency (Hz)", editCfg.NightFrequency, 100, 20000);
            else if (choice.StartsWith("🔢") && choice.Contains("Daytime")) editCfg.DayCount = ReadInt("Daytime Beep Count", editCfg.DayCount, 1, 20);
            else if (choice.StartsWith("🔢") && choice.Contains("Nighttime")) editCfg.NightCount = ReadInt("Nighttime Beep Count", editCfg.NightCount, 1, 20);
            else if (choice.StartsWith("🌅")) editCfg.BeepDayStart = ReadInt("Daytime Start Hour (0-23)", editCfg.BeepDayStart, 0, 23);
            else if (choice.StartsWith("🌌")) editCfg.NightStartHour = ReadInt("Nighttime Start Hour (0-23)", editCfg.NightStartHour, 0, 23);
        }
    }

    private async Task ManageTargetsAsync(MonitorConfiguration editCfg)
    {
        var targets = new List<string>(editCfg.HealthCheckTargets);
        bool goBack = false;
        while (!goBack)
        {
            Console.Clear();
            ConsoleHelper.WriteLine("MANAGE TEST TARGETS", ConsoleColor.Cyan, clear: true);
            if (targets.Count == 0) ConsoleHelper.WriteLine("No targets defined.", ConsoleColor.Yellow);
            else for (int i = 0; i < targets.Count; i++) ConsoleHelper.WriteLine($"  [{i + 1}] {targets[i]}", ConsoleColor.White);
            Console.WriteLine();
            ConsoleHelper.WriteLine("  [A]dd  [R]emove  [D]elete all  [B]ack", ConsoleColor.Gray);
            ConsoleHelper.Write("Press a key...", ConsoleColor.Gray);
            var key = Console.ReadKey(true).KeyChar.ToString().ToUpperInvariant();
            switch (key)
            {
                case "A":
                    ConsoleHelper.Write("Enter URL (must start with http): ", ConsoleColor.Gray);
                    string? url = Console.ReadLine()?.Trim();
                    if (string.IsNullOrWhiteSpace(url) || !url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                        ConsoleHelper.WriteLine("Invalid URL. It must start with http.", ConsoleColor.Red);
                    else { targets.Add(url); ConsoleHelper.WriteLine("✓ URL added.", ConsoleColor.Green); }
                    break;
                case "R":
                    if (targets.Count == 0) { ConsoleHelper.WriteLine("No URLs to remove.", ConsoleColor.Yellow); break; }
                    ConsoleHelper.Write("Enter number of URL to remove: ", ConsoleColor.Gray);
                    if (int.TryParse(Console.ReadLine(), out int num) && num >= 1 && num <= targets.Count)
                    { targets.RemoveAt(num - 1); ConsoleHelper.WriteLine("✓ URL removed.", ConsoleColor.Green); }
                    else ConsoleHelper.WriteLine("Invalid number.", ConsoleColor.Red);
                    break;
                case "D":
                    if (targets.Count > 0 && ConsoleHelper.Confirm("Delete all targets?"))
                    { targets.Clear(); ConsoleHelper.WriteLine("All targets removed.", ConsoleColor.Yellow); }
                    break;
                case "B": goBack = true; break;
            }
            if (!goBack) { Console.Clear(); }
        }
        editCfg.HealthCheckTargets = targets.ToArray();
        ConsoleHelper.WriteLine($"✓ Target list now contains {targets.Count} URL(s).", ConsoleColor.Green);
        await Task.Delay(1000);
    }

    // ---- Configuration helpers ----
    private static MonitorConfiguration CloneConfiguration(MonitorConfiguration source) => new()
    {
        ParallelWorkers = source.ParallelWorkers, RequestDelayMs = source.RequestDelayMs, GlobalTimeoutSec = source.GlobalTimeoutSec,
        EnableBeep = source.EnableBeep, BeepDayStart = source.BeepDayStart, LogVerbosityLevel = source.LogVerbosityLevel,
        HealthCheckTargets = source.HealthCheckTargets.ToArray(), EndpointListFile = source.EndpointListFile,
        ReportFile = source.ReportFile, NetworkToolPath = source.NetworkToolPath, DedupedFile = source.DedupedFile,
        SnapshotFile = source.SnapshotFile, TempOutput = source.TempOutput, BlacklistFile = source.BlacklistFile,
        ResultsDir = source.ResultsDir, AggregationKeyPattern = source.AggregationKeyPattern, FragmentFormat = source.FragmentFormat,
        EndpointSourceFilePath = source.EndpointSourceFilePath, DayFrequency = source.DayFrequency, NightFrequency = source.NightFrequency,
        DayCount = source.DayCount, NightCount = source.NightCount, NightStartHour = source.NightStartHour
    };

    private static void ApplyConfiguration(MonitorConfiguration from, MonitorConfiguration to)
    {
        to.ParallelWorkers = from.ParallelWorkers; to.RequestDelayMs = from.RequestDelayMs; to.GlobalTimeoutSec = from.GlobalTimeoutSec;
        to.EnableBeep = from.EnableBeep; to.BeepDayStart = from.BeepDayStart; to.LogVerbosityLevel = from.LogVerbosityLevel;
        to.HealthCheckTargets = from.HealthCheckTargets.ToArray(); to.AggregationKeyPattern = from.AggregationKeyPattern;
        to.FragmentFormat = from.FragmentFormat; to.EndpointSourceFilePath = from.EndpointSourceFilePath;
        to.DayFrequency = from.DayFrequency; to.NightFrequency = from.NightFrequency; to.DayCount = from.DayCount;
        to.NightCount = from.NightCount; to.NightStartHour = from.NightStartHour;
    }

    private static MonitorConfiguration CreateDefaultConfiguration() => new()
    {
        ParallelWorkers = 150, RequestDelayMs = 15000, GlobalTimeoutSec = 500, EnableBeep = true, BeepDayStart = 12,
        LogVerbosityLevel = "Normal", HealthCheckTargets = new[] { "https://www.wikipedia.org/robots.txt","https://www.github.com/robots.txt","https://www.stackoverflow.com/robots.txt","https://www.cloudflare.com/robots.txt","https://www.apache.org/robots.txt","https://www.mozilla.org/robots.txt","https://www.gnu.org/robots.txt","https://www.w3.org/robots.txt","https://www.ietf.org/robots.txt","https://www.archlinux.org/robots.txt" },
        AggregationKeyPattern = @"^(?:.*?@)?([^?/]+)", FragmentFormat = "{date}  **MIZI**  {time}", EndpointSourceFilePath = "",
        DayFrequency = 4500, NightFrequency = 800, DayCount = 5, NightCount = 1, NightStartHour = 0
    };

    private async Task SaveSettingsToFileAsync(MonitorConfiguration cfg)
    {
        try
        {
            var dto = new MonitorSettingsDto
            {
                HealthCheckTargets = cfg.HealthCheckTargets, ParallelWorkers = cfg.ParallelWorkers, RequestDelayMs = cfg.RequestDelayMs,
                GlobalTimeoutSec = cfg.GlobalTimeoutSec, EnableBeep = cfg.EnableBeep, BeepDayStart = cfg.BeepDayStart,
                LogVerbosityLevel = cfg.LogVerbosityLevel, AggregationKeyPattern = cfg.AggregationKeyPattern, FragmentFormat = cfg.FragmentFormat,
                EndpointSourceFilePath = cfg.EndpointSourceFilePath, DayFrequency = cfg.DayFrequency, NightFrequency = cfg.NightFrequency,
                DayCount = cfg.DayCount, NightCount = cfg.NightCount, NightStartHour = cfg.NightStartHour
            };
            string path = Path.Combine(cfg.ResultsDir, "network_monitor_config.json");
            string json = JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(path, json);
        }
        catch (Exception ex) { ConsoleHelper.WriteLine($"⚠ Warning: Could not save config file: {ex.Message}", ConsoleColor.Yellow); }
    }

    // ---- Core monitoring (identical to v1.5) ----
    private async Task LoadBlacklistAsync(CancellationToken token)
    {
        if (!File.Exists(_cfg.BlacklistFile)) { _blacklist.Clear(); return; }
        try
        {
            var lines = await File.ReadAllLinesAsync(_cfg.BlacklistFile, token);
            _blacklist = new HashSet<string>(lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim()), StringComparer.OrdinalIgnoreCase);
            await LogAsync($"🚫 Loaded {_blacklist.Count} blacklist entries", token);
        }
        catch (Exception ex) { await LogAsync($"⚠ Failed to load blacklist: {ex.Message}", token); }
    }

    private async Task LogAsync(string message, CancellationToken token = default)
    {
        if (!ShouldLogMessage(message)) return;
        try { await _logChannel.Writer.WriteAsync(message, token); } catch (ChannelClosedException) { }
    }

    private bool ShouldLogMessage(string message)
    {
        string level = _cfg.LogVerbosityLevel; if (string.IsNullOrEmpty(level)) level = "Normal";
        if (level == "Verbose") return true;
        bool containsError = message.Contains("❌") || message.IndexOf("fatal", StringComparison.OrdinalIgnoreCase) >= 0;
        bool cycleCompleted = message.Contains("✅ Cycle completed");
        if (level == "Minimal") return containsError || cycleCompleted;
        return containsError || cycleCompleted || message.Contains("⚠") || message.Contains("🚫 Loaded") ||
               message.Contains("📄") || message.Contains("⏸") || message.Contains("⏯") ||
               message.Contains("✅ Responsive endpoint") || message.Contains("⏱");
    }

    private async Task LoadPreviousReportsAsync()
    {
        if (!File.Exists(_cfg.ReportFile)) return;
        var lines = await File.ReadAllLinesAsync(_cfg.ReportFile);
        int loaded = 0;
        foreach (var line in lines)
        {
            var (endpointId, fragmentEscaped) = SplitFragment(line);
            if (string.IsNullOrEmpty(endpointId)) continue;
            string fragment = Uri.UnescapeDataString(fragmentEscaped);
            string aggKey = GetAggregationKey(endpointId);
            _responsiveServers.AddOrUpdate(aggKey, _ => (endpointId, fragment), (_, existing) => (existing.EndpointId, fragment));
            loaded++;
        }
        if (loaded > 0) await LogAsync($"📂 Loaded {loaded} previous responsive endpoints");
    }

    private async Task<int> RefreshEndpointListAsync(CancellationToken token)
    {
        if (!File.Exists(_cfg.EndpointListFile)) return 0;
        string[] sourceLines = Array.Empty<string>();
        for (int retry = 0; retry < 3; retry++)
        {
            try { sourceLines = await File.ReadAllLinesAsync(_cfg.EndpointListFile, token); break; } catch (IOException) { await Task.Delay(1000, token); }
        }
        if (sourceLines.Length == 0) { await LogAsync("⚠ Could not read endpoint list (file in use)", token); return 0; }
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
            foreach (var line in sourceLines) { if (!string.IsNullOrWhiteSpace(line) && !line.Contains("splithttp", StringComparison.OrdinalIgnoreCase) && unique.Add(line)) deduped.Add(line); }
            await File.WriteAllLinesAsync(_cfg.DedupedFile, deduped, token);
            await File.WriteAllLinesAsync(_cfg.SnapshotFile, sourceLines, token);
            _uiState.WorkingEndpoints = deduped.Count;
            await LogAsync($"📄 Endpoint list deduplicated: {sourceLines.Length} → {_uiState.WorkingEndpoints} unique entries", token);
        }
        else
        {
            _uiState.WorkingEndpoints = File.Exists(_cfg.DedupedFile) ? await CountLinesAsync(_cfg.DedupedFile, token) : 0;
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

    private async Task CheckTargetAgainstEndpointsAsync(string targetUrl, CancellationToken token)
    {
        if (File.Exists(_cfg.TempOutput)) try { File.Delete(_cfg.TempOutput); } catch { }

        _uiState.ScanPhase = "Launching";
        await LogAsync($"▶ Launching check: {Truncate(targetUrl, 50)}", token);
        int workingEndpoints = Volatile.Read(ref _uiState.WorkingEndpoints);
        double estimatedSeconds = 0;
        if (workingEndpoints > 0 && _cfg.ParallelWorkers > 0) estimatedSeconds = (workingEndpoints / (double)_cfg.ParallelWorkers) * (_cfg.RequestDelayMs / 1000.0);
        int dynamicTimeoutSec = Math.Max(_cfg.GlobalTimeoutSec, (int)estimatedSeconds + 120);

        var args = $"http -f \"{_cfg.DedupedFile}\" --thread {_cfg.ParallelWorkers} --mdelay {_cfg.RequestDelayMs} --insecure=true --url \"{targetUrl}\" -o \"{_cfg.TempOutput}\"";
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
        psi.Environment.Remove("HTTP_PROXY"); psi.Environment.Remove("HTTPS_PROXY"); psi.Environment.Remove("http_proxy"); psi.Environment.Remove("https_proxy"); psi.Environment.Remove("ALL_PROXY"); psi.Environment.Remove("all_proxy");

        using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var stdErr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) Interlocked.Increment(ref _uiState.TestedThisRound); };
        proc.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) { lock (stdErr) stdErr.AppendLine(e.Data); Interlocked.Increment(ref _uiState.TestedThisRound); } };
        if (!proc.Start()) { await LogAsync("❌ Failed to launch network testing tool", token); return; }
        _uiState.ScanPhase = "Running";
        proc.BeginOutputReadLine(); proc.BeginErrorReadLine();
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
            else { try { await exitTask; } catch { } }
        }
        finally
        {
            monitorCts.Cancel(); try { await monitorTask; } catch { }
            try { proc.CancelOutputRead(); } catch { } try { proc.CancelErrorRead(); } catch { }
        }

        _uiState.ScanPhase = "Parsing";
        var errorText = stdErr.ToString().Trim();
        if (!string.IsNullOrWhiteSpace(errorText) && proc.ExitCode != 0) await LogAsync($"⚠ Tool warning (code {proc.ExitCode}): {Truncate(errorText, 100)}", token);

        if (File.Exists(_cfg.TempOutput))
        {
            var lines = await File.ReadAllLinesAsync(_cfg.TempOutput, token);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || !line.Contains("://")) continue;
                var (endpointId, _) = SplitFragment(line);
                if (string.IsNullOrEmpty(endpointId)) continue;
                if (_blacklist.Count > 0 && _blacklist.Any(pattern => endpointId.Contains(pattern, StringComparison.OrdinalIgnoreCase) || line.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                { await LogAsync($"🚫 Blacklisted endpoint skipped: {Truncate(endpointId, 24)}", token); continue; }

                var now = DateTime.Now;
                string date = now.ToString("dd/MM/yyyy");
                string time = now.ToString("HH:mm");
                string fragment = _cfg.FragmentFormat.Replace("{date}", date).Replace("{time}", time);
                string aggKey = GetAggregationKey(endpointId);

                var isNew = !_responsiveServers.ContainsKey(aggKey);
                _responsiveServers.AddOrUpdate(aggKey, _ => (endpointId, fragment), (_, existing) => (existing.EndpointId, fragment));
                if (isNew)
                {
                    Interlocked.Increment(ref _uiState.NewThisSession);
                    Interlocked.Increment(ref _uiState.FoundThisRound);
                    string alertLine = $"{endpointId}#{Uri.EscapeDataString(fragment)}";
                    await _alertChannel.Writer.WriteAsync(alertLine, token);
                }
                TriggerDebouncedSave();
            }
        }
        _uiState.CurrentProgress = 100;
        _uiState.ScanPhase = "Done";
        try { File.Delete(_cfg.TempOutput); } catch { }
    }

    private string GetAggregationKey(string endpointId)
    {
        if (string.IsNullOrWhiteSpace(_cfg.AggregationKeyPattern)) return endpointId;
        try
        {
            var match = Regex.Match(endpointId, _cfg.AggregationKeyPattern);
            if (match.Success && match.Groups.Count > 1)
            {
                string key = match.Groups[1].Value.Trim();
                if (!string.IsNullOrEmpty(key)) return key;
            }
        }
        catch (RegexParseException) { }
        return endpointId;
    }

    private async Task MonitorProgressLoopAsync(Process proc, CancellationToken token)
    {
        while (!token.IsCancellationRequested && !proc.HasExited)
        {
            _pauseManager.WaitIfPaused(token);
            int working = Volatile.Read(ref _uiState.WorkingEndpoints);
            int tested = Volatile.Read(ref _uiState.TestedThisRound);
            double progress = working > 0 ? (tested / (double)working) * 100.0 : 0;
            double fallback = _cfg.GlobalTimeoutSec > 0 ? Math.Min(95, ((DateTime.Now - _uiState.ScanStartTime).TotalSeconds / _cfg.GlobalTimeoutSec) * 100.0) : 0;
            _uiState.CurrentProgress = Math.Clamp(Math.Max(progress, fallback), 0, 100);
            try { await Task.Delay(300, token); } catch (OperationCanceledException) { break; }
        }
    }

    private void TriggerDebouncedSave()
    {
        lock (_debounceLock)
        {
            _debounceCts?.Cancel(); _debounceCts?.Dispose();
            _debounceCts = new CancellationTokenSource(); var token = _debounceCts.Token;
            _ = Task.Run(async () => { try { await Task.Delay(5000, token); await SaveReportSortedAsync(token); } catch (TaskCanceledException) { } }, token);
        }
    }

    private async Task SaveReportSortedAsync(CancellationToken token = default)
    {
        bool acquired = false;
        try
        {
            await _fileLock.WaitAsync(token);
            acquired = true;
        }
        catch (OperationCanceledException) { return; }

        try
        {
            var sortedLines = _responsiveServers.Values.OrderByDescending(v => ExtractTimestampFromFragment(v.Fragment))
                .Select(v => $"{v.EndpointId}#{Uri.EscapeDataString(v.Fragment)}").ToList();
            await File.WriteAllLinesAsync(_cfg.ReportFile, sortedLines, token);
        }
        finally { if (acquired) _fileLock.Release(); }
    }

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
        bool isDaytime;
        int dayStart = _cfg.BeepDayStart, nightStart = _cfg.NightStartHour;
        if (dayStart == nightStart) isDaytime = true;
        else if (dayStart < nightStart) isDaytime = hour >= dayStart && hour < nightStart;
        else isDaytime = hour >= dayStart || hour < nightStart;
        try
        {
            if (isDaytime) { for (int i = 0; i < _cfg.DayCount; i++) { Console.Beep(_cfg.DayFrequency, 100); Thread.Sleep(40); } }
            else for (int i = 0; i < _cfg.NightCount; i++) { Console.Beep(_cfg.NightFrequency, 250); if (i < _cfg.NightCount - 1) Thread.Sleep(40); }
        }
        catch { }
    }

    private (string link, string name) SplitFragment(string raw)
    {
        raw = raw.Trim();
        var idx = raw.IndexOf('#');
        var link = idx > 0 ? raw[..idx].Trim() : raw;
        var name = idx > 0 ? raw[(idx + 1)..].Trim() : "Endpoint";
        name = ScrubDateRegex.Replace(name, ""); name = ScrubPrefixRegex.Replace(name, ""); name = name.Trim();
        if (string.IsNullOrEmpty(name)) name = "Endpoint";
        return (link, name);
    }

    private static DateTime ExtractTimestampFromFragment(string fragment)
    {
        var dateMatch = Regex.Match(fragment, @"\b(\d{2}/\d{2}/\d{4})\b");
        var timeMatch = Regex.Match(fragment, @"\b(\d{2}:\d{2})\b");
        if (dateMatch.Success && timeMatch.Success &&
            DateTime.TryParseExact($"{dateMatch.Groups[1].Value} {timeMatch.Groups[1].Value}", "dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt)) return dt;

        var defaultMatch = Regex.Match(fragment, @"^(\d{2}/\d{2}/\d{4})\s+\*\*MIZI\*\*\s+(\d{2}:\d{2})$");
        if (defaultMatch.Success &&
            DateTime.TryParseExact($"{defaultMatch.Groups[1].Value} {defaultMatch.Groups[2].Value}", "dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt2)) return dt2;

        return DateTime.MinValue;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..(max - 3)] + "...";

    private async Task RunDashboardAsync(CancellationToken token)
    {
        var logs = new List<string>(MaxLogLines);
        var layout = new Layout("Root").SplitRows(new Layout("Header").Size(4), new Layout("Main").SplitColumns(new Layout("Left").Size(60), new Layout("Right")));
        try
        {
            await AnsiConsole.Live(layout).AutoClear(true).Overflow(VerticalOverflow.Ellipsis).StartAsync(async ctx =>
            {
                while (!token.IsCancellationRequested)
                {
                    while (_logChannel.Reader.TryRead(out var msg)) { logs.Add($"[{DateTime.Now:HH:mm:ss}] {msg}"); if (logs.Count > MaxLogLines) logs.RemoveAt(0); }

                    var uptime = DateTime.Now - _appStartTime;
                    var scanElapsed = DateTime.Now - _uiState.ScanStartTime;
                    int totalTargets = _cfg.HealthCheckTargets.Length;
                    int completed = Math.Clamp(_uiState.CompletedChecks, 0, totalTargets);
                    double targetProgress = Math.Clamp(_uiState.CurrentProgress, 0, 100);
                    double cycleProgress = totalTargets > 0 ? Math.Clamp(((completed + targetProgress / 100.0) / totalTargets) * 100.0, 0, 100) : 0;
                    int estRemaining = Math.Max(0, _uiState.WorkingEndpoints - (int)(_uiState.WorkingEndpoints * targetProgress / 100));
                    TimeSpan eta = TimeSpan.Zero;
                    if (cycleProgress > 0 && cycleProgress < 100) { var remainingSec = (scanElapsed.TotalSeconds / (cycleProgress / 100.0)) - scanElapsed.TotalSeconds; if (remainingSec > 0) eta = TimeSpan.FromSeconds(remainingSec); }
                    bool isPaused = _pauseManager.IsPaused;
                    var phaseColor = _uiState.ScanPhase is "Running" or "Scanning" ? "green" : _uiState.ScanPhase is "Waiting" or "Idle" ? "yellow" : "cyan";
                    var pauseInfo = isPaused ? " [bold red]⏸ PAUSED[/]" : "";
                    var keybindHints = isPaused ? "[grey](P=Resume, S=Settings)[/]" : "[grey](P=Pause, S=Settings)[/]";

                    var headerMarkup = $"[bold cyan]🌐 NETWORK AVAILABILITY MONITOR[/]{pauseInfo}   [bold {phaseColor}]● {Markup.Escape(_uiState.ScanPhase.ToUpper())}[/]   [grey]UPTIME {uptime:hh\\:mm\\:ss}[/]   [bold green]RESPONSIVE {_responsiveServers.Count:N0}[/]  [cyan]CYCLE {_uiState.CycleCount}[/]  [yellow]TARGET {_uiState.CurrentTargetNum}/{totalTargets}[/]\n{keybindHints}";
                    var header = new Panel(Align.Center(new Markup(headerMarkup))).Border(BoxBorder.Heavy).BorderStyle(new Style(Color.Cyan1)).Expand();

                    var cycleBarColor = cycleProgress < 50 ? "yellow" : cycleProgress < 90 ? "cyan" : "green";
                    var cycleBar = BuildBar(cycleProgress, 24);
                    var targetBar = BuildBar(targetProgress, 24);

                    var checkedList = new List<IRenderable>();
                    lock (_uiState.CheckedUrls)
                    {
                        if (_uiState.CheckedUrls.Count > 0)
                        {
                            foreach (var u in _uiState.CheckedUrls.TakeLast(5).Reverse())
                                checkedList.Add(new Markup($"  {(u.Status == "Done" ? "[green]✓[/]" : u.Status == "Testing" ? "[yellow]⏳[/]" : "[grey]…[/]")} {Markup.Escape(Truncate(u.Url, 50))}"));
                        }
                        else checkedList.Add(new Markup("  [grey]No targets checked yet[/]"));
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
                    var leftPanel = new Panel(Align.Left(leftContent)).Border(BoxBorder.Rounded).BorderStyle(new Style(Color.Cyan1)).Header("[bold cyan] NETWORK STATUS [/]").Expand();
                    var visibleLogs = logs.TakeLast(14).Select(ColorizeLogLine).Cast<IRenderable>().ToArray();
                    IRenderable logContent = visibleLogs.Length > 0 ? new Rows(visibleLogs) : new Markup("[grey]Waiting for monitoring data…[/]");
                    var logPanel = new Panel(Align.Left(logContent)).Border(BoxBorder.Rounded).BorderStyle(new Style(Color.Grey)).Header("[bold grey] ACTIVITY LOG [/]").Expand();

                    layout["Header"].Update(header); layout["Left"].Update(leftPanel); layout["Right"].Update(logPanel);
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
        if (line.Contains("✅") || line.Contains("NEW")) return new Markup($"[green]{safe}[/]");
        if (line.Contains("❌") || line.Contains("Fatal")) return new Markup($"[red]{safe}[/]");
        if (line.Contains("⚠") || line.Contains("Timeout")) return new Markup($"[yellow]{safe}[/]");
        if (line.Contains("▶") || line.Contains("Cycle")) return new Markup($"[cyan]{safe}[/]");
        return new Markup($"[grey]{safe}[/]");
    }

    private static string BuildBar(double percent, int width = 24)
    {
        percent = Math.Clamp(percent, 0, 100);
        int filled = Math.Clamp((int)Math.Round((percent / 100.0) * width), 0, width);
        return new string('█', filled) + new string('░', width - filled);
    }
}

// ---------------------- UI State --------------------------
public class MonitorUIState
{
    public long CycleCount; public int NewThisSession; public int CurrentTargetNum;
    public string CurrentTargetUrl = ""; public double CurrentProgress; public int FoundThisRound; public int TestedThisRound;
    public string ScanPhase = "Idle"; public int TotalEndpoints; public int WorkingEndpoints; public int CompletedChecks;
    public DateTime ScanStartTime = DateTime.Now; public List<CheckedUrlStatus> CheckedUrls = new();
}
public class CheckedUrlStatus { public string Url { get; init; } = ""; public string Status { get; set; } = "Waiting"; }
public class PauseManager
{
    private readonly ManualResetEventSlim _event = new(true); private volatile bool _paused;
    public bool IsPaused => _paused;
    public void Pause() { _paused = true; _event.Reset(); }
    public void Resume() { _paused = false; _event.Set(); }
    public void WaitIfPaused(CancellationToken token) { _event.Wait(token); }
}
public static class PathHelper
{
    public static string? FindResultsFolder()
    {
        var current = AppContext.BaseDirectory;
        while (current != null)
        {
            var candidate = Path.Combine(current, "RESULTS");
            if (Directory.Exists(candidate)) return candidate;
            current = Directory.GetParent(current)?.FullName;
        }
        return null;
    }
}

// ---------------------- Simple Menu (fast navigation) -----
public static class SimpleMenu
{
    public static int Show(string title, List<string> choices, int initialSelection = 0, bool allowBack = false)
    {
        int selected = Math.Clamp(initialSelection, 0, choices.Count - 1);
        Console.Clear();
        ConsoleHelper.WriteLine(title, ConsoleColor.Cyan);
        ConsoleHelper.WriteLine(new string('─', title.Length), ConsoleColor.DarkGray);
        for (int i = 0; i < choices.Count; i++) RenderChoice(choices[i], i == selected);
        Console.CursorVisible = false;
        try
        {
            while (true)
            {
                var key = Console.ReadKey(true);
                int previous = selected;
                if (key.Key == ConsoleKey.UpArrow) selected = (selected == 0) ? choices.Count - 1 : selected - 1;
                else if (key.Key == ConsoleKey.DownArrow) selected = (selected == choices.Count - 1) ? 0 : selected + 1;
                else if (key.Key == ConsoleKey.Enter) return selected;
                else if (key.Key == ConsoleKey.Escape || (allowBack && key.KeyChar.ToString().ToUpperInvariant() == "B")) return -1;
                if (previous != selected)
                {
                    Console.SetCursorPosition(0, previous + 2); RenderChoice(choices[previous], false);
                    Console.SetCursorPosition(0, selected + 2); RenderChoice(choices[selected], true);
                }
            }
        }
        finally { Console.CursorVisible = true; }
    }

    private static void RenderChoice(string raw, bool highlight)
    {
        (ConsoleColor fg, string clean) = ParseMarkupColor(raw);
        Console.Write(" ");
        if (highlight) { Console.BackgroundColor = ConsoleColor.Gray; Console.ForegroundColor = ConsoleColor.Black; }
        else { Console.ForegroundColor = fg; Console.BackgroundColor = ConsoleColor.Black; }
        Console.WriteLine(clean.PadRight(Console.WindowWidth - 2));
        Console.ResetColor();
    }

    private static (ConsoleColor color, string text) ParseMarkupColor(string input)
    {
        if (input.StartsWith("[green]")) return (ConsoleColor.Green, input.Replace("[green]", "").Replace("[/]", ""));
        if (input.StartsWith("[yellow]")) return (ConsoleColor.Yellow, input.Replace("[yellow]", "").Replace("[/]", ""));
        if (input.StartsWith("[red]")) return (ConsoleColor.Red, input.Replace("[red]", "").Replace("[/]", ""));
        if (input.StartsWith("[cyan]")) return (ConsoleColor.Cyan, input.Replace("[cyan]", "").Replace("[/]", ""));
        if (input.StartsWith("[grey]")) return (ConsoleColor.DarkGray, input.Replace("[grey]", "").Replace("[/]", ""));
        return (ConsoleColor.White, input);
    }
}

public static class ConsoleHelper
{
    public static void WriteLine(string msg, ConsoleColor color = ConsoleColor.White, bool clear = false)
    {
        if (clear) Console.Clear();
        Console.ForegroundColor = color;
        Console.WriteLine(msg);
        Console.ResetColor();
    }
    public static void Write(string msg, ConsoleColor color = ConsoleColor.White)
    {
        Console.ForegroundColor = color;
        Console.Write(msg);
        Console.ResetColor();
    }
    public static bool Confirm(string question)
    {
        Console.Write($"{question} (y/n): ");
        var key = Console.ReadKey(true);
        Console.WriteLine(key.KeyChar);
        return key.KeyChar == 'y' || key.KeyChar == 'Y';
    }
}