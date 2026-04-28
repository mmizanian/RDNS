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

// ═══════════════════ CONFIG ═══════════════════
var urls = new[]
{
    "https://www.reddit.com/robots.txt",
    "https://twitter.com/robots.txt",
    "https://x.com/robots.txt",
    "https://www.youtube.com/robots.txt",
    "https://www.facebook.com/robots.txt",
    "https://www.instagram.com/robots.txt",
    "https://web.telegram.org/k/robots.txt",
    "https://1.1.1.1/generate_204",
    "https://detectportal.firefox.com/success.txt",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.apple.com/library/test/success.html",
    "https://captive.apple.com/hotspot-detect.html",
    "https://checkip.amazonaws.com/",
};

string resultsDir = PathHelper.FindResultsFolder()
    ?? Path.Combine(AppContext.BaseDirectory, "RESULTS");
Directory.CreateDirectory(resultsDir);

string configFilePath = Path.Combine(resultsDir, "scanner_config.json");
if (File.Exists(configFilePath))
{
    try
    {
        var json = File.ReadAllText(configFilePath);
        var cfgFromFile = JsonSerializer.Deserialize<ConfigFile>(json);
        if (cfgFromFile?.TestURLs?.Length > 0)
        {
            urls = cfgFromFile.TestURLs;
            AnsiConsole.MarkupLine("[green]Loaded URLs from scanner_config.json[/]");
        }
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[yellow]Could not read scanner_config.json: {ex.Message}. Using defaults.[/]");
    }
}

var cfg = new Config
{
    TestURLs = urls,
    ScanThreads = 50,
    MdelayMs = 7000,
    TimeoutSec = 500,
    EnableBeep = true,
    BeepDayStart = 12,
    BeepDayEnd = 24
};

cfg.SourceFile        = Path.Combine(resultsDir, "tcp_alive.txt");
cfg.OutputFile        = Path.Combine(resultsDir, "Really_alive.txt");
cfg.DedupedFile       = Path.Combine(resultsDir, "deduped_working.txt");
cfg.DedupSnapshotFile = Path.Combine(resultsDir, "last_deduped_snapshot.txt");
cfg.TempOutput        = Path.Combine(resultsDir, "scan_result.tmp");
cfg.BlacklistFile     = Path.Combine(resultsDir, "blacklist.txt");
cfg.XrayKnifePath     = Path.Combine(AppContext.BaseDirectory, "xray-knife.exe");

AnsiConsole.MarkupLine($"[yellow]Source:[/] {cfg.SourceFile}");
AnsiConsole.MarkupLine($"[yellow]Output:[/] {cfg.OutputFile}");
AnsiConsole.MarkupLine($"[yellow]XrayKnife:[/] {cfg.XrayKnifePath}");

cfg.ScanThreads = AnsiConsole.Prompt(
    new TextPrompt<int>("[green]Number of parallel workers (1-500)[/]:")
        .DefaultValue(100)
        .Validate(w => w > 0 && w <= 500
            ? ValidationResult.Success()
            : ValidationResult.Error("Enter 1-500")));

cfg.MdelayMs = AnsiConsole.Prompt(
    new TextPrompt<int>("[green]Maximum real delay per config in ms (0-30000)[/]:")
        .DefaultValue(7000)
        .Validate(d => d >= 0 && d <= 30000
            ? ValidationResult.Success()
            : ValidationResult.Error("Enter 0-30000")));

var app = new RDScannerEngine(cfg);
await app.RunAsync();

// ═══════════════════ MODELS ═══════════════════
public class Config
{
    public string   SourceFile        { get; set; } = "";
    public string   OutputFile        { get; set; } = "";
    public string   XrayKnifePath     { get; set; } = "";
    public string   DedupedFile       { get; set; } = "deduped_working.txt";
    public string   DedupSnapshotFile { get; set; } = "last_deduped_snapshot.txt";
    public string   TempOutput        { get; set; } = "";
    public string   BlacklistFile     { get; set; } = "blacklist.txt";
    public string[] TestURLs          { get; set; } = Array.Empty<string>();
    public int      ScanThreads       { get; set; }
    public int      MdelayMs          { get; set; }
    public int      TimeoutSec        { get; set; }
    public bool     EnableBeep        { get; set; }
    public int      BeepDayStart      { get; set; }
    public int      BeepDayEnd        { get; set; }
}

public class ConfigFile
{
    public string[] TestURLs { get; set; } = Array.Empty<string>();
}

// ═══════════════════ MAIN ENGINE ═══════════════════
public class RDScannerEngine
{
    private const int MaxLogLines = 40;

    private readonly Config _cfg;
    private readonly ConcurrentDictionary<string, string> _aliveDB = new();
    private readonly Channel<string> _logChannel = Channel.CreateUnbounded<string>();
    private readonly Channel<string> _newAliveChannel = Channel.CreateUnbounded<string>();
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private HashSet<string> _blacklist = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _saveDebounceCts;
    private readonly object _saveDebounceLock = new();
    private readonly PauseManager _pauseManager = new();
    private readonly UIState _uiState = new();
    private readonly string _reportFilePath;
    private DateTime _appStartTime = DateTime.Now;

    private static readonly Regex ScrubDateRegex   = new(@"-Seen-.*", RegexOptions.Compiled);
    private static readonly Regex ScrubPrefixRegex = new(@"^\d{2}:\d{2}-\d{4}/\d{2}/\d{2}_", RegexOptions.Compiled);

    public RDScannerEngine(Config cfg)
    {
        _cfg = cfg;
        _reportFilePath = Path.Combine(
            Path.GetDirectoryName(cfg.OutputFile) ?? ".", "scan_report.txt");
    }

    public async Task RunAsync()
    {
        try
        {
            if (!File.Exists(_cfg.SourceFile))
            { AnsiConsole.MarkupLine($"[red]ERROR: Source file not found: {_cfg.SourceFile}[/]"); return; }
            if (!File.Exists(_cfg.XrayKnifePath))
            { AnsiConsole.MarkupLine($"[red]ERROR: xray-knife.exe not found: {_cfg.XrayKnifePath}[/]"); return; }

            var outputDir = Path.GetDirectoryName(_cfg.OutputFile);
            if (!string.IsNullOrWhiteSpace(outputDir)) Directory.CreateDirectory(outputDir);
            if (!File.Exists(_cfg.OutputFile)) await File.WriteAllTextAsync(_cfg.OutputFile, "");

            await LoadExistingConfigsAsync();

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

            var keyTask = ListenForPauseKey(cts.Token);
            var uiTask = RunUIAsync(cts.Token);
            var processorTask = ProcessNewConfigsAsync(cts.Token);

            while (!cts.Token.IsCancellationRequested)
            {
                _pauseManager.WaitIfPaused(cts.Token);
                _uiState.CycleCount++;
                var cycleStartTime = DateTime.Now;
                _uiState.ScanPhase = "Preparing";
                _uiState.UrlsCompletedThisCycle = 0;
                await LogAsync($"▶ Cycle #{_uiState.CycleCount} started", cts.Token);

                await LoadBlacklistAsync(cts.Token);

                var workingCount = await RefreshWorkingFileAsync(cts.Token);
                if (workingCount <= 0)
                {
                    await LogAsync("⚠ Deduped file is empty. Skipping scan cycle.", cts.Token);
                    _uiState.ScanPhase = "Waiting";
                    await Task.Delay(5000, cts.Token);
                    continue;
                }

                _uiState.ScanPhase = "Scanning";
                _uiState.UrlStatuses.Clear();

                for (int i = 0; i < _cfg.TestURLs.Length; i++)
                {
                    _pauseManager.WaitIfPaused(cts.Token);
                    cts.Token.ThrowIfCancellationRequested();

                    _uiState.CurrentUrlNum = i + 1;
                    _uiState.CurrentUrl = _cfg.TestURLs[i];
                    _uiState.ScanStartTime = DateTime.Now;
                    _uiState.CurrentUrlProgress = 0;
                    _uiState.CurrentUrlFound = 0;
                    Interlocked.Exchange(ref _uiState.TestedThisUrl, 0);

                    await LogAsync($"[{_uiState.CurrentUrlNum}/{_cfg.TestURLs.Length}] Testing: {Truncate(_uiState.CurrentUrl, 45)}", cts.Token);
                    await ScanUrlWithProgressAsync(_uiState.CurrentUrl, cts.Token);
                    _uiState.UrlsCompletedThisCycle = i + 1;

                    lock (_uiState.UrlStatuses)
                    {
                        var status = _uiState.UrlStatuses.FirstOrDefault(u => u.Url == _uiState.CurrentUrl);
                        if (status == null)
                        {
                            status = new UrlTestStatus { Url = _uiState.CurrentUrl, Status = "Done" };
                            _uiState.UrlStatuses.Add(status);
                        }
                        else status.Status = "Done";
                    }
                }

                var cycleTime = (DateTime.Now - cycleStartTime).TotalSeconds;
                _uiState.ScanPhase = "Waiting";
                await LogAsync($"✅ Cycle completed in {cycleTime:F0}s. Waiting 5s...", cts.Token);
                await File.AppendAllTextAsync(_reportFilePath,
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | Cycle {_uiState.CycleCount} | Alive: {_aliveDB.Count} | New: {_uiState.NewThisSession} | Time: {cycleTime:F0}s\n",
                    cts.Token);
                await Task.Delay(5000, cts.Token);
            }

            cts.Cancel();
            _newAliveChannel.Writer.Complete();
            _logChannel.Writer.Complete();
            try { await Task.WhenAll(uiTask, processorTask, keyTask); } catch { }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            try { await LogAsync($"❌ Fatal error: {ex.Message}"); } catch { }
            AnsiConsole.MarkupLine($"[red]Fatal error:[/] {ex.Message}");
        }
        finally
        {
            _newAliveChannel.Writer.TryComplete();
            _logChannel.Writer.TryComplete();
        }
    }

    private async Task ListenForPauseKey(CancellationToken token)
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
                        await LogAsync("⏯ Resumed by user", token);
                    }
                    else
                    {
                        _pauseManager.Pause();
                        await LogAsync("⏸ Paused by user (press P to resume)", token);
                    }
                }
            }
            await Task.Delay(100, token);
        }
    }

    // ──────── Blacklist ────────
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
            await LogAsync($"🚫 Loaded {_blacklist.Count} blacklist patterns", token);
        }
        catch (Exception ex)
        {
            await LogAsync($"⚠ Failed to load blacklist: {ex.Message}", token);
        }
    }

    private async Task LogAsync(string message, CancellationToken token = default)
        => await _logChannel.Writer.WriteAsync(message, token);

    private async Task LoadExistingConfigsAsync()
    {
        if (!File.Exists(_cfg.OutputFile)) return;
        var lines = await File.ReadAllLinesAsync(_cfg.OutputFile);
        int loaded = 0;
        foreach (var line in lines)
        {
            var (link, _) = ParseConfig(line);
            if (string.IsNullOrEmpty(link)) continue;
            _aliveDB[link] = line;
            loaded++;
        }
        if (loaded > 0)
            await LogAsync($"📂 Loaded {loaded} configs from database");
    }

    private async Task<int> RefreshWorkingFileAsync(CancellationToken token)
    {
        if (!File.Exists(_cfg.SourceFile)) return 0;

        string[] sourceLines = Array.Empty<string>();
        for (int retry = 0; retry < 3; retry++)
        {
            try { sourceLines = await File.ReadAllLinesAsync(_cfg.SourceFile, token); break; }
            catch (IOException) { await Task.Delay(1000, token); }
        }
        if (sourceLines.Length == 0)
        {
            await LogAsync("⚠ Could not read source file (in use by another process)", token);
            return 0;
        }

        _uiState.SourceConfigCount = sourceLines.Length;

        bool needsDedup = true;
        if (File.Exists(_cfg.DedupSnapshotFile))
        {
            var snap = await File.ReadAllLinesAsync(_cfg.DedupSnapshotFile, token);
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
            await File.WriteAllLinesAsync(_cfg.DedupSnapshotFile, sourceLines, token);
            _uiState.WorkingConfigCount = deduped.Count;
            await LogAsync($"📄 Source deduped: {sourceLines.Length} -> {_uiState.WorkingConfigCount} unique lines", token);
        }
        else
        {
            _uiState.WorkingConfigCount = File.Exists(_cfg.DedupedFile)
                ? await CountLinesAsync(_cfg.DedupedFile, token)
                : 0;
        }
        return _uiState.WorkingConfigCount;
    }

    private static async Task<int> CountLinesAsync(string path, CancellationToken token)
    {
        int count = 0;
        using var reader = new StreamReader(path);
        while (await reader.ReadLineAsync(token) != null) count++;
        return count;
    }

    private async Task ScanUrlWithProgressAsync(string url, CancellationToken token)
    {
        if (File.Exists(_cfg.TempOutput))
            try { File.Delete(_cfg.TempOutput); } catch { }

        _uiState.ScanPhase = "Launching";
        await LogAsync($"▶ Starting: {Truncate(url, 50)}", token);

        double estimatedSeconds = 0;
        if (_uiState.WorkingConfigCount > 0 && _cfg.ScanThreads > 0)
            estimatedSeconds = (_uiState.WorkingConfigCount / (double)_cfg.ScanThreads) * (_cfg.MdelayMs / 1000.0);

        int dynamicTimeoutSec = Math.Max(_cfg.TimeoutSec, (int)estimatedSeconds + 120);

        var args = $"http -f \"{_cfg.DedupedFile}\" --thread {_cfg.ScanThreads} --mdelay {_cfg.MdelayMs} " +
                   $"--insecure=true --url \"{url}\" -o \"{_cfg.TempOutput}\"";

        var psi = new ProcessStartInfo
        {
            FileName = _cfg.XrayKnifePath,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = AppContext.BaseDirectory
        };

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
                Interlocked.Increment(ref _uiState.TestedThisUrl);
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
            {
                lock (stdErr) stdErr.AppendLine(e.Data);
                Interlocked.Increment(ref _uiState.TestedThisUrl);
            }
        };

        if (!proc.Start())
        {
            await LogAsync("❌ Failed to start xray-knife.exe", token);
            return;
        }

        _uiState.ScanPhase = "Running";
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var monitorCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        var monitorTask = MonitorProgressAsync(proc, monitorCts.Token);

        try
        {
            var exitTask = proc.WaitForExitAsync(token);
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(dynamicTimeoutSec), token);
            var completed = await Task.WhenAny(exitTask, timeoutTask);

            if (completed == timeoutTask && !proc.HasExited)
            {
                _uiState.ScanPhase = "Timeout";
                try { proc.Kill(entireProcessTree: true); } catch { }
                await LogAsync($"⏱ Scan timeout after {dynamicTimeoutSec}s (~{estimatedSeconds:F0}s estimated)", token);
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
            await LogAsync($"⚠ xray-knife error (code {proc.ExitCode}): {Truncate(errorText, 100)}", token);

        if (File.Exists(_cfg.TempOutput))
        {
            var lines = await File.ReadAllLinesAsync(_cfg.TempOutput, token);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || !line.Contains("://")) continue;

                var (link, name) = ParseConfig(line);
                if (string.IsNullOrEmpty(link)) continue;

                if (_blacklist.Count > 0 && _blacklist.Any(pattern =>
                    link.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                    name.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                {
                    await LogAsync($"🚫 Blocked by blacklist: {Truncate(name, 24)}", token);
                    continue;
                }

                var now = DateTime.Now;
                string date = now.ToString("dd/MM/yyyy");
                string time = now.ToString("HH:mm");
                string rawFragment = $"{date}  **MIZIsub**  {time}";
                string newLine = $"{link}#{Uri.EscapeDataString(rawFragment)}";

                if (_aliveDB.TryAdd(link, newLine))
                {
                    Interlocked.Increment(ref _uiState.NewThisSession);
                    Interlocked.Increment(ref _uiState.CurrentUrlFound);
                    await _newAliveChannel.Writer.WriteAsync(newLine, token);
                    await AppendToFileAsync(newLine, token);
                }
                else
                {
                    _aliveDB[link] = newLine;
                }

                TriggerDebouncedSave();
            }
        }

        _uiState.CurrentUrlProgress = 100;
        _uiState.ScanPhase = "Done";
        try { File.Delete(_cfg.TempOutput); } catch { }
    }

    private async Task MonitorProgressAsync(Process proc, CancellationToken token)
    {
        while (!token.IsCancellationRequested && !proc.HasExited)
        {
            double progress = _uiState.WorkingConfigCount > 0
                ? (_uiState.TestedThisUrl / (double)_uiState.WorkingConfigCount) * 100.0
                : 0;
            double fallback = _cfg.TimeoutSec > 0
                ? Math.Min(95, ((DateTime.Now - _uiState.ScanStartTime).TotalSeconds / _cfg.TimeoutSec) * 100.0)
                : 0;
            _uiState.CurrentUrlProgress = Math.Clamp(Math.Max(progress, fallback), 0, 100);
            try { await Task.Delay(300, token); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void TriggerDebouncedSave()
    {
        lock (_saveDebounceLock)
        {
            _saveDebounceCts?.Cancel();
            _saveDebounceCts?.Dispose();
            _saveDebounceCts = new CancellationTokenSource();
            var token = _saveDebounceCts.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(5000, token);
                    await SaveFullDatabaseAsync();
                }
                catch (TaskCanceledException) { }
            }, token);
        }
    }

    private async Task AppendToFileAsync(string line, CancellationToken token)
    {
        await _fileLock.WaitAsync(token);
        try { await File.AppendAllTextAsync(_cfg.OutputFile, line + Environment.NewLine, token); }
        finally { _fileLock.Release(); }
    }

    private async Task SaveFullDatabaseAsync()
    {
        await _fileLock.WaitAsync();
        try
        {
            var sorted = _aliveDB.Values
                .OrderByDescending(ExtractSortDateTime)
                .ToList();
            await File.WriteAllLinesAsync(_cfg.OutputFile, sorted);
        }
        finally { _fileLock.Release(); }
    }

    private static DateTime ExtractSortDateTime(string fullLine)
    {
        var idx = fullLine.IndexOf('#');
        if (idx < 0) return DateTime.MinValue;
        var fragment = Uri.UnescapeDataString(fullLine[(idx + 1)..]);

        var matchNew = Regex.Match(fragment, @"^(\d{2}/\d{2}/\d{4})\s+\*\*MIZIsub\*\*\s+(\d{2}:\d{2})$");
        if (matchNew.Success)
        {
            if (DateTime.TryParseExact($"{matchNew.Groups[1].Value} {matchNew.Groups[2].Value}",
                "dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                return dt;
        }
        return DateTime.MinValue;
    }

    private async Task ProcessNewConfigsAsync(CancellationToken token)
    {
        try
        {
            await foreach (var line in _newAliveChannel.Reader.ReadAllAsync(token))
            {
                var (_, name) = ParseConfig(line);
                await LogAsync($"✨ NEW: {Truncate(name, 24)}", token);
                BeepNewConfig();
            }
        }
        catch (OperationCanceledException) { }
    }

    private void BeepNewConfig()
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

    private (string link, string name) ParseConfig(string raw)
    {
        raw = raw.Trim();
        var idx = raw.IndexOf('#');
        var link = idx > 0 ? raw[..idx].Trim() : raw;
        var name = idx > 0 ? raw[(idx + 1)..].Trim() : "Scan";
        name = ScrubDateRegex.Replace(name, "");
        name = ScrubPrefixRegex.Replace(name, "");
        name = name.Trim();
        if (string.IsNullOrEmpty(name)) name = "Scan";
        return (link, name);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 3)] + "...";

    // ═══════════ UI ═══════════
    private async Task RunUIAsync(CancellationToken token)
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
                        while (_logChannel.Reader.TryRead(out var msg))
                        {
                            logs.Add($"[{DateTime.Now:HH:mm:ss}] {msg}");
                            if (logs.Count > MaxLogLines) logs.RemoveAt(0);
                        }

                        var uptime = DateTime.Now - _appStartTime;
                        var scanElapsed = DateTime.Now - _uiState.ScanStartTime;
                        int totalUrls = _cfg.TestURLs.Length;
                        int doneUrls = Math.Clamp(_uiState.UrlsCompletedThisCycle, 0, totalUrls);
                        double urlProgress = Math.Clamp(_uiState.CurrentUrlProgress, 0, 100);
                        double cycleProgress = totalUrls > 0
                            ? Math.Clamp(((doneUrls + urlProgress / 100.0) / totalUrls) * 100.0, 0, 100)
                            : 0;
                        int estRemaining = Math.Max(0, _uiState.WorkingConfigCount - (int)(_uiState.WorkingConfigCount * urlProgress / 100));
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
                        var headerMarkup = $"[bold cyan]⏱ REAL DELAY SCANNER[/]{pauseInfo}   [bold {phaseColor}]● {Markup.Escape(_uiState.ScanPhase.ToUpper())}[/]" +
                                           $"   [grey]UPTIME {uptime:hh\\:mm\\:ss}[/]" +
                                           $"   [bold green]ALIVE {_aliveDB.Count:N0}[/]  [cyan]CYCLE {_uiState.CycleCount}[/]  [yellow]URL {_uiState.CurrentUrlNum}/{totalUrls}[/]";
                        var header = new Panel(Align.Center(new Markup(headerMarkup)))
                            .Border(BoxBorder.Heavy).BorderStyle(new Style(Color.Cyan1)).Expand();

                        var cycleBarColor = cycleProgress < 50 ? "yellow" : cycleProgress < 90 ? "cyan" : "green";
                        var cycleBar = BuildBar(cycleProgress, 24);
                        var urlBar   = BuildBar(urlProgress, 24);

                        var urlStatusList = new List<IRenderable>();
                        if (_uiState.UrlStatuses.Count > 0)
                        {
                            foreach (var u in _uiState.UrlStatuses.TakeLast(5).Reverse())
                            {
                                var mark = u.Status == "Done" ? "[green]✓[/]" :
                                           u.Status == "Testing" ? "[yellow]⏳[/]" : "[grey]…[/]";
                                urlStatusList.Add(new Markup($"  {mark} {Markup.Escape(Truncate(u.Url, 50))}"));
                            }
                        }
                        else
                        {
                            urlStatusList.Add(new Markup("  [grey]No URLs tested yet[/]"));
                        }
                        var urlStatusRows = new Rows(urlStatusList);

                        var leftContent = new Rows(
                            new Markup("[bold white]-- RESULTS -----------------[/]"),
                            new Markup($"  [bold green]👍 ALIVE   {_aliveDB.Count,7:N0}[/]"),
                            new Markup($"  [yellow]🔄 CYCLE   {_uiState.CycleCount,7:N0}[/]"),
                            new Markup($"  [cyan]🔗 URL     {_uiState.CurrentUrlNum,3}/{totalUrls}[/]"),
                            new Markup($"  [grey]📄 SOURCE  {_uiState.SourceConfigCount,7:N0}[/]"),
                            new Markup($"  [grey]✨ NEW     {_uiState.NewThisSession,7:N0}[/]"),
                            new Markup($"  [grey]⏳ LEFT    {estRemaining,7:N0}[/]"),
                            new Text(""),
                            new Markup("[bold white]-- PROGRESS ----------------[/]"),
                            new Markup($"  [grey]Cycle:[/]  [{cycleBarColor}]{cycleBar}[/] [bold]{cycleProgress,5:0.0}%[/]"),
                            new Markup($"  [grey]URL  :[/]  [cyan]{urlBar}[/] [bold]{urlProgress,5:0.0}%[/]"),
                            new Markup($"  [grey]ETA  :[/]  [yellow]{eta:hh\\:mm\\:ss}[/]"),
                            new Text(""),
                            new Markup("[bold white]-- CURRENT URL -------------[/]"),
                            new Markup($"  [grey]{Markup.Escape(Truncate(_uiState.CurrentUrl, 55))}[/]"),
                            new Text(""),
                            new Markup("[bold white]-- TESTED URLs -------------[/]"),
                            urlStatusRows,
                            new Text(""),
                            new Markup("[bold white]-- CONFIG ------------------[/]"),
                            new Markup($"  [grey]Threads :[/]  [yellow]{_cfg.ScanThreads}[/]"),
                            new Markup($"  [grey]Delay   :[/]  [yellow]{_cfg.MdelayMs} ms[/]"),
                            new Markup($"  [grey]Beep    :[/]  [yellow]{(_cfg.EnableBeep ? "ON" : "OFF")}[/]"),   // ← اصلاح شده
                            new Markup($"  [grey]Pause   :[/]  [yellow]{(isPaused ? "PAUSED" : "Running")}[/]")
                        );
                        var leftPanel = new Panel(Align.Left(leftContent))
                            .Border(BoxBorder.Rounded).BorderStyle(new Style(Color.Cyan1))
                            .Header("[bold cyan] STATS [/]").Expand();

                        var visibleLogs = logs.TakeLast(14).Select(ColorizeLogLine).Cast<IRenderable>().ToArray();
                        IRenderable logContent = visibleLogs.Length > 0
                            ? new Rows(visibleLogs)
                            : new Markup("[grey]Waiting for data…[/]");
                        var logPanel = new Panel(Align.Left(logContent))
                            .Border(BoxBorder.Rounded).BorderStyle(new Style(Color.Grey))
                            .Header("[bold grey] DATA STREAM [/]").Expand();

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
        if (line.Contains("✨") || line.Contains("NEW")) return new Markup($"[green]{safe}[/]");
        if (line.Contains("❌") || line.Contains("Fatal") || line.Contains("error")) return new Markup($"[red]{safe}[/]");
        if (line.Contains("⚠") || line.Contains("Timeout") || line.Contains("Waiting")) return new Markup($"[yellow]{safe}[/]");
        if (line.Contains("✅") || line.Contains("Cycle") || line.Contains("Flushed")) return new Markup($"[cyan]{safe}[/]");
        return new Markup($"[grey]{safe}[/]");
    }

    private static string BuildBar(double percent, int width = 24)
    {
        percent = Math.Clamp(percent, 0, 100);
        var filled = Math.Clamp((int)Math.Round((percent / 100.0) * width), 0, width);
        return new string('█', filled) + new string('░', width - filled);
    }
}

// ═══════════════ HELPERS ═══════════════
public class UIState
{
    public long CycleCount;
    public int NewThisSession;
    public int CurrentUrlNum;
    public string CurrentUrl = "";
    public double CurrentUrlProgress;
    public int CurrentUrlFound;
    public int TestedThisUrl;
    public string ScanPhase = "Idle";
    public int SourceConfigCount;
    public int WorkingConfigCount;
    public int UrlsCompletedThisCycle;
    public DateTime ScanStartTime = DateTime.Now;
    public List<UrlTestStatus> UrlStatuses = new();
}

public class UrlTestStatus
{
    public string Url { get; init; } = "";
    public string Status { get; set; } = "Waiting";
}

public class PauseManager
{
    private readonly ManualResetEventSlim _pauseEvent = new(true);
    private volatile bool _isPaused;

    public bool IsPaused => _isPaused;

    public void Pause()
    {
        _isPaused = true;
        _pauseEvent.Reset();
    }

    public void Resume()
    {
        _isPaused = false;
        _pauseEvent.Set();
    }

    public void WaitIfPaused(CancellationToken token)
    {
        _pauseEvent.Wait(token);
    }
}

public static class PathHelper
{
    public static string? FindResultsFolder()
    {
        var baseDir = AppContext.BaseDirectory;
        while (baseDir != null)
        {
            var candidate = Path.Combine(baseDir, "RESULTS");
            if (Directory.Exists(candidate))
                return candidate;
            baseDir = Directory.GetParent(baseDir)?.FullName;
        }
        return null;
    }
}