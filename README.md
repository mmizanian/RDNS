# RDScanner

A tool to test proxy configurations using xray-knife.

## What it does

Reads a list of proxy configs (vless, vmess, trojan, ss, etc.) and tests each one against multiple HTTP endpoints to find which ones are alive and working.

## Requirements

- .NET 8.0
- xray-knife.exe in the same folder

## Setup

1. Create a `RESULTS` folder
2. Put your configs in `RESULTS/tcp_alive.txt`
3. Put `xray-knife.exe` in the root folder

## Run

`dotnet run`

The program will ask for:
- Number of threads
- Delay between requests (ms)

## Input Format

One config per line in `tcp_alive.txt`:

`vless://uuid@server.com:443?encryption=none`
`vmess://base64...`
`trojan://password@server.com:443`

## Output

Results saved to `RESULTS/Really_alive.txt` with timestamp and verification status.

## Configuration

Edit `Config` section in `Program.cs`:
- `TestURLs`: URLs used for testing
- `ScanThreads`: concurrent workers
- `MdelayMs`: delay between requests
- `EnableVerification`: test with YouTube

## Files

| File | Purpose |
|------|---------|
| `tcp_alive.txt` | Input configs |
| `Really_alive.txt` | Output (verified working configs) |
| `blacklist.txt` | Configs to skip (optional) |
| `deduped_working.txt` | Temp deduplicated file |

## Stop

Press `Ctrl + C` to stop and save results.
