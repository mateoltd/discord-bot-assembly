# Discord Bot in MASM x64 (Windows)

MVP goal: a Discord bot written in pure x64 assembly (MASM) that connects to the Gateway over TLS WebSocket and replies "pong" to "ping" (guild messages). Networking will use Winsock + SChannel; crypto RNG via BCrypt.

## Prerequisites
- Windows 10/11 x64
- Visual Studio Build Tools or Visual Studio with C++ workload (includes ml64.exe, link.exe)
- Windows 10/11 SDK (libraries: kernel32.lib, ws2_32.lib, secur32.lib, crypt32.lib, bcrypt.lib)

## Build
Recommended: run from "x64 Native Tools Command Prompt for VS" so environment variables are set.

```
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

If the script cannot find the tools, install VS Build Tools and Windows SDK, or run from the native tools prompt.

## Run
```
.\build\bot.exe
```
It prints a bootstrap message, verifies Winsock, attempts to load `DISCORD_BOT_TOKEN` from the environment, and performs a simple TCP connect to `discord.com:443`.

You can provide the bot token in any of these ways (checked in this order):

- `DISCORD_BOT_TOKEN` environment variable.
- `DISCORD_TOKEN_FILE` environment variable pointing to a file path.
- `config/token.txt` (this repo ignores the entire `config/` dir by default).

Set your token in the current shell before running:

```powershell
$env:DISCORD_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
```

Or write it once to `config/token.txt`

## Roadmap (MVP)
See the root TODOs managed in our session: Winsock layer, TLS via SChannel, HTTP/1.1, WebSocket, Discord Gateway (HELLO/IDENTIFY/heartbeat), simple ping→pong responder.
