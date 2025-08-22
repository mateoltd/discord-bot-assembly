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
It should print a bootstrap message. Next steps will wire up Winsock + SChannel, HTTP, WebSocket, and Discord Gateway.

## Roadmap (MVP)
See the root TODOs managed in our session: Winsock layer, TLS via SChannel, HTTP/1.1, WebSocket, Discord Gateway (HELLO/IDENTIFY/heartbeat), simple ping→pong responder.
