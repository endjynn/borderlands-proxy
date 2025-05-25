# Borderlands GOTY Enhanced - Exit Hang Fix

A `version.dll` proxy for Borderlands GOTY Enhanced (x64) that resolves a common game hang issue occurring upon exit.

This fix works by intercepting a specific `WaitForSingleObjectEx` call made by the game's main thread during the shutdown sequence and modifying its timeout from `INFINITE` to `1ms`, preventing a deadlock.

## Features

* Fixes the game hang on exit.
* Includes optional debug logging (controlled via `PROXY_DEBUG_LOGGING` in `dllmain.c`).
* Built using MinHook for API hooking.

## Usage

Place the compiled `version.dll` into the main Borderlands GOTY Enhanced game directory where `BorderlandsGOTY.exe` is located.

A typical Steam installation path might be:
`C:\Program Files (x86)\Steam\steamapps\common\BorderlandsGOTYEnhanced\Binaries\Win64\`

Ensure it's in the same directory as `BorderlandsGOTY.exe`.

---

*A more detailed explanation of the issue is available in [DETAILED_SUMMARY.md](DETAILED_SUMMARY.md).*
