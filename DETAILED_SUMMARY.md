# Borderlands GOTY Enhanced - Exit Hang

## 0. Introduction

This document provides a technical summary detailing the diagnostic journey and ultimate resolution of a persistent thread deadlock issue encountered in "Borderlands GOTY Enhanced" (`BorderlandsGOTY.exe`, x64). This deadlock caused the game to hang reliably upon exit, requiring manual process termination. The solution involved developing a `version.dll` proxy that utilizes the MinHook library to intercept and modify a specific `WaitForSingleObjectEx` call at runtime. This summary is intended for an audience with a strong understanding of debugging, Windows internals, and x64 assembly.

## 1. Executive Summary

This report outlines the comprehensive diagnostic process and successful resolution of a thread deadlock that caused "Borderlands GOTY Enhanced" to hang during its exit sequence. Initial investigations confirmed a deadlock scenario: the main game thread would stall in an infinite `WaitForSingleObjectEx` (WSOEx) call, while a worker thread was also similarly blocked. A significant debugging effort, leveraging WinDbg with custom JavaScript extensions and an iterative breakpoint strategy, was undertaken to navigate challenges, including debugger-induced application instability.

The investigation pinpointed the root cause: a specific `WaitForSingleObjectEx` call made by the main thread (returning to RVA `0x1F6B90` within `BorderlandsGOTY.exe`) was using an `INFINITE` timeout. The instruction initiating this call is located at RVA `0x1F6B8A`, with critical parameter setup (the handle and timeout) occurring at RVAs `0x1F6B83` and `0x1F6B87` respectively, all within a code block beginning at RVA `0x1F6B80`.

A crucial "Heisenbug" was observed: a software breakpoint placed at RVA `0x1F6B80` inadvertently allowed the game to exit cleanly. This validated the direct involvement of this code path in the hang. The implemented solution is a `version.dll` proxy employing MinHook to intercept the problematic WSOEx call. The detour function intelligently modifies the `INFINITE` timeout to a nominal `1ms` for this specific call instance, thereby preventing the deadlock and enabling the game to terminate gracefully. This solution, fully implemented in `dllmain.c` (v5.0.0), has been verified as effective.

## 2. Initial Problem Definition and Deadlock Analysis

The central issue was the consistent failure of `BorderlandsGOTY.exe` to terminate after a user initiated a quit, resulting in a hung process. Detailed preliminary analysis identified this as a classic inter-thread deadlock with the following characteristics:

* **Main Game Thread:** Became indefinitely blocked in `KERNELBASE!WaitForSingleObjectEx`.
    * Timeout Parameter: `INFINITE` (`0xFFFFFFFF`).
    * Alertable Status: `FALSE`.
    * Return Address (within `BorderlandsGOTY.exe`): RVA `0x1F6B90`.
    * Waited-on Object: A handle corresponding to a specific Worker Thread.

* **Worker Thread:** Was concurrently blocked in `KERNEL32!WaitForSingleObject`.
    * Timeout Parameter: `INFINITE`.
    * Call Origin: An indirect call sequence originating at RVA `0x133EC0` (within a function symbolically related to `GMatrix2D::Swap`), which executed `call qword ptr [rax+28h]`, invoking a "WrapperFunc".
    * `WrapperFunc` Details: This function, located at RVA `0x1F7EC0`, performed several key operations: at RVA `0x1F7EC4`, it loaded an event handle via `mov rcx, qword ptr [rcx+8]` (from an object `ObjW`, where `ObjW[+0x8]` held the event handle). Subsequently, it called `WaitForSingleObject` at RVA `0x1F7EC8`. The VTable for `ObjW` (which contained the pointer to `WrapperFunc`) was located at RVA `0x1995C50`. The `ObjW` structure also contained a `DWORD` at offset `+0x38` with the value `0x80000000`. An associated object, `ObjS` (pointed to by the `r14` register in the frame calling `WrapperFunc`), contained a GUID-like string, and a pointer to `ObjW` was found at `[r14+68h]`.
    * Event Object: An unnamed, auto-reset event.
    * Timeout Setup for Worker's Wait: The `INFINITE` timeout for this worker thread's wait was frequently established by an `or edx, 0xFFFFFFFF` instruction at RVA `0x133EBD`.

The deadlock condition arose because the main thread initiated its indefinite wait before the worker thread's associated event object was signaled. Given that the game executable was likely packed or protected, a runtime patching approach was deemed most appropriate.

## 3. Diagnostic Strategy & Initial Challenges with Proxy Hooking

A `version.dll` proxy, leveraging the MinHook x64 library, was selected as the primary method for runtime intervention. However, initial implementation attempts encountered several significant difficulties:
* **Imprecise Hooking:** Broadly hooking `WaitForSingleObjectEx` for all threads led to an excessive number of detour invocations from unrelated system and game threads. Universally altering timeouts in these hooks caused instability and crashes.
* **Instability with Direct Function Hooks:** Attempts to directly hook specific game functions (e.g., the `WrapperFunc` at RVA `0x1F7EC0` or its caller at RVA `0x133EC0`) at application startup frequently resulted in immediate crashes, possibly due to anti-tamper mechanisms or uninitialized game state.
* **"Just-In-Time" Hooking Latency:** Strategies involving dynamic hooking, where patches were intended to be applied only upon heuristic detection of a game exit sequence, proved too slow to reliably prevent the deadlock.
  These challenges underscored the necessity of precisely identifying a stable and relevant `RVA_QuitEntryPoint` or the specific problematic call site active only during the hang condition.

## 4. Debugging Methodology: WinDbg, Scripting, and Iterative Refinement

### 4.1. WinDbg and Scripting Environment Evolution
The debugging environment evolved from classic WinDbg scripts (`.wds`), which proved inadequate for complex conditional logic and state tracking, to utilizing WinDbg's more powerful JavaScript engine (via `.scriptload` and the `dx` command). This transition enabled more sophisticated breakpoint management and on-the-fly state analysis. A key challenge encountered during this phase was significant game slowdown or "thrashing" when `KERNELBASE!WaitForSingleObjectEx` breakpoints invoking JavaScript were active during general gameplay. This necessitated developing strategies for careful, conditional application of these advanced breakpoints.

### 4.2. Breakpoint Strategy Evolution & Key Observations

A series of breakpoint strategies were employed to narrow down the cause:

* **Targeting `user32!PostQuitMessage`:** A software breakpoint on this common exit API did not result in a clean debugger break as initially hoped. Instead, it consistently triggered the game's internal "General protection fault!" dialog. The call stack provided by this dialog, however, offered valuable RVAs within `BorderlandsGOTY.exe` (e.g., `0x1FA6E30`, `0x1FA12F8`, `0x20B0A92`) associated with this specific debugger-induced crash pathway.

* **Targeting RVAs from Crash Stacks (Hardware Breakpoints - HWBPs):** HWBPs (`ba e1`) were subsequently set on the RVAs obtained from the `PostQuitMessage` crash, as well as another distinct crash stack (which included a reference to `GThread::OnExit` at RVA `0x125DE63`). These HWBPs were not triggered when the game was quit in a manner that led to the typical *hang*, suggesting these specific RVAs were more related to pathways activated under debugger interference rather than the hang itself.

* **Focusing on the Known Hanging Call Site (RVAs `0x1F6B8A`, `0x1F6B83`):**
  The investigation then concentrated on the main thread's `WaitForSingleObjectEx` call, known to return to RVA `0x1F6B90`. Disassembly confirmed the surrounding instructions:
    * RVA `0x1F6B8A`: The `call qword ptr [IAT_WSOEx_Entry]` instruction itself.
    * RVA `0x1F6B87`: The `or edx,0xFFFFFFFFh` instruction, setting the `INFINITE` timeout.
    * RVA `0x1F6B83`: The `mov rcx,qword ptr [rbx+8]` instruction, setting the `hHandle` parameter.
      Attempts to set HWBPs on `0x1F6B8A` or `0x1F6B83` did not permit the breakpoint's command script to execute cleanly; the game would generate a GPF at the exact RVA of the HWBP. Software breakpoints (`bp`) on these RVAs exhibited similar behavior, with the GPF occurring at or immediately following the breakpointed instruction, indicating high sensitivity in this code region.

* **The "Heisenbug" Discovery (Software Breakpoint at RVA `0x1F6B80`):**
  A pivotal moment occurred when a software breakpoint was placed at RVA `0x1F6B80` (an `add dword ptr [rbp+0Dh],esi` instruction, marking the beginning of the code block that leads to the problematic `WaitForSingleObjectEx`).
    * **Outcome:** With this SWBP active (whether its command was a JavaScript call or a simple `".break"`), the game consistently exited cleanly without any hang or crash. Notably, the WinDbg breakpoint itself was not visibly triggered in a way that halted the debugger for user interaction before the process terminated.
    * **Significance:** This "Heisenbug" effect strongly indicated that the mere presence and debugger handling of the `INT 3` instruction at `0x1F6B80` subtly altered the execution timing or state in a way that prevented the deadlock. This confirmed that RVA `0x1F6B80` and its containing function were integral to the hang pathway. The `sxe gp` command was also refined in the loader script during this period to better handle first-chance exceptions.

## 5. Solution Formulation & Implementation

The "Heisenbug" discovery provided strong validation that the code block commencing at RVA `0x1F6B80`, which includes the `WaitForSingleObjectEx` call at RVA `0x1F6B8A` (returning to RVA `0x1F6B90`), is executed during the problematic exit sequence. The core issue was this call's use of an `INFINITE` timeout.

The implemented solution, detailed in the `version.dll` proxy's `dllmain.c` file and utilizing MinHook, involves the following steps:
1.  Hooking the `KERNELBASE!WaitForSingleObjectEx` API function.
2.  In the custom detour function (`DetourWaitForSingleObjectEx_ApplyFix`):
    * The call's return address within `BorderlandsGOTY.exe` is retrieved.
    * This return address is converted to an RVA relative to the game's base address.
    * A conditional check is performed: if the calculated return RVA matches `0x1F6B90` (the specific site identified) AND the `dwMilliseconds` parameter for the wait is `INFINITE`, then the `dwMilliseconds` parameter is modified to `1ms` (defined as `PATCHED_TIMEOUT_MS` in `dllmain.c`).
3.  The original `WaitForSingleObjectEx` function is then called, using the original handle and alertable status, but with the potentially modified timeout value.

This targeted modification directly addresses the faulty wait condition without broadly affecting other uses of `WaitForSingleObjectEx`. The final version of `dllmain.c` (v5.0.0) incorporates this logic, along with robust MinHook initialization and uninitialization procedures. The solution was verified to successfully resolve the game's exit hang.

## Appendix A: Key Relative Virtual Addresses (RVAs) and Memory Details
(Module: `BorderlandsGOTY.exe`. Assumed Game Base for RVA calculation, e.g., `0x7ff6f1870000`. Known Module Size: `0x2959000`)

This appendix provides a reference list of important RVAs within `BorderlandsGOTY.exe` and other memory-related details identified during the debugging process.

* **Main Thread's Problematic `WaitForSingleObjectEx` Call Site (Central to Hang/Fix):**
    * `RVA 0x1F6B80`: `add dword ptr [rbp+0Dh],esi`. This instruction marks the beginning of the critical code block. A software breakpoint at this RVA led to the "Heisenbug" (clean game exit). WinDbg symbolically associated this with `GetOutermost+0x379f0`.
    * `RVA 0x1F6B83`: `mov rcx,qword ptr [rbx+8]`. This instruction sets the `hHandle` (first parameter, `rcx`) for the `WaitForSingleObjectEx` call.
    * `RVA 0x1F6B87`: `or edx,0xFFFFFFFFh`. This instruction sets the `dwMilliseconds` (second parameter, `edx`) to `INFINITE` for the `WaitForSingleObjectEx` call.
    * `RVA 0x1F6B8A`: `call qword ptr [BorderlandsGOTY!GColor::SetHSV+0x1cd028]` (example symbolic name from one debugging session for the IAT entry). This is the actual `call` instruction to `KERNELBASE!WaitForSingleObjectEx` via an IAT entry.
    * `RVA 0x1F6B90`: The return address in `BorderlandsGOTY.exe` immediately after the `WaitForSingleObjectEx` call originating from RVA `0x1F6B8A`. This RVA is the primary identifier used in the proxy DLL patch, defined as `RVA_MainThread_WSOEx_ReturnSite` in `dllmain.c`.
    * `WSOEX_TARGET_TIMEOUT_CONST`: `0xFFFFFFFF` (Value used as a constant in JavaScript diagnostic scripts for the infinite timeout).

* **Worker Thread's `WaitForSingleObject` Call Site (Identified in Initial Deadlock Analysis):**
    * `RVA 0x133EBD`: `or edx, 0xFFFFFFFF`. An instruction setting an `INFINITE` timeout related to the worker thread's wait, symbolically associated with `GMatrix2D::Swap+0x6d42d`.
    * `RVA 0x133EC0`: `call qword ptr [rax+28h]`. The indirect call instruction leading to the worker thread's wait condition.
    * `RVA 0x1F7EC0`: The start RVA of the "WrapperFunc" (the target of the indirect call from RVA `0x133EC0`), symbolically associated with `GetOutermost+0x38d30`.
    * `RVA 0x1F7EC4`: `mov rcx, qword ptr [rcx+8]`. Instruction within `WrapperFunc` that loads the event `HANDLE` from an object structure (referred to as `ObjW[+0x8]`).
    * `RVA 0x1F7EC8`: `call qword ptr [IAT_Entry_for_WaitForSingleObject]`. The call to `KERNEL32!WaitForSingleObject` within `WrapperFunc`.
    * `RVA 0x1F7ECE`: The return site within `WrapperFunc` after its `WaitForSingleObject` call.
    * `RVA 0x1995C50`: The address of the VTable for the `ObjW` object, which contained a pointer to `WrapperFunc`.
    * `ObjW[+0x38]`: A `DWORD` field within the `ObjW` structure, observed to hold the value `0x80000000`.
    * `ObjS`: An object pointed to by the `r14` register in the frame that indirectly called `WrapperFunc`. This object contained a GUID-like Unicode string (e.g., `S:\DRIVERS\ENUM\{741A2100-1023-11E9-B56E-0800200C9A66}`). The pointer to `ObjW` was found at offset `[r14+68h]` within `ObjS`.

* **RVAs from Game's Internal "General Protection Fault!" Dialog (Triggered by `user32!PostQuitMessage` Breakpoint):**
    * `RVA 0x1FA6E30`: (Labeled `GetOutermost()` by the game's crash handler).
    * `RVA 0x1FA12F8`: (Labeled `GetOutermost()` by the game's crash handler).
    * `RVA 0x20B0A92`: (Labeled `GThread::OnExit()` by the game's crash handler).

* **RVA from Game's Internal "General Protection Fault!" Dialog (Triggered by HWBPs on the WSOEx block):**
  (The RVA is calculated from the fault address provided in the game's dialog, relative to the game's base address).
    * `RVA 0x125DE63`: (Labeled `GThread::OnExit()` by the game's crash handler).

* **Module Information:**
    * Target Module Filename: `BORDERLANDSGOTY.EXE`
    * Known Module Size (used in JavaScript scripts for base/end address calculation): `0x2959000` bytes.

## Appendix B: WinDbg Scripting Evolution Summary

The diagnostic process involved an iterative development of WinDbg loader scripts (e.g., `loader-discovery.wds`) and JavaScript extensions (e.g., `bl_discovery_script.js`). This appendix textually summarizes their evolution and key strategic shifts.

1.  **Initial Scripting Phase:**
    * **Focus:** Primarily on basic JavaScript loading and function invocation (using `dx`) from breakpoints set on `KERNELBASE!WaitForSingleObjectEx` to observe its parameters.
    * **Challenges:** Overcoming syntax limitations of classic WinDbg scripts. A significant issue was severe game slowdown or "thrashing" when active `KERNELBASE!WaitForSingleObjectEx` breakpoints called JavaScript functions. This required careful management and conditional enabling of such breakpoints. Early JavaScript functions like `initializeModuleInfoForWSOEx` and `checkWaitCallForWSOEx` were developed for this purpose.

2.  **Loader Script Stabilization:**
    * **Objective:** Achieve syntactically correct and reliable WinDbg loader scripts.
    * **Achievements:** Successfully resolved issues related to `.if` block parsing, correct syntax for `ba`/`bp`/`bd` commands, and proper usage of pseudo-registers. This phase resulted in loader scripts that could consistently establish the intended breakpoint states for each debugging session (e.g., specific HWBPs enabled, certain SWBPs disabled).
    * **Findings:** HWBPs set on RVAs derived from initial crash logs (particularly those related to `PostQuitMessage`-induced crashes) were found not to be hit during the typical game *hang* scenario, suggesting those paths were not part of the primary deadlock.

3.  **`PostQuitMessage` Investigation:**
    * **Strategy:** To target `user32!PostQuitMessage` as a potential high-level indicator of the game's quit sequence.
    * **Method:** Employed software breakpoints with breakpoint commands ranging from JavaScript calls (e.g., an `onUser32PostQuitMessageHit` function) to simpler direct debugger commands (like `.echo; kc10; .break`).
    * **Outcome:** Breakpointing `user32!PostQuitMessage` consistently induced a game-internal "General protection fault!" dialog rather than a clean debugger break. However, the call stack displayed by this GPF dialog provided valuable new RVAs within `BorderlandsGOTY.exe` that were clearly involved in this specific (debugger-induced) crash pathway.

4.  **Direct Targeting of the Main Thread's WSOEx Call Site:**
    * **Strategy:** To place breakpoints directly on, or immediately before, the instructions involved in the main thread's problematic `WaitForSingleObjectEx` call (specifically RVAs `0x1F6B8A`, `0x1F6B87`, `0x1F6B83`).
    * **Method:** Utilized both Hardware Breakpoints (`ba e1`) and Software Breakpoints (`bp`). Breakpoint commands ranged from JavaScript calls (e.g., `onMainThreadHangWaitCandidateHit`, `onPreWSOExParamSetupHit`) to a simple `".break"` command.
    * **Outcome:** These attempts generally resulted in the game crashing *at* the targeted RVA, with the game's own GPF dialog appearing. The debugger's breakpoint command script did not get a chance to execute cleanly before the fault occurred, indicating extreme instability or sensitivity in this code region during shutdown when under direct debug observation.

5.  **"Heisenbug" Discovery and Confirmation:**
    * **Strategy:** A software breakpoint (`bp`) was placed at RVA `0x1F6B80` (the start of the code block leading to the WSOEx call). The `sxe gp` command was included in the loader script to attempt breaking on first-chance General Protection faults.
    * **Outcome:** With the SWBP active at RVA `0x1F6B80` (irrespective of whether its command was a complex JS call like `onEarlyWsoExBlockHit` or a simple `".break"`), the game consistently exited cleanly without hanging or crashing. The breakpoint at `0x1F6B80` did not visibly halt the debugger for user interaction before the process terminated.
    * **Significance:** This "Heisenbug" effect was the pivotal finding. It confirmed that RVA `0x1F6B80` was on the critical execution path for the hang, and that minimal debugger interference (specifically, the handling of the `INT 3` software interrupt) was sufficient to alter program behavior and prevent the hang. This strongly guided the final proxy DLL patch strategy.

## Appendix C: Proxy DLL (`dllmain.c`) Fix Implementation Overview

The final, successful solution to the exit hang was implemented in a `version.dll` proxy, with the core logic contained in `dllmain.c` (version 5.0.0). This appendix provides a textual description of its essential components and operational logic.

1.  **Core Proxy Functionality:**
    * The DLL masquerades as the legitimate system `version.dll` by forwarding all 17 of its standard exports to the actual system `version.dll`. This is achieved by loading the system's `version.dll` (typically from `System32`) via `LoadLibraryW` during `DLL_PROCESS_ATTACH`. The addresses of all original exported functions are resolved using `GetProcAddress` and stored in global function pointers, which are then used by the proxy's exported stub functions.

2.  **MinHook Integration:**
    * The MinHook x64 library is compiled into the proxy DLL (either statically linked or its sources directly included).
    * `MH_Initialize()` is called once during `DLL_PROCESS_ATTACH`, after successfully loading the real `version.dll` and mapping its export addresses.
    * `MH_Uninitialize()` is called once during `DLL_PROCESS_DETACH` as part of the cleanup process.

3.  **Hooking `WaitForSingleObjectEx`:**
    * The address of `KERNELBASE!WaitForSingleObjectEx` is obtained using `GetProcAddress`. A fallback to `kernel32!WaitForSingleObjectEx` is included for compatibility with older systems, though `KernelBase.dll` is standard on modern Windows.
    * `MH_CreateHook` is used to redirect calls from this API to the custom detour function, `DetourWaitForSingleObjectEx_ApplyFix`. A global function pointer, `pfnOriginalWaitForSingleObjectEx`, is populated by `MH_CreateHook` to store the address of the trampoline function (which calls the original `WaitForSingleObjectEx`).
    * `MH_EnableHook` is called to activate the hook on `WaitForSingleObjectEx`, making the detour function live.
    * During `DLL_PROCESS_DETACH`, the hook is first disabled via `MH_DisableHook` and then removed using `MH_RemoveHook` before MinHook itself is uninitialized.

4.  **Detour Function Logic (`DetourWaitForSingleObjectEx_ApplyFix`):**
    * This function intercepts every call to `WaitForSingleObjectEx` made by any thread within the game process.
    * It first retrieves the base address of the main game module, `BorderlandsGOTY.exe`, which is determined and stored globally (as `g_gameModuleBase`) during the proxy's initialization.
    * It then obtains the return address of the current `WaitForSingleObjectEx` call. This is done using compiler-specific intrinsics: `_ReturnAddress()` for MSVC or `__builtin_return_address(0)` for GCC/Clang.
    * The Relative Virtual Address (RVA) of this return address within `BorderlandsGOTY.exe` is calculated by subtracting `g_gameModuleBase` from the absolute return address.
    * A critical conditional check is performed to identify the specific problematic call:
        * Is the calculated return RVA equal to the constant `RVA_MainThread_WSOEx_ReturnSite` (which is hardcoded to `0x1F6B90`)?
        * AND, is the `dwMilliseconds` parameter passed to `WaitForSingleObjectEx` equal to `INFINITE` (`0xFFFFFFFF`)?
    * If both conditions are true, the detour function identifies this as the specific call instance responsible for the main thread hang.
    * The `dwMilliseconds` value for this call is then modified from `INFINITE` to a predefined short timeout, `PATCHED_TIMEOUT_MS` (which is set to `1` millisecond).
    * If debug logging is enabled (via the `PROXY_DEBUG_LOGGING` macro), a log entry is generated via the `FileLog` utility to record that the patch was applied for this specific call.
    * Finally, the detour function calls the original `WaitForSingleObjectEx` (via the `pfnOriginalWaitForSingleObjectEx` trampoline) using the original `hHandle` and `bAlertable` parameters, but with the `dwMilliseconds` value that has now been potentially modified to `1ms`.
    * If the conditions for patching are not met (i.e., it's a different call to `WaitForSingleObjectEx` or a different timeout), the original `WaitForSingleObjectEx` is called with its original, unmodified parameters.

5.  **Logging Implementation (`FileLog`):**
    * A static utility function, `FileLog`, provides simple, timestamped logging to a consistent file path (e.g., `C:\temp\borderlands_proxy_log.txt`).
    * The inclusion of logging code and its execution is controlled by the `PROXY_DEBUG_LOGGING` preprocessor directive defined at the top of `dllmain.c`. When this macro is not defined, logging calls compile out to no-ops.