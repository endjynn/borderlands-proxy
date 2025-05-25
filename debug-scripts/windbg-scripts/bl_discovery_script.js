// Script Internal Version: JS-DISCOVERY-V1.2.6
// File: C:\Temp\windbg\bl_discovery_script.js
"use strict"; 

const LOG_PREFIX = "[BLD_JS_TRIG] ";
const SCRIPT_VERSION_JS = "JS-DISCOVERY-V1.2.6"; 

const RVA_EARLY_WSOEX_BLOCK = 0x1F6B80;
const RVA_MOV_RCX_FOR_WSOEX = 0x1F6B83;
const RVA_OR_EDX_FOR_WSOEX  = 0x1F6B87;
const RVA_CALL_WSOEX        = 0x1F6B8A; 
const RVA_WSOEX_RETURN_SITE_IN_GAME = 0x1F6B90;             
const WSOEX_TARGET_TIMEOUT_CONST = 0xFFFFFFFF;            

var g_moduleBase_WSOEX = null; 
var g_moduleEnd_WSOEX = null;  
var g_moduleInfoInitialized_WSOEX = false; 
var g_performFullWSOExChecks = false;

function jsLog(message, prefix = LOG_PREFIX) { 
    try {
        let safeMessage = String(message).replace(/"/g, "''").replace(/%/g, "%%");
        host.namespace.Debugger.Utility.Control.ExecuteCommand(".echo " + prefix + SCRIPT_VERSION_JS + ": " + safeMessage);
    } catch (e) { /* Silently fail */ }
}

// Renamed from onGeneralQuitPathCandidateHit
function onEarlyWsoExBlockHit(rvaHitStringDescription) {
    let msg = "Early WSOEx Block BP HIT: " + rvaHitStringDescription;
    jsLog(msg);
    jsLog("This breakpoint is at RVA 0x" + RVA_EARLY_WSOEX_BLOCK.toString(16) + " (start of the code block that sets up the problematic WaitForSingleObjectEx).");
    jsLog("Call stack (kc10):");
    try { host.namespace.Debugger.Utility.Control.ExecuteCommand("kc10"); } catch (e) {}

    jsLog("Current Registers (r):");
    try { host.namespace.Debugger.Utility.Control.ExecuteCommand("r"); } catch (e) {}
    
    jsLog("--- ACTION REQUIRED ---");
    jsLog("Execution IS PAUSED at " + rvaHitStringDescription + ".");
    jsLog("The function containing this RVA is a strong candidate for RVA_QuitEntryPoint.");
    jsLog("From here, you want to reach the 'call KERNELBASE!WaitForSingleObjectEx' at RVA 0x" + RVA_CALL_WSOEX.toString(16) + ".");
    jsLog("Instructions to reach the CALL:");
    jsLog("  Current instruction (@rip = $t0+0x" + RVA_EARLY_WSOEX_BLOCK.toString(16) + "): add dword ptr [rbp+0Dh],esi");
    jsLog("  1. Type 'p' (step over). You should land at RVA 0x" + RVA_MOV_RCX_FOR_WSOEX.toString(16) + " ('mov rcx, qword ptr [rbx+8]').");
    jsLog("     Then execute: r rbx; dq rbx+8 L1");
    jsLog("  2. Type 'p' (step over). You should land at RVA 0x" + RVA_OR_EDX_FOR_WSOEX.toString(16) + " ('or edx, 0xFFFFFFFF').");
    jsLog("     Then execute: r rdx");
    jsLog("  3. Type 'p' (step over). You should land ON the 'call ...WSOEx' at RVA 0x" + RVA_CALL_WSOEX.toString(16) + ".");
    jsLog("     Then execute: r rdx (ensure it's FFFFFFFF), r rcx (check handle).");
    jsLog("  4. At this point, on the CALL, DO NOT use 'p'. Use 't' (step into) to see if it enters WSOEx or GPFs.");
    jsLog("If a GPF occurs at any step, the debugger will break (due to 'sxe gpf'). Note the instruction and registers.");
    jsLog("If you successfully step into WSOEx and rdx was FFFFFFFF, this confirms the critical path.");
        
    return LOG_PREFIX + msg + ". Execution PAUSED. Follow stepping instructions."; 
}

function initialize_DiscoveryFramework() {
    let msg = SCRIPT_VERSION_JS + " loaded. Break on First-Chance GPF enabled by loader. Ready for discovery BPs.";
    jsLog(msg);
    return msg;
}

function initializeModuleInfoForWSOEx() {
    if (g_moduleInfoInitialized_WSOEX) return; 
    jsLog("WSOEx_Check: Initializing module info...", LOG_PREFIX);
    g_moduleBase_WSOEX = null; g_moduleEnd_WSOEX = null;
    try {
        let modules = host.currentProcess.Modules;
        let foundModule = null;
        for (let mod of modules) {
            if (mod.Name.toUpperCase().endsWith("BORDERLANDSGOTY.EXE")) {
                foundModule = mod; break;
            }
        }
        if (foundModule != null) {
            g_moduleBase_WSOEX = foundModule.BaseAddress;
            let sizeInt64 = host.parseInt64("0x2959000");
            g_moduleEnd_WSOEX = g_moduleBase_WSOEX.add(sizeInt64); 
            jsLog("WSOEx_Check: Module info VALID. Base: " + g_moduleBase_WSOEX, LOG_PREFIX);
        } else { jsLog("WSOEx_Check: ERROR - Module not found.", LOG_PREFIX); }
    } catch (e) { jsLog("WSOEx_Check: EXCEPTION in init - " + e, LOG_PREFIX); }
    g_moduleInfoInitialized_WSOEX = true; 
}

function checkWaitCallForWSOEx() { 
    if (!g_performFullWSOExChecks) return undefined; 
    if (!g_moduleInfoInitialized_WSOEX) initializeModuleInfoForWSOEx();
    if (g_moduleBase_WSOEX == null) return LOG_PREFIX + "WSOEx_ERR: ModInfo Unavail";
    try {
        let regs = host.currentThread.Registers.User;
        let rdx_timeout = regs.rdx; 
        if (rdx_timeout.compareTo(host.parseInt64(WSOEX_TARGET_TIMEOUT_CONST.toString())) === 0) { 
            let rsp = regs.rsp;
            let returnAddress = host.memory.readMemoryValues(rsp, 1, 8)[0]; 
            let rcx_handle = regs.rcx;
            if (returnAddress.compareTo(g_moduleBase_WSOEX) >= 0 && returnAddress.compareTo(g_moduleEnd_WSOEX) < 0) { 
                let rva = returnAddress.subtract(g_moduleBase_WSOEX);
                if (rva.compareTo(host.parseInt64(RVA_WSOEX_RETURN_SITE_IN_GAME.toString())) === 0) { 
                    return LOG_PREFIX + "WSOEx_MATCH (via KERNELBASE BP)! RA:0x" + returnAddress.toString(16) + " RVA:0x" + rva.toString(16) + " HND:0x" + rcx_handle.toString(16) + " TIMEOUT:0x" + rdx_timeout.toString(16);
                }
            }
        }
    } catch (e) { return LOG_PREFIX + "WSOEx_EXC: " + e; }
    return undefined; 
}

function enableFullWSOExChecks() { 
    if (!g_moduleInfoInitialized_WSOEX) initializeModuleInfoForWSOEx();
    g_performFullWSOExChecks = true;
    let msg = "Full WSOEx checks ENABLED via enableFullWSOExChecks(). Base: " + (g_moduleBase_WSOEX ? g_moduleBase_WSOEX.toString(16) : "Not Init") + ". Watching for WSOEx calls returning to game RVA " + RVA_WSOEX_RETURN_SITE_IN_GAME.toString(16) + " with INFINITE timeout.";
    jsLog(msg, LOG_PREFIX); 
    return msg;   
}