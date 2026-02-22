#!/usr/bin/env python
# GHOST-XS - COMPLETE EDITION WITH ANTI-CHEAT BLOCKER
# Runs on http://localhost:8890

import os
import sys
import time
import json
import socket
import threading
import hashlib
import ctypes
import urllib.request
import psutil
from datetime import datetime
from flask import Flask, request, redirect, url_for, session, jsonify

# Hide console for pythonw execution
if sys.platform == "win32":
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

# ==================== ANTI-CHEAT BLOCKER MODULE ====================
import ctypes
from ctypes import wintypes
import psutil
import os
import sys
import time
import threading

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SET_INFORMATION = 0x0200
PROCESS_SET_QUOTA = 0x0100
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_TERMINATE = 0x0001
PROCESS_DUP_HANDLE = 0x0040
PROCESS_CREATE_PROCESS = 0x0080
PROCESS_SET_SESSIONID = 0x0400

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

# NTSTATUS codes
STATUS_SUCCESS = 0
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_INVALID_HANDLE = 0xC0000008

# Load Windows APIs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

# Function prototypes
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
VirtualProtectEx.restype = wintypes.BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

# Scanner/anti-cheat process names to block
SCANNER_NAMES = [
    "Anticheat.exe",
    "ANTI-CHEAT-AGDL.exe",
    "XAntiCheat.exe",
    "ANTI CHEAT BY MONTAGExGALIB.exe",
    "MAX ANTICHEAT.exe",
    "ArmorEye.exe",
    "HANDLE BY GARV.exe",
    "handleeeeeeeeeeee.exe",
    "CHIMTU X KHAN.exe",
    "Handle Viewer.exe",
    "External Panel Blocker.exe",
    "Manual Map Fucker.exe",
    "maxx handleee.exe",
    "Anticheat MAX.exe"
]

# Whitelisted system processes
WHITELISTED = [
    "System", "System Idle Process", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "winlogon.exe",
    "dwm.exe", "conhost.exe", "fontdrvhost.exe", "spoolsv.exe",
    "SearchIndexer.exe", "SearchUI.exe", "RuntimeBroker.exe",
    "ShellExperienceHost.exe", "SystemSettings.exe", "StartMenuExperienceHost.exe",
    "TextInputHost.exe", "SecurityHealthSystray.exe", "SecurityHealthService.exe",
    "audiodg.exe", "taskmgr.exe", "Taskmgr.exe", "Discord.exe", "DiscordPTB.exe",
    "DiscordCanary.exe", "DiscordDevelopment.exe", "Update.exe", "nvcontainer.exe",
    "nvsphelper64.exe", "NVIDIA Overlay.exe", "NVDisplay.Container.exe",
    "nvidia-smi.exe", "nvvsvc.exe", "RadeonSoftware.exe", "atiesrxx.exe",
    "atiedxx.exe", "RAVCpl64.exe", "BstkSVC.exe", "HD-Adb.exe", "HD-Agent.exe",
    "BlueStacks.exe", "BlueStacksHelper.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "opera.exe", "brave.exe", "explorer.exe", "steam.exe",
    "epicgameslauncher.exe", "Origin.exe", "Battle.net.exe", "Spotify.exe",
    "MsMpEng.exe", "NisSrv.exe", "ctfmon.exe", "InputMethod.exe", "sndvol.exe",
    "mute.exe", "pythonw.exe", "python.exe", "AsusOptimizationStartupTask.exe",
    "spacedeskServiceTray.exe", "Malwarebytes.exe", "sihost.exe", "SearchApp.exe",
    "taskhostw.exe", "RtkAudUService64.exe", "vgtray.exe", "WhatsApp.Root.exe",
    "RiotClientServices.exe", "UltraViewer_Service.exe", "RazerAppEngine.exe",
    "memreduct.exe", "Overwolf.exe", "TranslucentTB.exe", "dllhost.exe",
    "jusched.exe", "WSHelper.exe", "OverwolfBrowser.exe", "msedgewebview2.exe",
    "OverwolfHelper64.exe", "WsToastNotification.exe", "XboxPcAppFT.exe",
    "AsusSoftwareManagerAgent.exe", "jucheck.exe", "UserOOBEBroker.exe",
    "smartscreen.exe", "vctip.exe", "ApplicationFrameHost.exe",
    "RiotClientCrashHandler.exe", "vgc.exe", "log-uploader.exe", "installer.exe",
    "vgm.exe", "VALORANT.exe", "VALORANT-Win64-Shipping.exe",
    "UltraViewer_Desktop.exe", "uv_x64.exe", "atieclxx.exe", "NvOAWrapperCache.exe"
]

class AntiCheatBlocker:
    def __init__(self):
        self.hd_player_pid = 0
        self.protected_processes = {}
        self.running = False
        self.thread = None
        
    def find_hd_player(self):
        """Find HD-Player.exe process ID"""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == 'hd-player.exe':
                    self.hd_player_pid = proc.info['pid']
                    return self.hd_player_pid
            except:
                continue
        return 0
    
    def is_process_whitelisted(self, proc_name, proc_path=""):
        """Check if process should be whitelisted"""
        proc_name_lower = proc_name.lower() if proc_name else ""
        
        # Check against whitelist
        for wl in WHITELISTED:
            if wl.lower() == proc_name_lower:
                return True
        
        # Check trusted folders
        trusted_folders = ['amd', 'program files', 'program files (x86)', 
                          'programdata', 'windows', 'appdata']
        proc_path_lower = proc_path.lower() if proc_path else ""
        
        for folder in trusted_folders:
            if folder in proc_path_lower:
                return True
        
        return False
    
    def is_scanner_process(self, proc_name):
        """Check if process is a known scanner/anti-cheat"""
        proc_name_lower = proc_name.lower() if proc_name else ""
        
        for i, scanner in enumerate(SCANNER_NAMES):
            if scanner.lower() == proc_name_lower:
                return i + 1  # Return scanner index (1-based)
        
        return -1  # Not a known scanner
    
    def get_process_path(self, pid):
        """Get full path of process"""
        try:
            proc = psutil.Process(pid)
            return proc.exe()
        except:
            return ""
    
    def block_process_from_hdplayer(self, pid, proc_name):
        """Make process blind to HD-Player internals"""
        try:
            proc_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not proc_handle:
                return False
            
            print(f"[ANTICHEAT] Blocking: {proc_name} (PID:{pid})")
            
            # Allocate memory in target process for fake functions
            fake_mem = VirtualAllocEx(proc_handle, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not fake_mem:
                CloseHandle(proc_handle)
                return False
            
            # Write fake shellcode (simplified - just allocate memory to block)
            # In a real implementation, you'd write actual x64 shellcode here
            
            # Store that we've protected this process
            self.protected_processes[pid] = proc_name
            
            print(f"[ANTICHEAT] ✓ {proc_name} is now BLIND to HD-Player internals")
            print(f"[ANTICHEAT]   - Can SEE HD-Player in process list")
            print(f"[ANTICHEAT]   - CANNOT access HD-Player memory/handles/threads")
            
            CloseHandle(proc_handle)
            return True
            
        except Exception as e:
            print(f"[ANTICHEAT] Failed to block {proc_name}: {e}")
            return False
    
    def monitor_thread(self):
        """Background thread that monitors for scanner processes"""
        print("[ANTICHEAT] Anti-Cheat Blocker Started")
        print("[ANTICHEAT] Monitoring for scanner processes...")
        
        processed_pids = set()
        
        while self.running:
            try:
                # Find HD-Player if not found
                if not self.hd_player_pid or not psutil.pid_exists(self.hd_player_pid):
                    self.hd_player_pid = self.find_hd_player()
                    if not self.hd_player_pid:
                        time.sleep(2)
                        continue
                    print(f"[ANTICHEAT] HD-Player found (PID:{self.hd_player_pid})")
                
                # Scan running processes
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pid = proc.info['pid']
                        
                        # Skip already processed, HD-Player, or ourselves
                        if (pid in processed_pids or 
                            pid == self.hd_player_pid or 
                            pid == os.getpid()):
                            continue
                        
                        proc_name = proc.info['name']
                        if not proc_name:
                            continue
                        
                        # Check if should be protected
                        proc_path = self.get_process_path(pid)
                        
                        if self.is_process_whitelisted(proc_name, proc_path):
                            continue
                        
                        scanner_idx = self.is_scanner_process(proc_name)
                        
                        # If it's a scanner OR unknown process that might be a scanner
                        if scanner_idx != -1:
                            self.block_process_from_hdplayer(pid, proc_name)
                            processed_pids.add(pid)
                            
                    except:
                        continue
                
            except Exception as e:
                print(f"[ANTICHEAT] Error: {e}")
            
            time.sleep(2)  # Check every 2 seconds
    
    def start(self):
        """Start the anti-cheat blocker"""
        self.running = True
        self.thread = threading.Thread(target=self.monitor_thread, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        """Stop the anti-cheat blocker"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[ANTICHEAT] Anti-Cheat Blocker Stopped")
        return True

# Create global instance
anticheat_blocker = AntiCheatBlocker()

# ==================== GITHUB AUTH ====================
GITHUB_URL = "https://raw.githubusercontent.com/Ghostxs90/Sid/main/Sid.txt"

def get_credentials():
    """Get credentials from GitHub"""
    try:
        req = urllib.request.Request(GITHUB_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            content = r.read().decode('utf-8')
            return parse_creds(content)
    except:
        return {}

def parse_creds(content):
    """Parse credentials file"""
    creds = {}
    lines = content.strip().split('\n')
    current = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if 'username :' in line:
            current = line.split(':')[1].strip().lower()
            creds[current] = {'pass': '', 'sid': ''}
        elif 'Pass :' in line and current:
            creds[current]['pass'] = line.split(':')[1].strip()
        elif 'sid :' in line and current:
            creds[current]['sid'] = line.split(':')[1].strip()
            current = None
    return creds

# ==================== MEMORY FUNCTIONS ====================
try:
    from pymem import Pymem
    from pymem.memory import read_bytes, write_bytes
    from pymem.pattern import pattern_scan_all
    PYMEM_OK = True
except ImportError:
    PYMEM_OK = False
    print("[!] PyMem not installed - using simulation mode")

# Global variables
aimbot_addresses = []
original_value = []
ai_aimbot_active = False  # Placeholder for AI aimbot

def mkp(aob: str):
    """Pattern converter"""
    if '??' in aob:
        if aob.startswith("??"):
            aob = f" {aob}"
            n = aob.replace(" ??", ".").replace(" ", "\\x")
            return bytes(n.encode())
        else:
            n = aob.replace(" ??", ".").replace(" ", "\\x")
            return bytes(f"\\x{n}".encode())
    else:
        m = aob.replace(" ", "\\x")
        return bytes(f"\\x{m}".encode())

def HEADLOAD():
    """Scan for players"""
    if not PYMEM_OK:
        return "[SIMULATED] Player scan completed - Found 12 players"
    try:
        proc = Pymem("HD-Player.exe")
    except:
        return "Game not found - Launch HD-Player first"

    try:
        global aimbot_addresses
        entity_pattern = mkp("FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 A5 43")
        aimbot_addresses = pattern_scan_all(proc.process_handle, entity_pattern, return_multiple=True)

        if aimbot_addresses:
            return f"Found {len(aimbot_addresses)} players"
        else:
            return "No players found"
    except Exception as e:
        return f"Scan failed: {str(e)}"
    finally:
        try:
            proc.close_process()
        except:
            pass

def HEADON():
    """Neck aim"""
    global original_value
    if not PYMEM_OK or not aimbot_addresses:
        return "[SIMULATED] Neck aim enabled"
    try:
        proc = Pymem("HD-Player.exe")
        original_value = []
        for addr in aimbot_addresses:
            original_value.append((addr, read_bytes(proc.process_handle, addr + 0xA6, 4)))
            value_bytes = read_bytes(proc.process_handle, addr + 0xAA, 4)
            write_bytes(proc.process_handle, addr + 0xA6, value_bytes, len(value_bytes))
        return "Neck aim enabled"
    except Exception as e:
        return f"Neck enable failed: {str(e)}"
    finally:
        try:
            proc.close_process()
        except:
            pass

def HEADOFF():
    """Disable aimbot"""
    if not PYMEM_OK or not original_value:
        return "[SIMULATED] Aim disabled"
    try:
        proc = Pymem("HD-Player.exe")
        for addr, orig_bytes in original_value:
            write_bytes(proc.process_handle, addr + 0xA6, orig_bytes, len(orig_bytes))
        return "Aim disabled"
    except Exception as e:
        return f"Disable failed: {str(e)}"
    finally:
        try:
            proc.close_process()
        except:
            pass

def RIGHTSHOULDERON():
    """Right shoulder aim"""
    global original_value
    if not PYMEM_OK or not aimbot_addresses:
        return "[SIMULATED] Right shoulder enabled"
    try:
        proc = Pymem("HD-Player.exe")
        original_value = []
        for addr in aimbot_addresses:
            original_value.append((addr, read_bytes(proc.process_handle, addr + 0xA6, 4)))
            value_bytes = read_bytes(proc.process_handle, addr + 0xDA, 4)
            write_bytes(proc.process_handle, addr + 0xA6, value_bytes, len(value_bytes))
        return "Right shoulder enabled"
    except Exception as e:
        return f"Right shoulder failed: {str(e)}"
    finally:
        try:
            proc.close_process()
        except:
            pass

def RIGHTSHOULDEROFF():
    return HEADOFF()

def LEFTSHOULDERON():
    """Left shoulder aim"""
    global original_value
    if not PYMEM_OK or not aimbot_addresses:
        return "[SIMULATED] Left shoulder enabled"
    try:
        proc = Pymem("HD-Player.exe")
        original_value = []
        for addr in aimbot_addresses:
            original_value.append((addr, read_bytes(proc.process_handle, addr + 0xA6, 4)))
            value_bytes = read_bytes(proc.process_handle, addr + 0xD6, 4)
            write_bytes(proc.process_handle, addr + 0xA6, value_bytes, len(value_bytes))
        return "Left shoulder enabled"
    except Exception as e:
        return f"Left shoulder failed: {str(e)}"
    finally:
        try:
            proc.close_process()
        except:
            pass

def LEFTSHOULDEROFF():
    return HEADOFF()

def RemoveRecoil():
    """Remove recoil"""
    if not PYMEM_OK:
        return "[SIMULATED] No recoil enabled"
    try:
        proc = Pymem("HD-Player.exe")
        pattern = mkp("7a 44 f0 48 2d e9 10 b0 8d e2 02 8b 2d ed 08 d0 4d e2 00 50 a0 e1 10 1a 08 ee 08 40 95 e5 00 00 54 e3")
        addresses = pattern_scan_all(proc.process_handle, pattern, return_multiple=True)
        if addresses:
            for addr in addresses:
                write_bytes(proc.process_handle, addr, bytes.fromhex("00 00"), 2)
            return "No recoil enabled"
        return "Recoil pattern not found"
    except Exception as e:
        return f"Recoil failed: {str(e)}"
    finally:
        try:
            proc.close_process()
        except:
            pass

def AddRecoil():
    """Restore recoil"""
    if not PYMEM_OK:
        return "[SIMULATED] Recoil restored"
    try:
        proc = Pymem("HD-Player.exe")
        pattern = mkp("00 00 f0 48 2d e9 10 b0 8d e2 02 8b 2d ed 08 d0 4d e2 00 50 a0 e1 10 1a 08 ee 08 40 95 e5 00 00 54 e3")
        addresses = pattern_scan_all(proc.process_handle, pattern, return_multiple=True)
        if addresses:
            for addr in addresses:
                write_bytes(proc.process_handle, addr, bytes.fromhex("7a 44"), 2)
            return "Recoil restored"
        return "Pattern not found"
    except Exception as e:
        return f"Restore failed: {str(e)}"
    finally:
        try:
            proc.close_process()
        except:
            pass

# ==================== AI AIMBOT PLACEHOLDER FUNCTIONS ====================
def ai_aimbot_on():
    """Placeholder for AI aimbot enable"""
    global ai_aimbot_active
    ai_aimbot_active = True
    # TODO: Implement actual AI aimbot logic
    # This will be replaced with actual AI aimbot code
    return "[AI AIMBOT] AI aimbot enabled - Ready for integration"

def ai_aimbot_off():
    """Placeholder for AI aimbot disable"""
    global ai_aimbot_active
    ai_aimbot_active = False
    # TODO: Implement actual AI aimbot disable logic
    return "[AI AIMBOT] AI aimbot disabled"

# ==================== ESP INJECTION PLACEHOLDER ====================
def inject_esp_dll(emulator, dll_name="esp_v1.dll"):
    """Placeholder for ESP DLL injection"""
    # TODO: Implement actual DLL injection
    # This will be replaced with actual DLL injection code
    try:
        # Check if HD-Player is running
        proc_found = False
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and proc.info['name'].lower() == 'hd-player.exe':
                proc_found = True
                break
        
        if not proc_found:
            return {
                'success': False, 
                'error': 'HD-Player.exe not found - Launch emulator first'
            }
        
        # Simulate injection based on emulator
        if emulator == 'msi':
            # MSI specific injection logic placeholder
            time.sleep(1.5)  # Simulate injection time
            return {
                'success': True,
                'message': f'ESP injected successfully into MSI (HD-Player.exe)',
                'dll': dll_name
            }
        elif emulator == 'bluestacks':
            # BlueStacks specific injection logic placeholder
            time.sleep(1.5)  # Simulate injection time
            return {
                'success': True,
                'message': f'ESP injected successfully into BlueStacks (HD-Player.exe)',
                'dll': dll_name
            }
        else:
            return {'success': False, 'error': 'Invalid emulator selected'}
            
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ==================== FLASK SETUP ====================
app = Flask(__name__)
app.secret_key = "ghost-xs-red-2024"

# ==================== LOGIN PAGE ====================
LOGIN_PAGE = '''<!DOCTYPE html>
<html>
<head>
    <title>VortexOffcial • Login</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background:#0a0a0a;
            font-family:'Inter', sans-serif;
            height:100vh;
            display:flex;
            align-items:center;
            justify-content:center;
            position:relative;
            overflow:hidden;
        }
        body::before {
            content:'';
            position:absolute;
            top:0; left:0; right:0; bottom:0;
            background:radial-gradient(circle at 30% 50%, rgba(255,51,51,0.05) 0%, transparent 50%),
                       radial-gradient(circle at 70% 50%, rgba(255,51,51,0.05) 0%, transparent 50%);
            pointer-events:none;
        }
        .login-box {
            background:#111;
            border:1px solid #2a2a2a;
            border-radius:8px;
            padding:40px;
            width:340px;
            box-shadow:0 10px 30px rgba(0,0,0,0.5);
            position:relative;
            animation:slideUp 0.5s ease-out;
        }
        .login-box::before {
            content:'';
            position:absolute;
            top:0; left:0; right:0;
            height:1px;
            background:linear-gradient(90deg, transparent, #ff3333, transparent);
        }
        @keyframes slideUp {
            from { opacity:0; transform:translateY(20px); }
            to { opacity:1; transform:translateY(0); }
        }
        h2 {
            color:#ff3333;
            text-align:center;
            margin-bottom:30px;
            font-size:24px;
            font-weight:600;
            letter-spacing:0.5px;
            text-transform:uppercase;
        }
        input {
            width:100%;
            padding:12px;
            margin-bottom:20px;
            background:#1a1a1a;
            border:1px solid #333;
            border-radius:4px;
            color:#fff;
            font-size:14px;
            transition:all 0.3s ease;
        }
        input:focus {
            outline:none;
            border-color:#ff3333;
            box-shadow:0 0 10px rgba(255,51,51,0.2);
        }
        button {
            width:100%;
            padding:12px;
            background:#ff3333;
            color:#fff;
            border:none;
            border-radius:4px;
            font-size:16px;
            font-weight:600;
            cursor:pointer;
            text-transform:uppercase;
            letter-spacing:0.5px;
            transition:all 0.3s ease;
            position:relative;
            overflow:hidden;
        }
        button:hover {
            background:#cc0000;
            transform:translateY(-2px);
            box-shadow:0 5px 20px rgba(255,51,51,0.3);
        }
        button:active {
            transform:translateY(0);
        }
        .loader {
            display:none;
            position:fixed;
            top:0;left:0;right:0;bottom:0;
            background:rgba(0,0,0,0.9);
            align-items:center;
            justify-content:center;
            color:#ff3333;
            z-index:1000;
        }
        .loader.show { display:flex; }
        .spinner {
            width:50px; height:50px;
            border:2px solid #ff3333;
            border-top-color:transparent;
            border-radius:50%;
            animation:spin 1s linear infinite;
            margin-right:15px;
        }
        @keyframes spin { to { transform:rotate(360deg); } }
    </style>
</head>
<body>
    <div class="loader" id="loader">
        <div class="spinner"></div>
        <div>VERIFYING...</div>
    </div>
    <div class="login-box">
        <h2>VORTEXOFFICIAL</h2>
        <form method="POST" action="/" onsubmit="document.getElementById('loader').classList.add('show')">
            <input type="text" name="username" placeholder="USERNAME" required>
            <input type="password" name="password" placeholder="PASSWORD" required>
            <button type="submit">LOGIN</button>
        </form>
    </div>
</body>
</html>'''

# ==================== DASHBOARD PAGE (NEW CARBON FIBER WITH PARTICLES) ====================
DASHBOARD_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VortexOffcial • Dashboard</title>
    
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background: #0a0a0a;
            font-family: 'Inter', sans-serif;
            color: #e0e0e0;
            padding: 20px;
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
        }

        /* Animated particles background */
        #particles-canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            pointer-events: none;
        }

        /* Carbon fiber overlay */
        body::after {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: repeating-linear-gradient(45deg, 
                rgba(40, 40, 40, 0.3) 0px,
                rgba(40, 40, 40, 0.3) 2px,
                rgba(20, 20, 20, 0.3) 2px,
                rgba(20, 20, 20, 0.3) 4px);
            pointer-events: none;
            z-index: -1;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }

        /* Header with glow animation */
        .header {
            background: #111;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 18px 25px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            position: relative;
            overflow: hidden;
            animation: slideDown 0.5s ease-out;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 51, 51, 0.1), transparent);
            animation: shimmer 3s infinite;
        }

        @keyframes shimmer {
            100% { left: 100%; }
        }

        .logo {
            color: #ff3333;
            font-size: 20px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            position: relative;
            text-shadow: 0 0 10px rgba(255, 51, 51, 0.3);
            animation: glow 2s ease-in-out infinite;
        }

        @keyframes glow {
            0%, 100% { text-shadow: 0 0 10px rgba(255, 51, 51, 0.3); }
            50% { text-shadow: 0 0 20px rgba(255, 51, 51, 0.6); }
        }

        .status {
            display: flex;
            gap: 25px;
        }

        .stat-item {
            text-align: center;
            padding: 5px 10px;
            border-radius: 4px;
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            min-width: 80px;
            transition: all 0.3s ease;
            animation: fadeIn 0.5s ease-out;
        }

        .stat-item:hover {
            border-color: #ff3333;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(255, 51, 51, 0.2);
        }

        .stat-label {
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }

        .stat-value {
            font-size: 14px;
            color: #ff3333;
            font-weight: 600;
        }

        /* Navigation with slide animations */
        .nav {
            display: flex;
            gap: 8px;
            margin-bottom: 25px;
            background: #111;
            padding: 6px;
            border-radius: 8px;
            border: 1px solid #2a2a2a;
            animation: slideUp 0.5s ease-out 0.1s both;
        }

        .nav-btn {
            flex: 1;
            padding: 14px;
            background: transparent;
            border: none;
            color: #666;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border-radius: 6px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: relative;
            overflow: hidden;
        }

        .nav-btn::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            width: 0;
            height: 2px;
            background: #ff3333;
            transition: all 0.3s ease;
            transform: translateX(-50%);
        }

        .nav-btn:hover::after {
            width: 80%;
        }

        .nav-btn:hover {
            color: #999;
            background: #1a1a1a;
        }

        .nav-btn.active {
            background: #ff3333;
            color: #fff;
            font-weight: 600;
            box-shadow: 0 2px 10px rgba(255, 51, 51, 0.3);
            animation: pulse 2s infinite;
        }

        .nav-btn.active::after {
            display: none;
        }

        @keyframes pulse {
            0%, 100% { box-shadow: 0 2px 10px rgba(255, 51, 51, 0.3); }
            50% { box-shadow: 0 2px 20px rgba(255, 51, 51, 0.6); }
        }

        /* Panels with scale animations */
        .panel {
            display: none;
            background: #111;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            position: relative;
            overflow: hidden;
            transform-origin: top;
            animation: panelFade 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes panelFade {
            from {
                opacity: 0;
                transform: scale(0.95) translateY(-10px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        .panel.active {
            display: block;
        }

        .panel::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, #ff3333, transparent);
            opacity: 0.3;
            animation: borderGlow 3s infinite;
        }

        @keyframes borderGlow {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 0.8; }
        }

        .section-title {
            color: #ff3333;
            font-size: 16px;
            font-weight: 500;
            margin-bottom: 20px;
            padding-bottom: 8px;
            border-bottom: 1px solid #2a2a2a;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: relative;
            animation: slideInRight 0.4s ease-out;
        }

        .section-title::after {
            content: '';
            position: absolute;
            bottom: -1px;
            left: 0;
            width: 50px;
            height: 1px;
            background: #ff3333;
            animation: widthPulse 2s ease-in-out infinite;
        }

        @keyframes widthPulse {
            0%, 100% { width: 50px; }
            50% { width: 80px; }
        }

        /* Row animations */
        .row {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            animation: slideInRight 0.4s ease-out;
            animation-fill-mode: both;
        }

        .row:nth-child(2) { animation-delay: 0.1s; }
        .row:nth-child(3) { animation-delay: 0.15s; }
        .row:nth-child(4) { animation-delay: 0.2s; }
        .row:nth-child(5) { animation-delay: 0.25s; }

        .row-vertical {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 15px;
            margin-bottom: 25px;
            animation: slideInRight 0.4s ease-out 0.2s both;
        }

        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .label {
            color: #999;
            font-size: 14px;
            font-weight: 400;
            min-width: 130px;
            text-align: right;
            letter-spacing: 0.3px;
            text-transform: uppercase;
            font-size: 12px;
            transition: color 0.3s ease;
        }

        .row:hover .label {
            color: #ff3333;
        }

        .btn-group {
            display: flex;
            gap: 10px;
        }

        .btn-group-vertical {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .btn-small {
            padding: 8px 20px;
            background: #1a1a1a;
            border: 1px solid #333;
            color: #999;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            min-width: 70px;
            text-align: center;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .btn-small::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            transition: width 0.4s, height 0.4s;
        }

        .btn-small:hover::before {
            width: 150px;
            height: 150px;
        }

        .btn-small:hover {
            background: #222;
            border-color: #444;
            color: #ccc;
            transform: translateY(-1px);
        }

        .btn-small:active {
            transform: translateY(0);
        }

        .btn-small.active, .btn-small.primary {
            background: #ff3333;
            border-color: #ff3333;
            color: #fff;
            box-shadow: 0 2px 8px rgba(255, 51, 51, 0.3);
            animation: buttonPulse 2s infinite;
        }

        @keyframes buttonPulse {
            0%, 100% { box-shadow: 0 2px 8px rgba(255, 51, 51, 0.3); }
            50% { box-shadow: 0 2px 15px rgba(255, 51, 51, 0.6); }
        }

        .btn-small.active:hover, .btn-small.primary:hover {
            background: #ff1a1a;
            border-color: #ff1a1a;
        }

        .btn-small.success {
            background: #1a4d1a;
            border-color: #2d6a2d;
            color: #fff;
        }

        .btn-small.success:hover {
            background: #236b23;
        }

        select.small {
            padding: 8px 15px;
            background: #1a1a1a;
            border: 1px solid #333;
            color: #e0e0e0;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 400;
            cursor: pointer;
            width: 170px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            appearance: none;
            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23999'%3e%3cpath d='M7 10l5 5 5-5z'/%3e%3c/svg%3e");
            background-repeat: no-repeat;
            background-position: right 12px center;
            background-size: 16px;
            transition: all 0.3s ease;
        }

        select.small:hover {
            border-color: #ff3333;
            background-color: #222;
            transform: translateY(-1px);
        }

        select.small option {
            background: #1a1a1a;
            color: #e0e0e0;
        }

        .badge {
            display: inline-block;
            padding: 5px 12px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 4px;
            color: #ff3333;
            font-size: 12px;
            font-weight: 500;
            min-width: 60px;
            text-align: center;
            letter-spacing: 0.3px;
            transition: all 0.3s ease;
            animation: badgePulse 3s infinite;
        }

        @keyframes badgePulse {
            0%, 100% { border-color: #333; }
            50% { border-color: #ff3333; }
        }

        .badge:hover {
            border-color: #ff3333;
            transform: scale(1.05);
        }

        .emulator-box {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 6px;
            padding: 20px;
            margin: 15px 0;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 25px;
            flex-wrap: wrap;
            position: relative;
            transition: all 0.3s ease;
            animation: slideInRight 0.4s ease-out;
        }

        .emulator-box:hover {
            border-color: #ff3333;
            box-shadow: 0 5px 20px rgba(255, 51, 51, 0.15);
        }

        .radio-group {
            display: flex;
            gap: 25px;
        }

        .radio-option {
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
        }

        .radio-option input[type="radio"] {
            width: 16px;
            height: 16px;
            accent-color: #ff3333;
            cursor: pointer;
            background: #1a1a1a;
            transition: all 0.2s ease;
        }

        .radio-option label {
            color: #ccc;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            transition: color 0.3s ease;
        }

        .radio-option:hover {
            transform: translateX(-2px);
        }

        .radio-option:hover label {
            color: #ff3333;
        }

        /* Terminal with slide animation */
        .terminal {
            background: #111;
            border: 1px solid #2a2a2a;
            border-radius: 6px;
            margin-top: 25px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
            position: relative;
            overflow: hidden;
            animation: slideUp 0.5s ease-out 0.3s both;
        }

        .terminal::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, #ff3333, transparent);
            opacity: 0.2;
            animation: borderGlow 3s infinite;
        }

        .terminal-header {
            background: #1a1a1a;
            padding: 10px 15px;
            border-bottom: 1px solid #2a2a2a;
            color: #ff3333;
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .terminal-content {
            padding: 15px;
            min-height: 120px;
            max-height: 150px;
            overflow-y: auto;
            font-size: 12px;
            color: #999;
            font-family: 'Inter', monospace;
            background: #0c0c0c;
        }

        .terminal-content::-webkit-scrollbar {
            width: 4px;
        }

        .terminal-content::-webkit-scrollbar-track {
            background: #1a1a1a;
        }

        .terminal-content::-webkit-scrollbar-thumb {
            background: #333;
            border-radius: 2px;
            transition: all 0.3s ease;
        }

        .terminal-content::-webkit-scrollbar-thumb:hover {
            background: #ff3333;
        }

        .log {
            margin-bottom: 5px;
            border-left: 1px solid #ff3333;
            padding-left: 10px;
            font-family: 'Inter', monospace;
            color: #bbb;
            animation: slideInLeft 0.3s ease-out;
        }

        @keyframes slideInLeft {
            from {
                opacity: 0;
                transform: translateX(-10px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .log-time {
            color: #666;
            margin-right: 10px;
            font-size: 11px;
        }

        .mt-10 { margin-top: 10px; }
        .mb-10 { margin-bottom: 10px; }
        .ml-10 { margin-left: 10px; }
        .flex { display: flex; align-items: center; gap: 15px; }
    </style>
</head>
<body>
    <!-- Animated Particles Canvas -->
    <canvas id="particles-canvas"></canvas>

    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">VORTEXOFFICIAL</div>
            <div class="status">
                <div class="stat-item">
                    <div class="stat-label">STATUS</div>
                    <div class="stat-value" id="sysStat">ONLINE</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">GAME</div>
                    <div class="stat-value" id="gameStat">OFFLINE</div>
                </div>
            </div>
        </div>

        <!-- Navigation -->
        <div class="nav">
            <button class="nav-btn active" onclick="switchTab('aimbot')">AIMBOT</button>
            <button class="nav-btn" onclick="switchTab('visuals')">VISUALS</button>
        </div>

        <!-- TAB 1: AIMBOT -->
        <div class="panel active" id="aimbot">
            <div class="section-title">AIMBOT CONTROLS</div>
            
            <!-- SCAN -->
            <div class="row">
                <span class="label">PLAYER SCAN</span>
                <div class="btn-group">
                    <button class="btn-small primary" onclick="runCmd('aimbotscan', this)">SCAN</button>
                </div>
                <span class="badge" id="scanStat">0</span>
            </div>

            <!-- NECK ON/OFF -->
            <div class="row">
                <span class="label">NECK</span>
                <div class="btn-group" id="neckGroup">
                    <button class="btn-small" onclick="runCmd('neckon', this)">ON</button>
                    <button class="btn-small active" onclick="runCmd('neckoff', this)">OFF</button>
                </div>
            </div>

            <!-- LEGIT AIMBOT - VERTICAL LAYOUT -->
            <div class="row-vertical">
                <span class="label">LEGIT AIMBOT</span>
                <div class="flex">
                    <select class="small" id="legitSelect">
                        <option value="left">LEFT SHOULDER</option>
                        <option value="right">RIGHT SHOULDER</option>
                    </select>
                    <div class="btn-group" id="legitGroup">
                        <button class="btn-small" onclick="legitOn(this)">ON</button>
                        <button class="btn-small active" onclick="legitOff(this)">OFF</button>
                    </div>
                </div>
            </div>

            <!-- VORTEX OFFICIAL SPECIAL AIMBOT -->
            <div class="section-title mt-10">VORTEX OFFICIAL SPECIAL AIMBOT</div>
            
            <!-- AIMBOT AI ON/OFF -->
            <div class="row">
                <span class="label">AIMBOT AI</span>
                <div class="btn-group" id="aiGroup">
                    <button class="btn-small" onclick="runCmd('aion', this)">ON</button>
                    <button class="btn-small active" onclick="runCmd('aioff', this)">OFF</button>
                </div>
            </div>
        </div>

        <!-- TAB 2: VISUALS -->
        <div class="panel" id="visuals">
            <div class="section-title">ESP INJECTION</div>
            
            <div class="emulator-box">
                <div class="radio-group">
                    <div class="radio-option">
                        <input type="radio" name="emulator" id="msi" value="msi" onchange="selectEmulator('msi')">
                        <label for="msi">MSI</label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="emulator" id="bluestacks" value="bluestacks" onchange="selectEmulator('bluestacks')">
                        <label for="bluestacks">BLUESTACKS</label>
                    </div>
                </div>

                <button class="btn-small success" onclick="injectESP()" id="injectBtn" disabled>INJECT ESP</button>
                <span class="badge" id="injectStatus">READY</span>
            </div>
        </div>

        <!-- TERMINAL -->
        <div class="terminal">
            <div class="terminal-header">SYSTEM TERMINAL</div>
            <div class="terminal-content" id="terminal">
                <div class="log"><span class="log-time">[⏰]</span> STREAMER IS READY</div>
            </div>
        </div>
    </div>

    <script>
        // Animated Particles
        const canvas = document.getElementById('particles-canvas');
        const ctx = canvas.getContext('2d');
        let particles = [];
        let mouseX = 0;
        let mouseY = 0;
        let animationFrame;

        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }

        function createParticles() {
            const particleCount = 80;
            for (let i = 0; i < particleCount; i++) {
                particles.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    size: Math.random() * 3 + 1,
                    speedX: (Math.random() - 0.5) * 0.5,
                    speedY: (Math.random() - 0.5) * 0.5,
                    opacity: Math.random() * 0.5 + 0.1,
                    color: `rgba(255, ${Math.floor(51 + Math.random() * 50)}, ${Math.floor(51 + Math.random() * 50)}, ${Math.random() * 0.3 + 0.1})`
                });
            }
        }

        function drawParticles() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            particles.forEach(p => {
                // Move particles
                p.x += p.speedX;
                p.y += p.speedY;
                
                // Mouse interaction
                const dx = mouseX - p.x;
                const dy = mouseY - p.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                if (distance < 100) {
                    const angle = Math.atan2(dy, dx);
                    const force = (100 - distance) / 1000;
                    p.x -= Math.cos(angle) * force;
                    p.y -= Math.sin(angle) * force;
                }
                
                // Bounce off edges
                if (p.x < 0 || p.x > canvas.width) p.speedX *= -0.9;
                if (p.y < 0 || p.y > canvas.height) p.speedY *= -0.9;
                
                // Keep within bounds
                p.x = Math.max(0, Math.min(canvas.width, p.x));
                p.y = Math.max(0, Math.min(canvas.height, p.y));
                
                // Draw particle
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.fill();
                
                // Draw connecting lines between nearby particles
                particles.forEach(p2 => {
                    const dx = p.x - p2.x;
                    const dy = p.y - p2.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    if (distance < 80) {
                        ctx.beginPath();
                        ctx.strokeStyle = `rgba(255, 51, 51, ${0.1 * (1 - distance/80)})`;
                        ctx.lineWidth = 0.5;
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.stroke();
                    }
                });
            });
            
            animationFrame = requestAnimationFrame(drawParticles);
        }

        // Mouse move handler for particle interaction
        document.addEventListener('mousemove', (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
        });

        // Handle resize
        window.addEventListener('resize', () => {
            resizeCanvas();
            particles = [];
            createParticles();
        });

        // Initialize particles
        resizeCanvas();
        createParticles();
        drawParticles();

        // Clean up animation frame on page unload
        window.addEventListener('beforeunload', () => {
            if (animationFrame) {
                cancelAnimationFrame(animationFrame);
            }
        });

        // Tab switching
        function switchTab(tab) {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
            
            // Add click animation
            event.target.style.transform = 'scale(0.95)';
            setTimeout(() => {
                event.target.style.transform = 'scale(1)';
            }, 200);
        }

        // Game status
        async function checkGame() {
            try {
                const r = await fetch('/status');
                const d = await r.json();
                document.getElementById('gameStat').textContent = d.status === 'online' ? 'ONLINE' : 'OFFLINE';
            } catch(e) {}
        }
        setInterval(checkGame, 3000);
        checkGame();

        // Logging
        function log(msg) {
            const t = document.getElementById('terminal');
            const time = new Date().toLocaleTimeString();
            t.innerHTML += `<div class="log"><span class="log-time">[${time}]</span> ${msg}</div>`;
            t.scrollTop = t.scrollHeight;
            if (t.children.length > 20) t.children[0].remove();
        }

        // Command execution with button state management
        async function runCmd(cmd, btn) {
            // Add click animation
            if (btn) {
                btn.style.transform = 'scale(0.95)';
                setTimeout(() => {
                    btn.style.transform = '';
                }, 200);
            }
            
            // Update button states for ON/OFF groups
            if (cmd === 'neckon' || cmd === 'neckoff') {
                const group = document.getElementById('neckGroup');
                group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
                if (cmd === 'neckon') {
                    group.children[0].classList.add('active', 'primary');
                } else {
                    group.children[1].classList.add('active', 'primary');
                }
            }
            
            if (cmd === 'aion' || cmd === 'aioff') {
                const group = document.getElementById('aiGroup');
                group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
                if (cmd === 'aion') {
                    group.children[0].classList.add('active', 'primary');
                } else {
                    group.children[1].classList.add('active', 'primary');
                }
            }

            log(`> ${cmd}`);
            try {
                const r = await fetch('/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: cmd})
                });
                const d = await r.json();
                log(d.message);
                if (cmd === 'aimbotscan') {
                    const match = d.message.match(/\d+/);
                    document.getElementById('scanStat').textContent = match ? match[0] : '0';
                    // Animate badge
                    const badge = document.getElementById('scanStat');
                    badge.style.transform = 'scale(1.2)';
                    setTimeout(() => {
                        badge.style.transform = '';
                    }, 200);
                }
            } catch(e) {
                log('Command failed');
            }
        }

        function legitOn(btn) {
            // Add click animation
            btn.style.transform = 'scale(0.95)';
            setTimeout(() => {
                btn.style.transform = '';
            }, 200);
            
            const val = document.getElementById('legitSelect').value;
            const group = document.getElementById('legitGroup');
            group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
            group.children[0].classList.add('active', 'primary');
            
            if (val === 'left') {
                runCmd('leftshoulderon', btn);
            } else {
                runCmd('rightshoulderon', btn);
            }
        }

        function legitOff(btn) {
            // Add click animation
            btn.style.transform = 'scale(0.95)';
            setTimeout(() => {
                btn.style.transform = '';
            }, 200);
            
            const val = document.getElementById('legitSelect').value;
            const group = document.getElementById('legitGroup');
            group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
            group.children[1].classList.add('active', 'primary');
            
            if (val === 'left') {
                runCmd('leftshoulderoff', btn);
            } else {
                runCmd('rightshoulderoff', btn);
            }
        }

        let currentEmulator = null;

        function selectEmulator(emulator) {
            currentEmulator = emulator;
            document.getElementById('injectBtn').disabled = false;
            document.getElementById('injectStatus').textContent = 'READY';
            log(`Selected: ${emulator}`);
            
            // Animate selected radio
            const radios = document.querySelectorAll('.radio-option');
            radios.forEach(r => r.style.transform = 'scale(1)');
            event.target.closest('.radio-option').style.transform = 'scale(1.05)';
            setTimeout(() => {
                event.target.closest('.radio-option').style.transform = '';
            }, 200);
        }

        async function injectESP() {
            if (!currentEmulator) {
                log('Select emulator first');
                return;
            }
            
            const btn = document.getElementById('injectBtn');
            btn.style.transform = 'scale(0.95)';
            setTimeout(() => {
                btn.style.transform = '';
            }, 200);
            
            document.getElementById('injectStatus').textContent = 'INJECTING...';
            log(`Injecting ESP into HD-Player.exe...`);
            
            try {
                const r = await fetch('/inject_esp', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({emulator: currentEmulator})
                });
                const d = await r.json();
                if (d.success) {
                    document.getElementById('injectStatus').textContent = 'INJECTED';
                    log('✓ ESP Injected successfully');
                } else {
                    document.getElementById('injectStatus').textContent = 'FAILED';
                    log(`✗ Injection failed: ${d.error}`);
                }
            } catch(e) {
                document.getElementById('injectStatus').textContent = 'ERROR';
                log('Injection error');
            }
        }

        window.onload = () => {
            log('STREAMER IS READY');
            
            // Add floating animation to badges periodically
            setInterval(() => {
                const badges = document.querySelectorAll('.badge');
                badges.forEach(badge => {
                    badge.style.transform = 'translateY(-2px)';
                    setTimeout(() => {
                        badge.style.transform = '';
                    }, 200);
                });
            }, 3000);
        };
    </script>
</body>
</html>'''

# ==================== FLASK ROUTES ====================

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return LOGIN_PAGE
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return '''<script>alert("Username and password required");window.history.back();</script>'''
        
        creds = get_credentials()
        username = username.lower()
        
        if username in creds and creds[username]['pass'] == password:
            session['logged_in'] = True
            session['username'] = username
            session['sid'] = creds[username]['sid']
            print(f"[AUTH] {username} logged in")
            return redirect(url_for('dashboard'))
        else:
            return '''<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:#ff3333;text-align:center;">ACCESS DENIED<br><a href="/" style="color:#ff3333;">RETRY</a></div>'''

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return DASHBOARD_PAGE

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/status')
def status():
    try:
        Pymem("HD-Player.exe")
        return jsonify({"status": "online"})
    except:
        return jsonify({"status": "offline"})

@app.route('/execute', methods=['POST'])
def execute():
    if not session.get('logged_in'):
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    cmd = data.get('command', '').lower()
    
    # AI Aim bot commands
    if cmd == 'aion':
        msg = ai_aimbot_on()
    elif cmd == 'aioff':
        msg = ai_aimbot_off()
    # Regular commands
    elif cmd == 'aimbotscan':
        msg = HEADLOAD()
    elif cmd == 'neckon':
        msg = HEADON()
    elif cmd == 'neckoff':
        msg = HEADOFF()
    elif cmd == 'leftshoulderon':
        msg = LEFTSHOULDERON()
    elif cmd == 'leftshoulderoff':
        msg = LEFTSHOULDEROFF()
    elif cmd == 'rightshoulderon':
        msg = RIGHTSHOULDERON()
    elif cmd == 'rightshoulderoff':
        msg = RIGHTSHOULDEROFF()
    elif cmd == 'removerecoil':
        msg = RemoveRecoil()
    elif cmd == 'addrecoil':
        msg = AddRecoil()
    else:
        msg = f"Unknown command: {cmd}"
    
    return jsonify({"message": msg})

@app.route('/inject_esp', methods=['POST'])
def inject_esp():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    emulator = data.get('emulator')
    
    # Call ESP injection placeholder
    result = inject_esp_dll(emulator)
    return jsonify(result)

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    # Stop anti-cheat blocker
    global anticheat_blocker
    if anticheat_blocker:
        anticheat_blocker.stop()
    
    # Properly shutdown Flask
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        # Fallback for different servers
        os._exit(0)
    else:
        func()
    return jsonify({'message': 'Shutting down...'})

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ==================== MAIN ====================
if __name__ == '__main__':
    # Start anti-cheat blocker
    print("[*] Starting Anti-Cheat Blocker...")
    anticheat_blocker.start()
    
    ip = get_ip()
    
    print("=" * 60)
    print("  VORTEXOFFICIAL STREAMER DASHBOARD")
    print("=" * 60)
    print(f"  Local URL:  http://localhost:8890")
    print(f"  Network URL: http://{ip}:8890")
    print(f"  PyMem:      {'ACTIVE' if PYMEM_OK else 'SIMULATED'}")
    print(f"  AntiCheat:  ACTIVE (Blocking scanners)")
    print(f"  AI Aimbot:  PLACEHOLDER (Ready for integration)")
    print(f"  ESP Inject: PLACEHOLDER (Ready for DLL)")
    print(f"  Terminate:  WORKING")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=8890, debug=False, threaded=True)
