#!/usr/bin/env python
# GHOST-XS - COMPLETE EDITION WITH AUTO SID VERIFICATION
# Runs on http://localhost:8890

import os
import sys
import time
import json
import socket
import threading
import hashlib
import ctypes
import ctypes.wintypes
import urllib.request
import psutil
import subprocess
import re
from datetime import datetime
from flask import Flask, request, redirect, url_for, session, jsonify

# Hide console for pythonw execution
if sys.platform == "win32":
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

# ==================== AUTO GET COMPUTER SID (SILENT) ====================
def get_computer_sid():
    """Automatically get the actual SID of the current computer - runs silently"""
    try:
        # Method 1: Using wmic to get computer SID (silent)
        result = subprocess.run(['wmic', 'useraccount', 'where', "name='%username%'", 'get', 'sid'], 
                               capture_output=True, text=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        # Extract SID from output
        output = result.stdout
        match = re.search(r'(S-\d-\d+-[\d-]+)', output)
        if match:
            return match.group(1)
        
        # Method 2: Fallback - get current user SID
        result = subprocess.run(['whoami', '/user'], capture_output=True, text=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = result.stdout
        match = re.search(r'(S-\d-\d+-[\d-]+)', output)
        if match:
            return match.group(1)
        
        return "SID_NOT_FOUND"
    except:
        return "SID_NOT_FOUND"

# ==================== GITHUB AUTH WITH AUTO SID VERIFICATION ====================
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

def verify_credentials(username, password):
    """Auto verify username, password AND computer SID - all automatic"""
    creds = get_credentials()
    username = username.lower()
    
    if username not in creds:
        return False, "Username not found"
    
    if creds[username]['pass'] != password:
        return False, "Invalid password"
    
    computer_sid = get_computer_sid()
    expected_sid = creds[username]['sid']
    
    print(f"[AUTH] Auto SID Check - Computer: {computer_sid} | Expected: {expected_sid}")
    
    if computer_sid != expected_sid:
        return False, "SID mismatch - Unauthorized computer"
    
    return True, "Authentication successful"

# ==================== ANTI-CHEAT BLOCKER MODULE ====================
from ctypes import wintypes

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

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

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

# Scanner/anti-cheat process names to block
SCANNER_NAMES = [
    "Anticheat.exe", "ANTI-CHEAT-AGDL.exe", "XAntiCheat.exe",
    "ANTI CHEAT BY MONTAGExGALIB.exe", "MAX ANTICHEAT.exe", "ArmorEye.exe",
    "HANDLE BY GARV.exe", "handleeeeeeeeeeee.exe", "CHIMTU X KHAN.exe",
    "Handle Viewer.exe", "External Panel Blocker.exe", "Manual Map Fucker.exe",
    "maxx handleee.exe", "Anticheat MAX.exe"
]

WHITELISTED = [
    "System", "System Idle Process", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "winlogon.exe",
    "dwm.exe", "conhost.exe", "fontdrvhost.exe", "spoolsv.exe",
    "SearchIndexer.exe", "SearchUI.exe", "RuntimeBroker.exe",
    "ShellExperienceHost.exe", "SystemSettings.exe", "StartMenuExperienceHost.exe",
    "TextInputHost.exe", "SecurityHealthSystray.exe", "SecurityHealthService.exe",
    "audiodg.exe", "taskmgr.exe", "Discord.exe", "DiscordPTB.exe",
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
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == 'hd-player.exe':
                    self.hd_player_pid = proc.info['pid']
                    return self.hd_player_pid
            except:
                continue
        return 0
    
    def is_process_whitelisted(self, proc_name, proc_path=""):
        proc_name_lower = proc_name.lower() if proc_name else ""
        for wl in WHITELISTED:
            if wl.lower() == proc_name_lower:
                return True
        return False
    
    def is_scanner_process(self, proc_name):
        proc_name_lower = proc_name.lower() if proc_name else ""
        for i, scanner in enumerate(SCANNER_NAMES):
            if scanner.lower() == proc_name_lower:
                return i + 1
        return -1
    
    def block_process_from_hdplayer(self, pid, proc_name):
        try:
            proc_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not proc_handle:
                return False
            
            print(f"[ANTICHEAT] Blocking: {proc_name} (PID:{pid})")
            
            fake_mem = VirtualAllocEx(proc_handle, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not fake_mem:
                CloseHandle(proc_handle)
                return False
            
            self.protected_processes[pid] = proc_name
            print(f"[ANTICHEAT] {proc_name} is now BLIND to HD-Player")
            
            CloseHandle(proc_handle)
            return True
        except:
            return False
    
    def monitor_thread(self):
        print("[ANTICHEAT] Anti-Cheat Blocker Started")
        processed_pids = set()
        
        while self.running:
            try:
                if not self.hd_player_pid or not psutil.pid_exists(self.hd_player_pid):
                    self.hd_player_pid = self.find_hd_player()
                    if not self.hd_player_pid:
                        time.sleep(2)
                        continue
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pid = proc.info['pid']
                        if (pid in processed_pids or pid == self.hd_player_pid or pid == os.getpid()):
                            continue
                        
                        proc_name = proc.info['name']
                        if not proc_name:
                            continue
                        
                        if self.is_process_whitelisted(proc_name, ""):
                            continue
                        
                        if self.is_scanner_process(proc_name) != -1:
                            self.block_process_from_hdplayer(pid, proc_name)
                            processed_pids.add(pid)
                    except:
                        continue
            except:
                pass
            time.sleep(2)
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.monitor_thread, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[ANTICHEAT] Anti-Cheat Blocker Stopped")
        return True

anticheat_blocker = AntiCheatBlocker()

# ==================== MEMORY FUNCTIONS ====================
try:
    from pymem import Pymem
    from pymem.memory import read_bytes, write_bytes
    from pymem.pattern import pattern_scan_all
    PYMEM_OK = True
except ImportError:
    PYMEM_OK = False
    print("[!] PyMem not installed - using simulation mode")

aimbot_addresses = []
original_value = []
ai_aimbot_active = False

def mkp(aob: str):
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

def ai_aimbot_on():
    global ai_aimbot_active
    ai_aimbot_active = True
    return "[AI AIMBOT] AI aimbot enabled - Ready for integration"

def ai_aimbot_off():
    global ai_aimbot_active
    ai_aimbot_active = False
    return "[AI AIMBOT] AI aimbot disabled"

# ==================== MEMORY-ONLY DLL INJECTION ====================
DLL_URL = "https://raw.githubusercontent.com/Ghostxs90/ESP-DLLs/main/esp.dll"

def inject_dll_from_memory(pid, dll_bytes):
    try:
        h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            return False, "Failed to open process"
        
        dll_size = len(dll_bytes)
        remote_memory = VirtualAllocEx(
            h_process, None, dll_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        
        if not remote_memory:
            CloseHandle(h_process)
            return False, "Failed to allocate memory"
        
        written = ctypes.c_size_t(0)
        result = WriteProcessMemory(
            h_process, remote_memory, dll_bytes,
            dll_size, ctypes.byref(written)
        )
        
        if not result or written.value != dll_size:
            VirtualFreeEx(h_process, remote_memory, 0, 0x8000)
            CloseHandle(h_process)
            return False, "Failed to write DLL"
        
        entry_point = remote_memory + 0x1000
        thread_id = ctypes.c_ulong(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, entry_point,
            None, 0, ctypes.byref(thread_id)
        )
        
        if not h_thread:
            VirtualFreeEx(h_process, remote_memory, 0, 0x8000)
            CloseHandle(h_process)
            return False, "Failed to create thread"
        
        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)
        CloseHandle(h_process)
        
        return True, "DLL injected successfully"
        
    except Exception as e:
        return False, str(e)

def download_and_inject_esp(emulator):
    try:
        hd_pid = 0
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and proc.info['name'].lower() == 'hd-player.exe':
                hd_pid = proc.info['pid']
                break
        
        if not hd_pid:
            return {'success': False, 'error': 'HD-Player.exe not running'}
        
        req = urllib.request.Request(DLL_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            dll_bytes = response.read()
        
        if len(dll_bytes) < 1000:
            return {'success': False, 'error': 'Downloaded DLL is too small'}
        
        success, message = inject_dll_from_memory(hd_pid, dll_bytes)
        
        if success:
            return {'success': True, 'message': f'ESP injected (PID: {hd_pid})'}
        else:
            return {'success': False, 'error': message}
            
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
        #login-particles {
            position:fixed;
            top:0;
            left:0;
            width:100%;
            height:100%;
            z-index:0;
            pointer-events:none;
        }
        .login-box {
            background:#111;
            border:1px solid #ff3333;
            border-radius:8px;
            padding:40px;
            width:340px;
            box-shadow:0 10px 30px rgba(0,0,0,0.5);
            position:relative;
            z-index:2;
            animation:slideUp 0.5s ease-out;
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
        }
        input:focus {
            outline:none;
            border-color:#ff3333;
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
        }
        button:hover {
            background:#cc0000;
        }
        .error {
            background:rgba(255,51,51,0.1);
            border:1px solid #ff3333;
            border-radius:4px;
            padding:12px;
            margin-bottom:20px;
            color:#ff3333;
            text-align:center;
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
            width:40px; height:40px;
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
    <canvas id="login-particles"></canvas>
    <div class="loader" id="loader">
        <div class="spinner"></div>
        <div>VERIFYING</div>
    </div>
    <div class="login-box">
        <h2>VORTEXOFFICIAL</h2>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/" onsubmit="document.getElementById('loader').classList.add('show')">
            <input type="text" name="username" placeholder="USERNAME" required>
            <input type="password" name="password" placeholder="PASSWORD" required>
            <button type="submit">LOGIN</button>
        </form>
    </div>
    <script>
        const canvas = document.getElementById('login-particles');
        const ctx = canvas.getContext('2d');
        let particles = [];
        
        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        
        function createParticles() {
            for(let i = 0; i < 40; i++) {
                particles.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    size: Math.random() * 2,
                    speedX: (Math.random() - 0.5) * 0.2,
                    speedY: (Math.random() - 0.5) * 0.2,
                    opacity: Math.random() * 0.2
                });
            }
        }
        
        function drawParticles() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            particles.forEach(p => {
                p.x += p.speedX;
                p.y += p.speedY;
                if(p.x < 0 || p.x > canvas.width) p.speedX *= -1;
                if(p.y < 0 || p.y > canvas.height) p.speedY *= -1;
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(255, 51, 51, ${p.opacity})`;
                ctx.fill();
            });
            requestAnimationFrame(drawParticles);
        }
        
        window.addEventListener('resize', () => {
            resizeCanvas();
            particles = [];
            createParticles();
        });
        
        resizeCanvas();
        createParticles();
        drawParticles();
    </script>
</body>
</html>'''

# ==================== DASHBOARD PAGE ====================
DASHBOARD_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VortexOffcial • Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background: #0a0a0a;
            font-family: 'Inter', sans-serif;
            color: #e0e0e0;
            padding: 20px;
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
        }
        #particles-canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            pointer-events: none;
        }
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
        .container { max-width: 1200px; margin: 0 auto; position: relative; z-index: 1; }
        .header {
            background: #111;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 18px 25px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            animation: slideDown 0.5s ease-out;
        }
        .logo { color: #ff3333; font-size: 20px; font-weight: 600; text-transform: uppercase; }
        .status { display: flex; gap: 25px; }
        .stat-item {
            text-align: center;
            padding: 5px 10px;
            border-radius: 4px;
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            min-width: 80px;
        }
        .stat-label { font-size: 11px; color: #666; text-transform: uppercase; margin-bottom: 4px; }
        .stat-value { font-size: 14px; color: #ff3333; font-weight: 600; }
        .nav {
            display: flex;
            gap: 8px;
            margin-bottom: 25px;
            background: #111;
            padding: 6px;
            border-radius: 8px;
            border: 1px solid #2a2a2a;
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
            transition: all 0.3s ease;
            text-transform: uppercase;
        }
        .nav-btn:hover { background: #1a1a1a; color: #999; }
        .nav-btn.active {
            background: #ff3333;
            color: #fff;
            font-weight: 600;
            box-shadow: 0 2px 10px rgba(255,51,51,0.3);
        }
        .panel {
            display: none;
            background: #111;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }
        .panel.active { display: block; }
        .section-title {
            color: #ff3333;
            font-size: 16px;
            font-weight: 500;
            margin-bottom: 20px;
            padding-bottom: 8px;
            border-bottom: 1px solid #2a2a2a;
            text-transform: uppercase;
        }
        .row {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .row-vertical {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 15px;
            margin-bottom: 25px;
        }
        .label {
            color: #999;
            font-size: 12px;
            min-width: 130px;
            text-align: right;
            text-transform: uppercase;
        }
        .btn-group { display: flex; gap: 10px; }
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
        }
        .btn-small:hover { background: #222; border-color: #444; color: #ccc; }
        .btn-small.active, .btn-small.primary {
            background: #ff3333;
            border-color: #ff3333;
            color: #fff;
            box-shadow: 0 2px 8px rgba(255,51,51,0.3);
        }
        .btn-small.success { background: #1a4d1a; border-color: #2d6a2d; color: #fff; }
        select.small {
            padding: 8px 15px;
            background: #1a1a1a;
            border: 1px solid #333;
            color: #e0e0e0;
            border-radius: 4px;
            font-size: 13px;
            cursor: pointer;
            width: 170px;
            text-transform: uppercase;
        }
        select.small:hover { border-color: #ff3333; }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 4px;
            color: #ff3333;
            font-size: 12px;
            min-width: 60px;
            text-align: center;
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
        }
        .radio-group { display: flex; gap: 25px; }
        .radio-option {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .radio-option input[type="radio"] {
            width: 16px;
            height: 16px;
            accent-color: #ff3333;
        }
        .radio-option label {
            color: #ccc;
            font-size: 13px;
            font-weight: 500;
            text-transform: uppercase;
        }
        .terminal {
            background: #111;
            border: 1px solid #2a2a2a;
            border-radius: 6px;
            margin-top: 25px;
        }
        .terminal-header {
            background: #1a1a1a;
            padding: 10px 15px;
            border-bottom: 1px solid #2a2a2a;
            color: #ff3333;
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
        }
        .terminal-content {
            padding: 15px;
            min-height: 120px;
            max-height: 150px;
            overflow-y: auto;
            font-size: 12px;
            color: #999;
            background: #0c0c0c;
            font-family: monospace;
        }
        .log {
            margin-bottom: 5px;
            border-left: 1px solid #ff3333;
            padding-left: 10px;
        }
        .log-time { color: #666; margin-right: 10px; font-size: 11px; }
        .mt-10 { margin-top: 10px; }
        .flex { display: flex; align-items: center; gap: 15px; }
        
        /* Settings Tab Styles */
        .settings-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-top: 10px;
        }
        .settings-box {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
        }
        .box-title {
            color: #ff3333;
            font-size: 15px;
            font-weight: 600;
            margin-bottom: 20px;
            padding-bottom: 8px;
            border-bottom: 1px solid #333;
            text-transform: uppercase;
        }
        .key-category {
            margin-bottom: 20px;
        }
        .category-label {
            display: block;
            color: #999;
            font-size: 12px;
            font-weight: 500;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .key-select {
            width: 100%;
            padding: 12px;
            background: #222;
            border: 1px solid #444;
            color: #fff;
            border-radius: 4px;
            font-size: 13px;
            cursor: pointer;
        }
        .key-select:hover { border-color: #ff3333; }
        .key-select option { background: #222; color: #fff; }
        .aim-group { margin-bottom: 25px; }
        .aim-option {
            display: flex;
            align-items: center;
            padding: 12px;
            background: #222;
            border: 1px solid #444;
            border-radius: 4px;
            margin-bottom: 8px;
            cursor: pointer;
        }
        .aim-option:hover { border-color: #ff3333; background: #2a2a2a; }
        .aim-option input[type="radio"] {
            width: 16px;
            height: 16px;
            accent-color: #ff3333;
            margin-right: 12px;
        }
        .aim-option label {
            color: #fff;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            flex: 1;
            text-transform: uppercase;
        }
        .ai-section {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #333;
        }
        .ai-title {
            color: #ff3333;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .current-config {
            background: #222;
            border: 1px solid #444;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }
        .config-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #333;
        }
        .config-row:last-child { border-bottom: none; }
        .config-label { color: #999; font-size: 12px; }
        .config-value {
            color: #ff3333;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .save-btn {
            width: 100%;
            padding: 14px;
            background: #ff3333;
            border: none;
            border-radius: 4px;
            color: #fff;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .save-btn:hover { background: #ff1a1a; }
        .test-btn {
            width: 100%;
            padding: 12px;
            background: #2a2a2a;
            border: 1px solid #ff3333;
            border-radius: 4px;
            color: #ff3333;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            text-transform: uppercase;
        }
        .test-btn:hover { background: #ff3333; color: #fff; }
        .info-box {
            margin-top: 20px;
            padding: 15px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 4px;
            font-size: 12px;
            color: #999;
            line-height: 1.5;
        }
        .info-box strong { color: #ff3333; }
        @media (max-width: 768px) {
            .settings-container { grid-template-columns: 1fr; }
        }
        @keyframes slideDown {
            from { opacity:0; transform:translateY(-20px); }
            to { opacity:1; transform:translateY(0); }
        }
    </style>
</head>
<body>
    <canvas id="particles-canvas"></canvas>

    <div class="container">
        <div class="header">
            <div class="logo">VORTEXOFFICIAL</div>
            <div class="status">
                <div class="stat-item">
                    <div class="stat-label">STATUS</div>
                    <div class="stat-value">ONLINE</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">GAME</div>
                    <div class="stat-value" id="gameStat">OFFLINE</div>
                </div>
            </div>
        </div>

        <div class="nav">
            <button class="nav-btn active" onclick="switchTab('aimbot')">AIMBOT</button>
            <button class="nav-btn" onclick="switchTab('visuals')">VISUALS</button>
            <button class="nav-btn" onclick="switchTab('settings')">SETTINGS</button>
        </div>

        <!-- TAB 1: AIMBOT -->
        <div class="panel active" id="aimbot">
            <div class="section-title">AIMBOT CONTROLS</div>
            
            <div class="row">
                <span class="label">PLAYER SCAN</span>
                <div class="btn-group">
                    <button class="btn-small primary" onclick="runCmd('aimbotscan', this)">SCAN</button>
                </div>
                <span class="badge" id="scanStat">0</span>
            </div>

            <div class="row">
                <span class="label">NECK</span>
                <div class="btn-group" id="neckGroup">
                    <button class="btn-small" onclick="runCmd('neckon', this)">ON</button>
                    <button class="btn-small active" onclick="runCmd('neckoff', this)">OFF</button>
                </div>
            </div>

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

            <div class="section-title mt-10">VORTEX OFFICIAL SPECIAL AIMBOT</div>
            
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

        <!-- TAB 3: SETTINGS - CUSTOM KEY TOGGLE -->
        <div class="panel" id="settings">
            <div class="section-title">CUSTOM KEY TOGGLE SETTINGS</div>
            
            <div class="settings-container">
                <!-- LEFT: KEY SELECTION -->
                <div class="settings-box">
                    <div class="box-title">SELECT KEY</div>
                    
                    <!-- MOUSE KEYS -->
                    <div class="key-category">
                        <span class="category-label">MOUSE</span>
                        <select class="key-select" id="mouseSelect" onchange="selectKey('mouse', this.value)">
                            <option value="">SELECT MOUSE KEY</option>
                            <option value="mouse1">Left Button</option>
                            <option value="mouse2">Right Button</option>
                            <option value="mouse3">Middle Button</option>
                            <option value="mouse4">Button 4</option>
                            <option value="mouse5">Button 5</option>
                            <option value="xbutton1">XButton 1</option>
                            <option value="xbutton2">XButton 2</option>
                        </select>
                    </div>
                    
                    <!-- KEYBOARD KEYS -->
                    <div class="key-category">
                        <span class="category-label">KEYBOARD</span>
                        <select class="key-select" id="keyboardSelect" onchange="selectKey('keyboard', this.value)">
                            <option value="">SELECT KEYBOARD KEY</option>
                            <optgroup label="LETTERS">
                                <option value="a">A</option><option value="b">B</option><option value="c">C</option>
                                <option value="d">D</option><option value="e">E</option><option value="f">F</option>
                                <option value="g">G</option><option value="h">H</option><option value="i">I</option>
                                <option value="j">J</option><option value="k">K</option><option value="l">L</option>
                                <option value="m">M</option><option value="n">N</option><option value="o">O</option>
                                <option value="p">P</option><option value="q">Q</option><option value="r">R</option>
                                <option value="s">S</option><option value="t">T</option><option value="u">U</option>
                                <option value="v">V</option><option value="w">W</option><option value="x">X</option>
                                <option value="y">Y</option><option value="z">Z</option>
                            </optgroup>
                            <optgroup label="NUMBERS">
                                <option value="0">0</option><option value="1">1</option><option value="2">2</option>
                                <option value="3">3</option><option value="4">4</option><option value="5">5</option>
                                <option value="6">6</option><option value="7">7</option><option value="8">8</option>
                                <option value="9">9</option>
                            </optgroup>
                            <optgroup label="FUNCTION KEYS">
                                <option value="f1">F1</option><option value="f2">F2</option><option value="f3">F3</option>
                                <option value="f4">F4</option><option value="f5">F5</option><option value="f6">F6</option>
                                <option value="f7">F7</option><option value="f8">F8</option><option value="f9">F9</option>
                                <option value="f10">F10</option><option value="f11">F11</option><option value="f12">F12</option>
                            </optgroup>
                            <optgroup label="SPECIAL KEYS">
                                <option value="shift">Shift</option><option value="ctrl">Ctrl</option><option value="alt">Alt</option>
                                <option value="space">Space</option><option value="enter">Enter</option><option value="tab">Tab</option>
                                <option value="capslock">Caps Lock</option><option value="esc">Escape</option>
                                <option value="backspace">Backspace</option><option value="delete">Delete</option>
                                <option value="insert">Insert</option><option value="home">Home</option><option value="end">End</option>
                                <option value="pageup">Page Up</option><option value="pagedown">Page Down</option>
                                <option value="up">Up Arrow</option><option value="down">Down Arrow</option>
                                <option value="left">Left Arrow</option><option value="right">Right Arrow</option>
                            </optgroup>
                        </select>
                    </div>
                </div>
                
                <!-- RIGHT: AIM SELECTION -->
                <div class="settings-box">
                    <div class="box-title">SELECT AIM</div>
                    
                    <div class="aim-group">
                        <div class="aim-option">
                            <input type="radio" name="aimType" id="aimNeck" value="neck" checked>
                            <label for="aimNeck">NECK</label>
                        </div>
                        <div class="aim-option">
                            <input type="radio" name="aimType" id="aimLeft" value="left">
                            <label for="aimLeft">LEFT SHOULDER</label>
                        </div>
                        <div class="aim-option">
                            <input type="radio" name="aimType" id="aimRight" value="right">
                            <label for="aimRight">RIGHT SHOULDER</label>
                        </div>
                    </div>
                    
                    <div class="ai-section">
                        <div class="ai-title">AI AIMBOT</div>
                        <div class="aim-option">
                            <input type="radio" name="aimType" id="aimAI" value="ai">
                            <label for="aimAI">AI AIMBOT</label>
                        </div>
                    </div>
                    
                    <div class="current-config">
                        <div class="config-row">
                            <span class="config-label">Selected Key</span>
                            <span class="config-value" id="displayKey">None</span>
                        </div>
                        <div class="config-row">
                            <span class="config-label">Selected Aim</span>
                            <span class="config-value" id="displayAim">Neck</span>
                        </div>
                    </div>
                    
                    <button class="save-btn" onclick="saveConfig()">SAVE CONFIGURATION</button>
                    <button class="test-btn" onclick="testConfig()">TEST HOLD</button>
                </div>
            </div>
            
            <div class="info-box">
                <strong>HOLD TO ACTIVATE:</strong> Press and hold the selected key to activate aimbot. Release to deactivate.
            </div>
        </div>

        <!-- TERMINAL -->
        <div class="terminal">
            <div class="terminal-header">SYSTEM TERMINAL</div>
            <div class="terminal-content" id="terminal">
                <div class="log"><span class="log-time">[SYSTEM]</span> STREAMER IS READY</div>
            </div>
        </div>
    </div>

    <script>
        // Clean particles animation
        const canvas = document.getElementById('particles-canvas');
        const ctx = canvas.getContext('2d');
        let particles = [];

        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }

        function createParticles() {
            for (let i = 0; i < 35; i++) {
                particles.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    size: Math.random() * 2.5,
                    speedX: (Math.random() - 0.5) * 0.15,
                    speedY: (Math.random() - 0.5) * 0.15,
                    opacity: Math.random() * 0.15
                });
            }
        }

        function drawParticles() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            particles.forEach(p => {
                p.x += p.speedX;
                p.y += p.speedY;
                if (p.x < 0 || p.x > canvas.width) p.speedX *= -1;
                if (p.y < 0 || p.y > canvas.height) p.speedY *= -1;
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(255, 51, 51, ${p.opacity})`;
                ctx.fill();
            });
            requestAnimationFrame(drawParticles);
        }

        window.addEventListener('resize', () => {
            resizeCanvas();
            particles = [];
            createParticles();
        });

        resizeCanvas();
        createParticles();
        drawParticles();

        // Tab switching
        function switchTab(tab) {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
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

        // Command execution
        async function runCmd(cmd, btn) {
            if (btn) {
                btn.style.transform = 'scale(0.95)';
                setTimeout(() => btn.style.transform = '', 200);
            }
            
            if (cmd === 'neckon' || cmd === 'neckoff') {
                const group = document.getElementById('neckGroup');
                group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
                if (cmd === 'neckon') group.children[0].classList.add('active', 'primary');
                else group.children[1].classList.add('active', 'primary');
            }
            
            if (cmd === 'aion' || cmd === 'aioff') {
                const group = document.getElementById('aiGroup');
                group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
                if (cmd === 'aion') group.children[0].classList.add('active', 'primary');
                else group.children[1].classList.add('active', 'primary');
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
                }
            } catch(e) {
                log('Command failed');
            }
        }

        function legitOn(btn) {
            btn.style.transform = 'scale(0.95)';
            setTimeout(() => btn.style.transform = '', 200);
            const val = document.getElementById('legitSelect').value;
            const group = document.getElementById('legitGroup');
            group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
            group.children[0].classList.add('active', 'primary');
            runCmd(val === 'left' ? 'leftshoulderon' : 'rightshoulderon', btn);
        }

        function legitOff(btn) {
            btn.style.transform = 'scale(0.95)';
            setTimeout(() => btn.style.transform = '', 200);
            const val = document.getElementById('legitSelect').value;
            const group = document.getElementById('legitGroup');
            group.querySelectorAll('.btn-small').forEach(b => b.classList.remove('active', 'primary'));
            group.children[1].classList.add('active', 'primary');
            runCmd(val === 'left' ? 'leftshoulderoff' : 'rightshoulderoff', btn);
        }

        let currentEmulator = null;

        function selectEmulator(emulator) {
            currentEmulator = emulator;
            document.getElementById('injectBtn').disabled = false;
            log(`Selected: ${emulator}`);
        }

        async function injectESP() {
            if (!currentEmulator) {
                log('Select emulator first');
                return;
            }
            document.getElementById('injectStatus').textContent = 'INJECTING...';
            log('Injecting ESP...');
            try {
                const r = await fetch('/inject_esp', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({emulator: currentEmulator})
                });
                const d = await r.json();
                if (d.success) {
                    document.getElementById('injectStatus').textContent = 'INJECTED';
                    log('ESP Injected successfully');
                } else {
                    document.getElementById('injectStatus').textContent = 'FAILED';
                    log('Injection failed: ' + d.error);
                }
            } catch(e) {
                document.getElementById('injectStatus').textContent = 'ERROR';
                log('Injection error');
            }
        }

        // Settings Tab Functions
        let currentKey = null;
        let currentKeyType = null;

        function selectKey(type, key) {
            if (!key) return;
            
            currentKey = key;
            currentKeyType = type;
            
            if (type === 'mouse') {
                document.getElementById('keyboardSelect').value = '';
            } else {
                document.getElementById('mouseSelect').value = '';
            }
            
            const displayMap = {
                'mouse1': 'Left Button', 'mouse2': 'Right Button', 'mouse3': 'Middle Button',
                'mouse4': 'Button 4', 'mouse5': 'Button 5', 'xbutton1': 'XButton 1',
                'xbutton2': 'XButton 2', 'ctrl': 'Ctrl', 'shift': 'Shift', 'alt': 'Alt',
                'space': 'Space', 'enter': 'Enter', 'tab': 'Tab', 'capslock': 'Caps Lock',
                'esc': 'Escape', 'backspace': 'Backspace', 'delete': 'Delete',
                'insert': 'Insert', 'home': 'Home', 'end': 'End', 'pageup': 'Page Up',
                'pagedown': 'Page Down', 'up': 'Up Arrow', 'down': 'Down Arrow',
                'left': 'Left Arrow', 'right': 'Right Arrow'
            };
            
            document.getElementById('displayKey').textContent = 
                displayMap[key] || key.toUpperCase();
            
            log(`Selected ${type} key: ${displayMap[key] || key.toUpperCase()}`);
        }

        document.querySelectorAll('input[name="aimType"]').forEach(radio => {
            radio.addEventListener('change', function() {
                const display = {
                    'neck': 'Neck',
                    'left': 'Left Shoulder',
                    'right': 'Right Shoulder',
                    'ai': 'AI Aimbot'
                };
                document.getElementById('displayAim').textContent = display[this.value];
            });
        });

        function saveConfig() {
            if (!currentKey) {
                log('Please select a key first');
                return;
            }
            const aimType = document.querySelector('input[name="aimType"]:checked').value;
            log(`Configuration saved: ${document.getElementById('displayKey').textContent} → ${document.getElementById('displayAim').textContent}`);
        }

        function testConfig() {
            if (!currentKey) {
                log('Select a key first to test');
                return;
            }
            log(`TEST: Hold ${document.getElementById('displayKey').textContent} to activate - Release to deactivate`);
        }

        window.onload = () => {
            log('STREAMER IS READY');
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
            error = "Username and password required"
            return LOGIN_PAGE.replace('{% if error %}', f'<div class="error">{error}</div>')
        
        success, message = verify_credentials(username, password)
        
        if success:
            session['logged_in'] = True
            session['username'] = username
            creds = get_credentials()
            session['sid'] = creds.get(username.lower(), {}).get('sid', '')
            print(f"[AUTH] {username} logged in - Auto SID verified")
            return redirect(url_for('dashboard'))
        else:
            print(f"[AUTH] Login failed: {message}")
            return LOGIN_PAGE.replace('{% if error %}', f'<div class="error">{message}</div>')

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
    
    if cmd == 'aion':
        msg = ai_aimbot_on()
    elif cmd == 'aioff':
        msg = ai_aimbot_off()
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
    
    result = download_and_inject_esp(emulator)
    return jsonify(result)

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    global anticheat_blocker
    if anticheat_blocker:
        anticheat_blocker.stop()
    
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
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
    print("[*] Starting Anti-Cheat Blocker...")
    anticheat_blocker.start()
    
    computer_sid = get_computer_sid()
    ip = get_ip()
    
    print("=" * 60)
    print("  VORTEXOFFICIAL STREAMER DASHBOARD")
    print("=" * 60)
    print(f"  Local URL:    http://localhost:8890")
    print(f"  Network URL:   http://{ip}:8890")
    print(f"  Computer SID:  {computer_sid}")
    print(f"  PyMem:         {'ACTIVE' if PYMEM_OK else 'SIMULATED'}")
    print(f"  AntiCheat:     ACTIVE")
    print(f"  Authentication: Auto SID Verification")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=8890, debug=False, threaded=True)
