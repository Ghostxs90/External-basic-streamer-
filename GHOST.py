#!/usr/bin/env python
# GHOST-XS - HACKER GREEN EDITION
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
from datetime import datetime
from flask import Flask, request, redirect, url_for, session, jsonify

# Hide console for pythonw execution
if sys.platform == "win32":
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

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

# ==================== MEMORY FUNCTIONS (from your Memory.py) ====================
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
aim_legit_active = False
aim_legit_mode = "hold"  # "hold" or "toggle"
aim_legit_key = "xbutton1"  # Default mouse button
aim_legit_target = "neck"

def mkp(aob: str):
    """Pattern converter - exactly from your Memory.py"""
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
    """Scan for players - from your Memory.py"""
    if not PYMEM_OK:
        return "[SIMULATED] Player scan completed"
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
    """Neck aim - from your Memory.py"""
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
    """Disable aimbot - from your Memory.py"""
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
    """Right shoulder aim - from your Memory.py"""
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
    """Left shoulder aim - from your Memory.py"""
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
    """Remove recoil - from your Memory.py"""
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
    """Restore recoil - from your Memory.py"""
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

# ==================== AIM LEGIT FUNCTIONS ====================
def set_aim_legit_target(target):
    global aim_legit_target
    aim_legit_target = target
    return f"Target set to {target}"

def set_aim_legit_mode(mode):
    global aim_legit_mode
    aim_legit_mode = mode
    return f"Mode set to {mode}"

def set_aim_legit_key(key):
    global aim_legit_key
    aim_legit_key = key
    return f"Key set to {key}"

def aim_legit_activate():
    """Activate aim based on target"""
    global aim_legit_active
    aim_legit_active = True
    
    if aim_legit_target == "neck":
        return HEADON()
    elif aim_legit_target == "left":
        return LEFTSHOULDERON()
    elif aim_legit_target == "right":
        return RIGHTSHOULDERON()
    return "Aim Legit activated"

def aim_legit_deactivate():
    """Deactivate aim"""
    global aim_legit_active
    aim_legit_active = False
    return HEADOFF()

def aim_legit_toggle():
    """Toggle aim on/off"""
    global aim_legit_active
    if aim_legit_active:
        return aim_legit_deactivate()
    else:
        return aim_legit_activate()

def aim_legit_status():
    """Get current status"""
    return {
        'active': aim_legit_active,
        'mode': aim_legit_mode,
        'key': aim_legit_key,
        'target': aim_legit_target
    }

# ==================== FLASK SETUP ====================
app = Flask(__name__)
app.secret_key = "ghost-xs-green-2024"

# Hybrid mode globals
hybrid_active = False
hybrid_aim1 = None
hybrid_aim2 = None
hybrid_frequency = 50
hybrid_current = None
hybrid_count = 0
hybrid_last_switch = None

# ==================== LOGIN PAGE ====================
LOGIN_PAGE = '''<!DOCTYPE html>
<html>
<head>
    <title>GHOST-XS</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background:#0a0a0a;
            font-family:'Courier New', monospace;
            height:100vh;
            display:flex;
            align-items:center;
            justify-content:center;
        }
        .login-box {
            background:#111;
            border:2px solid #00ff00;
            border-radius:8px;
            padding:40px;
            width:340px;
            box-shadow:0 0 20px #00ff00;
        }
        h2 {
            color:#00ff00;
            text-align:center;
            margin-bottom:30px;
            font-size:24px;
            text-shadow:0 0 10px #00ff00;
        }
        input {
            width:100%;
            padding:12px;
            margin-bottom:20px;
            background:#222;
            border:1px solid #00ff00;
            border-radius:4px;
            color:#00ff00;
            font-size:14px;
            font-family:'Courier New', monospace;
        }
        input:focus {
            outline:none;
            box-shadow:0 0 10px #00ff00;
        }
        button {
            width:100%;
            padding:12px;
            background:#00ff00;
            color:#000;
            border:none;
            border-radius:4px;
            font-size:16px;
            font-weight:bold;
            cursor:pointer;
            font-family:'Courier New', monospace;
        }
        button:hover {
            background:#00cc00;
            box-shadow:0 0 20px #00ff00;
        }
        .loader {
            display:none;
            position:fixed;
            top:0;left:0;right:0;bottom:0;
            background:rgba(0,0,0,0.9);
            align-items:center;
            justify-content:center;
            color:#00ff00;
        }
        .loader.show { display:flex; }
        .spinner {
            width:50px; height:50px;
            border:3px solid #00ff00;
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
        <h2>GHOST-XS</h2>
        <form method="POST" action="/" onsubmit="document.getElementById('loader').classList.add('show')">
            <input type="text" name="username" placeholder="USERNAME" required>
            <input type="password" name="password" placeholder="PASSWORD" required>
            <button type="submit">LOGIN</button>
        </form>
    </div>
</body>
</html>'''

# ==================== DASHBOARD PAGE (GREEN HACKER THEME) ====================
DASHBOARD_PAGE = '''<!DOCTYPE html>
<html>
<head>
    <title>GHOST-XS TERMINAL</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background:#000000;
            font-family:'Courier New', monospace;
            color:#00ff00;
            padding:20px;
        }
        .container {
            max-width:1200px;
            margin:0 auto;
        }
        .header {
            background:#111111;
            border:2px solid #00ff00;
            border-radius:8px;
            padding:20px;
            margin-bottom:20px;
            display:flex;
            justify-content:space-between;
            align-items:center;
            box-shadow:0 0 15px #00ff00;
        }
        .logo {
            color:#00ff00;
            font-size:28px;
            font-weight:bold;
            text-shadow:0 0 10px #00ff00;
        }
        .status {
            display:flex;
            gap:20px;
        }
        .stat-item {
            text-align:center;
        }
        .stat-label {
            font-size:12px;
            color:#008800;
            margin-bottom:5px;
        }
        .stat-value {
            font-size:14px;
            color:#00ff00;
            font-weight:bold;
            text-shadow:0 0 5px #00ff00;
        }
        .nav {
            display:flex;
            gap:10px;
            margin-bottom:20px;
            background:#111;
            padding:5px;
            border-radius:8px;
            border:1px solid #00ff00;
        }
        .nav-btn {
            flex:1;
            padding:12px;
            background:transparent;
            border:none;
            color:#008800;
            font-size:14px;
            font-weight:bold;
            cursor:pointer;
            border-radius:6px;
            font-family:'Courier New', monospace;
        }
        .nav-btn:hover {
            background:#00ff00;
            color:#000;
        }
        .nav-btn.active {
            background:#00ff00;
            color:#000;
            box-shadow:0 0 15px #00ff00;
        }
        .panel {
            display:none;
            background:#111;
            border:1px solid #00ff00;
            border-radius:8px;
            padding:25px;
            margin-bottom:20px;
            box-shadow:0 0 10px #00ff00;
        }
        .panel.active {
            display:block;
        }
        .panel-title {
            color:#00ff00;
            font-size:18px;
            margin-bottom:20px;
            padding-bottom:10px;
            border-bottom:1px solid #00ff00;
            text-shadow:0 0 5px #00ff00;
        }
        .grid {
            display:grid;
            grid-template-columns:repeat(2,1fr);
            gap:20px;
        }
        .module {
            background:#1a1a1a;
            border:1px solid #00ff00;
            border-radius:6px;
            padding:20px;
        }
        .module-title {
            color:#00ff00;
            font-size:14px;
            font-weight:bold;
            margin-bottom:10px;
            text-shadow:0 0 5px #00ff00;
        }
        .module-desc {
            color:#008800;
            font-size:12px;
            margin-bottom:15px;
        }
        button {
            width:100%;
            padding:10px;
            margin-bottom:8px;
            background:#000;
            border:1px solid #00ff00;
            color:#00ff00;
            border-radius:4px;
            cursor:pointer;
            font-size:12px;
            font-weight:bold;
            font-family:'Courier New', monospace;
        }
        button:hover {
            background:#00ff00;
            color:#000;
            box-shadow:0 0 10px #00ff00;
        }
        button.primary {
            background:#00ff00;
            color:#000;
        }
        button.exit-btn {
            background:#00ff00;
            color:#000;
            margin-top:20px;
        }
        select {
            width:100%;
            padding:10px;
            margin-bottom:15px;
            background:#000;
            border:1px solid #00ff00;
            color:#00ff00;
            border-radius:4px;
            cursor:pointer;
            font-family:'Courier New', monospace;
        }
        select:hover {
            box-shadow:0 0 10px #00ff00;
        }
        select option {
            background:#000;
            color:#00ff00;
        }
        .badge {
            display:inline-block;
            padding:4px 8px;
            background:#000;
            border:1px solid #00ff00;
            border-radius:4px;
            color:#00ff00;
            font-size:11px;
        }
        .monitor {
            background:#000;
            border:1px solid #00ff00;
            border-radius:6px;
            padding:15px;
            margin-top:15px;
        }
        .monitor-row {
            display:flex;
            justify-content:space-between;
            margin-bottom:10px;
            font-size:13px;
            padding-bottom:5px;
            border-bottom:1px solid #00ff00;
        }
        .monitor-row:last-child {
            border-bottom:none;
        }
        .monitor-label {
            color:#008800;
        }
        .monitor-value {
            color:#00ff00;
            font-weight:bold;
            text-shadow:0 0 5px #00ff00;
        }
        .key-bind {
            background:#000;
            border:1px solid #00ff00;
            border-radius:4px;
            padding:12px;
            margin-bottom:15px;
            display:flex;
            justify-content:space-between;
            align-items:center;
        }
        .key-bind span:first-child {
            color:#008800;
        }
        .key-bind span:last-child {
            color:#00ff00;
            font-weight:bold;
            text-shadow:0 0 5px #00ff00;
        }
        .mode-selector {
            display:flex;
            gap:10px;
            margin-bottom:15px;
        }
        .mode-btn {
            flex:1;
            padding:10px;
            background:#000;
            border:1px solid #00ff00;
            color:#008800;
            border-radius:4px;
            cursor:pointer;
        }
        .mode-btn.active {
            background:#00ff00;
            color:#000;
        }
        .terminal {
            background:#000;
            border:1px solid #00ff00;
            border-radius:6px;
            margin-top:20px;
            box-shadow:0 0 15px #00ff00;
        }
        .terminal-header {
            background:#1a1a1a;
            padding:10px 15px;
            border-bottom:1px solid #00ff00;
            color:#00ff00;
            font-size:13px;
            font-weight:bold;
        }
        .terminal-content {
            padding:15px;
            min-height:150px;
            max-height:200px;
            overflow-y:auto;
            font-size:12px;
            color:#00ff00;
        }
        .log {
            margin-bottom:5px;
            border-left:2px solid #00ff00;
            padding-left:10px;
        }
        .log-time {
            color:#008800;
            margin-right:10px;
        }
        .flex {
            display:flex;
            gap:10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">GHOST-XS</div>
            <div class="status">
                <div class="stat-item">
                    <div class="stat-label">SYSTEM</div>
                    <div class="stat-value" id="sysStat">ONLINE</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">GAME</div>
                    <div class="stat-value" id="gameStat">OFFLINE</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">AIM</div>
                    <div class="stat-value" id="aimStat">OFF</div>
                </div>
            </div>
        </div>

        <div class="nav">
            <button class="nav-btn active" onclick="switchTab('aimbot')">AIMBOT</button>
            <button class="nav-btn" onclick="switchTab('hybrid')">HYBRID</button>
            <button class="nav-btn" onclick="switchTab('aimlegit')">AIM LEGIT</button>
            <button class="nav-btn" onclick="switchTab('settings')">SETTINGS</button>
        </div>

        <!-- AIMBOT PANEL -->
        <div class="panel active" id="aimbot">
            <div class="panel-title">> AIMBOT CONTROLS</div>
            <div class="grid">
                <div class="module">
                    <div class="module-title">PLAYER SCANNER</div>
                    <div class="module-desc">Scan for players in game</div>
                    <button onclick="runCmd('aimbotscan')">SCAN NOW</button>
                    <span class="badge" id="scanStat">READY</span>
                </div>
                <div class="module">
                    <div class="module-title">AIM SELECTOR</div>
                    <div class="module-desc">Select target bone</div>
                    <select id="aimSelect">
                        <option value="off">DISABLED</option>
                        <option value="neck">NECK</option>
                        <option value="left">LEFT SHOULDER</option>
                        <option value="right">RIGHT SHOULDER</option>
                    </select>
                    <button onclick="toggleAim()" id="aimBtn">ENABLE</button>
                </div>
                <div class="module">
                    <div class="module-title">RECOIL CONTROL</div>
                    <div class="module-desc">Remove weapon recoil</div>
                    <div class="flex">
                        <button onclick="runCmd('removerecoil')">ON</button>
                        <button onclick="runCmd('addrecoil')">OFF</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- HYBRID PANEL -->
        <div class="panel" id="hybrid">
            <div class="panel-title">> HYBRID SYSTEM</div>
            <div class="grid">
                <div class="module">
                    <div class="module-title">HYBRID CONFIG</div>
                    <div class="module-desc">Configure alternating aim</div>
                    <select id="hybAim1">
                        <option value="neck">NECK</option>
                        <option value="left">LEFT SHOULDER</option>
                        <option value="right">RIGHT SHOULDER</option>
                    </select>
                    <select id="hybAim2">
                        <option value="left">LEFT SHOULDER</option>
                        <option value="neck">NECK</option>
                        <option value="right">RIGHT SHOULDER</option>
                    </select>
                    <select id="hybFreq">
                        <option value="30">30ms (FAST)</option>
                        <option value="50" selected>50ms (MEDIUM)</option>
                        <option value="80">80ms (SLOW)</option>
                    </select>
                    <button class="primary" onclick="toggleHybrid()" id="hybBtn">ACTIVATE</button>
                </div>
                <div class="module">
                    <div class="module-title">HYBRID MONITOR</div>
                    <div class="monitor">
                        <div class="monitor-row">
                            <span class="monitor-label">CURRENT</span>
                            <span class="monitor-value" id="hybCurrent">NONE</span>
                        </div>
                        <div class="monitor-row">
                            <span class="monitor-label">SWITCHES</span>
                            <span class="monitor-value" id="hybCount">0</span>
                        </div>
                        <div class="monitor-row">
                            <span class="monitor-label">STATUS</span>
                            <span class="monitor-value" id="hybState">OFF</span>
                        </div>
                    </div>
                    <button onclick="resetHybrid()">RESET</button>
                </div>
            </div>
        </div>

        <!-- AIM LEGIT PANEL -->
        <div class="panel" id="aimlegit">
            <div class="panel-title">> AIM LEGIT MODE</div>
            <div class="grid">
                <div class="module">
                    <div class="module-title">CONFIGURATION</div>
                    <div class="module-desc">Configure aim on key press</div>
                    
                    <div style="margin-bottom:15px;">
                        <div style="color:#00ff00; margin-bottom:5px; font-size:12px;">TARGET</div>
                        <select id="legitTarget" onchange="updateLegitTarget()">
                            <option value="neck">NECK</option>
                            <option value="left">LEFT SHOULDER</option>
                            <option value="right">RIGHT SHOULDER</option>
                        </select>
                    </div>
                    
                    <div style="margin-bottom:15px;">
                        <div style="color:#00ff00; margin-bottom:5px; font-size:12px;">MOUSE BUTTONS</div>
                        <select id="legitKey" onchange="updateLegitKey()">
                            <option value="xbutton1">MOUSE 4 (Back/Thumb)</option>
                            <option value="xbutton2">MOUSE 5 (Forward/Thumb)</option>
                            <option value="mouse4">MOUSE 4 (Alternate)</option>
                            <option value="mouse5">MOUSE 5 (Alternate)</option>
                            <option value="mouse1">LEFT MOUSE BUTTON</option>
                            <option value="mouse2">RIGHT MOUSE BUTTON</option>
                            <option value="mouse3">MIDDLE MOUSE BUTTON</option>
                        </select>
                    </div>
                    
                    <div style="margin-bottom:15px;">
                        <div style="color:#00ff00; margin-bottom:5px; font-size:12px;">KEYBOARD KEYS</div>
                        <select id="legitKey2" onchange="updateLegitKey()">
                            <option value="">-- SELECT KEYBOARD KEY --</option>
                            <option value="control">CONTROL</option>
                            <option value="shift">SHIFT</option>
                            <option value="alt">ALT</option>
                            <option value="capslock">CAPS LOCK</option>
                            <option value="tab">TAB</option>
                            <option value="space">SPACE</option>
                            <option value="enter">ENTER</option>
                            <option value="esc">ESCAPE</option>
                            <option value="f1">F1</option>
                            <option value="f2">F2</option>
                            <option value="f3">F3</option>
                            <option value="f4">F4</option>
                            <option value="f5">F5</option>
                            <option value="f6">F6</option>
                            <option value="f7">F7</option>
                            <option value="f8">F8</option>
                            <option value="f9">F9</option>
                            <option value="f10">F10</option>
                            <option value="f11">F11</option>
                            <option value="f12">F12</option>
                            <option value="a">A</option>
                            <option value="b">B</option>
                            <option value="c">C</option>
                            <option value="d">D</option>
                            <option value="e">E</option>
                            <option value="f">F</option>
                            <option value="g">G</option>
                            <option value="h">H</option>
                            <option value="i">I</option>
                            <option value="j">J</option>
                            <option value="k">K</option>
                            <option value="l">L</option>
                            <option value="m">M</option>
                            <option value="n">N</option>
                            <option value="o">O</option>
                            <option value="p">P</option>
                            <option value="q">Q</option>
                            <option value="r">R</option>
                            <option value="s">S</option>
                            <option value="t">T</option>
                            <option value="u">U</option>
                            <option value="v">V</option>
                            <option value="w">W</option>
                            <option value="x">X</option>
                            <option value="y">Y</option>
                            <option value="z">Z</option>
                            <option value="1">1</option>
                            <option value="2">2</option>
                            <option value="3">3</option>
                            <option value="4">4</option>
                            <option value="5">5</option>
                            <option value="6">6</option>
                            <option value="7">7</option>
                            <option value="8">8</option>
                            <option value="9">9</option>
                            <option value="0">0</option>
                        </select>
                    </div>
                    
                    <div style="margin-bottom:15px;">
                        <div style="color:#00ff00; margin-bottom:5px; font-size:12px;">MODE</div>
                        <div class="mode-selector">
                            <button class="mode-btn active" id="modeHold" onclick="setLegitMode('hold')">HOLD</button>
                            <button class="mode-btn" id="modeToggle" onclick="setLegitMode('toggle')">TOGGLE</button>
                        </div>
                    </div>
                    
                    <div class="key-bind">
                        <span>CURRENT BIND</span>
                        <span id="currentBind">MOUSE 4 (HOLD)</span>
                    </div>
                    
                    <button class="primary" onclick="testLegit()">TEST ACTIVATION</button>
                </div>
                
                <div class="module">
                    <div class="module-title">STATUS</div>
                    <div class="monitor">
                        <div class="monitor-row">
                            <span class="monitor-label">STATE</span>
                            <span class="monitor-value" id="legitState">INACTIVE</span>
                        </div>
                        <div class="monitor-row">
                            <span class="monitor-label">TARGET</span>
                            <span class="monitor-value" id="legitTargetDisplay">NECK</span>
                        </div>
                        <div class="monitor-row">
                            <span class="monitor-label">MODE</span>
                            <span class="monitor-value" id="legitModeDisplay">HOLD</span>
                        </div>
                        <div class="monitor-row">
                            <span class="monitor-label">KEY</span>
                            <span class="monitor-value" id="legitKeyDisplay">MOUSE 4</span>
                        </div>
                    </div>
                    
                    <div style="margin-top:20px; padding:10px; background:#000; border-left:3px solid #00ff00;">
                        <div style="color:#00ff00; font-size:12px;">HOLD: Press and hold to activate</div>
                        <div style="color:#00ff00; font-size:12px; margin-top:5px;">TOGGLE: Press once to enable/disable</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- SETTINGS PANEL -->
        <div class="panel" id="settings">
            <div class="panel-title">> SETTINGS</div>
            <div class="grid">
                <div class="module">
                    <div class="module-title">APPLICATION</div>
                    <div class="module-desc">Control application behavior</div>
                    
                    <div style="background:#000; padding:15px; border-radius:4px; margin-bottom:15px; border:1px solid #00ff00;">
                        <div style="color:#00ff00; margin-bottom:10px;">EXIT APPLICATION</div>
                        <div style="color:#008800; font-size:12px; margin-bottom:15px;">This will terminate the entire application.</div>
                        <button class="exit-btn" onclick="exitApplication()">TERMINATE</button>
                    </div>
                    
                    <div style="background:#000; padding:15px; border-radius:4px; border:1px solid #00ff00;">
                        <div style="color:#00ff00; margin-bottom:10px;">SYSTEM INFO</div>
                        <div style="color:#008800; font-size:12px;">Status: <span style="color:#00ff00;">Running</span></div>
                        <div style="color:#008800; font-size:12px;">Port: <span style="color:#00ff00;">8890</span></div>
                        <div style="color:#008800; font-size:12px;">URL: <span style="color:#00ff00;">http://localhost:8890</span></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TERMINAL -->
        <div class="terminal">
            <div class="terminal-header">> TERMINAL</div>
            <div class="terminal-content" id="terminal">
                <div class="log"><span class="log-time">[--:--:--]</span> GHOST-XS READY</div>
            </div>
        </div>
    </div>

    <script>
        let aimOn = false;
        let hybridOn = false;
        let hybInterval = null;
        let legitMode = 'hold';
        let legitTarget = 'neck';
        let legitKey = 'xbutton1';

        function switchTab(tab) {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
        }

        async function checkGame() {
            try {
                const r = await fetch('/status');
                const d = await r.json();
                document.getElementById('gameStat').textContent = d.status === 'online' ? 'ONLINE' : 'OFFLINE';
            } catch(e) {}
        }
        setInterval(checkGame, 3000);
        checkGame();

        function log(msg) {
            const t = document.getElementById('terminal');
            const time = new Date().toLocaleTimeString();
            t.innerHTML += `<div class="log"><span class="log-time">[${time}]</span> ${msg}</div>`;
            t.scrollTop = t.scrollHeight;
            if (t.children.length > 20) t.children[0].remove();
        }

        async function runCmd(cmd) {
            log(`> ${cmd}`);
            try {
                const r = await fetch('/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: cmd})
                });
                const d = await r.json();
                log(d.message);
                if (cmd === 'aimbotscan') document.getElementById('scanStat').textContent = 'SCANNED';
            } catch(e) {
                log('Command failed');
            }
        }

        function toggleAim() {
            const sel = document.getElementById('aimSelect');
            const btn = document.getElementById('aimBtn');
            
            if (sel.value === 'off') {
                runCmd('aimbotdisable');
                aimOn = false;
                btn.textContent = 'ENABLE';
                document.getElementById('aimStat').textContent = 'OFF';
                return;
            }
            
            aimOn = !aimOn;
            if (aimOn) {
                btn.textContent = 'DISABLE';
                document.getElementById('aimStat').textContent = 'ON';
                let cmd = sel.value === 'neck' ? 'aimbotenable' : 
                         sel.value === 'left' ? 'leftShoulderOn' : 'rightShoulderOn';
                runCmd(cmd);
            } else {
                btn.textContent = 'ENABLE';
                document.getElementById('aimStat').textContent = 'OFF';
                runCmd('aimbotdisable');
            }
        }

        async function toggleHybrid() {
            if (hybridOn) {
                await fetch('/hybrid_stop', {method: 'POST'});
                hybridOn = false;
                document.getElementById('hybBtn').textContent = 'ACTIVATE';
                document.getElementById('hybState').textContent = 'OFF';
                if (hybInterval) clearInterval(hybInterval);
                log('Hybrid stopped');
                return;
            }
            
            const a1 = document.getElementById('hybAim1').value;
            const a2 = document.getElementById('hybAim2').value;
            const f = document.getElementById('hybFreq').value;
            
            if (a1 === a2) {
                log('Error: Select different aim points');
                return;
            }
            
            const r = await fetch('/hybrid_start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({aim1: a1, aim2: a2, frequency: parseInt(f)})
            });
            
            if (r.ok) {
                hybridOn = true;
                document.getElementById('hybBtn').textContent = 'DEACTIVATE';
                document.getElementById('hybState').textContent = 'ON';
                log(`Hybrid: ${a1} + ${a2} @ ${f}ms`);
                startMonitor();
            }
        }

        function startMonitor() {
            if (hybInterval) clearInterval(hybInterval);
            hybInterval = setInterval(async () => {
                const r = await fetch('/hybrid_status');
                const d = await r.json();
                if (d.active) {
                    document.getElementById('hybCurrent').textContent = d.current?.toUpperCase() || 'NONE';
                    document.getElementById('hybCount').textContent = d.count || 0;
                }
            }, 100);
        }

        function resetHybrid() {
            document.getElementById('hybCurrent').textContent = 'NONE';
            document.getElementById('hybCount').textContent = '0';
        }

        // AIM LEGIT FUNCTIONS
        function updateLegitTarget() {
            legitTarget = document.getElementById('legitTarget').value;
            runCmd(`setLegitTarget:${legitTarget}`);
            document.getElementById('legitTargetDisplay').textContent = 
                legitTarget === 'neck' ? 'NECK' : 
                legitTarget === 'left' ? 'LEFT SHOULDER' : 'RIGHT SHOULDER';
            updateBindDisplay();
        }

        function updateLegitKey() {
            // Get value from either mouse select or keyboard select
            const mouseSelect = document.getElementById('legitKey');
            const keyboardSelect = document.getElementById('legitKey2');
            
            if (keyboardSelect.value) {
                legitKey = keyboardSelect.value;
                keyboardSelect.value = ''; // Reset after selection
            } else {
                legitKey = mouseSelect.value;
            }
            
            runCmd(`setLegitKey:${legitKey}`);
            updateBindDisplay();
        }

        function setLegitMode(mode) {
            legitMode = mode;
            document.getElementById('modeHold').classList.remove('active');
            document.getElementById('modeToggle').classList.remove('active');
            document.getElementById(`mode${mode.charAt(0).toUpperCase() + mode.slice(1)}`).classList.add('active');
            runCmd(`setLegitMode:${mode}`);
            document.getElementById('legitModeDisplay').textContent = mode.toUpperCase();
            updateBindDisplay();
        }

        function updateBindDisplay() {
            const keyNames = {
                'xbutton1': 'MOUSE 4 (Back)',
                'xbutton2': 'MOUSE 5 (Forward)',
                'mouse4': 'MOUSE 4',
                'mouse5': 'MOUSE 5',
                'mouse1': 'LEFT MOUSE',
                'mouse2': 'RIGHT MOUSE',
                'mouse3': 'MIDDLE MOUSE',
                'control': 'CTRL',
                'shift': 'SHIFT',
                'alt': 'ALT',
                'capslock': 'CAPS LOCK',
                'tab': 'TAB',
                'space': 'SPACE',
                'enter': 'ENTER',
                'esc': 'ESCAPE',
                'f1': 'F1', 'f2': 'F2', 'f3': 'F3', 'f4': 'F4',
                'f5': 'F5', 'f6': 'F6', 'f7': 'F7', 'f8': 'F8',
                'f9': 'F9', 'f10': 'F10', 'f11': 'F11', 'f12': 'F12'
            };
            const displayName = keyNames[legitKey] || legitKey.toUpperCase();
            document.getElementById('currentBind').textContent = `${displayName} (${legitMode.toUpperCase()})`;
            document.getElementById('legitKeyDisplay').textContent = displayName;
        }

        async function testLegit() {
            log('> Testing Aim Legit...');
            const r = await fetch('/aimlegit_toggle', {method: 'POST'});
            const d = await r.json();
            log(d.message);
            updateLegitState();
        }

        async function updateLegitState() {
            try {
                const r = await fetch('/aimlegit_status');
                const d = await r.json();
                document.getElementById('legitState').textContent = d.active ? 'ACTIVE' : 'INACTIVE';
            } catch(e) {}
        }
        setInterval(updateLegitState, 500);

        async function exitApplication() {
            if (confirm('Terminate GHOST-XS?')) {
                log('> TERMINATING...');
                await fetch('/shutdown', {method: 'POST'});
                document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#000;color:#00ff00;font-family:monospace;"><h1>GHOST-XS TERMINATED</h1></div>';
            }
        }

        window.onload = () => {
            log('System ready');
            log('Aim Legit: Select mouse/keyboard button');
            updateLegitState();
            updateBindDisplay();
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
            return '''<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:#00ff00;text-align:center;">ACCESS DENIED<br><a href="/" style="color:#00ff00;">RETRY</a></div>'''

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
    
    # Aim Legit commands
    if cmd.startswith('setlegittarget:'):
        target = cmd.split(':')[1]
        msg = set_aim_legit_target(target)
    elif cmd.startswith('setlegitkey:'):
        key = cmd.split(':')[1]
        msg = set_aim_legit_key(key)
    elif cmd.startswith('setlegitmode:'):
        mode = cmd.split(':')[1]
        msg = set_aim_legit_mode(mode)
    elif cmd == 'aimlegit_toggle':
        msg = aim_legit_toggle()
    # Regular commands
    elif cmd == 'aimbotscan':
        msg = HEADLOAD()
    elif cmd == 'aimbotenable':
        msg = HEADON()
    elif cmd == 'aimbotdisable':
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
        msg = f"Unknown: {cmd}"
    
    return jsonify({"message": msg})

@app.route('/aimlegit_status', methods=['GET'])
def aimlegit_status():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify(aim_legit_status())

@app.route('/aimlegit_toggle', methods=['POST'])
def aimlegit_toggle():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    msg = aim_legit_toggle()
    return jsonify({'message': msg, 'active': aim_legit_active})

@app.route('/hybrid_start', methods=['POST'])
def hybrid_start():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    global hybrid_active, hybrid_aim1, hybrid_aim2, hybrid_frequency
    global hybrid_current, hybrid_count, hybrid_last_switch
    
    data = request.get_json()
    a1 = data.get('aim1')
    a2 = data.get('aim2')
    freq = data.get('frequency', 50)
    
    if a1 == a2:
        return jsonify({'error': 'Same aim points'}), 400
    
    hybrid_active = True
    hybrid_aim1 = a1
    hybrid_aim2 = a2
    hybrid_frequency = freq
    hybrid_current = a1
    hybrid_count = 0
    hybrid_last_switch = datetime.now()
    
    if a1 == 'neck':
        HEADON()
    elif a1 == 'left':
        LEFTSHOULDERON()
    elif a1 == 'right':
        RIGHTSHOULDERON()
    
    return jsonify({'message': 'Hybrid started'})

@app.route('/hybrid_stop', methods=['POST'])
def hybrid_stop():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    global hybrid_active, hybrid_count
    hybrid_active = False
    HEADOFF()
    cnt = hybrid_count
    hybrid_count = 0
    return jsonify({'message': 'Hybrid stopped', 'switches': cnt})

@app.route('/hybrid_status', methods=['GET'])
def hybrid_status():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    return jsonify({
        'active': hybrid_active,
        'current': hybrid_current,
        'count': hybrid_count,
        'freq': hybrid_frequency
    })

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        os._exit(0)
    else:
        func()
    return jsonify({'message': 'Shutting down'})

# Hybrid background thread
def hybrid_loop():
    global hybrid_active, hybrid_current, hybrid_count, hybrid_last_switch
    while True:
        if hybrid_active and hybrid_last_switch:
            now = datetime.now()
            diff = (now - hybrid_last_switch).total_seconds() * 1000
            if diff >= hybrid_frequency:
                new = hybrid_aim2 if hybrid_current == hybrid_aim1 else hybrid_aim1
                
                if new == 'neck':
                    HEADON()
                elif new == 'left':
                    LEFTSHOULDERON()
                elif new == 'right':
                    RIGHTSHOULDERON()
                
                hybrid_current = new
                hybrid_last_switch = now
                hybrid_count += 1
        time.sleep(0.01)

# Keyboard hook thread
def keyboard_hook_thread():
    try:
        import keyboard
        def on_key_event(e):
            if e.event_type == 'down':
                if e.name == aim_legit_key:
                    if aim_legit_mode == 'hold':
                        aim_legit_activate()
                    else:
                        aim_legit_toggle()
            elif e.event_type == 'up':
                if e.name == aim_legit_key and aim_legit_mode == 'hold':
                    aim_legit_deactivate()
        
        keyboard.hook(on_key_event)
        keyboard.wait()
    except:
        while True:
            time.sleep(1)

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
    # Start threads
    t1 = threading.Thread(target=hybrid_loop, daemon=True)
    t1.start()
    
    t2 = threading.Thread(target=keyboard_hook_thread, daemon=True)
    t2.start()
    
    ip = get_ip()
    
    print("=" * 50)
    print("GHOST-XS HACKER EDITION")
    print("=" * 50)
    print(f"Local URL:  http://localhost:8890")
    print(f"Network URL: http://{ip}:8890")
    print(f"PyMem:      {'ACTIVE' if PYMEM_OK else 'SIMULATED'}")
    print(f"Aim Legit:  READY (All mouse/keyboard buttons)")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=8890, debug=False, threaded=True)