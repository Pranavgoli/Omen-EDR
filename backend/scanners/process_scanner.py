import psutil
import os
import sys

# Platform detection
IS_WINDOWS = os.name == 'nt'
IS_MACOS = sys.platform == 'darwin'
IS_LINUX = sys.platform.startswith('linux')

# Conditional imports for Windows
if IS_WINDOWS:
    try:
        import win32api
    except ImportError:
        pass

# Cache verified publishers to avoid re-hashing/re-verifying known files every 5s
verified_cache = {}

# OWASP A06:2025 - Insecure Design Prevention
# Hard-coded whitelist of processes that MUST NOT be terminated
PROTECTED_PIDS = {0, 4} # Idle, System
PROTECTED_NAMES = {
    "system", "idle", "registry", "smss.exe", "csrss.exe", 
    "wininit.exe", "services.exe", "lsass.exe", "memcompression",
    "winlogon.exe", "fontdrvhost.exe", "dwm.exe"
}

def is_verified_publisher(file_path):
    # Skip if missing
    if not file_path or not os.path.exists(file_path):
        return False
        
    if file_path in verified_cache:
        return verified_cache[file_path]

    try:
        # Check actual file metadata first if possible (Windows only)
        if IS_WINDOWS:
            try:
                import win32api
                lang, codepage = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')[0]
                str_info = u'\\StringFileInfo\\%04X%04X\\CompanyName' % (lang, codepage)
                company = win32api.GetFileVersionInfo(file_path, str_info)
                if company and len(company) > 1:
                    # A non-empty company string from the PE headers implies a legitimate build process
                    verified_cache[file_path] = True
                    return True
            except Exception:
                pass
        
        # macOS specific verification (rudimentary check for now)
        if IS_MACOS:
            if "/System/Library/" in file_path or "/Applications/" in file_path:
                verified_cache[file_path] = True
                return True
        
        # Linux specific verification (rudimentary check for now)
        if IS_LINUX:
            if "/usr/bin/" in file_path or "/bin/" in file_path or "/lib/" in file_path:
                verified_cache[file_path] = True
                return True
            
        # Fallback rudimentary checking
        lower_path = file_path.lower()

        # Hard whitelists (OS core)
        if IS_WINDOWS:
            if "c:\\windows\\system32" in lower_path or "c:\\windows\\syswow64" in lower_path:
                verified_cache[file_path] = True
                return True
            # Trust Program Files directories as they require privileges to install
            if "program files" in lower_path or "programdata" in lower_path or "windows" in lower_path:
                verified_cache[file_path] = True
                return True

        # Quick check for known trusted paths
        verified_cache[file_path] = False
        return False
    except Exception:
        return False


def get_threat_score_and_evidence(process_info):
    score = 0
    evidence = []

    name_lower = process_info.get("name") or "unknown"
    if not isinstance(name_lower, str): name_lower = "unknown"
    name_lower = name_lower.lower()
    
    path = process_info.get("exe") or ""
    if not isinstance(path, str): path = ""
    path_lower = path.lower()
    
    cmdline = process_info.get("cmdline") or []
    if not isinstance(cmdline, list): cmdline = []
    
    cwd = process_info.get("cwd") or ""
    if not isinstance(cwd, str): cwd = ""
    cwd = cwd.lower()
    
    connections = process_info.get("connections") or []
    if not isinstance(connections, list): connections = []
    
    # 1. Path Anomaly (Deep Path Heuristics & OS Specific)
    
    # Windows Critical Root Check (C:\)
    if IS_WINDOWS:
        if path_lower.startswith("c:\\") and "\\" not in path_lower[3:]:
            score += 40
            evidence.append("Running from Drive Root (C:\) (+40)")
        if "users\\public" in path_lower:
            score += 30
            evidence.append("Running from Public Folder (+30)")
        if "programdata" in path_lower and "microsoft" not in path_lower:
             score += 30
             evidence.append("Running from ProgramData (+30)")

    # General Suspicious Paths (All OS)
    suspicious_keywords = ["temp", "tmp", "appdata"]
    if IS_LINUX or IS_MACOS:
        suspicious_keywords += ["/tmp", "/dev/shm", "/var/tmp", ".local/bin"]
    
    if any(k in path_lower for k in suspicious_keywords) or any(k in cwd for k in suspicious_keywords):
        score += 50
        evidence.append(f"Running from/in Suspicious Path (+50)")

    # 2. Network Activity
    if len(connections) > 0:
        # Keyloggers often exfiltrate, but so do browsers.
        if not is_verified_publisher(path):
            score += 20
            evidence.append(f"Network Socket Open ({len(connections)}) (+20)")

    # 3. Unsigned / Non-Verified
    if path and not is_verified_publisher(path):
        score += 15
        evidence.append("Publisher not verified (+15)")

    # 4. Parent-Child Suspicion (Shell execution chain)
    shell_names = ["python", "cmd.exe", "powershell.exe", "bash", "sh", "zsh"]
    if any(s in name_lower for s in shell_names):
        if len(cmdline) > 1 and any(k in str(cmdline).lower() for k in suspicious_keywords):
            score += 50
            evidence.append(f"Suspicious Shell execution chain (+50)")

    # 5. Process Hollowing/Ghosting Check (Windows Specific primarily)
    if IS_WINDOWS and path and os.path.exists(path):
        actual_name = os.path.basename(path).lower()
        if actual_name != name_lower:
            score += 80
            evidence.append(f"Masquerading detected! logical name '{name_lower}' != actual payload '{actual_name}' (+80)")

    return score, evidence


def get_threat_analysis(score, path, name):
    if score == 0:
        return "Benign"
    
    path_lower = str(path).lower()
    name_lower = str(name).lower()
    
    # Common False Positives (IDE, browser, standard services)
    # BUT: If it's running from Temp/AppData with a high score, it's NOT a false positive anymore.
    is_dev_tool = "code.exe" in name_lower or "cursor.exe" in name_lower or "antigravity" in name_lower \
                  or "language_server" in name_lower or "python" in name_lower or "chrome.exe" in name_lower or "node" in name_lower
    
    if is_dev_tool and score < 40:
        return "False Positive (Known Developer/System Tool)"

    if score >= 50:
        return "Critical Threat (True Positive Candidate)"
    
    return "Suspicious (Requires Review)"


def run_full_scan():
    cpu_usage = psutil.cpu_percent(interval=0)
    ram_usage = psutil.virtual_memory().percent
    
    disk_path = "C:\\" if os.name == 'nt' else "/"
    disk_usage = psutil.disk_usage(disk_path).percent

    scanned_processes = []
    total_threads = 0

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'memory_info', 'connections', 'num_threads', 'cwd']):
        try:
            info = proc.info
            
            threads = info.get('num_threads', 0)
            if threads:
                total_threads += threads
                
            # Basic stats
            mem_mb = info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0
            
            # Score
            score, evidence = get_threat_score_and_evidence(info)
            
            # If the process is incredibly safe and uses barely any memory, we don't need to bloat the WS feed
            # But for the dashboard we want to show a decent list. Let's send the top 100 or those with scores > 0
            
            # Scoring
            score, evidence = get_threat_score_and_evidence(info)
            
            # OWASP A06:2025 Protection Flag
            is_protected = (
                info['pid'] in PROTECTED_PIDS or 
                (info['name'] and info['name'].lower() in PROTECTED_NAMES)
            )
            
            proc_dict = {
                "pid": info['pid'],
                "name": info['name'] or "Unknown",
                "path": info['exe'] or "Access Denied",
                "threads": threads,
                "memory_mb": round(mem_mb, 1),
                "connections_count": len(info['connections']) if info['connections'] else 0,
                "threat_score": score,
                "is_protected": is_protected,
                "evidence": evidence,
                "analysis": get_threat_analysis(score, info['exe'] or "", info['name'] or "")
            }
            
            scanned_processes.append(proc_dict)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            # Log unexpected errors so we don't fail silently
            print(f"[ERROR] Scanning process {getattr(proc, 'pid', 'unknown')}: {e}")
            continue
            
    # Sort by threat score descending
    scanned_processes.sort(key=lambda x: x['threat_score'], reverse=True)

    return {
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "disk_usage": disk_usage,
        "total_threads": total_threads,
        "processes": scanned_processes
    }


def kill_process(pid):
    # OWASP A06:2025 & A10:2025 - Defense in Depth
    if pid in PROTECTED_PIDS:
        return False, "ERR_SYSTEM_PROTECTED: This is a core Windows process and cannot be terminated."
        
    try:
        proc = psutil.Process(pid)
        name = proc.name().lower()
        
        if name in PROTECTED_NAMES:
            return False, f"ERR_SYSTEM_PROTECTED: '{name}' is a protected system component."

        proc.terminate()
        return True, f"Process {pid} ({name}) terminated successfully."
        
    except psutil.NoSuchProcess:
        return False, "ERR_PROCESS_NOT_FOUND: The process is no longer running."
    except psutil.AccessDenied:
        return False, "ERR_ACCESS_DENIED: Insufficient privileges to terminate this process. It may be a System-Protected process."
    except Exception as e:
        return False, f"ERR_INTERNAL: {str(e)}"
