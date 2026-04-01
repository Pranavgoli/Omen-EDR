# 🕵️‍♂️ Omen KLD (Keylogger Detector) v0.1

**Omen KLD v0.1** is an experimental high-fidelity Windows, Linux, and macOS process monitor. It combines real-time forensics with advanced heuristics to detect potential keylogging activity, hidden payloads, and suspicious system behavior across the entire filesystem.

---

## 🛡️ Security & OWASP 2025 Compliance
This project has been hardened to meet the **OWASP Top 10:2025** security standards:
- **A01:2025 (Access Control)**: Secure Session Handshake prevents unauthorized local API calls.
*   **A03:2025 (Supply Chain)**: Fully pinned and audited dependencies (Starlette/FastAPI) to prevent "Dependency Confusion" attacks.
*   **A06:2025 (Insecure Design)**: Hard-coded kernel protections for critical Windows processes (System, Idle, MemCompression).
*   **A10:2025 (Exceptional Conditions)**: Structured security error codes to prevent system data leakage.

---

## 📸 Dashboard Preview & Features
# OS
.DS_Store
Thumbs.db
.env.local
.env.*.local
- **Real-time Monitoring**: Live CPU/RAM/Disk stats and process threads.
- **Deep Path Heuristics**: Automatic flagging of processes in root directories (e.g., `C:\`), `ProgramData`, `Public` folders, and Unix `/tmp` or `/dev/shm`.
- **Targeted Forensics**: Analysis of Shell Execution Chains (Python/Bash/PS) to detect hidden scripts.
- **Security Handshake**: OWASP A01:2025 compliant local-only WebSocket authentication.
- **Network Telemetry**: Track which processes are opening active network sockets.
- **One-Click Quarantine**: Securely terminate non-critical suspicious processes.

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ (for frontend development)
- **Windows Administrator Privileges** (required for process scanning)

### 2. Quick Launch

#### Windows
Run the provided `start_tool.py` script as Administrator.
```powershell
python start_tool.py
```

#### Linux / macOS
Run the script with `sudo` to allow process memory and path scanning.
```bash
sudo python3 start_tool.py
```

---

## 🔍 Simulation / Verification Drill
You can safely test the detection engine without running real malware:
1.  **Critical Path Check**: Move any binary (like `python.exe`) to your **C:\ Root** or **%TEMP%** folder.
2.  **Execution Check**: Run the binary from that location.
3.  **Alert**: Refresh the Omen KLD dashboard. You should see a **Threat Score of 50+** flagged as "Running from Drive Root" or "Suspicious Path".

---

## ⚠️ Legal Disclaimer
**THIS TOOL IS FOR EDUCATIONAL AND DEFENSIVE RESEARCH PURPOSES ONLY.**

Neither the author nor the contributors are responsible for any misuse, damage, or legal consequences resulting from the use of this software. By using this tool, you agree to always act within the scope of local and international laws. **NEVER use this tool on a computer you do not own.**

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
