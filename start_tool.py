import os
import sys
import ctypes
import subprocess

def is_admin():
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        # Linux/macOS
        return os.getuid() == 0

def run_as_admin():
    if os.name == 'nt':
        print("Requesting Administrator privileges...")
        script = os.path.abspath(sys.argv[0])
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
        if int(ret) <= 32:
            print("Failed to get admin privileges. The tool requires it to scan processes properly.")
            sys.exit(1)
        sys.exit(0)
    else:
        print("Error: This tool must be run with sudo on Linux/macOS.")
        print("Example: sudo python3 start_tool.py")
        sys.exit(1)

def main():
    if not is_admin():
        run_as_admin()

    print("[+] Administrator privileges confirmed.")
    print("[+] Setting up Keylogger Detection Tool environment...")
    
    # Move to the current script directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_dir)

    # Setup Python venv
    venv_dir = os.path.join(base_dir, "venv")
    if not os.path.exists(venv_dir):
        print("[+] Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "venv"])
    else:
        print("[+] Virtual environment already exists.")

    # Paths to the venv python
    if os.name == 'nt':
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
        venv_pip = os.path.join(venv_dir, "Scripts", "pip.exe")
    else:
        venv_python = os.path.join(venv_dir, "bin", "python")
        venv_pip = os.path.join(venv_dir, "bin", "pip")

    # Install requirements
    req_file = os.path.join(base_dir, "backend", "requirements.txt")
    print("[+] Installing backend dependencies from requirements.txt...")
    subprocess.run([venv_pip, "install", "-r", req_file, "--quiet"])
    print("[+] Backend dependencies installed.")

    # Check for frontend node_modules, install if missing
    frontend_dir = os.path.join(base_dir, "frontend")
    node_modules_dir = os.path.join(frontend_dir, "node_modules")
    if os.path.exists(frontend_dir) and not os.path.exists(node_modules_dir):
         if os.path.exists(os.path.join(frontend_dir, "package.json")):
             print("[+] Installing frontend dependencies (npm install)...")
             npm_cmd = "npm.cmd" if os.name == 'nt' else "npm"
             subprocess.run([npm_cmd, "install"], cwd=frontend_dir, shell=(os.name == 'nt'))

    print("\n" + "="*50)
    print("   ENVIRONMENT READY. STARTING SERVICES")
    print("="*50 + "\n")

    # Start FastAPI Backend
    # Popen so it runs non-blocking
    print("[+] Starting FastAPI Backend on ws://localhost:8192")
    backend = subprocess.Popen([venv_python, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8192"])

    # Start Vite Frontend if initialized
    if os.path.exists(os.path.join(frontend_dir, "package.json")):
        print("[+] Starting Vite Development Server...")
        npm_cmd = "npm.cmd" if os.name == 'nt' else "npm"
        frontend = subprocess.Popen([npm_cmd, "run", "dev"], cwd=frontend_dir, shell=(os.name == 'nt'))

    print("\n[!] PRESS CTRL+C TO STOP ALL SERVICES [!]\n")

    try:
        backend.wait()
        if 'frontend' in locals():
            frontend.wait()
    except KeyboardInterrupt:
        print("\n[-] Shutting down services...")
        backend.terminate()
        if 'frontend' in locals():
            frontend.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
