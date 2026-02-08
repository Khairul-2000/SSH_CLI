#!/usr/bin/env python3
"""
SSH Transfer System - Command Line Interface
Cross-platform file and message transfer tool
"""

import paramiko
import os
import sys
import json
import argparse
import getpass
from pathlib import Path
import subprocess
import platform
import socket

class SSHTransfer:
    def __init__(self):
        self.ssh_client = None
        self.sftp_client = None
        self.config_file = Path.home() / ".ssh_transfer_config.json"

    def _is_port_open(self, host, port, timeout=5):
        """Quick TCP reachability check to give actionable errors."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def load_config(self):
        """Load saved configuration"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_config(self, config):
        """Save configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Configuration saved to {self.config_file}")
    
    def connect(self, host, username, port=22, password=None, key_file=None):
        """Connect to SSH server"""
        try:
            if not host or not username:
                print("✗ Host and username are required")
                return False

            if not self._is_port_open(host, port):
                print(f"✗ Cannot reach {host}:{port}")
                print("  Common causes:")
                print("  - SSH server is not running on the target machine")
                print("  - Firewall is blocking the port")
                print("  - Wrong IP/port (default SSH port is 22)")
                print("  - Target is not reachable from this network")
                return False

            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if key_file:
                print(f"Connecting to {username}@{host}:{port} using key file...")
                self.ssh_client.connect(
                    host,
                    port=port,
                    username=username,
                    key_filename=os.path.expanduser(key_file),
                    timeout=10,
                    banner_timeout=10,
                    auth_timeout=10,
                    look_for_keys=False,
                    allow_agent=False,
                )
            elif password:
                print(f"Connecting to {username}@{host}:{port} using password...")
                self.ssh_client.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=10,
                    banner_timeout=10,
                    auth_timeout=10,
                    look_for_keys=False,
                    allow_agent=False,
                )
            else:
                # Try to use default SSH keys
                print(f"Connecting to {username}@{host}:{port} using default keys...")
                self.ssh_client.connect(
                    host,
                    port=port,
                    username=username,
                    timeout=10,
                    banner_timeout=10,
                    auth_timeout=10,
                )

            self.sftp_client = self.ssh_client.open_sftp()
            print("✓ Connected successfully!")
            return True
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from SSH server"""
        if self.sftp_client:
            self.sftp_client.close()
        if self.ssh_client:
            self.ssh_client.close()
        print("✓ Disconnected")
    
    def upload(self, local_file, remote_path):
        """Upload file to remote server"""
        if not self.sftp_client:
            print("✗ Not connected to server")
            return False
        
        try:
            if not os.path.exists(local_file):
                print(f"✗ Local file not found: {local_file}")
                return False
            
            file_size = os.path.getsize(local_file)
            print(f"Uploading {local_file} ({file_size} bytes) to {remote_path}...")
            
            self.sftp_client.put(local_file, remote_path)
            print(f"✓ Upload complete: {remote_path}")
            return True
        except Exception as e:
            print(f"✗ Upload failed: {e}")
            return False

    def upload_dir(self, local_dir, remote_dir):
        """Upload directory recursively to remote server"""
        if not self.sftp_client:
            print("✗ Not connected to server")
            return False

        if not os.path.isdir(local_dir):
            print(f"✗ Local directory not found: {local_dir}")
            return False

        local_dir = os.path.abspath(local_dir)
        remote_dir = remote_dir.rstrip("/") or "."

        def ensure_remote_dir(path):
            try:
                self.sftp_client.stat(path)
            except IOError:
                parent = os.path.dirname(path.rstrip("/"))
                if parent and parent not in [".", "/"]:
                    ensure_remote_dir(parent)
                try:
                    self.sftp_client.mkdir(path)
                except IOError:
                    pass

        try:
            print(f"Uploading directory {local_dir} to {remote_dir}...")
            ensure_remote_dir(remote_dir)

            for root, dirs, files in os.walk(local_dir):
                rel = os.path.relpath(root, local_dir)
                rel = "" if rel == "." else rel
                remote_root = remote_dir if not rel else f"{remote_dir}/{rel}"
                ensure_remote_dir(remote_root)

                for d in dirs:
                    ensure_remote_dir(f"{remote_root}/{d}")

                for f in files:
                    local_path = os.path.join(root, f)
                    remote_path = f"{remote_root}/{f}"
                    self.sftp_client.put(local_path, remote_path)

            print(f"✓ Directory upload complete: {remote_dir}")
            return True
        except Exception as e:
            print(f"✗ Directory upload failed: {e}")
            return False
    
    def download(self, remote_file, local_path):
        """Download file from remote server"""
        if not self.sftp_client:
            print("✗ Not connected to server")
            return False
        
        try:
            print(f"Downloading {remote_file} to {local_path}...")
            self.sftp_client.get(remote_file, local_path)
            print(f"✓ Download complete: {local_path}")
            return True
        except Exception as e:
            print(f"✗ Download failed: {e}")
            return False

    def download_dir(self, remote_dir, local_dir):
        """Download directory recursively from remote server"""
        if not self.sftp_client:
            print("✗ Not connected to server")
            return False

        local_dir = os.path.abspath(local_dir)

        def is_dir(path):
            try:
                return paramiko.S_ISDIR(self.sftp_client.stat(path).st_mode)
            except Exception:
                return False

        if not is_dir(remote_dir):
            print(f"✗ Remote directory not found: {remote_dir}")
            return False

        try:
            print(f"Downloading directory {remote_dir} to {local_dir}...")
            os.makedirs(local_dir, exist_ok=True)

            def walk(rdir, ldir):
                os.makedirs(ldir, exist_ok=True)
                for item in self.sftp_client.listdir_attr(rdir):
                    rpath = f"{rdir.rstrip('/')}/{item.filename}"
                    lpath = os.path.join(ldir, item.filename)
                    if paramiko.S_ISDIR(item.st_mode):
                        walk(rpath, lpath)
                    else:
                        self.sftp_client.get(rpath, lpath)

            walk(remote_dir, local_dir)
            print(f"✓ Directory download complete: {local_dir}")
            return True
        except Exception as e:
            print(f"✗ Directory download failed: {e}")
            return False
    
    def execute(self, command):
        """Execute command on remote server"""
        if not self.ssh_client:
            print("✗ Not connected to server")
            return False
        
        try:
            print(f"Executing: {command}")
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            if output:
                print("\n--- Output ---")
                print(output)
            
            if error:
                print("\n--- Error ---")
                print(error)
            
            return True
        except Exception as e:
            print(f"✗ Command execution failed: {e}")
            return False
    
    def send_message(self, message, remote_file):
        """Write message to remote file"""
        if not self.sftp_client:
            print("✗ Not connected to server")
            return False
        
        try:
            print(f"Writing message to {remote_file}...")
            with self.sftp_client.file(remote_file, 'w') as f:
                f.write(message)
            print(f"✓ Message saved to {remote_file}")
            return True
        except Exception as e:
            print(f"✗ Failed to write message: {e}")
            return False
    
    def list_remote(self, path='.'):
        """List files in remote directory"""
        if not self.sftp_client:
            print("✗ Not connected to server")
            return False
        
        try:
            print(f"Listing: {path}")
            files = self.sftp_client.listdir_attr(path)
            
            print("\n{:<40} {:>10} {}".format("Name", "Size", "Permissions"))
            print("-" * 60)
            
            for f in files:
                size = f.st_size if f.st_size else 0
                perms = oct(f.st_mode)[-3:] if f.st_mode else '---'
                print("{:<40} {:>10} {}".format(f.filename, size, perms))
            
            return True
        except Exception as e:
            print(f"✗ Failed to list directory: {e}")
            return False

def generate_ssh_key():
    """Generate SSH key pair"""
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(exist_ok=True)
    key_path = ssh_dir / "id_rsa_transfer"
    
    if key_path.exists():
        response = input(f"Key already exists at {key_path}. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Cancelled")
            return
    
    try:
        print("Generating SSH key pair...")
        cmd = ['ssh-keygen', '-t', 'rsa', '-b', '4096', '-f', str(key_path), '-N', '']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✓ SSH key generated successfully!")
            print(f"  Private key: {key_path}")
            print(f"  Public key: {key_path}.pub")
            print("\nPublic key content:")
            with open(f"{key_path}.pub", 'r') as f:
                print(f.read())
        else:
            print(f"✗ Failed to generate key: {result.stderr}")
    except Exception as e:
        print(f"✗ Error: {e}")

def check_ssh():
    """Check SSH installation"""
    system = platform.system()
    
    try:
        if system == "Windows":
            result = subprocess.run(['where', 'ssh'], capture_output=True, text=True)
        else:
            result = subprocess.run(['which', 'ssh'], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✓ SSH client is installed at: {result.stdout.strip()}")
            version = subprocess.run(['ssh', '-V'], capture_output=True, text=True)
            print(f"  Version: {version.stderr.strip()}")
            return True
        else:
            print("✗ SSH client is not installed")
            return False
    except Exception as e:
        print(f"✗ Error checking SSH: {e}")
        return False

def check_ssh_server():
    """Check if SSH server is installed and running"""
    system = platform.system()
    
    try:
        if system == "Windows":
            # Check for OpenSSH Server on Windows
            result = subprocess.run(['sc', 'query', 'sshd'], capture_output=True, text=True)
            return 'RUNNING' in result.stdout
        else:
            # Check for SSH server on Linux/Mac
            result = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
            if result.returncode == 0:
                return True
            # Try sshd for some distros
            result = subprocess.run(['systemctl', 'is-active', 'sshd'], capture_output=True, text=True)
            return result.returncode == 0
    except Exception as e:
        return False

def configure_ssh_port(port):
    """Configure SSH to listen on custom port"""
    if port == 22:
        return True
    
    print(f"\nConfiguring SSH to listen on port {port}...")
    
    try:
        system = platform.system()
        
        if system == "Linux":
            # Backup original config
            subprocess.run(['sudo', 'cp', '/etc/ssh/sshd_config', '/etc/ssh/sshd_config.backup'], check=True)
            
            # Add custom port to SSH config
            config_line = f"Port {port}\n"
            
            # Check if Port directive exists
            result = subprocess.run(['grep', '^Port', '/etc/ssh/sshd_config'], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Port already configured, update it
                subprocess.run(['sudo', 'sed', '-i', f's/^Port .*/Port {port}/', '/etc/ssh/sshd_config'], check=True)
            else:
                # Add Port directive
                subprocess.run(['sudo', 'sh', '-c', f'echo "Port {port}" >> /etc/ssh/sshd_config'], check=True)
            
            # Restart SSH service
            ssh_service = 'ssh' if os.path.exists('/lib/systemd/system/ssh.service') else 'sshd'
            subprocess.run(['sudo', 'systemctl', 'restart', ssh_service], check=True)
            
            # Configure firewall
            try:
                # Check if ufw is active
                ufw_status = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
                if 'Status: active' in ufw_status.stdout:
                    subprocess.run(['sudo', 'ufw', 'allow', f'{port}/tcp'], check=True)
                    print(f"✓ Firewall configured to allow port {port}")
            except:
                pass
            
            print(f"✓ SSH configured to listen on port {port}")
            return True
            
        elif system == "Darwin":
            # macOS - edit plist or sshd_config
            subprocess.run(['sudo', 'sed', '-i', '.bak', f's/#Port 22/Port {port}/', '/etc/ssh/sshd_config'], check=True)
            subprocess.run(['sudo', 'launchctl', 'stop', 'com.openssh.sshd'], check=False)
            subprocess.run(['sudo', 'launchctl', 'start', 'com.openssh.sshd'], check=False)
            print(f"✓ SSH configured to listen on port {port}")
            return True
            
        elif system == "Windows":
            # Windows - edit sshd_config
            config_path = r'C:\ProgramData\ssh\sshd_config'
            subprocess.run(['powershell', '-Command', 
                          f'(Get-Content {config_path}) -replace "^#?Port 22", "Port {port}" | Set-Content {config_path}'],
                          check=True, shell=True)
            subprocess.run(['powershell', '-Command', 'Restart-Service sshd'], check=True, shell=True)
            print(f"✓ SSH configured to listen on port {port}")
            return True
            
    except Exception as e:
        print(f"⚠ Could not configure custom port automatically: {e}")
        print(f"\nManual configuration required:")
        print(f"1. Edit /etc/ssh/sshd_config")
        print(f"2. Add or change: Port {port}")
        print(f"3. Restart SSH: sudo systemctl restart ssh")
        print(f"4. Allow firewall: sudo ufw allow {port}/tcp")
        return False
    
    return True

def install_ssh_auto(port=22):
    """Automatically install SSH with user permission"""
    system = platform.system()
    
    print("\n" + "="*60)
    print("SSH Server Not Found")
    print("="*60)
    
    # Check if SSH server is running
    if check_ssh_server():
        print("✓ SSH server is already installed and running!")
        if port != 22:
            response = input(f"\nDo you want to configure SSH to use port {port}? (y/n): ").strip().lower()
            if response == 'y':
                return configure_ssh_port(port)
        return True
    
    print("\nSSH server is required to accept incoming connections.")
    print("This script can automatically install it for you.")
    
    if port != 22:
        print(f"Note: Will configure SSH to listen on port {port}")
    
    response = input("\nDo you want to install SSH server now? (y/n): ").strip().lower()
    
    if response != 'y':
        print("Installation cancelled. You can install SSH manually:")
        print_install_instructions()
        return False
    
    print("\nInstalling SSH server...")
    print("You may be prompted for your sudo password.\n")
    
    try:
        if system == "Linux":
            # Detect distro
            distro = None
            if os.path.exists('/etc/debian_version'):
                distro = 'debian'
            elif os.path.exists('/etc/redhat-release'):
                distro = 'redhat'
            elif os.path.exists('/etc/arch-release'):
                distro = 'arch'
            
            if distro == 'debian':
                # Ubuntu/Debian
                print("Detected Debian/Ubuntu system")
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'install', '-y', 'openssh-server'], check=True)
                subprocess.run(['sudo', 'systemctl', 'start', 'ssh'], check=True)
                subprocess.run(['sudo', 'systemctl', 'enable', 'ssh'], check=True)
                
                # Configure firewall if ufw is active
                ufw_status = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
                if 'Status: active' in ufw_status.stdout:
                    print("\nConfiguring firewall...")
                    subprocess.run(['sudo', 'ufw', 'allow', '22/tcp'], check=True)
                
            elif distro == 'redhat':
                # Fedora/RHEL/CentOS
                print("Detected RedHat-based system")
                subprocess.run(['sudo', 'dnf', 'install', '-y', 'openssh-server'], check=True)
                subprocess.run(['sudo', 'systemctl', 'start', 'sshd'], check=True)
                subprocess.run(['sudo', 'systemctl', 'enable', 'sshd'], check=True)
                subprocess.run(['sudo', 'firewall-cmd', '--permanent', '--add-service=ssh'], check=False)
                subprocess.run(['sudo', 'firewall-cmd', '--reload'], check=False)
                
            elif distro == 'arch':
                # Arch Linux
                print("Detected Arch Linux system")
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', 'openssh'], check=True)
                subprocess.run(['sudo', 'systemctl', 'start', 'sshd'], check=True)
                subprocess.run(['sudo', 'systemctl', 'enable', 'sshd'], check=True)
                
            else:
                print("✗ Could not detect Linux distribution")
                print_install_instructions()
                return False
            
        elif system == "Darwin":
            # macOS
            print("Detected macOS")
            print("Enabling Remote Login...")
            subprocess.run(['sudo', 'systemsetup', '-setremotelogin', 'on'], check=True)
            
        elif system == "Windows":
            # Windows
            print("Detected Windows")
            print("Installing OpenSSH Server...")
            subprocess.run(['powershell', '-Command', 
                          'Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0'], 
                          check=True, shell=True)
            subprocess.run(['powershell', '-Command', 
                          'Start-Service sshd'], check=True, shell=True)
            subprocess.run(['powershell', '-Command', 
                          'Set-Service -Name sshd -StartupType Automatic'], 
                          check=True, shell=True)
        
        print("\n" + "="*60)
        print("✓ SSH server installed and started successfully!")
        print("="*60)
        
        # Configure custom port if needed
        if port != 22:
            print(f"\nConfiguring SSH to listen on port {port}...")
            configure_ssh_port(port)
        
        # Verify installation
        if check_ssh_server():
            print("✓ SSH server is now running")
            if port != 22:
                print(f"✓ SSH is listening on port {port}")
            return True
        else:
            print("⚠ SSH server installed but may need manual start")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Installation failed: {e}")
        print("\nPlease install SSH manually:")
        print_install_instructions()
        return False
    except Exception as e:
        print(f"\n✗ Error during installation: {e}")
        return False

def print_install_instructions():
    """Print SSH installation instructions"""
    system = platform.system()
    
    instructions = {
        "Windows": """
SSH Installation for Windows:
  PowerShell (Admin): Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
  Or download from: https://github.com/PowerShell/Win32-OpenSSH/releases
""",
        "Linux": """
SSH Installation for Linux:
  Ubuntu/Debian: sudo apt install openssh-client openssh-server
  Fedora/RHEL: sudo dnf install openssh-clients openssh-server
  Arch: sudo pacman -S openssh
""",
        "Darwin": """
SSH Installation for macOS:
  SSH client is pre-installed.
  Enable server: sudo systemsetup -setremotelogin on
"""
    }
    
    print(instructions.get(system, "Unknown operating system"))

def interactive_mode():
    """Interactive mode for SSH operations"""
    transfer = SSHTransfer()
    
    print("=" * 60)
    print("SSH Transfer System - Interactive Mode")
    print("=" * 60)
    
    # Check if connecting to localhost/same machine
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    # Load config
    config = transfer.load_config()
    
    # Get connection details
    host = input(f"Host [{config.get('host', '')}]: ").strip() or config.get('host', '')
    port = input(f"Port [{config.get('port', '22')}]: ").strip() or config.get('port', '22')
    username = input(f"Username [{config.get('username', '')}]: ").strip() or config.get('username', '')
    
    # Check if connecting to localhost
    is_localhost = host in ['localhost', '127.0.0.1', '0.0.0.0', local_ip, hostname]
    
    # If localhost and SSH server not running, offer to install
    if is_localhost and not check_ssh_server():
        print("\n⚠ You're connecting to your local machine, but SSH server is not running.")
        if not install_ssh_auto(int(port)):
            print("\nCannot proceed without SSH server. Exiting...")
            return
    
    auth_method = input("Authentication (1: Password, 2: Key file) [1]: ").strip() or '1'
    
    password = None
    key_file = None
    
    if auth_method == '2':
        key_file = input(f"Key file [{config.get('key_file', '')}]: ").strip() or config.get('key_file', '')
    else:
        password = getpass.getpass("Password: ")
    
    # Save config
    save = input("Save configuration? (y/n) [y]: ").strip() or 'y'
    if save.lower() == 'y':
        transfer.save_config({
            'host': host,
            'port': int(port),
            'username': username,
            'key_file': key_file
        })
    
    # Connect
    if not transfer.connect(host, username, int(port), password, key_file):
        return
    
    # Interactive commands
    print("\nAvailable commands:")
    print("  upload <local_file> <remote_path>")
    print("  upload-dir <local_dir> <remote_dir>")
    print("  download <remote_file> <local_path>")
    print("  download-dir <remote_dir> <local_dir>")
    print("  exec <command>")
    print("  message <remote_file> <message>")
    print("  list [remote_path]")
    print("  quit")
    
    while True:
        try:
            cmd = input("\n> ").strip()
            
            if not cmd:
                continue
            
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            
            if action == 'quit':
                break
            elif action == 'upload':
                args = parts[1].split() if len(parts) > 1 else []
                if len(args) >= 2:
                    transfer.upload(args[0], args[1])
                else:
                    print("Usage: upload <local_file> <remote_path>")
            elif action == 'upload-dir':
                args = parts[1].split() if len(parts) > 1 else []
                if len(args) >= 2:
                    transfer.upload_dir(args[0], args[1])
                else:
                    print("Usage: upload-dir <local_dir> <remote_dir>")
            elif action == 'download':
                args = parts[1].split() if len(parts) > 1 else []
                if len(args) >= 2:
                    transfer.download(args[0], args[1])
                else:
                    print("Usage: download <remote_file> <local_path>")
            elif action == 'download-dir':
                args = parts[1].split() if len(parts) > 1 else []
                if len(args) >= 2:
                    transfer.download_dir(args[0], args[1])
                else:
                    print("Usage: download-dir <remote_dir> <local_dir>")
            elif action == 'exec':
                if len(parts) > 1:
                    transfer.execute(parts[1])
                else:
                    print("Usage: exec <command>")
            elif action == 'message':
                args = parts[1].split(maxsplit=1) if len(parts) > 1 else []
                if len(args) >= 2:
                    transfer.send_message(args[1], args[0])
                else:
                    print("Usage: message <remote_file> <message>")
            elif action == 'list':
                path = parts[1] if len(parts) > 1 else '.'
                transfer.list_remote(path)
            else:
                print(f"Unknown command: {action}")
        
        except KeyboardInterrupt:
            print("\nUse 'quit' to exit")
        except Exception as e:
            print(f"Error: {e}")
    
    transfer.disconnect()

def main():
    parser = argparse.ArgumentParser(description='SSH Transfer System - CLI')
    
    parser.add_argument('--host', help='Remote host')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--user', help='Username')
    parser.add_argument('--password', help='Password (not recommended, use key)')
    parser.add_argument('--key', help='SSH key file path')
    
    parser.add_argument('--upload', nargs=2, metavar=('LOCAL', 'REMOTE'), 
                       help='Upload file: --upload local_file remote_path')
    parser.add_argument('--upload-dir', nargs=2, metavar=('LOCAL_DIR', 'REMOTE_DIR'),
                       help='Upload directory: --upload-dir local_dir remote_dir')
    parser.add_argument('--download', nargs=2, metavar=('REMOTE', 'LOCAL'), 
                       help='Download file: --download remote_file local_path')
    parser.add_argument('--download-dir', nargs=2, metavar=('REMOTE_DIR', 'LOCAL_DIR'),
                       help='Download directory: --download-dir remote_dir local_dir')
    parser.add_argument('--exec', dest='command', help='Execute command')
    parser.add_argument('--message', nargs=2, metavar=('REMOTE_FILE', 'MESSAGE'), 
                       help='Send message to file')
    parser.add_argument('--list', dest='list_path', nargs='?', const='.', 
                       help='List remote directory')
    
    parser.add_argument('--generate-key', action='store_true', 
                       help='Generate SSH key pair')
    parser.add_argument('--check-ssh', action='store_true', 
                       help='Check SSH installation')
    parser.add_argument('--install-ssh', action='store_true', 
                       help='Install SSH server automatically')
    parser.add_argument('--interactive', action='store_true', 
                       help='Interactive mode')
    
    args = parser.parse_args()
    
    # Utility commands
    if args.generate_key:
        generate_ssh_key()
        return
    
    if args.check_ssh:
        check_ssh()
        return
    
    if args.install_ssh:
        install_ssh_auto()
        return
    
    # Interactive mode
    if args.interactive or len(sys.argv) == 1:
        interactive_mode()
        return
    
    # Non-interactive mode
    if not args.host or not args.user:
        print("Error: --host and --user are required for non-interactive mode")
        parser.print_help()
        return
    
    transfer = SSHTransfer()
    
    # Get password if not using key
    password = args.password
    if not args.key and not password:
        password = getpass.getpass("Password: ")
    
    # Connect
    if not transfer.connect(args.host, args.user, args.port, password, args.key):
        return
    
    # Execute operations
    if args.upload:
        transfer.upload(args.upload[0], args.upload[1])

    if args.upload_dir:
        transfer.upload_dir(args.upload_dir[0], args.upload_dir[1])
    
    if args.download:
        transfer.download(args.download[0], args.download[1])

    if args.download_dir:
        transfer.download_dir(args.download_dir[0], args.download_dir[1])
    
    if args.command:
        transfer.execute(args.command)
    
    if args.message:
        transfer.send_message(args.message[1], args.message[0])
    
    if args.list_path is not None:
        transfer.list_remote(args.list_path)
    
    transfer.disconnect()

if __name__ == "__main__":
    main()
