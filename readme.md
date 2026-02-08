# SSH Transfer CLI - Command Line Tool

A lightweight, cross-platform SSH transfer tool (no GUI). Use it to upload/download files or folders, run remote commands, and send short messages over SSH.

## Requirements

- Python 3.8+
- `paramiko` library
- SSH **server** running on the target device (receiver)
- Network access between the two devices (firewall allows SSH port)

## Quick Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x ssh_transfer_cli.py
```

If you don’t want a virtual environment:
```bash
pip install paramiko
```

## How It Works

- You run the script on **your machine** (sender).
- The **target machine** only needs an SSH server running and an open port.
- Transfers use SFTP under the hood.

## Target Device Setup (Receiver)

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo ufw allow 22/tcp
```

Check SSH status:
```bash
sudo systemctl status ssh --no-pager
```

Check it is listening:
```bash
ss -tlnp | grep sshd
```

### Other OS (Quick Notes)
- macOS: enable Remote Login
- Windows: install OpenSSH Server and start `sshd`

## Usage

### Interactive Mode (Recommended)
```bash
python3 ssh_transfer_cli.py
```

Example flow:
```
Host [10.10.7.75]: 10.10.7.76
Port [22]: 22
Username [khairul]: mohammadsajal
Authentication (1: Password, 2: Key file) [1]: 1
Password:
```

Interactive commands:
```
> upload /local/file.txt /remote/path/file.txt
> upload-dir /local/folder /remote/path/folder
> download /remote/file.txt /local/path/file.txt
> download-dir /remote/folder /local/path/folder
> exec ls -la
> message /remote/message.txt Hello from my PC
> list /var/www
> quit
```

### Non-Interactive (CLI flags)

**Upload file**
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --upload /local/file.txt /home/mohammadsajal/file.txt
```

**Upload folder**
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --upload-dir /local/folder /home/mohammadsajal/folder
```

**Download file**
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --download /home/mohammadsajal/file.txt ./file.txt
```

**Download folder**
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --download-dir /home/mohammadsajal/folder ./folder
```

**Execute remote command**
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --exec "df -h && free -m"
```

**Send message to a file**
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --message /tmp/status.txt "Deployment completed"
```

**List remote directory**
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --list /var/www
```

## Keys vs Passwords

Use SSH keys for automation or frequent transfers.

Generate a key pair:
```bash
python3 ssh_transfer_cli.py --generate-key
```

Then copy the public key to the target device:
```bash
ssh-copy-id -i ~/.ssh/id_rsa_transfer.pub mohammadsajal@10.10.7.76
```

Use it:
```bash
python3 ssh_transfer_cli.py --host 10.10.7.76 --user mohammadsajal \
  --key ~/.ssh/id_rsa_transfer --upload /local/file /remote/file
```

## Configuration File

The script saves your last connection to:
`~/.ssh_transfer_config.json`

Example:
```json
{
  "host": "10.10.7.76",
  "port": 22,
  "username": "mohammadsajal",
  "key_file": "/home/user/.ssh/id_rsa_transfer"
}
```

## End-to-End Test (Two Devices)

On sender:
```bash
echo "hello from sender $(date)" > /tmp/ssh_transfer_test.txt
python3 ssh_transfer_cli.py
```

In interactive mode:
```
> upload /tmp/ssh_transfer_test.txt /home/mohammadsajal/ssh_transfer_test.txt
> download /home/mohammadsajal/ssh_transfer_test.txt /tmp/ssh_transfer_test_down.txt
```

Verify:
```bash
diff /tmp/ssh_transfer_test.txt /tmp/ssh_transfer_test_down.txt
```

## Troubleshooting

**Connection refused**
- SSH server not running on target
- Wrong port
- Firewall blocked

**Authentication failed**
- Wrong username/password
- Key not added to `~/.ssh/authorized_keys`
- Key permissions too open (`chmod 600` for private key)

**Cannot reach host**
- Wrong IP
- Different network/subnet
- Firewall/NAT blocking

## Notes

- Default SSH port is `22`. Use a custom port only if you configured the target SSH server.
- The script runs only on the sender; the receiver does not need the script installed.
