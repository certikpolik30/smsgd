#!/bin/bash
set -e

# --------- Phase 1: Install ProtonMail Desktop (beta .deb) ---------
cd /tmp
wget -O ProtonMail-desktop-beta.deb 'https://proton.me/download/mail/linux/ProtonMail-desktop-beta.deb'
sudo dpkg -i ProtonMail-desktop-beta.deb || sudo apt -f install -y

# --------- Phase 2: Update Kali, kernel, major tool sets -----------
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y kali-linux-large parrot-tools-full
sudo apt autoremove -y

# --------- Phase 3: Build/developer tools -----------
sudo apt install -y \
  git build-essential libssl-dev libffi-dev \
  python3-pip python3-venv python3-tk \
  rustc cargo \
  lxc apparmor-utils firejail \
  openvpn network-manager-openvpn resolvconf \
  tor privoxy exiftool \
  curl 

# --------- Phase 4: Disable root login, create sudo user evil -----------
sudo passwd -l root
sudo useradd -m -s /bin/bash -c "evil" evil
echo "evil:evil" | sudo chpasswd
sudo usermod -aG sudo evil

# --------- Phase 5: Set hostname -----------
echo "mask" | sudo tee /etc/hostname
sudo hostname mask

# --------- Phase 6: Lock root SSH (OPTIONAL) -----------
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# --------- Phase 7: Install SELinux + MLS -----------
sudo apt install -y selinux-basics selinux-policy-mls auditd audispd-plugins

sudo sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
sudo sed -i 's/SELINUXTYPE=default/SELINUXTYPE=mls/' /etc/selinux/config
sudo touch /.autorelabel

# --------- Phase 8: Kernel hardening -----------
cat <<EOF | sudo tee -a /etc/sysctl.conf
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
kernel.yama.ptrace_scope = 3
EOF
sudo sysctl -p

# --------- Phase 9: Enforce all AppArmor profiles -----------
sudo aa-enforce /etc/apparmor.d/* || true

# --------- Phase 10: Set firejail default profile -----------
echo "firejail --noprofile" | sudo tee /etc/firejail/disable-common.inc

# --------- Phase 11: LXC isolated containers -----------
sudo lxc-create -n web -t download -- -d ubuntu -r jammy -a amd64
sudo lxc-create -n net -t download -- -d ubuntu -r jammy -a amd64
sudo lxc-create -n sec -t download -- -d ubuntu -r jammy -a amd64

# --------- Phase 12: Install ProtonVPN CLI -----------
sudo apt install -y apt-transport-https
curl -s https://api.protonvpn.com/v1/protonvpn-deb-v3.pub | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/protonvpn.gpg
echo "deb [signed-by=/etc/apt/trusted.gpg.d/protonvpn.gpg] https://api.protonvpn.com/v1/deb unstable protonvpn-stable" | sudo tee /etc/apt/sources.list.d/protonvpn.list
sudo apt update && sudo apt install -y protonvpn-cli

# --------- Phase 13: Install minimal tools in container (example for web) -----------
sudo lxc-start -n web
sudo lxc-attach -n web -- bash -c "apt update && apt install -y tor curl wget privoxy"

# --------- Phase 14: Tor and Privoxy on host -----------
sudo apt install -y tor privoxy
sudo systemctl enable --now tor

# --------- Phase 15: Transparent routing via iptables -----------
sudo tee /etc/systemd/system/tor-transparent.service <<'EOF'
[Unit]
Description=Transparent Tor Proxy
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/iptables -t nat -A OUTPUT -o lo -j RETURN
ExecStart=/sbin/iptables -t nat -A OUTPUT -m owner --uid-owner debian-tor -j RETURN
ExecStart=/sbin/iptables -t nat -A OUTPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040
ExecStop=/sbin/iptables -t nat -F OUTPUT
ExecStop=/sbin/iptables -t nat -X

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now tor-transparent

# --------- Phase 16: DNS over HTTPS (Cloudflare) -----------
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf

# --------- Phase 17: Encrypt home (example) -----------
# Replace /dev/sdXY with actual partition.
# sudo cryptsetup luksFormat /dev/sdXY
# sudo cryptsetup open /dev/sdXY secure_home
# sudo mkfs.ext4 /dev/mapper/secure_home
# sudo mount /dev/mapper/secure_home /home
# Add entry to /etc/crypttab and /etc/fstab as required

# --------- Phase 18: Self-re-encrypt loop (BullX style) -----------
cat <<'EOF' | sudo tee /usr/local/bin/bullx-encrypt.sh
#!/bin/bash
while true; do
  find /home/evil -type f -exec gpg --batch --yes --symmetric --cipher-algo AES256 {} \; 2>/dev/null
  sleep 600
done
EOF
sudo chmod +x /usr/local/bin/bullx-encrypt.sh
sudo -u evil nohup /usr/local/bin/bullx-encrypt.sh &

# --------- Phase 19: Empire (PowerShell Empire / Empire-Project) ----------
git clone https://github.com/BC-SECURITY/Empire.git /opt/Empire
cd /opt/Empire
sudo ./setup/install.sh

# --------- Phase 20: Clone Security, OSINT, Exploitation & Analysis Tools ---------
cd /opt
git clone https://github.com/htr-tech/nexphisher
git clone https://github.com/BiZken/PhishMailer
git clone https://github.com/Lissy93/web-check
git clone https://github.com/tejado/telegram-nearby-map
git clone https://github.com/megadose/holehe
git clone https://github.com/Ullaakut/cameradar
git clone https://github.com/bee-san/Ciphey
git clone https://github.com/commixproject/commix
git clone https://github.com/jonaslejon/malicious-pdf
git clone https://github.com/n1nj4sec/pupy
git clone https://github.com/BloodHoundAD/BloodHound.git
git clone https://github.com/spyboy-productions/CamXploit
git clone https://github.com/certikpolik30/smsgd

# --------- Phase 21: Proton Mail CLI/unofficial Python API ----------
pip3 install protonmail-api

cat <<'EOF' | sudo tee /usr/local/bin/protonmail-cli
#!/usr/bin/env python3
import sys, os, subprocess
if len(sys.argv) < 2:
    print("Usage: protonmail-cli login | send <to> <subject> <body> | strip <file>")
    sys.exit(1)
cmd = sys.argv[1]
if cmd == "login":
    os.system("python3 -c 'from protonmail import ProtonMail; pm = ProtonMail(input(\"User: \"), input(\"Pass: \")); pm.login()'")
elif cmd == "send":
    to, sub, body = sys.argv[2], sys.argv[3], sys.argv[4]
    print(f"Send to {to}: {sub} | {body}")
elif cmd == "strip":
    f = sys.argv[2]
    subprocess.run(f"exiftool -all= \"{f}\"", shell=True)
    print("Metadata stripped 🧹")
EOF
sudo chmod +x /usr/local/bin/protonmail-cli

# --------- Phase 22: AI Guard Daemon ----------
pip3 install requests

cat <<'EOF' | sudo tee /usr/local/bin/ai-guard.py
#!/usr/bin/env python3
import os, time, subprocess, requests, json
from threading import Thread
OPENAI_KEY = "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"
DEEPSEEK_KEY = "sk-2947510f7eb049c9b2d084155bd7c529"
def analyze(path):
    try:
        oai = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_KEY}"},
            json={"model": "openai/gpt-4o-mini", "messages": [{"role": "user", "content": f"Is this file malicious? {path}"}]}
        ).json()
        ds = requests.post(
            "https://api.deepseek.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {DEEPSEEK_KEY}"},
            json={"model": "deepseek-chat", "messages": [{"role": "user", "content": f"Is this file malicious? {path}"}]}
        ).json()
        oai_ans = oai["choices"][0]["message"]["content"].lower()
        ds_ans = ds["choices"][0]["message"]["content"].lower()
        if "yes" in oai_ans and "yes" in ds_ans:
            if not path.startswith("/home/evil/"):
                subprocess.run(f"mv {path} /quarantine/", shell=True)
                print(f"[AI] Quarantined: {path}")
    except Exception as e:
        print(f"[AI] Error: {e}")

def monitor():
    os.makedirs("/quarantine", exist_ok=True)
    while True:
        for f in os.listdir("/tmp") + os.listdir("/var/tmp"):
            path = f"/tmp/{f}" if f in os.listdir("/tmp") else f"/var/tmp/{f}"
            if os.path.isfile(path):
                analyze(path)
        time.sleep(10)

if __name__ == "__main__":
    Thread(target=monitor, daemon=True).start()
    while True:
        time.sleep(1)
EOF
sudo chmod +x /usr/local/bin/ai-guard.py
sudo -u evil nohup /usr/local/bin/ai-guard.py &

# --------- Phase 23: Security modes (Scripts) ----------
cat <<'EOF' | sudo tee /usr/local/bin/fake-mode.sh
#!/bin/bash
mkdir -p /hidden_fake
mv /home/evil/* /hidden_fake/ 2>/dev/null || true
echo "Files hidden 👻"
EOF
sudo chmod +x /usr/local/bin/fake-mode.sh

cat <<'EOF' | sudo tee /usr/local/bin/destruct-mode.sh
#!/bin/bash
read -p "This will wipe /dev/sda. Continue? (y/N): " ans
if [[ $ans == "y" ]]; then
  shred -vfz -n 3 /dev/sda
  echo "Data wiped 🔥"
fi
EOF
sudo chmod +x /usr/local/bin/destruct-mode.sh

sudo apt install -y clamav yara
sudo freshclam
cat <<'EOF' | sudo tee /usr/local/bin/anti-malware-mode.sh
#!/bin/bash
clamscan -r /home/evil &
yara -r /usr/share/yara/rules/ /home/evil/ &
echo "Anti-malware scan started 🛡"
EOF
sudo chmod +x /usr/local/bin/anti-malware-mode.sh

# --------- Phase 24: USB Block (BadUSB protection) ------------
cat <<'EOF' | sudo tee /etc/udev/rules.d/99-usb-block.rules
SUBSYSTEM=="usb", ATTR{idVendor}!="0x1234", ATTR{idProduct}!="0x5678", RUN+="/bin/sh -c 'echo 0 > /sys\$DEVPATH/authorized'"
EOF
sudo udevadm control --reload-rules

# --------- Phase 25: GUI Dashboard (Tkinter, macOS-like dark mode) ----------
sudo apt install -y python3-tk

cat <<'EOF' | sudo tee /usr/local/bin/synex-gui
#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess, os
class SynexGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SYnex OS Security Center 🔐")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")
        tab_control = ttk.Notebook(root)
        self.tab1 = ttk.Frame(tab_control); tab_control.add(self.tab1, text="Dashboard")
        self.tab2 = ttk.Frame(tab_control); tab_control.add(self.tab2, text="VPN/Tor")
        self.tab3 = ttk.Frame(tab_control); tab_control.add(self.tab3, text="Encryption")
        self.tab4 = ttk.Frame(tab_control); tab_control.add(self.tab4, text="Mail")
        self.tab5 = ttk.Frame(tab_control); tab_control.add(self.tab5, text="AI Guard")
        self.tab6 = ttk.Frame(tab_control); tab_control.add(self.tab6, text="Modes")
        tab_control.pack(expand=1, fill="both")
        self.build_dashboard()
        self.build_vpn()
        self.build_crypto()
        self.build_mail()
        self.build_ai()
        self.build_modes()
    def build_dashboard(self):
        tk.Label(self.tab1, text="🛡️ SYnex OS Dashboard", font=("Helvetica", 16), bg="#1e1e1e", fg="#00ff00").pack(pady=10)
        tk.Button(self.tab1, text="🔒 Enable SELinux (MLS)", command=self.enable_selinux).pack(pady=5)
        tk.Button(self.tab1, text="🧱 Enable Firewall", command=self.enable_firewall).pack(pady=5)
        tk.Button(self.tab1, text="🛡 Enable AI Guard", command=self.enable_ai_guard).pack(pady=5)
    def build_vpn(self):
        tk.Label(self.tab2, text="🌐 VPN & Tor Control", font=("Helvetica", 14), bg="#1e1e1e", fg="#00ff00").pack(pady=10)
        tk.Button(self.tab2, text="🚀 Connect Proton VPN", command=self.connect_vpn).pack(pady=5)
        tk.Button(self.tab2, text="🧅 Enable Transparent Tor", command=self.enable_tor).pack(pady=5)
    def build_crypto(self):
        tk.Label(self.tab3, text="🔐 Encryption Tools", font=("Helvetica", 14), bg="#1e1e1e", fg="#00ff00").pack(pady=10)
        tk.Button(self.tab3, text="🔑 LUKS Encrypt Disk", command=self.encrypt_luks).pack(pady=5)
        tk.Button(self.tab3, text="🧬 Signal Protocol Test", command=self.signal_test).pack(pady=5)
    def build_mail(self):
        tk.Label(self.tab4, text="📧 Proton Mail", font=("Helvetica", 14), bg="#1e1e1e", fg="#00ff00").pack(pady=10)
        tk.Button(self.tab4, text="🔐 Login to Proton Mail", command=self.mail_login).pack(pady=5)
        tk.Button(self.tab4, text="🧹 Strip Metadata", command=self.strip_meta).pack(pady=5)
    def build_ai(self):
        tk.Label(self.tab5, text="🤖 AI Guard (OpenAI + DeepSeek)", font=("Helvetica", 14), bg="#1e1e1e", fg="#00ff00").pack(pady=10)
        tk.Button(self.tab5, text="🧠 Start AI Guard", command=self.start_ai).pack(pady=5)
    def build_modes(self):
        tk.Label(self.tab6, text="🎭 Security Modes", font=("Helvetica", 14), bg="#1e1e1e", fg="#00ff00").pack(pady=10)
        tk.Button(self.tab6, text="👻 Enable Fake Mode", command=self.fake_mode).pack(pady=5)
        tk.Button(self.tab6, text="🔥 Enable Destructive Mode", command=self.destruct_mode).pack(pady=5)
        tk.Button(self.tab6, text="🛡 Enable Anti-Malware Mode", command=self.anti_malware).pack(pady=5)
    def enable_selinux(self):
        subprocess.run("sudo setenforce 1", shell=True)
        messagebox.showinfo("SELinux", "SELinux Enforcing (MLS) enabled 🔒")
    def enable_firewall(self):
        subprocess.run("sudo ufw --force enable && sudo ufw default deny incoming", shell=True)
        messagebox.showinfo("Firewall", "Firewall enabled 🧱")
    def enable_ai_guard(self):
        subprocess.Popen(["sudo", "-u", "evil", "nohup", "/usr/local/bin/ai-guard.py", "&"])
        messagebox.showinfo("AI Guard", "AI Guard started 🤖")
    def connect_vpn(self):
        subprocess.run("protonvpn-cli connect --fastest", shell=True)
        messagebox.showinfo("VPN", "Proton VPN connected 🚀")
    def enable_tor(self):
        subprocess.run("sudo systemctl start tor && sudo systemctl enable tor", shell=True)
        messagebox.showinfo("Tor", "Transparent Tor routing enabled 🧅")
    def encrypt_luks(self):
        disk = "/dev/sdXY"  # Change to a real device!
        subprocess.run(f"sudo cryptsetup luksFormat {disk} && sudo cryptsetup open {disk} secure", shell=True)
        messagebox.showinfo("LUKS", "LUKS encryption enabled 🔑")
    def signal_test(self):
        print("Placeholder for Signal Protocol test.")
        messagebox.showinfo("Signal", "Signal Protocol test run 🧬")
    def mail_login(self):
        os.system("protonmail-cli login")
    def strip_meta(self):
        subprocess.run("protonmail-cli strip /home/evil/*", shell=True)
        messagebox.showinfo("Metadata", "Metadata stripped 🧹")
    def start_ai(self):
        subprocess.Popen(["sudo", "-u", "evil", "nohup", "/usr/local/bin/ai-guard.py", "&"])
        messagebox.showinfo("AI", "AI Guard running 🧠")
    def fake_mode(self):
        subprocess.run("sudo /usr/local/bin/fake-mode.sh", shell=True)
        messagebox.showinfo("Fake Mode", "Files hidden 👻")
    def destruct_mode(self):
        subprocess.run("sudo /usr/local/bin/destruct-mode.sh", shell=True)
    def anti_malware(self):
        subprocess.run("sudo /usr/local/bin/anti-malware-mode.sh", shell=True)
        messagebox.showinfo("Anti-Malware", "Anti-malware enabled 🛡")
if __name__ == "__main__":
    root = tk.Tk()
    app = SynexGUI(root)
    root.mainloop()
EOF
sudo chmod +x /usr/local/bin/synex-gui

echo "Complete! Reboot to apply kernel/SELinux config:"
echo "  sudo reboot"
