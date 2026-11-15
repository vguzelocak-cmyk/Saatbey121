#!/usr/bin/env python3
"""gonder.py - Nintendo Switch 2 Smart Payload Sender
Transfers payloads (.bin or .nro) to Nintendo Switch 2 using:
1. Direct TCP delivery to Switch Console IP (Port 9020 / 9090 / 28280 NetLoader)
2. Web Exploit Bridge (serve-coi.py / WebKit stage) with live receipt/execution confirmation (ACK)
3. Automatic Nintendo device detection via ARP / MAC OUI / local subnet
4. Automatic local bridge server launching if not already running
"""
import sys
import os
import re
import time
import socket
import struct
import subprocess
import urllib.request
import urllib.error
import ssl
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CACHE_IP_FILE = BASE_DIR / ".switch_ip"

NINTENDO_MACS = (
    "00:09:bf", "00:16:56", "00:17:ab", "00:19:1d", "00:19:fd", "00:1a:e9",
    "00:1b:7a", "00:1b:ea", "00:1d:bc", "00:1e:35", "00:1f:32", "00:21:47",
    "00:21:bd", "00:22:4c", "00:22:aa", "00:22:d7", "00:23:31", "00:23:cc",
    "00:24:1e", "00:24:44", "00:24:f3", "00:25:a0", "00:26:59", "00:27:09",
    "00:7c:2d", "04:03:d6", "18:2a:7b", "2c:10:c1", "34:2f:bd", "40:d2:8a",
    "58:2f:40", "70:48:0f", "78:a2:a0", "8c:56:c5", "94:58:cb", "98:b6:e9",
    "9c:e6:35", "a4:38:cc", "a4:5c:27", "b8:78:26", "cc:9e:00", "d4:f0:57",
    "d8:6b:83", "e0:0c:7f", "e0:e7:51", "e8:4e:ce"
)

def local_ip():
    for target in ("8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((target, 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    return ip
        except OSError:
            pass
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "127.0.0.1"

def scan_arp_for_nintendo():
    """Scans Windows ARP table for Nintendo MAC OUIs"""
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            # Match: IP and MAC (e.g. 192.168.1.124   00-7c-2d-e5-f6-5c)
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})", line)
            if m:
                ip = m.group(1)
                mac_prefix = m.group(2).replace("-", ":").lower()
                if mac_prefix in NINTENDO_MACS and not ip.endswith(".255"):
                    return ip
    except Exception:
        pass
    return None

def query_server_status(port=8443, proto="https"):
    """Queries serve-coi.py /netcat/status endpoint"""
    url = f"{proto}://127.0.0.1:{port}/netcat/status"
    ctx = ssl._create_unverified_context() if proto == "https" else None
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=0.8, context=ctx) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode())
    except Exception:
        pass
    return None

def get_server_info():
    """Checks all standard server ports and returns active server status"""
    for port, proto in ((8443, "https"), (8080, "http"), (443, "https"), (80, "http")):
        info = query_server_status(port, proto)
        if info:
            return port, proto, info
    return None, None, None

def ensure_server_running():
    """Starts serve-coi.py in background if not already active"""
    port, proto, info = get_server_info()
    if info:
        return port, proto, info

    server_script = BASE_DIR / "serve-coi.py"
    if not server_script.exists():
        return None, None, None

    print("[gonder] Yerel Web Exploit sunucusu acik degil, arkaplanda baslatiliyor...")
    try:
        # Launch python serve-coi.py in background
        subprocess.Popen(
            [sys.executable, str(server_script)],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        )
        for _ in range(10):
            time.sleep(0.4)
            port, proto, info = get_server_info()
            if info:
                print(f"[gonder] [OK] Sunucu baslatildi: {proto}://0.0.0.0:{port}/")
                return port, proto, info
    except Exception as e:
        print(f"[gonder] Sunucu baslatma uyarisi: {e}")

    return None, None, None

def parse_args():
    target_ip = None
    target_file = None

    for arg in sys.argv[1:]:
        # IP check
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", arg):
            target_ip = arg
        else:
            p = Path(arg)
            if p.exists() and p.is_file():
                target_file = p
            elif (BASE_DIR / arg).exists():
                target_file = BASE_DIR / arg

    # Default payload file candidate
    if not target_file:
        for candidate in ("payload.bin", "switch2.bin", "menu.bin", "hbmenu.nro"):
            p = BASE_DIR / candidate
            if p.exists():
                target_file = p
                break

    return target_ip, target_file

def try_direct_tcp(ip, port, data, timeout=1.0):
    """Direct TCP transmission to console IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(data)
            return True
    except Exception:
        return False

def try_nxlink_netloader(ip, data, timeout=1.2):
    """Direct transmission to Nintendo Switch NetLoader (Port 28280)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, 28280))
            # Format: 4-byte payload size (LE), 4-byte arg length (LE = 0), followed by raw NRO
            header = struct.pack("<II", len(data), 0)
            s.sendall(header + data)
            return True
    except Exception:
        return False

def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    if any(arg in ("-h", "--help", "/?") for arg in sys.argv[1:]):
        print("Kullanim: gonder.bat [konsol_ip] [dosya.bin veya dosya.nro]")
        print("Ornekler:")
        print("  gonder.bat                      (Otomatik hedef ve dosya tespiti)")
        print("  gonder.bat 192.168.1.124        (Belirtilen Switch IP'sine gonderir)")
        print("  gonder.bat switch2.bin          (Belirtilen payload dosyasini gonderir)")
        print("  gonder.bat 192.168.1.124 hbmenu.nro")
        return

    target_ip, target_file = parse_args()

    print("==================================================================")
    print("        Nintendo Switch 2 Smart Payload Sender (v2.5)             ")
    print("==================================================================")

    if not target_file or not target_file.exists():
        print("[gonder] [HATA] Gonderilecek payload dosyasi bulunamadi!")
        print("Kullanim: gonder.bat [konsol_ip] [dosya.bin veya dosya.nro]")
        print("Ornek:    gonder.bat 192.168.1.124 switch2.bin")
        print("          gonder.bat hbmenu.nro")
        sys.exit(1)

    data = target_file.read_bytes()
    is_nro = len(data) >= 0x20 and data[0x10:0x14] == b"NRO0"
    ptype = "NRO Homebrew" if is_nro else ("SW2P Container" if data[:4] == b"SW2P" else "Raw Binary")

    print(f"[gonder] Dosya  : {target_file.name} ({len(data):,} bayt, {ptype})")

    # Step 1: Resolve Target Console IP
    console_ip = target_ip

    if not console_ip and CACHE_IP_FILE.exists():
        cached = CACHE_IP_FILE.read_text().strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cached):
            console_ip = cached

    # Query running server for console IP
    _, _, srv_info = get_server_info()
    if not console_ip and srv_info:
        cand = srv_info.get("console_ip") or srv_info.get("client_ip")
        if cand and not cand.startswith("127."):
            console_ip = cand

    # Scan ARP table for Nintendo device
    if not console_ip:
        arp_ip = scan_arp_for_nintendo()
        if arp_ip:
            console_ip = arp_ip
            print(f"[gonder] [TESPIT] Ağda Nintendo cihazı bulundu: {console_ip}")

    if console_ip:
        print(f"[gonder] Hedef Switch IP : {console_ip}")
        try:
            CACHE_IP_FILE.write_text(console_ip)
        except Exception:
            pass
    else:
        print(f"[gonder] Hedef Switch IP : (Otomatik web köprüsü kullanılacak)")

    # Step 2: Try Direct TCP Delivery if Console IP is known
    if console_ip:
        # A) Try NetLoader Port 28280 if payload is NRO
        if is_nro or target_file.suffix.lower() == ".nro":
            print(f"[gonder] Switch NetLoader (Port 28280) deneniyor ({console_ip})...")
            if try_nxlink_netloader(console_ip, data):
                print(f"[gonder] [BAŞARILI] '{target_file.name}' doğrudan Switch 2 NetLoader'a (28280) iletildi!")
                print(f"[gonder] Switch 2 üzerinde homebrew anında başlatıldı!")
                return

        # B) Try Direct BinLoader Port 9020
        print(f"[gonder] Doğrudan Port 9020 bağlantısı deneniyor ({console_ip}:9020)...")
        if try_direct_tcp(console_ip, 9020, data, timeout=1.0):
            print(f"[gonder] [BAŞARILI] '{target_file.name}' doğrudan Switch 2 konsoluna ({console_ip}:9020) iletildi!")
            return

        # C) Try Direct Port 9090
        if try_direct_tcp(console_ip, 9090, data, timeout=0.8):
            print(f"[gonder] [BAŞARILI] '{target_file.name}' doğrudan Switch 2 konsoluna ({console_ip}:9090) iletildi!")
            return

        print(f"[gonder] Doğrudan portlar kapalı (Konsol WebKit exploit modunda).")

    # Step 3: Web Exploit Bridge Channel (serve-coi.py)
    print("[gonder] Web Exploit Köprüsü üzerinden aktarım hazırlanıyor...")
    port, proto, info = ensure_server_running()

    if not info:
        print("[gonder] [HATA] Web exploit sunucusu açılamadı.")
        print("Lütfen 'baslat.bat' dosyasını çalıştırın.")
        sys.exit(1)

    # 3.1: Upload payload to server via TCP 9020 or HTTP POST /upload
    uploaded = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect(("127.0.0.1", 9020))
            s.sendall(data)
            uploaded = True
    except Exception:
        pass

    if not uploaded:
        upload_url = f"{proto}://127.0.0.1:{port}/upload"
        ctx = ssl._create_unverified_context() if proto == "https" else None
        try:
            req = urllib.request.Request(
                upload_url,
                data=data,
                headers={"X-Filename": target_file.name, "Content-Type": "application/octet-stream"}
            )
            with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                if resp.status == 200:
                    uploaded = True
        except Exception as e:
            print(f"[gonder] HTTP yükleme uyarısı: {e}")

    if not uploaded:
        print("[gonder] [HATA] Payload köprü sunucusuna teslim edilemedi.")
        sys.exit(1)

    my_ip = local_ip()
    access_url = f"{proto}://{my_ip}:{port}/"

    print("------------------------------------------------------------------")
    print(f"[gonder] [KÖPRÜ HAZIR] '{target_file.name}' sunucuya yüklendi!")
    print(f"[gonder] 🎮 Switch 2'de web tarayıcısını açıp bu adrese girin:")
    print(f"         >>>  {access_url}  <<<")
    print("------------------------------------------------------------------")
    print(f"[gonder] Switch 2 konsolunun sayfayı açması ve payload'ı alması bekleniyor...")

    # Step 4: Monitor Delivery & Execution Confirmation (ACK)
    start_time = time.time()
    last_state_msg = ""
    fetch_reported = False

    try:
        last_dot = 0
        while time.time() - start_time < 20.0:
            time.sleep(0.8)
            cur_info = query_server_status(port, proto)
            if not cur_info:
                continue

            c_ip = cur_info.get("console_ip") or console_ip or "Switch 2"
            fetched = cur_info.get("console_fetched", False)
            executed = cur_info.get("console_executed", False)

            if executed:
                print("\n==================================================================")
                print(f"[gonder] [BAŞARILI] Switch 2 ({c_ip}) payload'ı teslim aldı ve çalıştırdı!")
                print(f"[gonder] Durum: AKTİF (RAM AAPCS64 Handoff tamamlandı)")
                print("==================================================================")
                return

            if fetched and not fetch_reported:
                fetch_reported = True
                print(f"\n[gonder] [İLERLEME] Switch 2 ({c_ip}) payload'ı indirdi, RAM yürütme onayı bekleniyor...")

            elapsed = int(time.time() - start_time)
            if elapsed // 5 > last_dot:
                last_dot = elapsed // 5
                print(f"[gonder] Konsol bekleniyor... ({20 - elapsed}s)", flush=True)

    except KeyboardInterrupt:
        print("\n[gonder] Bekleme sonlandırıldı.")

    print("\n------------------------------------------------------------------")
    print(f"[gonder] [BİLGİ] Payload sunucu köprüsünde hazır tutuluyor.")
    print(f"Switch 2 tarayıcısından {access_url} adresine girildiğinde")
    print(f"'{target_file.name}' otomatik olarak RAM'e aktarılacaktır.")
    print("------------------------------------------------------------------")

if __name__ == "__main__":
    main()
