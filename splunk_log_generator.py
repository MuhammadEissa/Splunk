#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
  Splunk Multi-Source Log Generator
  Author  : Muhammad Eissa | CISA · CISM · CISSP
  Website : muhammadeissa.me | ESLabs Academy
  Purpose : Generate realistic logs from Firewall, Linux/Windows Servers,
            Network Devices, Web Servers, IDS/IPS, DNS, DHCP, and AD/Auth
            — all sent to Splunk via Syslog UDP or HEC (HTTP Event Collector)
═══════════════════════════════════════════════════════════════════════════════
"""

import socket
import time
import random
import json
import threading
import argparse
import sys
import logging
import requests
import datetime
from itertools import cycle

# ─── suppress only the InsecureRequestWarning ────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CLI ARGUMENTS ────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="Splunk Multi-Source Log Generator — Muhammad Eissa / ESLabs Academy"
)
parser.add_argument("--mode",      choices=["syslog", "hec", "file"], default="syslog",
                    help="Output mode: syslog (UDP), hec (Splunk HEC), or file")
parser.add_argument("--host",      default="127.0.0.1",  help="Splunk host (syslog or HEC)")
parser.add_argument("--port",      type=int, default=514, help="Syslog UDP port (default 514)")
parser.add_argument("--hec-port",  type=int, default=8088, help="HEC port (default 8088)")
parser.add_argument("--hec-token", default="YOUR-HEC-TOKEN", help="Splunk HEC token")
parser.add_argument("--eps",       type=int, default=10,  help="Events per second (total)")
parser.add_argument("--duration",  type=int, default=0,   help="Run duration in seconds (0=forever)")
parser.add_argument("--output",    default="splunk_logs.log", help="Output file (file mode)")
parser.add_argument("--attack",    action="store_true",   help="Inject attack simulation events")
args = parser.parse_args()

# ─── LOGGING SETUP ────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
log = logging.getLogger("LogGen")

# ═══════════════════════════════════════════════════════════════════════════════
# FAKE DATA POOLS
# ═══════════════════════════════════════════════════════════════════════════════

INTERNAL_IPS = [f"10.0.{r}.{h}" for r in range(1, 6) for h in range(1, 30)]
DMZ_IPS      = [f"172.16.10.{h}" for h in range(1, 20)]
EXTERNAL_IPS = [
    "185.220.101.47","45.33.32.156","91.109.190.5","103.21.244.0",
    "198.71.233.68","77.247.181.162","51.15.246.131","192.42.116.16",
    "162.247.74.201","104.244.76.13","62.102.148.67","89.234.157.254",
]
MALICIOUS_IPS = [
    "185.220.101.47","91.109.190.5","77.247.181.162","51.15.246.131","89.234.157.254",
]

USERS = [
    "ahmed.hassan","sara.ali","khalid.omar","fatima.nasser","ibrahim.saleh",
    "mohammed.abdulla","layla.rashid","yusuf.mansoor","hana.karim","omar.sheikh",
    "svc_backup","svc_monitor","svc_splunk","admin","Administrator",
]
PRIV_USERS = ["admin","Administrator","root","svc_backup"]

SERVERS = {
    "dc01.corp.local":      "10.0.1.5",
    "dc02.corp.local":      "10.0.1.6",
    "fileserver01":         "10.0.2.10",
    "appserver01":          "10.0.3.15",
    "appserver02":          "10.0.3.16",
    "dbserver01":           "10.0.4.20",
    "webserver01":          "172.16.10.5",
    "webserver02":          "172.16.10.6",
    "mailserver01":         "10.0.2.25",
    "splunk-idx01":         "10.0.5.10",
}

NETWORK_DEVICES = {
    "fw-perimeter-01":  "10.0.0.1",
    "fw-internal-01":   "10.0.0.2",
    "sw-core-01":       "10.0.0.10",
    "sw-core-02":       "10.0.0.11",
    "sw-access-01":     "10.0.1.20",
    "router-edge-01":   "10.0.0.254",
    "vpn-gw-01":        "172.16.10.1",
    "ids-sensor-01":    "10.0.5.50",
}

FIREWALL_ACTIONS  = ["ALLOW", "DENY", "DROP", "REJECT"]
PROTOCOLS         = ["TCP", "UDP", "ICMP", "GRE", "ESP"]
SERVICES          = {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",23:"TELNET",
                     3389:"RDP",1433:"MSSQL",3306:"MYSQL",53:"DNS",
                     25:"SMTP",110:"POP3",143:"IMAP",8080:"HTTP-ALT",
                     8443:"HTTPS-ALT",445:"SMB",135:"RPC",5985:"WINRM"}
HTTP_METHODS      = ["GET","POST","PUT","DELETE","HEAD","OPTIONS"]
HTTP_CODES        = [200,200,200,200,301,302,400,401,403,404,500,503]
HTTP_URIS         = ["/","/login","/api/v1/users","/admin","/dashboard",
                     "/api/v1/data","/static/app.js","/logout","/health",
                     "/api/v2/reports","/wp-admin","/phpmyadmin",".env",
                     "/etc/passwd","/.git/config","/xmlrpc.php"]
USER_AGENTS       = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.68.0","python-requests/2.28.0",
    "Nmap Scripting Engine","sqlmap/1.7","nikto/2.1.6",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
]
IDS_SIGS = [
    (1001,"ET SCAN Nmap SYN Scan","MEDIUM"),
    (1002,"ET EXPLOIT MS17-010 EternalBlue","CRITICAL"),
    (1003,"ET MALWARE CobaltStrike Beacon","CRITICAL"),
    (1004,"ET POLICY SSH Brute Force Attempt","HIGH"),
    (1005,"ET WEB_SERVER SQL Injection Attempt","HIGH"),
    (1006,"ET SCAN Port Scan Detected","MEDIUM"),
    (1007,"ET MALWARE Mimikatz Activity","CRITICAL"),
    (1008,"ET DNS Query to Known Malware C2","HIGH"),
    (1009,"ET POLICY RDP from External IP","MEDIUM"),
    (1010,"GPL ICMP PING *NIX","LOW"),
]
WIN_EVENT_IDS = {
    4624:"An account was successfully logged on",
    4625:"An account failed to log on",
    4634:"An account was logged off",
    4648:"A logon was attempted using explicit credentials",
    4672:"Special privileges assigned to new logon",
    4688:"A new process has been created",
    4698:"A scheduled task was created",
    4720:"A user account was created",
    4722:"A user account was enabled",
    4725:"A user account was disabled",
    4740:"A user account was locked out",
    4756:"A member was added to a security-enabled universal group",
    7045:"A new service was installed in the system",
}
LINUX_FACILITIES = {0:"kern",1:"user",3:"daemon",4:"auth",9:"cron",16:"local0"}
LINUX_SEVERITIES = {0:"emerg",1:"alert",2:"crit",3:"err",4:"warning",5:"notice",6:"info",7:"debug"}


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def ts_now():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

def syslog_ts():
    return datetime.datetime.now().strftime("%b %d %H:%M:%S")

def rnd_port():
    return random.randint(1024, 65535)

def rnd_bytes():
    return random.randint(40, 1500000)

def pick(lst):
    return random.choice(lst)

def pick_service():
    port = pick(list(SERVICES.keys()))
    return port, SERVICES[port]

def internal_ip():
    return pick(INTERNAL_IPS)

def external_ip():
    return pick(EXTERNAL_IPS)

def malicious_ip():
    return pick(MALICIOUS_IPS)

def server_pair():
    name, ip = pick(list(SERVERS.items()))
    return name, ip


# ═══════════════════════════════════════════════════════════════════════════════
# LOG GENERATORS — one function per source type
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1. PALO ALTO / CHECKPOINT STYLE FIREWALL ──────────────────────────────────
def gen_firewall():
    fw_name, fw_ip = pick(list(NETWORK_DEVICES.items()))
    if "fw" not in fw_name:
        fw_name, fw_ip = "fw-perimeter-01", "10.0.0.1"

    action   = pick(FIREWALL_ACTIONS)
    proto    = pick(PROTOCOLS)
    src_ip   = pick(INTERNAL_IPS + EXTERNAL_IPS)
    dst_ip   = pick(INTERNAL_IPS + DMZ_IPS)
    dport, svc = pick_service()
    sport    = rnd_port()
    rule     = pick(["ALLOW-WEB","DENY-INBOUND","VPN-SPLIT","BLOCK-TOR",
                     "ALLOW-DNS","BLOCK-TELNET","ALLOW-ESTABLISHED","IPS-BLOCK"])
    session  = random.randint(100000, 9999999)
    pkts     = random.randint(1, 500)
    zone_src = pick(["OUTSIDE","DMZ","TRUST","VPN"])
    zone_dst = pick(["INSIDE","DMZ","SERVERS","MGMT"])

    # CEF-style (Palo Alto syslog)
    return (
        f"{syslog_ts()} {fw_name} 1,{ts_now()},{fw_name},TRAFFIC,end,{random.randint(1,9999)},"
        f"action={action},rule={rule},srcip={src_ip},dstip={dst_ip},"
        f"sport={sport},dport={dport},proto={proto},app={svc.lower()},"
        f"from={zone_src},to={zone_dst},session={session},"
        f"bytes={rnd_bytes()},pkts={pkts}"
    )

# ── 2. CISCO ASA FIREWALL ─────────────────────────────────────────────────────
def gen_cisco_asa():
    action  = pick(["Built","Teardown","Denied"])
    proto   = pick(["TCP","UDP"])
    src_ip  = pick(INTERNAL_IPS + EXTERNAL_IPS)
    dst_ip  = pick(INTERNAL_IPS)
    dport, _= pick_service()
    sport   = rnd_port()
    msg_id  = pick(["302013","302014","302015","302016","106001","106006",
                    "106023","302021","313001","710003"])
    duration= f"0:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
    return (
        f"{syslog_ts()} fw-perimeter-01 : %ASA-6-{msg_id}: "
        f"{action} {proto} connection {random.randint(1000,999999)} "
        f"for outside:{src_ip}/{sport} to inside:{dst_ip}/{dport} "
        f"duration {duration} bytes {rnd_bytes()}"
    )

# ── 3. WINDOWS SERVER / ACTIVE DIRECTORY ─────────────────────────────────────
def gen_windows_security():
    srv_name, srv_ip = server_pair()
    eid    = pick(list(WIN_EVENT_IDS.keys()))
    desc   = WIN_EVENT_IDS[eid]
    user   = pick(USERS)
    domain = "CORP"
    logon  = pick(["Interactive","Network","RemoteInteractive","Service","Batch"])
    proc   = pick(["C:\\Windows\\System32\\lsass.exe",
                   "C:\\Windows\\System32\\svchost.exe",
                   "C:\\Windows\\explorer.exe",
                   "C:\\Users\\Public\\payload.exe",
                   "C:\\Windows\\System32\\cmd.exe",
                   "powershell.exe"])
    ip_src = pick(INTERNAL_IPS + EXTERNAL_IPS)
    return (
        f"{syslog_ts()} {srv_name} MSWinEventLog\t1\tSecurity\t"
        f"EventID={eid}\tSource=Microsoft-Windows-Security-Auditing\t"
        f"User={domain}\\{user}\tMessage={desc}\t"
        f"SubjectUserName={user}\tSubjectDomainName={domain}\t"
        f"LogonType={logon}\tIpAddress={ip_src}\t"
        f"ProcessName={proc}\tComputerName={srv_name}"
    )

# ── 4. LINUX SERVER SYSLOG ────────────────────────────────────────────────────
def gen_linux_syslog():
    srv_name = pick(["appserver01","appserver02","dbserver01","fileserver01","splunk-idx01"])
    fac   = pick(list(LINUX_FACILITIES.values()))
    sev   = pick(list(LINUX_SEVERITIES.values()))
    proc  = pick(["sshd","sudo","cron","kernel","systemd","auditd","su","passwd"])
    user  = pick(USERS)
    pid   = random.randint(1000, 65000)
    msg_pool = [
        f"Accepted publickey for {user} from {pick(INTERNAL_IPS)} port {rnd_port()} ssh2",
        f"Failed password for {user} from {pick(EXTERNAL_IPS)} port {rnd_port()} ssh2",
        f"session opened for user {user} by (uid=0)",
        f"session closed for user {user}",
        f"{user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
        f"pam_unix(su:auth): authentication failure; user={user}",
        f"CRON[{pid}]: ({user}) CMD (/usr/bin/backup.sh)",
        f"kernel: [UFW BLOCK] IN=eth0 OUT= SRC={pick(EXTERNAL_IPS)} DST={pick(INTERNAL_IPS)} PROTO=TCP",
        f"auditd: avc:  denied  {{ read }} for  pid={pid} comm=\"{proc}\"",
        f"systemd[1]: Started {pick(['nginx','sshd','splunkd','auditd'])} daemon.",
    ]
    return f"{syslog_ts()} {srv_name} {proc}[{pid}]: {pick(msg_pool)}"

# ── 5. CISCO SWITCH / ROUTER ──────────────────────────────────────────────────
def gen_network_device():
    dev_name, dev_ip = pick([(k,v) for k,v in NETWORK_DEVICES.items() if "sw" in k or "router" in k])
    severity = pick(["3","4","5","6"])
    facility = pick(["SYS","LINK","CDP","OSPF","BGP","SEC","PORT","AAA","SNMP"])
    mnemonic = pick(["UPDOWN","DUPLEX_MISMATCH","ADJCHANGE","AUTHFAIL",
                     "LOGIN_SUCCESS","LOGIN_FAILED","MACFLAP_NOTIF",
                     "CPUHOG","LINKDOWN","LINKUP"])
    intf     = pick(["GigabitEthernet0/0","GigabitEthernet0/1","FastEthernet0/24",
                     "Vlan10","Vlan20","TenGigabitEthernet1/0/1"])
    user     = pick(USERS)
    src_ip   = pick(INTERNAL_IPS)
    msg_pool = [
        f"Interface {intf}, changed state to up",
        f"Interface {intf}, changed state to down",
        f"Line protocol on Interface {intf} changed state to down",
        f"SEC_LOGIN: An authentication attempt from {src_ip} FAILED user={user}",
        f"SEC_LOGIN: An authentication attempt from {src_ip} SUCCESS user={user}",
        f"MAC address flap detected on {intf} between port {intf} and port GigabitEthernet0/2",
        f"OSPF neighbor {pick(INTERNAL_IPS)} is DOWN on {intf}",
        f"%SNMP-5-COLDSTART: SNMP agent on host {dev_name} is undergoing a cold start",
    ]
    return (
        f"{syslog_ts()} {dev_name} %{facility}-{severity}-{mnemonic}: {pick(msg_pool)}"
    )

# ── 6. WEB SERVER (APACHE / NGINX) ───────────────────────────────────────────
def gen_web_server():
    srv = pick(["webserver01","webserver02"])
    src = pick(INTERNAL_IPS + EXTERNAL_IPS)
    method = pick(HTTP_METHODS)
    uri    = pick(HTTP_URIS)
    code   = pick(HTTP_CODES)
    size   = random.randint(200, 512000)
    ua     = pick(USER_AGENTS)
    ref    = pick(["-","https://google.com","https://linkedin.com","-","-"])
    # Combined Log Format
    return (
        f'{syslog_ts()} {srv} access_log: {src} - - [{ts_now()}] '
        f'"{method} {uri} HTTP/1.1" {code} {size} "{ref}" "{ua}"'
    )

# ── 7. IDS / IPS (SNORT / SURICATA STYLE) ────────────────────────────────────
def gen_ids():
    sid, sig, priority = pick(IDS_SIGS)
    src_ip  = pick(INTERNAL_IPS + EXTERNAL_IPS + MALICIOUS_IPS)
    dst_ip  = pick(INTERNAL_IPS + DMZ_IPS)
    dport, _= pick_service()
    sport   = rnd_port()
    proto   = pick(["TCP","UDP","ICMP"])
    action  = pick(["alert","drop","reject"])
    return (
        f"{syslog_ts()} ids-sensor-01 snort[{random.randint(1000,9999)}]: "
        f"[{sid}:1] {sig} [{priority}] "
        f"{{Proto: {proto}}} {src_ip}:{sport} -> {dst_ip}:{dport} "
        f"Action={action} Classification=Attempted-Admin"
    )

# ── 8. DNS SERVER ─────────────────────────────────────────────────────────────
def gen_dns():
    srv   = pick(["dc01.corp.local","dc02.corp.local"])
    src   = pick(INTERNAL_IPS)
    qtypes= ["A","AAAA","MX","TXT","PTR","CNAME","NS","SOA"]
    qtype = pick(qtypes)
    domains = [
        "google.com","microsoft.com","office365.com","corp.local",
        "pastebin.com","github.com","evil-c2-domain.xyz",
        "update.windows.com","cdn.cloudflare.com","malware-drop.ru",
        "dc01.corp.local","mail.corp.local",
    ]
    domain  = pick(domains)
    rc      = pick(["NOERROR","NXDOMAIN","SERVFAIL","REFUSED"])
    latency = random.randint(1, 200)
    return (
        f"{syslog_ts()} {srv} named[{random.randint(1000,9999)}]: "
        f"client {src}#{rnd_port()}: query: {domain} IN {qtype} "
        f"response: {rc} latency={latency}ms"
    )

# ── 9. DHCP SERVER ────────────────────────────────────────────────────────────
def gen_dhcp():
    srv    = "dc01.corp.local"
    action = pick(["DHCPREQUEST","DHCPACK","DHCPNAK","DHCPDISCOVER","DHCPRELEASE"])
    mac    = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
    ip     = pick(INTERNAL_IPS)
    host   = pick([f"LAPTOP-{random.randint(100,999)}",
                   f"DESKTOP-{random.randint(100,999)}",
                   f"MOBILE-{random.randint(100,999)}"])
    return (
        f"{syslog_ts()} {srv} dhcpd: "
        f"{action} for {ip} from {mac} ({host}) via eth0"
    )

# ── 10. VPN GATEWAY ──────────────────────────────────────────────────────────
def gen_vpn():
    user     = pick(USERS)
    ext_ip   = external_ip()
    int_ip   = internal_ip()
    action   = pick(["CONNECTED","DISCONNECTED","AUTH_FAILED","TUNNEL_UP","TUNNEL_DOWN"])
    proto    = pick(["IKEv2","SSL-VPN","OpenVPN","IPSec"])
    duration = f"{random.randint(0,8)}h {random.randint(0,59)}m"
    bytes_in = rnd_bytes()
    bytes_out= rnd_bytes()
    return (
        f"{syslog_ts()} vpn-gw-01 vpnd[{random.randint(1000,9999)}]: "
        f"User={user} Action={action} Proto={proto} "
        f"ExtIP={ext_ip} IntIP={int_ip} "
        f"BytesIn={bytes_in} BytesOut={bytes_out} Duration={duration}"
    )

# ── 11. ANTIVIRUS / EDR ───────────────────────────────────────────────────────
def gen_av():
    srv_name, _ = server_pair()
    user    = pick(USERS)
    action  = pick(["DETECTED","QUARANTINED","BLOCKED","CLEANED","ALLOWED"])
    threats = [
        "Trojan.GenericKD.46501823","Win32.Ransomware.WannaCry",
        "Exploit.EternalBlue.CVE-2017-0144","Backdoor.Cobalt.Strike",
        "PUP.Optional.OpenCandy","Trojan.Mimikatz","EICAR-Test-File",
        "Rootkit.Necurs","Worm.Conficker","Adware.BrowseFox",
    ]
    threat = pick(threats)
    path   = pick([
        f"C:\\Users\\{user}\\Downloads\\invoice.exe",
        f"C:\\Temp\\payload.dll",
        f"C:\\Windows\\Temp\\svch0st.exe",
        f"C:\\Users\\{user}\\AppData\\Local\\update.exe",
        "/tmp/exploit.sh","/var/tmp/shell.elf",
    ])
    return (
        f"{syslog_ts()} {srv_name} CrowdStrike[AV]: "
        f"Threat={threat} Action={action} "
        f"User={user} Path={path} SHA256={random.randbytes(32).hex()}"
    )

# ── ATTACK SIMULATION EVENTS (--attack flag) ──────────────────────────────────
def gen_attack_event():
    attack_type = pick([
        "brute_force","sql_injection","port_scan","lateral_movement",
        "data_exfil","c2_beacon","privilege_escalation","ransomware",
    ])
    attacker = malicious_ip()
    victim   = pick(INTERNAL_IPS)
    user     = pick(PRIV_USERS)

    if attack_type == "brute_force":
        return (
            f"{syslog_ts()} dc01.corp.local MSWinEventLog Security "
            f"EventID=4625 FailureReason=%%2313 "
            f"TargetUserName={user} IpAddress={attacker} "
            f"AttemptCount={random.randint(50,500)} ATTACK=BRUTE_FORCE"
        )
    elif attack_type == "sql_injection":
        payloads = ["' OR '1'='1","' UNION SELECT NULL--","'; DROP TABLE users--",
                    "' AND 1=1--","admin'--"]
        return (
            f'{syslog_ts()} webserver01 access_log: {attacker} - - '
            f'[{ts_now()}] "GET /login?user={pick(payloads)} HTTP/1.1" '
            f'500 512 "-" "sqlmap/1.7" ATTACK=SQL_INJECTION'
        )
    elif attack_type == "port_scan":
        return (
            f"{syslog_ts()} ids-sensor-01 snort[9999]: [1006:1] "
            f"ET SCAN Nmap SYN Scan [HIGH] "
            f"{{TCP}} {attacker}:{rnd_port()} -> {victim}:{random.randint(1,1024)} "
            f"Action=alert ATTACK=PORT_SCAN"
        )
    elif attack_type == "lateral_movement":
        return (
            f"{syslog_ts()} {pick(list(SERVERS.keys()))} MSWinEventLog Security "
            f"EventID=4648 SubjectUserName={user} TargetServerName={pick(list(SERVERS.keys()))} "
            f"IpAddress={victim} LogonType=3 ATTACK=LATERAL_MOVEMENT"
        )
    elif attack_type == "data_exfil":
        return (
            f"{syslog_ts()} fw-perimeter-01 TRAFFIC action=ALLOW "
            f"srcip={victim} dstip={attacker} dport=443 proto=TCP "
            f"bytes={random.randint(50000000,500000000)} ATTACK=DATA_EXFIL"
        )
    elif attack_type == "c2_beacon":
        c2_domains = ["evil-c2-domain.xyz","update-svc.ru","cdn-microsoft-update.com"]
        return (
            f"{syslog_ts()} ids-sensor-01 snort[9999]: [1008:1] "
            f"ET DNS Query to Known Malware C2 [CRITICAL] "
            f"{victim} querying {pick(c2_domains)} ATTACK=C2_BEACON"
        )
    elif attack_type == "privilege_escalation":
        return (
            f"{syslog_ts()} {pick(list(SERVERS.keys()))} MSWinEventLog Security "
            f"EventID=4672 SubjectUserName={user} PrivilegeList=SeTakeOwnershipPrivilege,SeDebugPrivilege "
            f"IpAddress={victim} ATTACK=PRIV_ESCALATION"
        )
    else:  # ransomware
        return (
            f"{syslog_ts()} fileserver01 CrowdStrike[AV]: "
            f"Threat=Win32.Ransomware.BlackCat Action=DETECTED "
            f"User={user} Path=C:\\Users\\{user}\\Documents\\.locked "
            f"FilesEncrypted={random.randint(100,5000)} ATTACK=RANSOMWARE"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE REGISTRY — weight = relative frequency
# ═══════════════════════════════════════════════════════════════════════════════
SOURCES = [
    (gen_firewall,        "Firewall-PaloAlto",  15),
    (gen_cisco_asa,       "Firewall-CiscoASA",  10),
    (gen_windows_security,"Windows-Security",   20),
    (gen_linux_syslog,    "Linux-Syslog",       15),
    (gen_network_device,  "Network-Device",     10),
    (gen_web_server,      "WebServer-Access",   10),
    (gen_ids,             "IDS-Snort",           8),
    (gen_dns,             "DNS-Server",          5),
    (gen_dhcp,            "DHCP-Server",         3),
    (gen_vpn,             "VPN-Gateway",         5),
    (gen_av,              "AV-EDR",              5),
]

# Build weighted pool
POOL = []
for fn, src, weight in SOURCES:
    POOL.extend([(fn, src)] * weight)


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT TRANSPORTS
# ═══════════════════════════════════════════════════════════════════════════════

def send_syslog(message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message.encode(), (args.host, args.port))

def send_hec(message: str, sourcetype: str):
    payload = {
        "time":       time.time(),
        "host":       "log-generator",
        "sourcetype": sourcetype,
        "event":      message,
    }
    try:
        r = requests.post(
            f"https://{args.host}:{args.hec_port}/services/collector/event",
            headers={"Authorization": f"Splunk {args.hec_token}"},
            json=payload,
            timeout=3,
            verify=False,
        )
        if r.status_code != 200:
            log.warning(f"HEC returned {r.status_code}: {r.text}")
    except Exception as e:
        log.error(f"HEC error: {e}")

file_handle = None
if args.mode == "file":
    file_handle = open(args.output, "a", encoding="utf-8")

def output(message: str, sourcetype: str):
    if args.mode == "syslog":
        send_syslog(message)
    elif args.mode == "hec":
        send_hec(message, sourcetype)
    else:
        file_handle.write(message + "\n")
        file_handle.flush()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    delay     = 1.0 / args.eps
    start     = time.time()
    count     = 0
    attack_every = 20  # inject attack event every N events (if --attack)

    log.info(f"═══ Splunk Log Generator — Muhammad Eissa / ESLabs Academy ═══")
    log.info(f"Mode       : {args.mode.upper()}")
    if args.mode in ("syslog","hec"):
        log.info(f"Target     : {args.host}:{args.port if args.mode == 'syslog' else args.hec_port}")
    else:
        log.info(f"Output file: {args.output}")
    log.info(f"EPS        : {args.eps}")
    log.info(f"Duration   : {'forever' if args.duration == 0 else str(args.duration) + 's'}")
    log.info(f"Attack sim : {'ON' if args.attack else 'OFF'}")
    log.info(f"Sources    : {len(SOURCES)}")
    log.info("Starting generation... Ctrl+C to stop.\n")

    try:
        while True:
            if args.duration > 0 and (time.time() - start) >= args.duration:
                break

            # Occasional attack event injection
            if args.attack and count > 0 and count % attack_every == 0:
                msg = gen_attack_event()
                output(msg, "ATTACK-SIM")
                log.warning(f"[ATTACK] {msg[:100]}...")
            else:
                fn, sourcetype = pick(POOL)
                msg = fn()
                output(msg, sourcetype)

                if count % 100 == 0:
                    elapsed = time.time() - start
                    actual_eps = count / elapsed if elapsed > 0 else 0
                    log.info(f"[{count:>8}] Events sent | EPS: {actual_eps:.1f} | Source: {sourcetype}")

            count += 1
            time.sleep(delay)

    except KeyboardInterrupt:
        log.info("\nStopped by user.")
    finally:
        elapsed = time.time() - start
        log.info(f"\n{'═'*55}")
        log.info(f"Total events : {count:,}")
        log.info(f"Duration     : {elapsed:.1f}s")
        log.info(f"Average EPS  : {count/elapsed:.1f}")
        log.info(f"{'═'*55}")
        if file_handle:
            file_handle.close()

if __name__ == "__main__":
    main()
