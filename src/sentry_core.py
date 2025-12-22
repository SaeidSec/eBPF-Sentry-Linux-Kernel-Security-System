#!/usr/bin/python3
import argparse
import json
import logging
import re
import socket
import sys
import threading
import yaml
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
import os
import signal

# Try to import watchdog for auto-reloading rules
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from bcc import BPF
from ctypes import (
    Structure, Union, POINTER,
    c_uint, c_uint64, c_uint32, c_ushort,
    c_char, c_uint8, cast
)

# ==================== GLOBALS ====================
RULES = {}
WHITELIST = set()
RULES_LOCK = threading.Lock()
IPS_MODE = False
IDS_LOGGER = None
IPS_LOGGER = None
bpf_ctx = None  

# ==================== STRUCTS ====================
class Daddr(Union):
    _fields_ = [("v4_addr", c_uint32), ("v6_addr", c_uint8 * 16)]

class SentryEvent(Structure):
    _fields_ = [
        ("type", c_uint), ("timestamp", c_uint64),
        ("pid", c_uint32), ("ppid", c_uint32),
        ("comm", c_char * 16), ("parent_comm", c_char * 16),
        ("filename", c_char * 256),
        ("family", c_ushort), ("dport", c_ushort),
        ("daddr", Daddr),
    ]

# ==================== LOGGING ====================
def setup_logging(logfile_ids="ids_alerts.json", logfile_ips="ips_actions.log"):
    global IDS_LOGGER, IPS_LOGGER
    # IDS/Alert Logger
    IDS_LOGGER = logging.getLogger('SENTRY_IDS')
    IDS_LOGGER.setLevel(logging.INFO)
    if IDS_LOGGER.handlers:
        IDS_LOGGER.handlers.clear()
    formatter = logging.Formatter('%(message)s') # JSON formatted
    fh = logging.FileHandler(logfile_ids)
    fh.setFormatter(formatter)
    IDS_LOGGER.addHandler(fh)
    IDS_LOGGER.addHandler(logging.StreamHandler(sys.stdout))

    # IPS/Action Logger
    IPS_LOGGER = logging.getLogger('SENTRY_IPS')
    IPS_LOGGER.setLevel(logging.INFO)
    if IPS_LOGGER.handlers:
        IPS_LOGGER.handlers.clear()
    ips_fh = logging.FileHandler(logfile_ips)
    ips_fh.setFormatter(logging.Formatter('%(asctime)s - [BLOCKED] %(message)s'))
    IPS_LOGGER.addHandler(ips_fh)

# ==================== CONFIGURATION LOADING ====================
def load_config(rule_file, whitelist_file):
    global RULES, WHITELIST
    
    # Load Rules
    try:
        with open(rule_file, 'r') as f:
            data = yaml.safe_load(f) or {}
            # Pre-compile regexes for performance
            for rule in data.get('rules', []):
                if not rule.get('enabled', False):
                    continue
                for k in list(rule.get('match', {})):
                    if k.endswith('_regex'):
                        rule['match'][k + '_compiled'] = re.compile(rule['match'][k])
                if rule.get('stateful') and 'source_event_match' in rule['stateful']:
                    sm = rule['stateful']['source_event_match']
                    for k in list(sm):
                        if k.endswith('_regex'):
                            sm[k + '_compiled'] = re.compile(sm[k])
            with RULES_LOCK:
                RULES = data
            print(f"[INFO] Loaded {len(data.get('rules', []))} security rules.")
    except Exception as e:
        print(f"[ERROR] Rule load failed: {e}")

    # Load Whitelist
    try:
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                wl_data = yaml.safe_load(f) or {}
                with RULES_LOCK:
                    WHITELIST = set(wl_data.get('processes', []))
            print(f"[INFO] Loaded {len(WHITELIST)} whitelisted processes.")
        else:
            print("[INFO] No whitelist file found. Continuing without whitelist.")
    except Exception as e:
        print(f"[ERROR] Whitelist load failed: {e}")

# ==================== WATCHDOG HANDLER ====================
class ConfigChangeHandler(FileSystemEventHandler):
    def __init__(self, rule_file, whitelist_file):
        self.rule_file = os.path.abspath(rule_file)
        self.whitelist_file = os.path.abspath(whitelist_file)

    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path == self.rule_file or event.src_path == self.whitelist_file:
            print(f"[INFO] Configuration changed: {event.src_path} -> Reloading...")
            load_config(self.rule_file, self.whitelist_file)

# ==================== HELPERS ====================
def ip_to_str(union, family):
    if family == socket.AF_INET:
        return str(IPv4Address(union.v4_addr))
    if family == socket.AF_INET6:
        return str(IPv6Address(bytes(union.v6_addr)))
    return "unknown"

def log_alert(rule, event, details=""):
    alert = {
        "timestamp": datetime.now().isoformat(),
        "tool": "eBPF-Sentry",
        "rule_name": rule['name'],
        "severity": rule.get('severity', 'info'),
        "description": rule['description'],
        "process": event.comm.decode('utf-8', 'replace').strip('\x00'),
        "pid": event.pid,
        "parent_process": event.parent_comm.decode('utf-8', 'replace').strip('\x00'),
        "ppid": event.ppid,
        "details": details
    }
    IDS_LOGGER.warning(json.dumps(alert))

def enforce_policy_kill(pid, rule_name, info):
    try:
        os.kill(pid, signal.SIGKILL)
        IPS_LOGGER.warning(f"PID {pid} TERMINATED -> {info} | Rule: {rule_name}")
    except ProcessLookupError:
        pass # Process already gone
    except PermissionError:
        IPS_LOGGER.error(f"Kill failed PID {pid}: Permission denied")
    except Exception as e:
        IPS_LOGGER.error(f"Kill failed PID {pid}: {e}")

# ==================== EVENT ANALYSIS ====================
def analyze_simple_event(rule, event):
    """Check standard EXEC or CONNECT events against rules."""
    data = {}
    if event.type == 0:  # EXEC
        data['filename'] = event.filename.decode('utf-8','replace').strip('\x00')
        data['child_process'] = event.comm.decode('utf-8','replace').strip('\x00')
        data['parent_process'] = event.parent_comm.decode('utf-8','replace').strip('\x00')
    
    for k, regex in rule.get('match', {}).items():
        if not k.endswith('_compiled'):
            continue
        field = k.replace('_regex_compiled', '')
        # Special handling if needed, or generic field lookup
        if field not in data and field == 'comm': # fallback
             data['comm'] = event.comm.decode('utf-8','replace').strip('\x00')
             
        if field in data and regex.search(data[field]):
            continue
        return False, ""
        
    return True, "Pattern matched"

def analyze_stateful_event(rule, event):
    """Check if this CONNECT event is linked to a previously tainted process (e.g. sensitive file open)."""
    global bpf_ctx
    if bpf_ctx is None: return False, ""

    tainted_map = bpf_ctx["tainted_procs"]
    key = c_uint32(event.ppid)

    # 1. Check if parent PPID is in tainted map
    if key not in tainted_map:
        return False, ""

    # 2. Check time window
    try:
        taint_ts = tainted_map[key].value
    except:
        return False, ""

    window_ns = rule['stateful']['time_window_seconds'] * 1_000_000_000
    if event.timestamp - taint_ts <= window_ns:
        target_ip = ip_to_str(event.daddr, event.family)
        # Cleanup map
        try:
            del tainted_map[key]
        except:
            pass 
        return True, f"Tainted process initiated connection to {target_ip}:{event.dport}"
    
    return False, ""

def process_open_event(event):
    """When a file Open event occurs, check if it matches a 'source' rule to taint the process."""
    global bpf_ctx
    if bpf_ctx is None: return

    filename = event.filename.decode('utf-8','replace').strip('\x00')
    tainted_map = bpf_ctx["tainted_procs"]
    key = c_uint32(event.ppid)
    val = c_uint64(event.timestamp)

    with RULES_LOCK:
        for rule in RULES.get('rules', []):
            if not rule.get('enabled', False) or not rule.get('stateful'):
                continue
            src = rule['stateful'].get('source_event_match', {})
            if src.get('event', '').upper() != 'OPEN':
                continue
            
            regex = src.get('filename_regex_compiled')
            if regex and regex.search(filename):
                try:
                    tainted_map[key] = val
                    # Debug print could go here
                except:
                    pass
                break

# ==================== MAIN CALLBACK ====================
def handle_event(cpu, data, size):
    try:
        event = cast(data, POINTER(SentryEvent)).contents
        process_name = event.comm.decode('utf-8', 'replace').strip('\x00')

        # 1. WHITELIST CHECK
        if process_name in WHITELIST:
            return

        # 2. OPEN Event -> Potential Taint
        if event.type == 2:
            process_open_event(event)
            return

        # 3. Security Rule Check
        with RULES_LOCK:
            if not RULES:
                return

            for rule in RULES.get('rules', []):
                if not rule.get('enabled', False):
                    continue

                matched = False
                details = ""
                
                # Logic for EXEC (0) and CONNECT (1)
                is_exec = (event.type == 0 and rule['event'].upper() == "EXEC")
                is_connect = (event.type == 1 and rule['event'].upper() == "CONNECT")

                if not rule.get('stateful'):
                    if is_exec or is_connect:
                        # For simple rules, we might need to implement specific matching in analyze_simple_event
                        # Here assuming simple regex matching on avail fields
                        # Note: original code had specific simple matching logic. 
                        # We'll rely on the rule definitions.
                         matched, details = analyze_simple_event(rule, event)
                
                elif rule.get('stateful') and is_connect:
                     matched, details = analyze_stateful_event(rule, event)

                if matched:
                    log_alert(rule, event, details)
                    
                    # IPS Action
                    if IPS_MODE and rule.get('severity', '').lower() == 'high' and event.pid > 1:
                        target = f" -> {ip_to_str(event.daddr, event.family)}" if is_connect else ""
                        enforce_policy_kill(event.pid, rule['name'], f"{process_name}{target}")

    except Exception as e:
        pass # Suppress runtime errors in fast path

# ==================== CLI & INIT ====================
def print_banner():
    print("""
    \033[1;36m
    ==========================================
         eBPF-Sentry | Linux Kernel Security
    ==========================================
    \033[0m
    1. Monitor Mode (IDS)
    2. Active Defense Mode (IDS + IPS)
    3. Exit
    """)

if __name__ == "__main__":
    # Get the directory where this script is located (src/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to project root
    project_root = os.path.dirname(script_dir)
    
    # Construct absolute default paths
    default_config = os.path.join(project_root, "config", "security_rules.yaml")
    default_whitelist = os.path.join(project_root, "config", "whitelist.yaml")
    default_ebpf = os.path.join(script_dir, "bpf", "sentry_probe.c")

    parser = argparse.ArgumentParser(description="eBPF-Sentry Security Tool")
    parser.add_argument("--config", default=default_config, help="Path to rules")
    parser.add_argument("--whitelist", default=default_whitelist, help="Path to process whitelist")
    parser.add_argument("--ebpf", default=default_ebpf, help="Path to eBPF source")
    args = parser.parse_args()

    print_banner()
    choice = input("Select Mode [1-3]: ").strip()
    if choice == "3":
        sys.exit(0)
    
    IPS_MODE = (choice == "2")
    
    setup_logging()
    load_config(args.config, args.whitelist)
    
    print(f"\n[INFO] Initializing eBPF-Sentry in {'ACTIVE DEFENSE' if IPS_MODE else 'MONITOR'} mode...")

    # Start Watchdog
    if WATCHDOG_AVAILABLE:
        obs = Observer()
        config_dir = os.path.dirname(args.config)
        obs.schedule(ConfigChangeHandler(args.config, args.whitelist), path=config_dir, recursive=False)
        obs.start()
    
    # Init BPF
    try:
        bpf_ctx = BPF(src_file=args.ebpf)
    except Exception as e:
        print(f"[ERROR] Failed to compile eBPF probe: {e}")
        sys.exit(1)

    # Attach Probes
    print("[INFO] Attaching kernel probes...")
    try:
        bpf_ctx.attach_kprobe(event="tcp_connect", fn_name="capture_connect")
        bpf_ctx.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="capture_exec")
        bpf_ctx.attach_tracepoint(tp="syscalls:sys_enter_open", fn_name="capture_open")
        bpf_ctx.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="capture_openat")
    except Exception as e:
         print(f"[ERROR] Probe attachment failed: {e}")

    # Open Perf Buffer
    bpf_ctx["sentry_events"].open_perf_buffer(handle_event)
    
    print("\n\033[1;32m[SUCCESS] SYSTEM ARMED AND RUNNING.\033[0m")
    print("Logs: ids_alerts.json | ips_actions.log")
    
    try:
        while True:
            bpf_ctx.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[INFO] Disarming...")
    finally:
        if 'obs' in locals():
            obs.stop()
            obs.join()

