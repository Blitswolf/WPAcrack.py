# wpacrack

Autonomous, lockout-safe WPA2 handshake **capture appliance** for a single **authorized** access
point. Built to run headless on a Raspberry Pi (Kali) as a systemd service: kick it off, drop the
SSH session, and come back to a status/result beacon.

It captures and validates a 4-way handshake and hands you a **hashcat-ready** file — it does **not**
crack the key itself. See "Why capture-only" below.

> ⚠️ **Authorized use only.** This tool deauthenticates clients of, and captures the handshake for,
> the one AP you name in `wpacrack.conf`. Run it **only** against a network you own or are explicitly
> authorized to test. It refuses to start without a configured target BSSID, specifically so it can
> never wander onto a neighbouring network.

---

## Why capture-only (the Pi doesn't crack)

WPA2 keys are derived with PBKDF2-HMAC-SHA1 at 4096 iterations — a deliberately slow hash. A
Raspberry Pi CPU manages only a few thousand guesses/second, so a rockyou run can take **hours**,
and rules/large lists are simply impractical. The same handshake on a modest laptop GPU
(`hashcat -m 22000`) runs **orders of magnitude faster** — rockyou finishes in *seconds*.

So wpacrack splits the work along the right seam:

- **The Pi does what it's good at:** reliably *capturing and validating* a handshake, patiently,
  headless, over hours if needed — then converting it to hashcat's `22000` format.
- **A GPU box does the cracking:** you copy the `.22000` file off and run hashcat there.

## Why "lockout-safe"

The point is to obtain the handshake **without tripping an authentication lockout or a WIDS ban**:

- **No online guessing, ever.** wpacrack only *captures* a handshake; the PSK is cracked offline
  on another machine. It never presents guessed keys to the live AP, so there is no failed-auth
  lockout to trip.
- **Gentle, capped, targeted deauth.** It listens passively first (a naturally rejoining client
  can hand over the handshake with **zero** deauth). If it must nudge, it sends a single minimal,
  **client-targeted** round (never a broadcast flood), spaced with jitter, under a **hard cap**
  on total rounds (`DEAUTH_ROUND_CAP`), after which it goes passive-only.
  - *Honest note on frame counts:* `aireplay-ng --deauth N` sends N **rounds of 64 frames**, not N
    frames. wpacrack therefore counts *rounds* (default 1 round/burst) and reports an estimated
    frame total in its status, so "gentle" means gentle in reality — not just on paper.

## How it works

```
monitor mode ─▶ capture 4-way handshake ─▶ convert to hashcat 22000 ─▶ restore box
   (wlan1)      (passive-first, then          (hcxpcapngtool, if           (managed mode,
                 gentle capped deauth)          present) + deliver           NM up, netwatch on)
                                                to home dirs
                                                        │
                                                        ▼
                                        crack OFF-BOX:  hashcat -m 22000
```

1. Pauses `netwatch` (interface self-heal), stops NetworkManager/wpa_supplicant, puts the
   interface into monitor mode.
2. Rotates across the configured BSSIDs/channels (e.g. the 2.4 GHz and 5 GHz BSS of one AP),
   listening for and (gently) eliciting a 4-way handshake, validated with `tshark` (EAPOL frames
   both to and from the AP for a common station).
3. On capture: converts to `wpa.22000` with `hcxpcapngtool` (if installed) and copies the
   handshake + hash to the home dirs for an easy pull. **No cracking.**
4. Restores managed mode, brings NetworkManager back, re-enables `netwatch`.
5. Writes a final result file with the exact off-box crack commands. Beacons progress throughout.

## Requirements

- Kali (or similar) with the `aircrack-ng` suite (`airodump-ng`, `aireplay-ng`), `iw`, `tshark`,
  and NetworkManager (`nmcli`).
- **`hcxtools`** (`hcxpcapngtool`) — *optional*; if absent, the `.cap` is still delivered and you
  convert it on the cracking box.
- A monitor-mode-capable adapter (developed against a Realtek RTL8812AU).
- Python 3, standard library only — no pip dependencies.
- **No hashcat/GPU on the Pi** — cracking happens elsewhere.

## Install

```bash
sudo mkdir -p /opt/wpacrack
sudo cp wpacrack.py /opt/wpacrack/
sudo cp wpacrack.conf.example /opt/wpacrack/wpacrack.conf   # then edit for your AP
sudo cp wpacrack-start wpacrack-stop wpacrack-status /usr/local/bin/ && sudo chmod +x /usr/local/bin/wpacrack-*
sudo cp wpacrack.service /etc/systemd/system/ && sudo systemctl daemon-reload
```

Edit `/opt/wpacrack/wpacrack.conf` to point at your authorized AP (see `wpacrack.conf.example`).

## Usage

```bash
sudo wpacrack-start     # begin capture (safe to disconnect afterwards)
sudo wpacrack-status    # phase, elapsed, deauth budget used, and final RESULT when done
sudo wpacrack-stop      # stop early; the box is restored to managed mode either way
```

When it finishes, `RESULT.txt` (and `~/wpacrack_RESULT.txt`) contains the handshake path and the
exact commands to crack it off-box. Then, on your GPU machine:

```bash
scp <pi>:/opt/wpacrack/wpa.22000 .
hashcat -m 22000 -a 0 wpa.22000 /path/to/rockyou.txt
# escalate if needed: add rules (-r rules/best64.rule) or a larger list
```

## Configuration (`wpacrack.conf`)

| key            | meaning                                                            |
|----------------|--------------------------------------------------------------------|
| `iface`        | monitor/managed interface (e.g. `wlan1`)                           |
| `essid`        | target SSID (label only)                                           |
| `targets`      | `BSSID:CHANNEL` pairs, comma-separated (2.4 GHz first = preferred) |
| `custom_seeds` | *optional* seed words; emitted as `candidates.txt` to copy to the cracking box (not used here) |

Capture/deauth tuning constants live at the top of `wpacrack.py`.

## Output (`/opt/wpacrack/`)

- `STATUS.txt` — live phase / elapsed / deauth-budget beacon
- `RESULT.txt` — final outcome + off-box crack commands (also `~/wpacrack_RESULT.txt`)
- `handshake.cap` — the captured handshake (also copied to the home dirs)
- `wpa.22000` — hashcat-ready hash (if `hcxpcapngtool` was available)
- `candidates.txt` — optional targeted candidate list from your seeds
- `wpacrack.log` — timestamped log

`wpacrack.conf` and every runtime artifact are `.gitignore`d, so no site identifiers or captures
are ever committed.

## Companion: `markovgen` — smarter-than-a-wordlist candidate generation

`markovgen.py` is a standalone candidate generator for the crack step. A static leak list like
rockyou can only ever produce passwords that were *already breached* — if the target's password
was never leaked, rockyou can't find it (exactly what happened in testing here). `markovgen`
instead **learns the character-level structure** of human passwords by training an order-k Markov
model on a corpus, then **generates candidates — including novel ones — in descending probability
order**.

The applied-CS core is the ordered enumeration: it's a **best-first (uniform-cost) search** over
the weighted trie of prefixes. Each partial string is a search node whose cost is the summed
negative log-probability of its characters; expanding the lowest-cost node and emitting completed
words yields candidates in (near-)optimal probability order. An optional `--beam` bounds the
frontier, turning exact best-first into memory-bounded beam search.

Why it beats a raw wordlist for WPA:
- **generalises** beyond the training leak (emits plausible unseen strings)
- **most-probable-first**, so early guesses carry the most weight
- **respects WPA's 8-char minimum** (rockyou wastes ~a third of its lines on <8)
- **seedable** with target words (name/SSID/org), which are tried first

Pipe it straight into hashcat's stdin mode:

```bash
./markovgen.py --train /usr/share/wordlists/rockyou.txt --order 3 --count 5000000 \
    --seed Smith --seed Acme | hashcat -m 22000 wpa.22000
```

Key flags: `--order` (context length), `--count` (max candidates), `--minlen/--maxlen`,
`--beam` (frontier bound; `0` = exact best-first), `--alpha` (back-off penalty), `--seed`
(repeatable), `--train-limit`, `--save-model`/`--model`.

### Model quality: back-off + train once, reuse

- **Katz-style back-off.** A high-order context that was never seen in training falls back to the
  longest shorter context that was, instead of dead-ending. This is what makes `--order 4`/`5`
  usable rather than sparse.
- **Train once, reuse.** Training is the slow part; do it once and cache the model:
  ```bash
  ./markovgen.py --train corpus.txt --order 3 --save-model corpus.mdl
  ./markovgen.py --model corpus.mdl --count 5000000 | hashcat -m 22000 wpa.22000
  ```

### Better training data than rockyou

rockyou (2009, ~14M, English-skewed) is a fine start but limited. A richer, more current, more
multilingual model comes from concatenating several corpora before training — e.g. rockyou +
SecLists `Pwdb_top-10000000`, `xato-net-10-million-passwords`, `md5decryptor-uk`, `openwall.net-all`.
More data = better character statistics = better-ordered guesses. (Don't bother de-duplicating for a
Markov model — repeated passwords rightly raise their own probability.)

### Making the most of the hardware

The model/generation runs on CPU; hashcat runs on the GPU. To keep a fast GPU saturated, don't rely
on the Python generator's throughput as the bottleneck — **pre-generate a candidate file, then let
hashcat rip through it** with an optimized, max-workload profile:

```bash
./markovgen.py --model corpus.mdl --count 50000000 -o cands.txt   # CPU, one-time
hashcat -m 22000 -w 4 -O wpa.22000 cands.txt                      # GPU flat-out (-w4 max, -O optimized)
```

`-w 4` is the maximum workload profile; `-O` uses optimized kernels (much faster, caps candidate
length — fine for WPA). Piping straight into hashcat still works and is simplest, but a file lets
the GPU run without waiting on the generator.

### The pipeline

```
   Pi (wpacrack)                 GPU box
 ┌───────────────┐   scp    ┌──────────────────────────────────┐
 │ capture 4-way │ ──────▶  │ markovgen ──stream──▶ hashcat -m  │
 │ → wpa.22000   │  .22000  │ (ordered guesses)      22000      │
 └───────────────┘          └──────────────────────────────────┘
   capture appliance          smart generation + fast cracking
```

## The continuous stack (distributed, two-Pi)

Beyond the one-shot capture, the tools compose into a standing pipeline across two machines:

```
        kali-pie  (capture + research)                    home-pie  (crack)
 ┌──────────────────────────────────────────┐      ┌───────────────────────────────┐
 │ wpacrack --harvest   (systemd service)     │      │ pull handshakes from library  │
 │   monitor mode set ONCE, loops the         │ scp  │ markovgen(model) │ hashcat     │
 │   authorized targets, archives handshakes  │─────▶│ (smart ordered candidates)    │
 │   -> /opt/wpacrack/library/<bssid>/*.22000 │      └───────────────────────────────┘
 │                                            │
 │ apresearch  (continuous, Nice=19)          │   exploit-intelligence MODEL: when
 │   builds a TF-IDF index over the local     │   searchsploit finds nothing, it infers
 │   exploit-db, infers nearest analogues +   │   the likely vuln classes and mines a
 │   vuln-class predictions + a mined test    │   concrete test plan from neighbours'
 │   plan from the AP fingerprint             │   exploit code — uses the idle cores.
 │ apvulnd    (hourly timer, Nice=19)         │
 │   fingerprints the AP from harvested       │
 │   beacons (WPS/RSN/PMF/cipher/vendor),     │
 │   searchsploit, and — when the AP is       │
 │   reachable — a bounded, non-destructive   │
 │   discovery sweep. Recon only, no lockout. │
 └──────────────────────────────────────────┘
```

### `wpacrack --harvest`
Continuous capture into a library on the capture box's disk. Sets monitor mode **once** (no
per-cycle NetworkManager churn), loops the authorized `targets`, archives each handshake under
`library/<bssid>/<ts>.{cap,22000}`, and idles once every target has a handshake newer than
`refresh_ttl`. Config keys: `library`, `cooldown`, `refresh_ttl`. Runs as `wpacrack-harvest.service`.

### `apvulnd` — AP vuln research (recon, not attack)
A low-priority timer that fingerprints the AP from the harvested beacons (vendor/OUI, WPS presence +
lock state + model, RSN AKM = WPA2 vs WPA3/SAE, pairwise cipher, PMF), derives a posture with
findings, runs `searchsploit`, and — only when the AP's management IP (`ap_mgmt_ip`) is reachable —
runs a **bounded, non-destructive** discovery sweep (service/version + light rate-limited web
enumeration). It never brute-forces WPS PINs or logins, so it can't trip a lockout.

### `apresearch` — exploit-intelligence model
The vuln-side counterpart to markovgen: a TF-IDF (word + char-4-gram) similarity model over the
local exploit-db (~47k entries). Given the AP fingerprint it returns the **nearest analogues**
(fuzzy — catches what an exact `searchsploit` grep misses), **predicts vulnerability classes**, and
deep-mines the top neighbours' exploit source for concrete **endpoints / parameters / payloads** to
test — a self-generated research plan for when exact exploit data doesn't exist. Runs continuously at
`Nice=19` / idle IO so a capture box's spare cores are actually put to work. Modes: `build`,
`predict TERMS...`, `serve`. Pure stdlib, so it **relocates** to a bigger box (e.g. the crack Pi) and
scales up (larger corpus, full-text index) unchanged.

## Notes / limitations

- If no handshake appears within the capture budget, it exits cleanly and tells you to retry when
  a client is powered on and associated (a handshake requires a client to (re)join).
- Adapter stability matters: the capture step needs reliable monitor mode + injection.
- Cracking is out of scope by design — bring your own GPU box and wordlists.

---

## WPS attack module (`wps_attack.py`) — lockout-safe, opt-in, **continual service**

A third leg of the kali-pie stack that recovers a WPA key via **WPS** when the
handshake won't crack. It runs as a **continual systemd service** that shares the
single `wlan1` radio with the WPA harvest through a file lock, so the two never
transmit at once and neither knocks the other off the air.

**Sequence (authorized targets only):**
1. **Recon** — `wash` on the target channel; proceed **only** if WPS is present
   **and not locked**. Otherwise report and stop — never attack blind.
2. **Pixie-dust** — offline-ish `reaver -K`, then `bully -d` as an alternate.
   Cheapest, lowest-noise shot. Success -> loot, done.
3. **Online PIN** — conservative `reaver` (`-d 15 -r 3:60 --lock-delay 300`)
   **only** if pixie failed, and it **aborts the instant** the AP signals a
   lock / rate-limit. Losing a run is fine; locking the AP is not.

**Never drives an AP into lockout:** lock/rate-limit detection with immediate
back-off, `-r`/`-d` throttling, no `--ignore-locks`, and a per-target cooldown
(6 h after a no-result, 24 h after any lock signal) so the continual loop can
never grind a target toward a blacklist — "continual" never means "hammering".

**Radio coexistence with the harvest:** both stay in **monitor** mode (no
managed/monitor churn). A shared flock at `/opt/wpacrack/.radio.lock` serialises
*who transmits*: the harvest holds it during a capture pass and releases it for
the cooldown, which is exactly when the WPS service takes its turn. WPS is
opportunistic — it waits for spare radio time and **never interrupts a capture**.

**Opt-in gate:** ships **disarmed**. Nothing transmits until `wps_enabled = true`
in `wpacrack.conf`; the running service re-reads the gate each cycle, so
`sudo wps-arm` / `sudo wps-disarm` take effect without a restart.

**Pipeline wiring:** `wps-attack.service` (`Type=simple`, `Nice=19`, idle IO,
`--daemon`) — continually active, up on boot and while the rig is already up.
Loot -> `/opt/wpacrack/loot/<BSSID>/<ts>.loot` plus `wps_loot.txt` in the home
dirs (mirrors how the harvest stores handshakes). Status -> `WPS_STATUS.txt`,
log -> `wps.log`.

**Helpers:** `wps-status`, `wps-run` (force an immediate sweep), `wps-arm`,
`wps-disarm`.

---

## Evil-twin module (`eviltwin.py`) — opt-in, time-bounded PSK credential capture

The recovery path when a PSK beats offline cracking **and** WPS. Instead of attacking the hash it
targets the human: stands up an **open AP impersonating the authorized ESSID**, a captive portal
asks the user to "re-enter the Wi-Fi password", and **every submission is validated against a real
4-way handshake we already captured** (`aircrack-ng`). Only the correct PSK is accepted — no
guessing, no false loot.

**Gated harder than WPS (it deceives a person):** hard scope-lock to the one authorized ESSID/BSSID;
opt-in `eviltwin_enabled`; **start-on-demand only, never enabled at boot**; a single **time-bounded**
session per start (TTL then full teardown); auto-disarm + loot on success; always tears the AP down
on exit/signal. Refuses to run if no captured handshake exists to validate against.

**Broken-chipset handling (radio auto-selection):** an evil twin needs a radio that can *sustain
AP-mode TX*. Some chipsets (e.g. **mt76x0u / Alfa AWUS036ACHM**) bring the AP up but then fail to
transmit beacons/probe-responses (`Failed to set beacon parameters`), so clients never join. The
module **health-probes each radio** (`eviltwin-radiocheck`), skips the Pi's built-in wifi and the
harvest radio, and if no dedicated radio passes it **falls back to borrowing the reliable harvest
radio** (RTL8812AU) via the shared `.radio.lock` (time-sliced, monitor restored after) — optionally
pre-herding clients on that radio before flipping it to the twin.

**Coexists with the harvest** the same way the WPS module does (shared radio lock, monitor restored).

**Helpers:** `eviltwin-radiocheck` (which adapters can be the AP), `eviltwin-arm` / `eviltwin-disarm`,
`eviltwin-run` (one bounded session now), `eviltwin-status`. Loot -> `/opt/wpacrack/loot/<BSSID>/eviltwin-<ts>.loot`.

---

## RF-enrichment recon (`aprecon.py`) + parallel research model

**`aprecon`** turns the research model's *generic* fingerprint into a *specific* one **without LAN
access**, from two RF sources — scope-locked to the authorized BSSID and radio-lock-coordinated with
the harvest:
- **Passive (monitor RX only):** connected-client inventory (MAC → OUI vendor) + probe-request PNLs.
- **WPS M1 device read (lockout-safe):** the AP sends M1 first, carrying real Manufacturer / Model /
  Model-Number / Device-Name / Serial / OS / UUID. aprecon reads M1 and **aborts before any PIN is
  guessed** (the PIN check is at M4/M6), so it adds no failed-auth and can't trip a lockout. It also
  **respects the WPS module's per-target cooldown** — it won't poke a rate-limited AP.

Results **merge** into `/opt/apvuln/fingerprints/<bssid>.json` (never clobbering apvulnd's beacon
fields), so `apresearch` reasons over "Netgear R7000" instead of "a wireless AP" — which is what
finally populates its analogues and test plan. Runs on `aprecon.timer` (every 6h); `aprecon-run`,
`aprecon-status` helpers.

**Parallel research model:** `apresearch` now parallelises its cosine-ranking hot loop across the
box's cores (`APRESEARCH_WORKERS`, default = all cores) — workers fork after the index is loaded, so
the 95 MB index is shared copy-on-write with no pickling. The service still runs under `SCHED_IDLE`,
so it bursts onto the (idle Pi 5) spare cores yet yields instantly to the RF stack. A one-shot
`apresearch.py research <bssid>` mode lets aprecon trigger an immediate regenerate after enrichment.

---

## Channel rediscovery (BSSID-anchored)

The BSSID is immutable; the channel is volatile — 2.4 GHz auto-channel selection, and especially
**5 GHz DFS** (an AP must vacate a DFS channel on radar detection). So the pipeline anchors on the
BSSID and *finds* the AP's current channel instead of trusting the pinned config value:

- The **harvest** (always-on RF presence) confirms the pinned channel with a cheap ~5 s beacon
  check each cycle; only if the AP is gone does it run a full **2.4 + 5 GHz `airodump` sweep** to
  relocate it, then **publishes** the current channel to `/opt/wpacrack/channels/<bssid>`.
- **WPS, eviltwin, aprecon** read that published channel (falling back to the config hint if it's
  missing/stale), so every RF leg follows the AP after a channel move instead of sitting blind on a
  dead channel. Scope-locked throughout — rediscovery only ever follows *that BSSID*.
