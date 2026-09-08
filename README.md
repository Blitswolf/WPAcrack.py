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
    --seed Robinson --seed Entropy | hashcat -m 22000 wpa.22000
```

Key flags: `--order` (context length), `--count` (max candidates), `--minlen/--maxlen`,
`--beam` (frontier bound; `0` = exact best-first), `--seed` (repeatable), `--train-limit`.

### The pipeline

```
   Pi (wpacrack)                 GPU box
 ┌───────────────┐   scp    ┌──────────────────────────────────┐
 │ capture 4-way │ ──────▶  │ markovgen ──stream──▶ hashcat -m  │
 │ → wpa.22000   │  .22000  │ (ordered guesses)      22000      │
 └───────────────┘          └──────────────────────────────────┘
   capture appliance          smart generation + fast cracking
```

## Notes / limitations

- If no handshake appears within the capture budget, it exits cleanly and tells you to retry when
  a client is powered on and associated (a handshake requires a client to (re)join).
- Adapter stability matters: the capture step needs reliable monitor mode + injection.
- Cracking is out of scope by design — bring your own GPU box and wordlists.
