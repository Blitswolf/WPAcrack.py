# wpacrack

Autonomous, lockout-safe WPA2 handshake capture + **offline** crack for a **single, authorized** access point.

Built to run headless on a Raspberry Pi (Kali) as a systemd service: kick it off, drop the SSH
session, and come back later to a status/result beacon — the same pattern as a long-running
recon job. On success it recovers the PSK and reconnects the capture interface to the target LAN
so follow-up work can pick up immediately.

> ⚠️ **Authorized use only.** This tool deauthenticates clients of, and cracks the PSK for, the
> one AP you name in `wpacrack.conf`. Run it **only** against a network you own or are explicitly
> authorized to test. It refuses to start without a configured target BSSID, specifically so it
> can never wander onto a neighbouring network.

---

## Why "lockout-safe"

The whole point is to recover the key **without ever tripping an authentication lockout or a
WIDS ban**, so the engagement completes cleanly on the first pass:

- **Offline crack, never online guessing.** wpacrack captures a single WPA2 4-way handshake and
  cracks it *offline* against wordlists. It never repeatedly presents guessed PSKs to the live AP,
  so there is no failed-auth lockout to trip.
- **Gentle, capped, targeted deauth.** It listens passively first (a naturally rejoining client
  can hand over the handshake with zero deauth). If it must nudge, it sends **small, jittered,
  client-targeted** deauth bursts — not a broadcast flood — under a **hard global cap**
  (`DEAUTH_TOTAL_CAP`, default 120 frames for the entire run). Past the cap it goes passive-only.
- **One clean join.** The only association it makes is a single connect with the **already-cracked
  (correct) key**, with backoff between retries to ride out a flaky adapter — never a
  wrong-credential hammer.

## How it works

```
monitor mode ─▶ capture 4-way handshake ─▶ offline crack ─▶ set PSK + reconnect to LAN
   (wlan1)      (passive-first, then         (escalating       (single clean join,
                 gentle capped deauth)         wordlists)         backoff retries)
```

1. Pauses `netwatch` (interface self-heal), stops NetworkManager/wpa_supplicant, puts the
   interface into monitor mode.
2. Rotates across the configured BSSIDs/channels (e.g. the 2.4 GHz and 5 GHz BSS of one AP),
   listening for and (gently) eliciting a 4-way handshake, validated with `tshark` (EAPOL frames
   both to and from the AP for a common station).
3. Cracks the captured handshake with `aircrack-ng` across an escalating wordlist set (a small
   high-probability custom list from your seeds first, then rockyou / SecLists).
4. On success: restores managed mode, writes the recovered PSK into the NetworkManager profile,
   connects the interface to the target LAN, and re-enables `netwatch`.
5. Beacons progress the whole time and writes a final result file. On stop/finish it always
   restores the box to a clean managed state.

## Requirements

- Kali (or similar) with the `aircrack-ng` suite (`airodump-ng`, `aireplay-ng`, `aircrack-ng`),
  `iw`, `tshark`, and NetworkManager (`nmcli`).
- A monitor-mode-capable adapter (developed against a Realtek RTL8812AU).
- Python 3. Standard library only — no pip dependencies.
- Root (systemd runs it as root).

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
sudo wpacrack-start     # begin the engagement (safe to disconnect afterwards)
sudo wpacrack-status    # phase, elapsed, deauth budget used, and final RESULT when done
sudo wpacrack-stop      # stop early; the box is restored to managed mode either way
```

Because it runs under systemd, you can close your SSH session and check back later with
`wpacrack-status`.

## Configuration (`wpacrack.conf`)

| key            | meaning                                                            |
|----------------|--------------------------------------------------------------------|
| `iface`        | monitor/managed interface (e.g. `wlan1`)                           |
| `essid`        | target SSID                                                        |
| `nm_profile`   | NetworkManager connection name to update + bring up on success     |
| `targets`      | `BSSID:CHANNEL` pairs, comma-separated (2.4 GHz first = preferred) |
| `lab_net`      | expected client subnet prefix once associated (e.g. `192.168.0.`)  |
| `lab_gw`       | LAN gateway (informational / next-step hint)                       |
| `custom_seeds` | optional PSK-guess seed words; case variants + suffixes auto-built |

Tuning constants (capture budget, dwell, and the deauth caps described above) live at the top of
`wpacrack.py`.

## Output

Under `/opt/wpacrack/`:

- `STATUS.txt` — live phase / elapsed / deauth-budget beacon
- `RESULT.txt` — final outcome (also copied to `~/wpacrack_RESULT.txt` for easy SSH viewing)
- `wpacrack.log` — timestamped log
- `handshake.cap` — the captured handshake (kept for offline re-cracking, e.g. `hashcat -m 22000`)

`wpacrack.conf` and every runtime artifact are `.gitignore`d, so no site identifiers, captures,
or recovered keys are ever committed.

## Notes / limitations

- If no handshake appears within the capture budget, it exits cleanly and tells you to retry when
  a client is powered on and associated (a handshake requires a client to (re)join).
- If the handshake is captured but the PSK isn't in the wordlists, the `.cap` is preserved for
  offline cracking with a bigger list or GPU (`hashcat`).
- Adapter stability matters: the capture step needs reliable monitor mode + injection.
