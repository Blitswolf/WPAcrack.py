# home-pie crack stack setup (deploy once SSH access exists)

Turns home-pie (.226) into an auto-cracker that pulls handshakes from kali-pie and works them.

## Prereqs on home-pie
- `python3`, `hashcat`, `rsync`, and a wordlist at `/usr/share/wordlists/rockyou.txt`
- an SSH key on home-pie that is authorized on kali-pie (for the read-only library pull)

## Install
```bash
sudo mkdir -p /opt/crackstack/model
sudo cp crackstack.sh /opt/crackstack/ && sudo chmod +x /opt/crackstack/crackstack.sh
# bring the smart generator + trained model over from the laptop/kali-pie:
sudo cp markovgen.py            /opt/crackstack/markovgen.py
sudo cp combined_o3.mdl         /opt/crackstack/model/combined_o3.mdl
sudo cp crackstack.service crackstack.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now crackstack.timer
```

## Scale-up option
`apresearch.py` is portable; copy it here too and run `apresearch.service` to move the (heavier)
exploit-intelligence model off the capture box onto home-pie, with a larger corpus / full-text index.
