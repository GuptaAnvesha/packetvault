#!/usr/bin/env bash
# PacketVault end-to-end demonstration (Linux / macOS / Git Bash).
set -euo pipefail
cd "$(dirname "$0")/.."
export PACKETVAULT_PASSPHRASE="lab-demo-passphrase"  # demo only - use the prompt in real cases
pv() { echo; echo "> packetvault $*"; python -m packetvault "$@"; }

rm -rf demo && mkdir demo
pv sample demo/lab_capture.pcap
pv keygen --out-dir demo/keys
pv seal demo/lab_capture.pcap --out demo/case-001 --key demo/keys/investigator_private.pem \
   --investigator "Anvesha Gupta" --case-id CASE-001
pv verify demo/case-001 --pubkey demo/keys/investigator_public.pem

for mode in modify delete insert recompute bitflip; do
  rm -rf demo/case-tampered && cp -r demo/case-001 demo/case-tampered
  pv tamper demo/case-tampered --mode "$mode" --index 1500
  pv verify demo/case-tampered --pubkey demo/keys/investigator_public.pem || true
done

pv detect demo/lab_capture.pcap --labels demo/lab_capture.labels.json
