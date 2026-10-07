# PacketVault end-to-end demonstration (Windows PowerShell).
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1            # pauses between steps
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -NoPause
param([switch]$NoPause)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:PACKETVAULT_PASSPHRASE = "lab-demo-passphrase"   # demo only - use the prompt in real cases
$pv = "python -m packetvault"

function Step($title, $cmd) {
    Write-Host ""
    Write-Host "== $title" -ForegroundColor Cyan
    Write-Host "> packetvault $cmd" -ForegroundColor DarkGray
    Invoke-Expression "$pv $cmd"
    if (-not $NoPause) { Read-Host "`n[Enter] to continue" | Out-Null }
}

Remove-Item -Recurse -Force demo -ErrorAction SilentlyContinue
New-Item -ItemType Directory demo | Out-Null

Step "1. Generate the lab capture (benign traffic + 2 Nmap-style scans)" "sample demo/lab_capture.pcap"
Step "2. Create the investigator's RSA-2048 keypair" "keygen --out-dir demo/keys"
Step "3. M1: parse the capture into XML + SQLite" "parse demo/lab_capture.pcap --out-dir demo/parsed"
Step "4. M1-M5: seal -> hash chain, AES-256-GCM, port-scan detection, signed report" `
     "seal demo/lab_capture.pcap --out demo/case-001 --key demo/keys/investigator_private.pem --investigator `"Anvesha Gupta`" --case-id CASE-001"
Get-Content demo/case-001/report.txt
Step "5. M6: verify the untouched bundle" "verify demo/case-001 --pubkey demo/keys/investigator_public.pem"
Step "6. Query the encrypted store (decrypted only in memory)" "query demo/case-001 --src 192.168.56.101 --flags SYN --limit 8"

Copy-Item -Recurse demo/case-001 demo/case-tampered
Step "7. ATTACK: insider changes the destination port of packet #1500" "tamper demo/case-tampered --mode modify --index 1500"
Step "8. M6: verifier pinpoints the tampered record" "verify demo/case-tampered --pubkey demo/keys/investigator_public.pem"

Remove-Item -Recurse -Force demo/case-tampered; Copy-Item -Recurse demo/case-001 demo/case-tampered
Step "9. ATTACK: insider edits packet #1500 AND recomputes every later hash" "tamper demo/case-tampered --mode recompute --index 1500"
Step "10. Signed root + checkpoints still catch and localise it" "verify demo/case-tampered --pubkey demo/keys/investigator_public.pem"

Step "11. M4: detection accuracy against ground truth" "detect demo/lab_capture.pcap --labels demo/lab_capture.labels.json"
Write-Host "`nDemo complete. Benchmarks: packetvault bench demo/lab_capture.pcap --out-dir demo/results" -ForegroundColor Green
