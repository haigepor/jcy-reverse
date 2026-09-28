# ROLLBACK.ps1 - Windows native rollback (same logic as ROLLBACK.sh)
# Restores pristine bytes from apk\base.apk and removes build artifacts.
param([string]$Dir = ".")
$ErrorActionPreference = 'Stop'
Set-Location $Dir

$pristine = "apk\base.apk"
$target   = "out\base_adfree_final-aligned-debugSigned.apk"
if (!(Test-Path $pristine)) { throw "pristine apk not found: $pristine" }

Write-Host "[ROLLBACK] 1/3 overwrite deliverable with pristine apk"
Copy-Item -Force $pristine $target
Copy-Item -Force $pristine "out\base_restored.apk"

Write-Host "[ROLLBACK] 2/3 remove patched build artifacts and intermediate dirs"
Remove-Item -Force "out\base_adfree_final-aligned-debugSigned.apk.idsig" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "out\base_nores","out\base_smali_patched","out\base_smali","out\base_decoded","out\jadx_src" -ErrorAction SilentlyContinue

Write-Host "[ROLLBACK] 3/3 verify restored hashes"
$base  = (Get-FileHash $pristine -Algorithm SHA256).Hash
$rest  = (Get-FileHash "out\base_restored.apk" -Algorithm SHA256).Hash
$deliv = (Get-FileHash $target -Algorithm SHA256).Hash
Write-Host "pristine : $base"
Write-Host "restored : $rest"
Write-Host "delivered: $deliv"
if (($base -ne $rest) -or ($base -ne $deliv)) { throw "hash mismatch, rollback failed" }
Write-Host "[ROLLBACK] OK: pristine bytes restored (kept DIFF_smali.patch and VERIFICATION.txt for audit)"
