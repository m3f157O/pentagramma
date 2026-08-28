# Tier-1 crypto-hook validation: benign CNG usage from the ROOT monitored
# process (hooks guaranteed live before the first instruction).
# Expect: BCryptHashData (SHA256Cng) + BCryptEncrypt (AesCng) apitrace events,
# NtDelayExecution (Start-Sleep), no behavioral-signature alerts.
$h = [System.Security.Cryptography.SHA256Cng]::new()
$bytes = [System.IO.File]::ReadAllBytes("C:\Windows\notepad.exe")
$null = $h.ComputeHash($bytes)

$aes = [System.Security.Cryptography.AesCng]::new()
$aes.GenerateKey()
$aes.GenerateIV()
$enc = $aes.CreateEncryptor()
$data = New-Object byte[] 1024
$null = $enc.TransformFinalBlock($data, 0, $data.Length)

Start-Sleep -Seconds 3
Write-Output "tier1-bcrypt-ok"
