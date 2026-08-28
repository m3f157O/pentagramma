param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$errors = $null
[System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw $Path), [ref]$errors) | Out-Null

if ($errors.Count -eq 0) {
    Write-Host "PowerShell syntax OK: $Path"
    exit 0
}
else {
    foreach ($err in $errors) {
        Write-Host ("Line {0}: {1}" -f $err.Token.StartLine, $err.Message) -ForegroundColor Red
    }
    exit 1
}
