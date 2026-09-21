#requires -RunAsAdministrator

# NOTE: no '#requires -Modules Hyper-V' -- local mode (-LocalMode, see
# docs/local-mode.md) runs on machines WITHOUT the Hyper-V role; VM-mode
# functions check the module in Assert-VMExists instead.

<#
.SYNOPSIS
    Snapshot-based Hyper-V helper for the malware analysis sandbox.

    IMPORTANT: This script never creates or deletes VMs. It only operates on
    an existing VM (configured in config.yaml) by taking/restoring snapshots.
#>

# No param() block — this script is driven entirely by $args.
$ErrorActionPreference = "Stop"

# Local mode (standalone package, docs/local-mode.md): when the -LocalMode
# switch is present in $args, every guest-targeted operation runs on the
# LOCAL machine instead of via PowerShell Direct. Set by the entrypoint at
# the bottom of this script.
$script:LocalMode = $false

function Invoke-AnalysisCommand {
    <#
    .SYNOPSIS
        Local-mode seam for guest scriptblock execution. Every guest
        operation in this script is a hashtable of Invoke-Command splat
        args; this wrapper either splats into Invoke-Command (PowerShell
        Direct, default) or invokes the scriptblock LOCALLY with its
        ArgumentList (-LocalMode). -ScriptBlock/-ArgumentList may override
        the hashtable entries, mirroring the
        'Invoke-Command @args -ScriptBlock {...}' call pattern.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [hashtable]$InvokeArgs,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [object[]]$ArgumentList
    )

    if ($PSBoundParameters.ContainsKey('ScriptBlock')) { $InvokeArgs['ScriptBlock'] = $ScriptBlock }
    if ($PSBoundParameters.ContainsKey('ArgumentList')) { $InvokeArgs['ArgumentList'] = $ArgumentList }
    if ($script:LocalMode) {
        $sb = $InvokeArgs.ScriptBlock
        if ($null -eq $InvokeArgs.ArgumentList) {
            $al = @()
        } else {
            $al = @($InvokeArgs.ArgumentList)
        }
        return (& $sb @al)
    }

    # VM mode: PowerShell Direct throws transient transport errors while the
    # guest is still booting after a snapshot restore -- PSSessionStateBroken
    # ("socket di Hyper-V ... terminato") and InvalidVMState. Start-SandboxVM
    # only waits for an IP, which appears well before the PSDirect service is
    # ready, so the first guest op of a job (Copy-Agent) can race the boot and
    # fail the whole job. Retry transport-class errors; rethrow real
    # scriptblock failures immediately.
    $maxAttempts = 24  # 24 x 10s = 4 min worst case (observed gap: ~2-3 min)
    for ($attempt = 1; ; $attempt++) {
        try {
            return (Invoke-Command @InvokeArgs)
        } catch {
            $fqid = [string]$_.FullyQualifiedErrorId
            $transient = $fqid -match 'PSSessionStateBroken|InvalidVMState' -or
                         $_.Exception -is [System.Management.Automation.Remoting.PSRemotingTransportException]
            if (-not $transient -or $attempt -ge $maxAttempts) { throw }
            Start-Sleep -Seconds 10
        }
    }
}

function Copy-AnalysisFileToTarget {
    <#
    .SYNOPSIS
        Local-mode seam for Copy-VMFile (host->guest file push): a plain
        filesystem copy in local mode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )
    if ($script:LocalMode) {
        $parent = Split-Path -Parent $DestinationPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
        return
    }
    Copy-VMFile -Name $VMName -SourcePath $SourcePath -DestinationPath $DestinationPath -CreateFullPath -FileSource Host -Force
}

function Test-SandboxPrerequisites {
    [CmdletBinding()]
    param()

    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if (-not $hv -or $hv.State -ne "Enabled") {
        throw "Hyper-V is not enabled. Run: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
    }

    if (-not (Get-Module -ListAvailable Hyper-V)) {
        throw "Hyper-V PowerShell module not found."
    }

    return $true
}

function Assert-VMExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )

    # Local mode: no VM exists -- the local machine IS the analysis
    # environment. VM-mode additionally needs the Hyper-V module (no longer
    # enforced by a #requires directive).
    if ($script:LocalMode) { return $null }
    if (-not (Get-Module -ListAvailable Hyper-V)) {
        throw "Hyper-V PowerShell module not found (required unless -LocalMode)."
    }

    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if (-not $vm) {
        throw "VM '$VMName' does not exist. This orchestrator does NOT create VMs. Please create the VM manually."
    }
    return $vm
}

function New-VmCredential {
    <#
    .SYNOPSIS
        Builds a PSCredential object from plaintext username/password when provided.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$Password
    )

    if (-not $Username -or -not $Password) {
        return $null
    }
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($Username, $secure)
}

function Ensure-SandboxSnapshot {
    <#
    .SYNOPSIS
        Creates a snapshot of the VM if it does not already exist.
        If the VM is running, it is shut down cleanly first.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotName = "SANDBOX-CLEAN"
    )

    $vm = Assert-VMExists -VMName $VMName

    $snapshot = Get-VMSnapshot -VMName $VMName -Name $SnapshotName -ErrorAction SilentlyContinue
    if ($snapshot) {
        return [PSCustomObject]@{
            VMName       = $VMName
            SnapshotName = $SnapshotName
            Status       = "already_exists"
            Created      = $snapshot.CreationTime.ToString("o")
        }
    }

    if ($vm.State -ne "Off") {
        Stop-VM -Name $VMName -Save -Force
    }

    $newSnapshot = Checkpoint-VM -Name $VMName -SnapshotName $SnapshotName -PassThru
    return [PSCustomObject]@{
        VMName       = $VMName
        SnapshotName = $SnapshotName
        Status       = "created"
        Created      = $newSnapshot.CreationTime.ToString("o")
    }
}

function Restore-SandboxSnapshot {
    <#
    .SYNOPSIS
        Reverts the VM to its clean snapshot. The VM is turned off first if needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotName = "SANDBOX-CLEAN"
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $snapshot = Get-VMSnapshot -VMName $VMName -Name $SnapshotName -ErrorAction SilentlyContinue
    if (-not $snapshot) {
        throw "Snapshot '$SnapshotName' not found for VM '$VMName'. Run Ensure-Snapshot first."
    }

    $vm = Get-VM -Name $VMName
    if ($vm.State -ne "Off") {
        Stop-VM -Name $VMName -TurnOff -Force
    }

    Restore-VMSnapshot -VMName $VMName -Name $SnapshotName -Confirm:$false
    return [PSCustomObject]@{
        VMName       = $VMName
        SnapshotName = $SnapshotName
        Status       = "restored"
    }
}

function Start-SandboxVM {
    <#
    .SYNOPSIS
        Starts the existing VM and waits for an IP address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $vm = Get-VM -Name $VMName
    if ($vm.State -ne "Running") {
        Start-VM -Name $VMName
    }

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $ip = (Get-VMNetworkAdapter -VMName $VMName).IPAddresses |
              Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
              Select-Object -First 1
        if ($ip) {
            return [PSCustomObject]@{
                VMName    = $VMName
                State     = "Running"
                IPAddress = $ip
            }
        }
        Start-Sleep -Seconds 2
    }

    throw "Timeout waiting for VM '$VMName' to acquire an IP address."
}

function Stop-SandboxVM {
    <#
    .SYNOPSIS
        Stops the VM. Default is save state; -Force turns it off.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $vm = Get-VM -Name $VMName
    if ($vm.State -eq "Off") {
        return Get-SandboxVMStatus -VMName $VMName
    }

    if ($Force) {
        Stop-VM -Name $VMName -TurnOff -Force
    }
    else {
        Stop-VM -Name $VMName -Save
    }

    return Get-SandboxVMStatus -VMName $VMName
}

function Get-SandboxVMStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )

    $vm = Assert-VMExists -VMName $VMName
    $ip = (Get-VMNetworkAdapter -VMName $VMName).IPAddresses |
          Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
          Select-Object -First 1

    return [PSCustomObject]@{
        VMName    = $VMName
        State     = $vm.State.ToString()
        Uptime    = $vm.Uptime.ToString()
        IPAddress = $ip
    }
}

function Copy-SampleToVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$SamplePath,

        [Parameter(Mandatory = $false)]
        [string]$DestinationFolder = "C:\\Sandbox",

        [Parameter(Mandatory = $false)]
        [string]$DestinationFileName,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    if (-not (Test-Path $SamplePath)) {
        throw "Sample not found: $SamplePath"
    }

    $prep = {
        param($folder)
        if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        return $folder
    }
    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{ VMName = $VMName; ScriptBlock = $prep; ArgumentList = $DestinationFolder }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    Invoke-AnalysisCommand $invokeArgs | Out-Null

    # DestinationFileName lets the orchestrator give the guest copy a
    # synthetic name carrying the sample's real extension (e.g. sample.js)
    # -- the host-side stored sample is an extensionless SHA256 file, and
    # some launchers (wscript/cscript) pick their scripting engine by
    # extension, so the guest file must have the correct one.
    $fileName = if ($DestinationFileName) { $DestinationFileName } else { Split-Path -Leaf $SamplePath }
    $destPath = Join-Path $DestinationFolder $fileName
    Copy-AnalysisFileToTarget -VMName $VMName -SourcePath $SamplePath -DestinationPath $destPath

    return [PSCustomObject]@{
        VMName          = $VMName
        DestinationPath = $destPath
    }
}

function Invoke-SampleExecution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$SamplePathInVM = "",

        [Parameter(Mandatory = $false)]
        [string]$Arguments = "",

        [Parameter(Mandatory = $false)]
        [string]$LauncherPath,

        [Parameter(Mandatory = $false)]
        [string]$LauncherArguments,

        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120,

        [Parameter(Mandatory = $false)]
        [string]$DumpsDir = "C:\SandboxAgent\dumps",

        [Parameter(Mandatory = $false)]
        [int]$DumpIntervalSeconds = 15,

        [Parameter(Mandatory = $false)]
        [int]$MaxDumps = 5,

        [Parameter(Mandatory = $false)]
        [long]$MaxWorkingSetBytes = 524288000,

        [Parameter(Mandatory = $false)]
        [int]$PollIntervalMs = 250,

        [Parameter(Mandatory = $false)]
        [switch]$BehavioralTracing,

        [Parameter(Mandatory = $false)]
        [string]$MonitorDllPath = "C:\SandboxAgent\monitor_x64.dll",

        [Parameter(Mandatory = $false)]
        [string]$MonitorLoaderPath = "C:\SandboxAgent\monitor_loader.exe",

        [Parameter(Mandatory = $false)]
        [string]$MonitorPidFile = "C:\SandboxAgent\sample_pid.txt",

        [Parameter(Mandatory = $false)]
        [int]$MonitorPidWaitSeconds = 8,

        # Adaptive detonation window (2026-09-11). 0 = disabled (today's fixed
        # window). When > 0 AND behavioral tracing engaged AND ActivityFilePath
        # points at the apitrace JSONL, a sample whose trace stays silent for
        # AdaptiveIdleGraceSeconds past the minimum window is stopped early --
        # the alive-but-stalled class (dead-C2 emotet) that today burns the
        # full timeout producing nothing.
        [Parameter(Mandatory = $false)]
        [int]$AdaptiveMinWindowSeconds = 0,

        [Parameter(Mandatory = $false)]
        [int]$AdaptiveIdleGraceSeconds = 45,

        [Parameter(Mandatory = $false)]
        [string]$ActivityFilePath = "",

        # Apitrace attached-pids file (collector --pids-file): pids the
        # monitor is attached to, including processes the sample INJECTED
        # into. The wait-loop adopts them as extra tree roots so a
        # sample that injects-and-exits still counts as alive (2026-09-11).
        [Parameter(Mandatory = $false)]
        [string]$AdoptedPidsFile = "",

        # Hard floor on the detonation window (2026-09-11): even if the whole
        # sample tree exits immediately, the run is not stopped before this
        # many seconds -- collectors still get a baseline of post-exit
        # telemetry (late Sysmon flush, dropped files landing, ...).
        [Parameter(Mandatory = $false)]
        [int]$MinRuntimeSeconds = 30,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($path, $launcherPath, $argumentString, $workingDirectory, $timeoutSeconds, $dumpsDir, $dumpIntervalSeconds, $maxDumps, $maxWorkingSetBytes, $pollIntervalMs, $behavioralTracing, $monitorDllPath, $monitorLoaderPath, $monitorPidFile, $monitorPidWaitSeconds, $adaptiveMinWindowSeconds, $adaptiveIdleGraceSeconds, $activityFilePath, $adoptedPidsFile, $minRuntimeSeconds)
        # NOTE: both streams must be drained asynchronously *before*
        # WaitForExit() -- redirecting both stdout+stderr and only reading
        # them after WaitForExit() is the classic .NET Process deadlock: the
        # child blocks once it fills the ~4KB anonymous pipe buffer, so
        # WaitForExit() always times out for any moderately verbose sample.
        # Verified empirically (reproduced the hang, then confirmed this
        # ReadToEndAsync-before-WaitForExit pattern fixes it).
        $maxOutputChars = 200000
        function Format-CapturedOutput($text, $max) {
            if ($null -eq $text) { return "" }
            if ($text.Length -gt $max) {
                return $text.Substring(0, $max) + "`n...(truncated, $($text.Length) total chars)"
            }
            return $text
        }

        # P/Invoke declaration for "passive" dynamic-unpacking dumps: since we
        # started the process ourselves, $proc.Handle is already a valid,
        # sufficiently-privileged handle from CreateProcess -- no separate
        # OpenProcess() call is needed (and therefore no new Sysmon EID10
        # ProcessAccess telemetry from this handle-reuse path; verify
        # empirically after the first real run -- see sysmonconfig.xml notes).
        $miniDumpSource = @"
using System;
using System.Runtime.InteropServices;
public class MiniDumpNative {
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType,
        IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);
}
"@
        Add-Type -TypeDefinition $miniDumpSource -ErrorAction Stop

        New-Item -ItemType Directory -Force -Path $dumpsDir | Out-Null

        function Invoke-ProcessDump {
            param($Process, $Index, $DumpsDir, $MaxWorkingSetBytes, $ElapsedSeconds, $IsFinal)
            $Process.Refresh()
            $workingSet = $Process.WorkingSet64
            if ($workingSet -gt $MaxWorkingSetBytes) {
                return [PSCustomObject]@{
                    Index = $Index; ElapsedSeconds = $ElapsedSeconds; Final = $IsFinal
                    Skipped = $true; Reason = "process_too_large"
                    WorkingSetBytes = $workingSet; Path = $null; Success = $false
                }
            }
            $dumpPath = Join-Path $DumpsDir ("sample_{0:D4}.dmp" -f $Index)
            $fs = $null
            try {
                $fs = [System.IO.File]::Create($dumpPath)
                $ok = [MiniDumpNative]::MiniDumpWriteDump(
                    $Process.Handle, [uint32]$Process.Id, $fs.SafeFileHandle.DangerousGetHandle(),
                    0x00000002, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
                $fs.Close()
                $fs = $null
                if (-not $ok) {
                    $win32Err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Remove-Item -Path $dumpPath -ErrorAction SilentlyContinue
                    return [PSCustomObject]@{
                        Index = $Index; ElapsedSeconds = $ElapsedSeconds; Final = $IsFinal
                        Skipped = $false; Reason = "minidumpwritedump_failed"
                        WorkingSetBytes = $workingSet; Path = $null; Success = $false; Win32Error = $win32Err
                    }
                }
                return [PSCustomObject]@{
                    Index = $Index; ElapsedSeconds = $ElapsedSeconds; Final = $IsFinal
                    Skipped = $false; Reason = $null
                    WorkingSetBytes = $workingSet; Path = $dumpPath; Success = $true
                }
            }
            catch {
                if ($fs) { try { $fs.Close() } catch {} }
                return [PSCustomObject]@{
                    Index = $Index; ElapsedSeconds = $ElapsedSeconds; Final = $IsFinal
                    Skipped = $false; Reason = "exception: $_"
                    WorkingSetBytes = $workingSet; Path = $null; Success = $false
                }
            }
        }

        # workingDirectory may not exist yet -- URL-browse mode never runs
        # Copy-SampleToVM (there's no sample file), so C:\Sandbox is never
        # created on that path.
        if (-not (Test-Path $workingDirectory)) {
            New-Item -ItemType Directory -Force -Path $workingDirectory | Out-Null
        }

        # Traced path (BehavioralTracing): run monitor_loader.exe instead of the
        # sample/launcher directly. The loader creates $launcherPath/$argumentString
        # SUSPENDED, injects monitor_x64.dll, waits for hooks to be live, then
        # resumes -- so $proc below becomes the LOADER, not the sample. The
        # loader forwards the child's stdout/stderr via normal handle
        # inheritance (its own redirected std handles are inherited by the
        # child it creates), so the existing ReadToEndAsync capture below is
        # unchanged and picks up both. LauncherPath/$path stay the ORIGINAL
        # sample identity throughout -- only the ACTUAL executed image changes.
        if ($behavioralTracing) {
            if (Test-Path $monitorPidFile) { Remove-Item -Path $monitorPidFile -Force -ErrorAction SilentlyContinue }
            # WoW64: a 32-bit PE target needs the 32-bit monitor + loader
            # (an x64 DLL can't load into a WoW64 process). Sniff the PE
            # machine type; fall back to x64 silently if anything is off.
            $dllToUse = $monitorDllPath
            $loaderToUse = $monitorLoaderPath
            try {
                $fs = [System.IO.File]::OpenRead($launcherPath)
                $br = New-Object System.IO.BinaryReader($fs)
                $fs.Seek([int64]0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
                $peOff = $br.ReadInt32()
                $fs.Seek([int64]$peOff + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
                $machine = $br.ReadUInt16()
                $br.Close(); $fs.Close()
                if ($machine -eq 0x14c) {  # IMAGE_FILE_MACHINE_I386
                    $dll86 = $monitorDllPath -replace 'monitor_x64\.dll$', 'monitor_x86.dll'
                    $ldr86 = $monitorLoaderPath -replace 'monitor_loader\.exe$', 'monitor_loader_x86.exe'
                    if ((Test-Path $dll86) -and (Test-Path $ldr86)) {
                        $dllToUse = $dll86
                        $loaderToUse = $ldr86
                    }
                }
            } catch { }
            $exeToRun = $loaderToUse
            $argsToRun = '"' + $dllToUse + '" "' + $launcherPath + '" ' + $argumentString
        } else {
            $exeToRun = $launcherPath
            $argsToRun = $argumentString
        }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exeToRun
        $psi.Arguments = $argsToRun
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.WorkingDirectory = $workingDirectory
        if ($behavioralTracing) { $psi.EnvironmentVariables["MONITOR_PID_FILE"] = $monitorPidFile }
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        # Traced path: the loader ($proc) writes the REAL sample's PID to
        # $monitorPidFile right after CreateProcess (before injection/resume) --
        # poll for it (bounded) so memory dumps target the actual sample, not
        # the tiny loader. $dumpTargetProcess is what Invoke-ProcessDump below
        # snapshots; falls back to $proc (today's behavior) when tracing is off
        # or the pid file never appears (degraded trace, not a hard failure).
        $dumpTargetProcess = $proc
        $tracedChildPid = $null
        if ($behavioralTracing) {
            $pidWaitDeadline = [System.Diagnostics.Stopwatch]::StartNew()
            while ($tracedChildPid -eq $null -and $pidWaitDeadline.Elapsed.TotalSeconds -lt $monitorPidWaitSeconds) {
                if (Test-Path $monitorPidFile) {
                    $raw = (Get-Content -Path $monitorPidFile -Raw -ErrorAction SilentlyContinue)
                    $parsed = 0
                    if ($raw -and [int]::TryParse($raw.Trim(), [ref]$parsed)) { $tracedChildPid = $parsed }
                }
                if ($tracedChildPid -eq $null) {
                    if ($proc.HasExited) { break }  # loader already gone -- injection never happened
                    Start-Sleep -Milliseconds 100
                }
            }
            if ($tracedChildPid -ne $null) {
                try { $dumpTargetProcess = [System.Diagnostics.Process]::GetProcessById($tracedChildPid) }
                catch { $tracedChildPid = $null; $dumpTargetProcess = $proc }  # child already exited
            }
        }

        # Adaptive detonation window (2026-09-11): track the whole sample
        # process TREE (root + descendants), not just $proc.
        #  - exit-stop: tree fully gone -> done (root-exits-but-persistent-child
        #    no longer tears collectors down early)
        #  - idle-stop: tree alive but the apitrace JSONL ($activityFilePath,
        #    line-buffered by the guest collector) hasn't grown for
        #    $adaptiveIdleGraceSeconds past $adaptiveMinWindowSeconds -> the
        #    alive-but-silent staller class; stop early WITH a final dump.
        # Tree root is the traced child when present, else $proc (the loader
        #    on the traced path is the sample's PARENT, so rooting at the
        #    traced child keeps the loader itself out of the tree).
        $treeRootPid = if ($tracedChildPid -ne $null) { $tracedChildPid } else { $proc.Id }
        $adaptiveActive = ($adaptiveMinWindowSeconds -gt 0 -and $activityFilePath -and $tracedChildPid -ne $null)
        function Get-SampleTreePids {
            param([int]$RootPid, [int[]]$AdditionalRoots = @())
            $all = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -ErrorAction SilentlyContinue)
            $byParent = @{}
            foreach ($p in $all) {
                $ppid = [int]$p.ParentProcessId
                if (-not $byParent.ContainsKey($ppid)) { $byParent[$ppid] = @() }
                $byParent[$ppid] += [int]$p.ProcessId
            }
            $found = @{}
            $queue = [System.Collections.Generic.Queue[int]]::new()
            $queue.Enqueue($RootPid)
            # adopted roots: injected-into processes count for aliveness even
            # though they are not descendants of the sample
            foreach ($extra in $AdditionalRoots) { $queue.Enqueue($extra) }
            while ($queue.Count -gt 0) {
                $cur = $queue.Dequeue()
                if ($found.ContainsKey($cur)) { continue }
                $found[$cur] = $true
                if ($byParent.ContainsKey($cur)) {
                    foreach ($child in $byParent[$cur]) { if (-not $found.ContainsKey($child)) { $queue.Enqueue($child) } }
                }
            }
            # only return pids that are actually still alive; $null = query
            # failed (caller falls back to the legacy $proc.HasExited check).
            # NB: unary comma -- a bare empty array return would enumerate to
            # $null and be misread as a query failure.
            if ($all.Count -eq 0) { return $null }
            $aliveIds = @{}
            foreach ($p in $all) { $aliveIds[[int]$p.ProcessId] = $true }
            return ,@($found.Keys | Where-Object { $aliveIds.ContainsKey($_) })
        }

        # Periodic-snapshot polling loop: replaces a single blocking
        # WaitForExit() so we can catch BOTH a hung/timed-out process AND a
        # naturally short-lived one (most real malware) -- whichever happens
        # first, we've likely already taken at least one memory dump while
        # it was still alive. A sample that exits faster than one
        # $dumpIntervalSeconds tick is still missed entirely -- this is the
        # accepted "passive" tier, not event-driven/breakpoint-based capture.
        $dumpAttempts = @()
        $dumpsTaken = 0
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastDumpSeconds = 0.0
        $exited = $false
        $stoppedEarly = $null  # 'idle' when the adaptive window cut a staller short
        # Adaptive-window state: tree refresh throttled to 1 Hz (WMI query cost),
        # activity probe to 2 s (file-size stat is cheap).
        $treePids = @()
        $treeKnown = $false
        $treeCheckAt = 0.0
        $lastActivitySize = -1
        $lastActivityAt = 0.0
        $nextActivityPollAt = $adaptiveMinWindowSeconds
        $treePidsMax = 0
        $adoptedPidsSeen = 0

        while ($true) {
            $elapsedSeconds = $stopwatch.Elapsed.TotalSeconds
            if ($elapsedSeconds -ge $treeCheckAt) {
                # Adopt apitrace-attached pids (injection targets) as extra
                # tree roots; exclude the loader itself ($proc.Id) -- it is
                # tooling whose liveness must not hold the window open.
                $adopted = @()
                if ($adoptedPidsFile) {
                    try {
                        foreach ($line in (Get-Content -Path $adoptedPidsFile -ErrorAction Stop)) {
                            $ap = 0
                            if ([int]::TryParse($line.Trim(), [ref]$ap) -and $ap -gt 0 -and $ap -ne $proc.Id) { $adopted += $ap }
                        }
                    } catch {}
                }
                if ($adopted.Count -gt $adoptedPidsSeen) { $adoptedPidsSeen = $adopted.Count }
                $refreshed = Get-SampleTreePids $treeRootPid $adopted
                # NB: $null on the LEFT -- with an empty-array result, the
                # filter semantics of "$refreshed -ne $null" yield @() (falsy)
                # and the update would be skipped, freezing a stale non-empty
                # tree forever (observed live 2026-09-11: canary idle-stopped
                # instead of exit-stopping 3s after sample death).
                if ($null -ne $refreshed) {
                    $treePids = @($refreshed)
                    $treeKnown = $true
                    if ($treePids.Count -gt $treePidsMax) { $treePidsMax = $treePids.Count }
                }
                $treeCheckAt = $elapsedSeconds + 1.0
            }
            # exit-stop: the TREE is what decides once it's known. Traced path
            # roots at the sample (loader is tooling -- its exit/lingering is
            # irrelevant); untraced path roots at $proc, requiring $proc itself
            # gone too (belt-and-braces against a mid-spawn snapshot). Any CIM
            # failure degrades to today's $proc.HasExited behavior. Gated on
            # the minimum-runtime floor: an instantly-exiting tree still gets
            # $minRuntimeSeconds of observation before we call it done.
            $sampleGone = $false
            if (-not $treeKnown) {
                if ($proc.HasExited) { $sampleGone = $true }
            } elseif ($tracedChildPid -ne $null) {
                if ($treePids.Count -eq 0) { $sampleGone = $true }
            } elseif ($proc.HasExited -and $treePids.Count -eq 0) {
                $sampleGone = $true
            }
            if ($sampleGone -and $elapsedSeconds -ge $minRuntimeSeconds) { $exited = $true; break }
            if ($elapsedSeconds -ge $timeoutSeconds) { break }

            # idle-stop: only on the traced path (the apitrace file is the
            # signal), only once the minimum observation window has elapsed.
            if ($adaptiveActive -and $elapsedSeconds -ge $nextActivityPollAt) {
                $nextActivityPollAt = $elapsedSeconds + 2.0
                $size = -1
                try { $size = (Get-Item -Path $activityFilePath -ErrorAction Stop).Length } catch { $size = -1 }
                if ($size -lt 0) {
                    # no signal (collector never created the file) -- never
                    # idle-stop blind; the hard timeout governs this run.
                } elseif ($size -ne $lastActivitySize) {
                    $lastActivitySize = $size
                    $lastActivityAt = $elapsedSeconds
                } elseif (($elapsedSeconds - $lastActivityAt) -ge $adaptiveIdleGraceSeconds) {
                    $stoppedEarly = 'idle'
                    break
                }
            }

            # no dump attempts against a dead tree (they only record failures)
            if ($treePids.Count -gt 0 -and $dumpsTaken -lt $maxDumps -and ($elapsedSeconds - $lastDumpSeconds) -ge $dumpIntervalSeconds) {
                try {
                    $attempt = Invoke-ProcessDump -Process $dumpTargetProcess -Index $dumpAttempts.Count -DumpsDir $dumpsDir `
                        -MaxWorkingSetBytes $maxWorkingSetBytes -ElapsedSeconds $elapsedSeconds -IsFinal $false
                } catch {
                    # Traced-path only: the child (a distinct Process object from
                    # $proc) can exit between our HasExited check and this dump --
                    # a narrower race than the untraced case, where $proc IS the
                    # thing HasExited already checked. Record and move on.
                    $attempt = [PSCustomObject]@{
                        Index = $dumpAttempts.Count; ElapsedSeconds = $elapsedSeconds; Final = $false
                        Skipped = $true; Reason = "target_process_error: $_"
                        WorkingSetBytes = 0; Path = $null; Success = $false
                    }
                }
                $dumpAttempts += $attempt
                if (-not $attempt.Skipped) { $dumpsTaken++ }
                $lastDumpSeconds = $stopwatch.Elapsed.TotalSeconds
            }

            Start-Sleep -Milliseconds $pollIntervalMs
        }

        if (-not $exited) {
            # Timeout OR idle-stop path: one final dump attempt, exempt from
            # $maxDumps (still size-guarded) -- the single highest-value dump,
            # since a process that's still alive at analysis end is very likely
            # still holding unpacked payload in memory (doubly true for an
            # idle-stopped staller).
            # Final-dump guard: check the DUMP TARGET (via the tree), not
            # $proc -- on the traced path the loader can exit long before the
            # sample, and the live sample is exactly what we want to dump.
            if ($treePids.Count -gt 0 -or -not $dumpTargetProcess.HasExited) {
                try {
                    $finalAttempt = Invoke-ProcessDump -Process $dumpTargetProcess -Index $dumpAttempts.Count -DumpsDir $dumpsDir `
                        -MaxWorkingSetBytes $maxWorkingSetBytes -ElapsedSeconds $stopwatch.Elapsed.TotalSeconds -IsFinal $true
                } catch {
                    $finalAttempt = [PSCustomObject]@{
                        Index = $dumpAttempts.Count; ElapsedSeconds = $stopwatch.Elapsed.TotalSeconds; Final = $true
                        Skipped = $true; Reason = "target_process_error: $_"
                        WorkingSetBytes = 0; Path = $null; Success = $false
                    }
                }
                $dumpAttempts += $finalAttempt
            }
            # kill the WHOLE DESCENDANT tree (a persistent child must not
            # survive the run), then wait on the launcher so ExitCode is safe
            # to read below. NB: descendants ONLY -- adopted injection-target
            # hosts (explorer/svchost/...) extend the observation window but
            # are deliberately NOT killed (killing an OS-critical host could
            # take the guest down before telemetry is pulled; the per-run VM
            # revert discards them anyway).
            $finalTree = Get-SampleTreePids $treeRootPid
            if ($null -ne $finalTree) { $treePids = @($finalTree) }
            foreach ($treePid in $treePids) {
                try {
                    $tp = [System.Diagnostics.Process]::GetProcessById([int]$treePid)
                    if (-not $tp.HasExited) { $tp.Kill() }
                } catch {}
            }
            try { $proc.Kill() } catch {}
            $proc.WaitForExit()
        }

        [System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 10000) | Out-Null
        $stdoutText = if ($stdoutTask.IsCompleted -and -not $stdoutTask.IsFaulted) { $stdoutTask.Result } else { "" }
        $stderrText = if ($stderrTask.IsCompleted -and -not $stderrTask.IsFaulted) { $stderrTask.Result } else { "" }
        if (-not $exited) {
            if ($stoppedEarly -eq 'idle') {
                $stderrText = "[adaptive] stopped early: no sample activity for ${adaptiveIdleGraceSeconds}s`n" + $stderrText
            } else {
                $stderrText = "Process did not exit within timeout`n" + $stderrText
            }
        }
        # ProcessId stays "the sample's own pid" regardless of tracing -- the
        # traced child pid when tracing engaged, else $proc.Id (today's
        # behavior). This is load-bearing: reporting.py's PID-lineage scoping
        # roots at execution_info.ProcessId, and must root at the SAMPLE, not
        # the loader (an ancestor of the sample on the traced path, whose own
        # injection activity -- CreateRemoteThread/VirtualAllocEx into the
        # child -- must stay OUT of sample scope, which it does automatically
        # since PID-lineage only walks DESCENDANTS of ProcessId).
        return [PSCustomObject]@{
            ProcessId               = if ($tracedChildPid -ne $null) { $tracedChildPid } else { $proc.Id }
            Started                 = $true
            Path                    = $path
            LauncherPath            = $launcherPath
            ExitCode                = $proc.ExitCode
            Stdout                  = Format-CapturedOutput $stdoutText $maxOutputChars
            Stderr                  = Format-CapturedOutput $stderrText $maxOutputChars
            TimedOut                = (-not $exited)
            StoppedEarly            = if ($exited) { 'exit' } elseif ($stoppedEarly) { $stoppedEarly } else { 'timeout' }
            AdaptiveWindowActive    = [bool]$adaptiveActive
            TreePidsMax             = $treePidsMax
            AdoptedPidsMax          = $adoptedPidsSeen
            ProcessDumps            = $dumpAttempts
            BehavioralTracingActive = [bool]($behavioralTracing -and $tracedChildPid -ne $null)
        }
    }

    # LauncherPath/LauncherArguments/WorkingDirectory default to today's
    # exact behavior (launch SamplePathInVM directly, args as given, cwd =
    # the sample's own parent folder) when the caller doesn't pass them --
    # so the only confirmed caller (hyperv.py::execute_sample via
    # SandboxExecutor.run_analysis) keeps working unchanged unless it
    # opts into a resolved launch plan (orchestrator/sample_types.py).
    $resolvedLauncherPath = if ($LauncherPath) { $LauncherPath } else { $SamplePathInVM }
    $resolvedLauncherArguments = if ($LauncherArguments) {
        if ($Arguments) { "$LauncherArguments $Arguments" } else { $LauncherArguments }
    } else { $Arguments }
    $resolvedWorkingDirectory = if ($WorkingDirectory) { $WorkingDirectory }
                                elseif ($SamplePathInVM) { Split-Path -Parent $SamplePathInVM }
                                else { $null }
    if (-not $resolvedLauncherPath) {
        throw "Invoke-SampleExecution: either -SamplePathInVM or -LauncherPath must be provided."
    }
    if (-not $resolvedWorkingDirectory) {
        throw "Invoke-SampleExecution: either -SamplePathInVM or -WorkingDirectory must be provided."
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName       = $VMName
        ScriptBlock  = $scriptBlock
        ArgumentList = @($SamplePathInVM, $resolvedLauncherPath, $resolvedLauncherArguments, $resolvedWorkingDirectory, $TimeoutSeconds, $DumpsDir, $DumpIntervalSeconds, $MaxDumps, $MaxWorkingSetBytes, $PollIntervalMs, $BehavioralTracing.IsPresent, $MonitorDllPath, $MonitorLoaderPath, $MonitorPidFile, $MonitorPidWaitSeconds, $AdaptiveMinWindowSeconds, $AdaptiveIdleGraceSeconds, $ActivityFilePath, $AdoptedPidsFile, $MinRuntimeSeconds)
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Copy-AgentToVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$AgentSourceDir,

        [Parameter(Mandatory = $false)]
        [string]$DestinationDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    if (-not (Test-Path $AgentSourceDir)) {
        throw "Agent source directory not found: $AgentSourceDir"
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword

    $prep = {
        param($folder)
        if (Test-Path $folder) { Remove-Item -Path $folder -Recurse -Force }
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        return $folder
    }
    $invokeArgsPrep = @{ VMName = $VMName; ScriptBlock = $prep; ArgumentList = $DestinationDir }
    if ($cred) { $invokeArgsPrep['Credential'] = $cred }
    Invoke-AnalysisCommand $invokeArgsPrep | Out-Null

    # Copy-VMFile only copies files, not directories recursively. Zip and copy.
    $zipPath = Join-Path $env:TEMP "SandboxAgent.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$AgentSourceDir\*" -DestinationPath $zipPath -Force

    Copy-AnalysisFileToTarget -VMName $VMName -SourcePath $zipPath -DestinationPath "$DestinationDir\agent.zip"

    $unpack = {
        param($folder)
        Expand-Archive -Path "$folder\agent.zip" -DestinationPath $folder -Force
        Remove-Item "$folder\agent.zip" -Force
        return $folder
    }
    $invokeArgsUnpack = @{ VMName = $VMName; ScriptBlock = $unpack; ArgumentList = $DestinationDir }
    if ($cred) { $invokeArgsUnpack['Credential'] = $cred }
    Invoke-AnalysisCommand $invokeArgsUnpack | Out-Null

    return [PSCustomObject]@{
        VMName          = $VMName
        DestinationDir  = $DestinationDir
        Status          = "copied"
    }
}

function Copy-SampleFolderToVM {
    <#
    .SYNOPSIS
        Multi-file zip staging: extract a HOST-side staging zip (all entries
        of a submitted archive, with sanitized relative paths built by
        orchestrator/sample_types.py::build_staging_zip) into the guest
        working dir, so DLL side-loading and companion payloads resolve
        next to the launched sample. Follows the Copy-AgentToVM idiom
        (Copy-VMFile a zip, guest-side Expand-Archive) because Copy-VMFile
        cannot copy directories recursively.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$StagingZipPath,

        [Parameter(Mandatory = $false)]
        [string]$DestinationFolder = "C:\Sandbox",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    if (-not (Test-Path $StagingZipPath)) {
        throw "Staging zip not found: $StagingZipPath"
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword

    $prep = {
        param($folder)
        if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        return $folder
    }
    $invokeArgsPrep = @{ VMName = $VMName; ScriptBlock = $prep; ArgumentList = $DestinationFolder }
    if ($cred) { $invokeArgsPrep['Credential'] = $cred }
    Invoke-AnalysisCommand $invokeArgsPrep | Out-Null

    $guestZip = "$DestinationFolder\_staging.zip"
    Copy-AnalysisFileToTarget -VMName $VMName -SourcePath $StagingZipPath -DestinationPath $guestZip

    $unpack = {
        param($folder, $zip)
        Expand-Archive -Path $zip -DestinationPath $folder -Force
        Remove-Item $zip -Force
        $count = @(Get-ChildItem -Path $folder -Recurse -File).Count
        return $count
    }
    $invokeArgsUnpack = @{ VMName = $VMName; ScriptBlock = $unpack; ArgumentList = @($DestinationFolder, $guestZip) }
    if ($cred) { $invokeArgsUnpack['Credential'] = $cred }
    $extracted = Invoke-AnalysisCommand $invokeArgsUnpack

    return [PSCustomObject]@{
        VMName            = $VMName
        DestinationFolder = $DestinationFolder
        Extracted         = [int]$extracted
        Status            = "staged"
    }
}

function Invoke-TelemetryInit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$AgentDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$Sources = "sysmon",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($agentDir, $sources)
        $python = Join-Path $agentDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) {
            # Prefer the Python installation deployed by the orchestrator
            $python = 'C:\Python311\python.exe'
            if (-not (Test-Path $python)) {
                # Last resort: system Python (may be a broken Store alias in remote sessions)
                $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
                if (-not $python) { throw "Python not found in VM" }
            }
        }
        $collector = Join-Path $agentDir "telemetry_collector.py"
        & $python $collector init --sources $sources
        return @{ ExitCode = $LASTEXITCODE }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{ VMName = $VMName; ScriptBlock = $scriptBlock; ArgumentList = $AgentDir, $Sources }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-TelemetryCollect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$AgentDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$Sources = "sysmon",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($agentDir, $sources)
        $python = Join-Path $agentDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) {
            $python = 'C:\Python311\python.exe'
            if (-not (Test-Path $python)) {
                $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
                if (-not $python) { throw "Python not found in VM" }
            }
        }
        $collector = Join-Path $agentDir "telemetry_collector.py"
        & $python $collector collect --sources $sources
        return @{ ExitCode = $LASTEXITCODE }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{ VMName = $VMName; ScriptBlock = $scriptBlock; ArgumentList = $AgentDir, $Sources }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Copy-TelemetryFromVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$HostDestinationPath,

        [Parameter(Mandatory = $false)]
        [string]$GuestSourcePath = "C:\SandboxAgent\telemetry.jsonl",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $destDir = Split-Path -Parent $HostDestinationPath
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $sessParams = @{ VMName = $VMName }
    if ($cred) { $sessParams['Credential'] = $cred }
    $sess = $null
    try {
        if ($script:LocalMode) {
            Copy-Item -Path $GuestSourcePath -Destination $HostDestinationPath -Force
        } else {
            $sess = New-PSSession @sessParams
            Copy-Item -FromSession $sess -Path $GuestSourcePath -Destination $HostDestinationPath -Force
        }
        $status = "copied"
    }
    catch {
        $status = "error: $_"
        throw
    }
    finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }

    return [PSCustomObject]@{
        VMName       = $VMName
        HostPath     = $HostDestinationPath
        GuestPath    = $GuestSourcePath
        Status       = $status
    }
}

function Invoke-NetworkCaptureStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$AgentDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$OutputDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$EtlFilename = "network.etl",

        [Parameter(Mandatory = $false)]
        [string]$PcapngFilename = "network.pcapng",

        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 256,

        [Parameter(Mandatory = $false)]
        [int]$SnaplenBytes = 0,

        [Parameter(Mandatory = $false)]
        [string]$Components = "all",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($agentDir, $outputDir, $etlFilename, $pcapngFilename, $maxFileSizeMB, $snaplenBytes, $components)
        $python = Join-Path $agentDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) {
            $python = 'C:\Python311\python.exe'
            if (-not (Test-Path $python)) {
                $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
                if (-not $python) { throw "Python not found in VM" }
            }
        }
        $capture = Join-Path $agentDir "network_capture.py"
        $output = & $python $capture start `
            --output-dir $outputDir `
            --etl-filename $etlFilename `
            --pcapng-filename $pcapngFilename `
            --max-file-size-mb $maxFileSizeMB `
            --snaplen-bytes $snaplenBytes `
            --components $components | Out-String
        return ($output | ConvertFrom-Json)
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName       = $VMName
        ScriptBlock  = $scriptBlock
        ArgumentList = $AgentDir, $OutputDir, $EtlFilename, $PcapngFilename, $MaxFileSizeMB, $SnaplenBytes, $Components
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-NetworkCaptureStop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$AgentDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$OutputDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$EtlFilename = "network.etl",

        [Parameter(Mandatory = $false)]
        [string]$PcapngFilename = "network.pcapng",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($agentDir, $outputDir, $etlFilename, $pcapngFilename)
        $python = Join-Path $agentDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) {
            $python = 'C:\Python311\python.exe'
            if (-not (Test-Path $python)) {
                $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
                if (-not $python) { throw "Python not found in VM" }
            }
        }
        $capture = Join-Path $agentDir "network_capture.py"
        $stopOutput = & $python $capture stop `
            --output-dir $outputDir `
            --etl-filename $etlFilename `
            --pcapng-filename $pcapngFilename | Out-String
        $convertOutput = & $python $capture convert `
            --output-dir $outputDir `
            --etl-filename $etlFilename `
            --pcapng-filename $pcapngFilename | Out-String
        return @{
            Stop    = ($stopOutput | ConvertFrom-Json)
            Convert = ($convertOutput | ConvertFrom-Json)
        }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName       = $VMName
        ScriptBlock  = $scriptBlock
        ArgumentList = $AgentDir, $OutputDir, $EtlFilename, $PcapngFilename
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-ApitraceStart {
    <#
    .SYNOPSIS
        Start apitrace_collector.py as a DETACHED background process in the
        guest, before the traced sample launches. Unlike network capture
        (pktmon runs as a kernel session independent of the calling python
        process, so its "start" command returns instantly), the collector IS a
        long-lived python process -- its own accept-loop must keep running
        after this Invoke-Command call returns, so it's launched via
        Start-Process (detached), not awaited directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$AgentDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$OutputFile = "C:\SandboxAgent\apitrace.jsonl",

        [Parameter(Mandatory = $false)]
        [string]$StopFile = "C:\SandboxAgent\apitrace_stop.flag",

        [Parameter(Mandatory = $false)]
        [string]$PidsFile = "",

        [Parameter(Mandatory = $false)]
        [int]$MaxSeconds = 900,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($agentDir, $outputFile, $stopFile, $maxSeconds, $pidsFile)
        $python = Join-Path $agentDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) {
            $python = 'C:\Python311\python.exe'
            if (-not (Test-Path $python)) {
                $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
                if (-not $python) { throw "Python not found in VM" }
            }
        }
        $collector = Join-Path $agentDir "apitrace_collector.py"
        # Clear stale state from any prior (crashed/killed) run before starting.
        foreach ($stale in @($outputFile, $stopFile, $pidsFile)) {
            if ($stale -and (Test-Path $stale)) { Remove-Item -Path $stale -Force -ErrorAction SilentlyContinue }
        }
        $collectorArgs = @($collector, '--out', $outputFile, '--stop-file', $stopFile, '--max-seconds', $maxSeconds, '--quiet')
        if ($pidsFile) { $collectorArgs += @('--pids-file', $pidsFile) }
        $proc = Start-Process -FilePath $python `
            -ArgumentList $collectorArgs `
            -WindowStyle Hidden -PassThru
        # Give the pipe server a moment to bind before the sample (which
        # connects to it almost immediately after injection) launches.
        Start-Sleep -Milliseconds 600
        return @{ Started = $true; CollectorPid = $proc.Id; OutputFile = $outputFile }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName       = $VMName
        ScriptBlock  = $scriptBlock
        ArgumentList = $AgentDir, $OutputFile, $StopFile, $MaxSeconds, $PidsFile
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-ApitraceStop {
    <#
    .SYNOPSIS
        Stop the apitrace collector: signal it via the stop-file (graceful --
        it flushes and closes apitrace.jsonl on its own), wait briefly, then
        force-kill by PID as a fallback if it hasn't exited. Must complete
        BEFORE telemetry_collect reads apitrace.jsonl, or the read can race an
        still-open file handle.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [int]$CollectorPid = 0,

        [Parameter(Mandatory = $false)]
        [string]$StopFile = "C:\SandboxAgent\apitrace_stop.flag",

        [Parameter(Mandatory = $false)]
        [int]$WaitSeconds = 8,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($collectorPid, $stopFile, $waitSeconds)
        New-Item -ItemType File -Path $stopFile -Force -ErrorAction SilentlyContinue | Out-Null
        $exitedGracefully = $false
        if ($collectorPid -gt 0) {
            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while ($deadline.Elapsed.TotalSeconds -lt $waitSeconds) {
                $p = Get-Process -Id $collectorPid -ErrorAction SilentlyContinue
                if (-not $p) { $exitedGracefully = $true; break }
                Start-Sleep -Milliseconds 200
            }
            if (-not $exitedGracefully) {
                try { Stop-Process -Id $collectorPid -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
        return @{ Stopped = $true; ExitedGracefully = $exitedGracefully }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName       = $VMName
        ScriptBlock  = $scriptBlock
        ArgumentList = $CollectorPid, $StopFile, $WaitSeconds
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-GuardianStart {
    <#
    .SYNOPSIS
        Start guardian_agent.py as a DETACHED background process in the
        guest, before the sample launches. Mirrors Invoke-ApitraceStart: the
        agent is long-lived (drains the SandboxGuard ring), so it is launched
        via Start-Process and returns its PID for Guardian-Stop to target.
        Fails open: if the driver is absent the agent emits a
        GuardianUnavailable meta event and exits 0.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$AgentDir = "C:\SandboxAgent",

        [Parameter(Mandatory = $false)]
        [string]$OutputFile = "C:\SandboxAgent\guardian.jsonl",

        [Parameter(Mandatory = $false)]
        [string]$StopFile = "C:\SandboxAgent\guardian_stop.flag",

        [Parameter(Mandatory = $false)]
        [int]$MaxSeconds = 900,

        [Parameter(Mandatory = $false)]
        [string]$TargetImage = "",

        [Parameter(Mandatory = $false)]
        [string]$DllX64 = "",

        [Parameter(Mandatory = $false)]
        [string]$DllX86 = "",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($agentDir, $outputFile, $stopFile, $maxSeconds, $targetImage, $dllX64, $dllX86)
        $python = Join-Path $agentDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) {
            $python = 'C:\Python311\python.exe'
            if (-not (Test-Path $python)) {
                $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
                if (-not $python) { throw "Python not found in VM" }
            }
        }
        $agent = Join-Path $agentDir "guardian_agent.py"
        foreach ($stale in @($outputFile, $stopFile)) {
            if (Test-Path $stale) { Remove-Item -Path $stale -Force -ErrorAction SilentlyContinue }
        }
        $argList = @($agent, '--out', $outputFile, '--stop-file', $stopFile, '--max-seconds', $maxSeconds, '--quiet')
        if ($targetImage) { $argList += @('--target-image', $targetImage) }
        if ($dllX64) { $argList += @('--dll-x64', $dllX64) }
        if ($dllX86) { $argList += @('--dll-x86', $dllX86) }
        $proc = Start-Process -FilePath $python -ArgumentList $argList -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 600
        return @{ Started = $true; AgentPid = $proc.Id; OutputFile = $outputFile }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName       = $VMName
        ScriptBlock  = $scriptBlock
        ArgumentList = $AgentDir, $OutputFile, $StopFile, $MaxSeconds, $TargetImage, $DllX64, $DllX86
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-GuardianStop {
    <#
    .SYNOPSIS
        Stop the guardian agent (stop-file -> graceful CLEAR_ALL + flush,
        force-kill fallback). Must run BEFORE telemetry_collect reads
        guardian.jsonl (mirrors Invoke-ApitraceStop's contract).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [int]$AgentPid = 0,

        [Parameter(Mandatory = $false)]
        [string]$StopFile = "C:\SandboxAgent\guardian_stop.flag",

        [Parameter(Mandatory = $false)]
        [int]$WaitSeconds = 8,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $scriptBlock = {
        param($agentPid, $stopFile, $waitSeconds)
        New-Item -ItemType File -Path $stopFile -Force -ErrorAction SilentlyContinue | Out-Null
        $exitedGracefully = $false
        if ($agentPid -gt 0) {
            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while ($deadline.Elapsed.TotalSeconds -lt $waitSeconds) {
                $p = Get-Process -Id $agentPid -ErrorAction SilentlyContinue
                if (-not $p) { $exitedGracefully = $true; break }
                Start-Sleep -Milliseconds 200
            }
            if (-not $exitedGracefully) {
                try { Stop-Process -Id $agentPid -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
        return @{ Stopped = $true; ExitedGracefully = $exitedGracefully }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName       = $VMName
        ScriptBlock  = $scriptBlock
        ArgumentList = $AgentPid, $StopFile, $WaitSeconds
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Copy-NetworkCaptureFromVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$HostDestinationPath,

        [Parameter(Mandatory = $false)]
        [string]$GuestSourcePath = "C:\SandboxAgent\network.pcapng",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $destDir = Split-Path -Parent $HostDestinationPath
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $sessParams = @{ VMName = $VMName }
    if ($cred) { $sessParams['Credential'] = $cred }
    $sess = $null
    try {
        if ($script:LocalMode) {
            Copy-Item -Path $GuestSourcePath -Destination $HostDestinationPath -Force
        } else {
            $sess = New-PSSession @sessParams
            Copy-Item -FromSession $sess -Path $GuestSourcePath -Destination $HostDestinationPath -Force
        }
        $size = (Get-Item $HostDestinationPath).Length
        $status = "copied"
    }
    catch {
        $size = 0
        $status = "error: $_"
    }
    finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }

    return [PSCustomObject]@{
        VMName       = $VMName
        HostPath     = $HostDestinationPath
        GuestPath    = $GuestSourcePath
        Status       = $status
        SizeBytes    = $size
    }
}

function Copy-ProcessDumpsFromVM {
    <#
    .SYNOPSIS
        Copies the whole guest-side dumps directory off the VM in one shot
        (Copy-Item -FromSession supports -Recurse over a PSRP session
        regardless of transport -- WinRM or, here, VMBus-based PS Direct).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$HostDestinationDir,

        [Parameter(Mandatory = $false)]
        [string]$GuestSourceDir = "C:\SandboxAgent\dumps",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    if (-not (Test-Path $HostDestinationDir)) { New-Item -ItemType Directory -Path $HostDestinationDir -Force | Out-Null }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $sessParams = @{ VMName = $VMName }
    if ($cred) { $sessParams['Credential'] = $cred }
    $sess = $null
    $files = @()
    try {
        if ($script:LocalMode) {
            $remoteHasDumps = Test-Path $GuestSourceDir
        } else {
            $sess = New-PSSession @sessParams
            $remoteHasDumps = Invoke-Command -Session $sess -ScriptBlock { param($p) Test-Path $p } -ArgumentList $GuestSourceDir
        }
        if ($remoteHasDumps) {
            if ($script:LocalMode) {
                Copy-Item -Path $GuestSourceDir -Destination $HostDestinationDir -Recurse -Force
            } else {
                Copy-Item -FromSession $sess -Path $GuestSourceDir -Destination $HostDestinationDir -Recurse -Force
            }
            $copiedDir = Join-Path $HostDestinationDir (Split-Path -Leaf $GuestSourceDir)
            if (Test-Path $copiedDir) {
                $files = Get-ChildItem -Path $copiedDir -File | ForEach-Object {
                    [PSCustomObject]@{ Filename = $_.Name; SizeBytes = $_.Length; HostPath = $_.FullName }
                }
            }
        }
        $status = "copied"
    }
    catch {
        $status = "error: $_"
    }
    finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }

    return [PSCustomObject]@{
        VMName       = $VMName
        HostDestinationDir = $HostDestinationDir
        GuestSourceDir      = $GuestSourceDir
        Status       = $status
        Files        = $files
    }
}

function Copy-SandboxArchiveFromVM {
    <#
    .SYNOPSIS
        Copies SELECTED files out of Sysmon's deleted-file archive
        (ArchiveDirectory, default C:\SandboxArchive) to the host.

        Two constraints, both empirically confirmed 2026-09-04:
        - the archive dir is protected with a SYSTEM-only ACL (gigi cannot
          even Test-Path inside it) -> all archive access goes through a
          one-shot scheduled task running as SYSTEM, staging matches into a
          gigi-readable dir;
        - archived filenames are the configured hash algorithms concatenated
          (uppercase hex, no separators) + the original extension, e.g.
          <md5><sha256>.exe -- so the host computes the exact expected names
          from FileDelete event hashes and passes them in as candidates
          (GuestFileCandidates, "|"-delimited, same convention as
          Copy-DroppedFilesFromVM). The archive can hold tens of thousands
          of residue files from the golden image -- never bulk-copy it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$HostDestinationDir,

        [Parameter(Mandatory = $true)]
        [string]$GuestFileCandidates,

        [Parameter(Mandatory = $false)]
        [string]$StagingDir = "C:\SandboxAgent\archive_pull",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null
    if (-not (Test-Path $HostDestinationDir)) { New-Item -ItemType Directory -Path $HostDestinationDir -Force | Out-Null }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{ VMName = $VMName }
    if ($cred) { $invokeArgs['Credential'] = $cred }

    # 1. Write the candidate list (gigi-readable spec file), then a SYSTEM
    #    task stages whichever candidates actually exist in the archive.
    $specPath = Join-Path (Split-Path -Parent $StagingDir) 'archive_pull_spec.json'
    $stageScript = Join-Path (Split-Path -Parent $StagingDir) 'archive_pull_stage.ps1'
    $candidates = @($GuestFileCandidates -split '\|' | Where-Object { $_ })
    Invoke-AnalysisCommand $invokeArgs -ScriptBlock {
        param($specPath, $candidates, $stageScript, $stagingDir)
        $candidates | ConvertTo-Json -Compress | Set-Content -Path $specPath -Encoding ascii
        $body = @'
$spec = Get-Content SPEC_PATH -Raw | ConvertFrom-Json
if ($spec -isnot [array]) { $spec = @($spec) }
if (Test-Path 'STAGING_DIR') { Remove-Item 'STAGING_DIR' -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path 'STAGING_DIR' -Force | Out-Null
foreach ($p in $spec) {
    if (Test-Path $p) {
        $dest = Join-Path 'STAGING_DIR' (Split-Path -Leaf $p)
        Copy-Item $p $dest -Force -ErrorAction SilentlyContinue
    }
}
'STAGED' | Set-Content -Path 'STAGING_DIR\_staged.txt' -Encoding ascii
'@
        $body = $body.Replace('SPEC_PATH', $specPath).Replace('STAGING_DIR', $stagingDir)
        Set-Content -Path $stageScript -Value $body -Encoding ascii
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$stageScript`""
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName 'SandboxArchivePull' -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName 'SandboxArchivePull'
    } -ArgumentList $specPath, $candidates, $stageScript, $StagingDir | Out-Null

    # 2. Wait for the staging marker (or timeout).
    $marker = "$StagingDir\_staged.txt"
    $staged = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 60) {
        $staged = Invoke-AnalysisCommand $invokeArgs -ScriptBlock { param($p) Test-Path $p } -ArgumentList $marker
        if ($staged) { break }
        Start-Sleep -Seconds 1
    }
    Invoke-AnalysisCommand $invokeArgs -ScriptBlock {
        Unregister-ScheduledTask -TaskName 'SandboxArchivePull' -Confirm:$false -ErrorAction SilentlyContinue
    } | Out-Null
    if (-not $staged) {
        return [PSCustomObject]@{ VMName = $VMName; HostDestinationDir = $HostDestinationDir; Status = 'stage_timeout'; Files = @() }
    }

    # 3. Pull the staging dir to the host (same recurse pattern as dumps).
    $sessParams = @{ VMName = $VMName }
    if ($cred) { $sessParams['Credential'] = $cred }
    $sess = $null
    $files = @()
    try {
        if ($script:LocalMode) {
            $hasStaging = Test-Path $StagingDir
        } else {
            $sess = New-PSSession @sessParams
            $hasStaging = Invoke-Command -Session $sess -ScriptBlock { param($p) Test-Path $p } -ArgumentList $StagingDir
        }
        if ($hasStaging) {
            if ($script:LocalMode) {
                Copy-Item -Path $StagingDir -Destination $HostDestinationDir -Recurse -Force
            } else {
                Copy-Item -FromSession $sess -Path $StagingDir -Destination $HostDestinationDir -Recurse -Force
            }
            $copiedDir = Join-Path $HostDestinationDir (Split-Path -Leaf $StagingDir)
            if (Test-Path $copiedDir) {
                $files = Get-ChildItem -Path $copiedDir -File -Recurse | Where-Object { $_.Name -ne '_staged.txt' } | ForEach-Object {
                    [PSCustomObject]@{ Filename = $_.Name; SizeBytes = $_.Length; HostPath = $_.FullName }
                }
            }
        }
        $status = 'copied'
    }
    catch {
        $status = "error: $_"
    }
    finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
        Invoke-AnalysisCommand $invokeArgs -ScriptBlock {
            param($p, $s, $spec) Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $s, $spec -Force -ErrorAction SilentlyContinue
        } -ArgumentList $StagingDir, $stageScript, $specPath | Out-Null
    }

    return [PSCustomObject]@{
        VMName             = $VMName
        HostDestinationDir = $HostDestinationDir
        Status             = $status
        Files              = $files
    }
}

function Clear-SandboxArchive {
    <#
    .SYNOPSIS
        Empties Sysmon's deleted-file archive (ArchiveDirectory, default
        C:\SandboxArchive) in the guest -- golden-image hygiene. The archive
        dir has a SYSTEM-only ACL (gigi cannot even Test-Path inside it), so
        the purge runs as a one-shot scheduled task as SYSTEM, same trick as
        Copy-SandboxArchiveFromVM. The directory itself is kept (Sysmon owns
        it). Before/after stats are written to a gigi-readable result file so
        the host can verify-gate the snapshot recapture.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$ArchiveDir = "C:\SandboxArchive",

        [Parameter(Mandatory = $false)]
        [string]$ResultPath = "C:\SandboxAgent\archive_clean_result.json",

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null
    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{ VMName = $VMName }
    if ($cred) { $invokeArgs['Credential'] = $cred }

    # 1. Register + start a one-shot SYSTEM task that purges the archive
    #    contents and writes before/after stats as JSON.
    $cleanScript = "C:\SandboxAgent\archive_clean.ps1"
    Invoke-AnalysisCommand $invokeArgs -ScriptBlock {
        param($cleanScript, $archiveDir, $resultPath)
        $body = @'
$dir = 'ARCHIVE_DIR'
$res = 'RESULT_PATH'
function Measure-Archive($d) {
    if (-not (Test-Path $d)) { return @{ files = 0; bytes = 0; exists = $false } }
    # .NET enumeration is much faster than Get-ChildItem for ~100k entries
    $count = 0; $bytes = [int64]0
    foreach ($p in [System.IO.Directory]::EnumerateFiles($d, '*', 'AllDirectories')) {
        $count++
        try { $bytes += (New-Object System.IO.FileInfo($p)).Length } catch {}
    }
    return @{ files = $count; bytes = $bytes; exists = $true }
}
$before = Measure-Archive $dir
if (Test-Path $dir) {
    # robocopy /MIR from an empty dir = fastest mass-delete on Windows;
    # mirrors CONTENT only (no /SEC), so the archive dir's own ACL is untouched
    $empty = Join-Path $env:TEMP 'sandbox_archive_empty'
    New-Item -ItemType Directory -Path $empty -Force | Out-Null
    robocopy $empty $dir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
    Remove-Item $empty -Recurse -Force -ErrorAction SilentlyContinue
}
$after = Measure-Archive $dir
@{ before = $before; after = $after } | ConvertTo-Json -Compress | Set-Content -Path $res -Encoding ascii
'@
        $body = $body.Replace('ARCHIVE_DIR', $archiveDir).Replace('RESULT_PATH', $resultPath)
        Set-Content -Path $cleanScript -Value $body -Encoding ascii
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$cleanScript`""
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName 'SandboxArchiveClean' -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName 'SandboxArchiveClean'
    } -ArgumentList $cleanScript, $ArchiveDir, $ResultPath | Out-Null

    # 2. Wait for the result file (purge of ~100k files: measure + robocopy +
    #    re-measure; generous budget for a spinning VHD).
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $done = $false
    while ($sw.Elapsed.TotalSeconds -lt 900) {
        $done = Invoke-AnalysisCommand $invokeArgs -ScriptBlock { param($p) Test-Path $p } -ArgumentList $ResultPath
        if ($done) { break }
        Start-Sleep -Seconds 3
    }
    $stats = $null
    if ($done) {
        $raw = Invoke-AnalysisCommand $invokeArgs -ScriptBlock { param($p) Get-Content $p -Raw } -ArgumentList $ResultPath
        $stats = $raw | ConvertFrom-Json
    }
    Invoke-AnalysisCommand $invokeArgs -ScriptBlock {
        param($c, $r)
        Unregister-ScheduledTask -TaskName 'SandboxArchiveClean' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $c, $r -Force -ErrorAction SilentlyContinue
    } -ArgumentList $cleanScript, $ResultPath | Out-Null

    if (-not $done) {
        return [PSCustomObject]@{ VMName = $VMName; ArchiveDir = $ArchiveDir; Status = 'clean_timeout' }
    }
    return [PSCustomObject]@{
        VMName      = $VMName
        ArchiveDir  = $ArchiveDir
        Status      = 'cleaned'
        BeforeFiles = [int]$stats.before.files
        BeforeBytes = [int64]$stats.before.bytes
        AfterFiles  = [int]$stats.after.files
        AfterBytes  = [int64]$stats.after.bytes
    }
}

function Copy-DroppedFilesFromVM {
    <#
    .SYNOPSIS
        Copies a specific list of guest-side files off the VM (as opposed
        to Copy-ProcessDumpsFromVM's whole-directory recurse) -- one open
        PSSession, looped per file, so a single locked/missing file never
        aborts retrieval of the others. Destination filenames are indexed
        (0000_, 0001_, ...) to avoid collisions between same-named files
        dropped in different guest directories.

        GuestSourcePaths is a single "|"-delimited string, not a native
        PowerShell array -- this script is invoked via
        `powershell.exe -File ... <command> <args>` from Python's
        subprocess, which can only pass scalar string args through
        hyperv.py::_run_ps(); "|" is used as the delimiter (not ",") since
        it's a reserved character that can never appear in a valid Windows
        file path, unlike a comma.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$HostDestinationDir,

        [Parameter(Mandatory = $true)]
        [string]$GuestSourcePaths,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    Assert-VMExists -VMName $VMName | Out-Null

    $pathList = $GuestSourcePaths -split '\|' | Where-Object { $_ }

    if (-not (Test-Path $HostDestinationDir)) { New-Item -ItemType Directory -Path $HostDestinationDir -Force | Out-Null }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $sessParams = @{ VMName = $VMName }
    if ($cred) { $sessParams['Credential'] = $cred }
    $sess = $null
    $files = @()
    try {
        if (-not $script:LocalMode) { $sess = New-PSSession @sessParams }
        $index = 0
        foreach ($guestPath in $pathList) {
            $originalName = Split-Path -Leaf $guestPath
            $destName = "{0:D4}_{1}" -f $index, $originalName
            $destPath = Join-Path $HostDestinationDir $destName
            try {
                if ($script:LocalMode) {
                    $exists = Test-Path $guestPath
                } else {
                    $exists = Invoke-Command -Session $sess -ScriptBlock { param($p) Test-Path $p } -ArgumentList $guestPath
                }
                if ($exists) {
                    if ($script:LocalMode) {
                        Copy-Item -Path $guestPath -Destination $destPath -Force
                    } else {
                        Copy-Item -FromSession $sess -Path $guestPath -Destination $destPath -Force
                    }
                    if (Test-Path $destPath) {
                        $files += [PSCustomObject]@{
                            Filename     = $destName
                            OriginalPath = $guestPath
                            SizeBytes    = (Get-Item $destPath).Length
                            HostPath     = $destPath
                            Status       = "copied"
                        }
                    }
                    else {
                        $files += [PSCustomObject]@{
                            Filename = $destName; OriginalPath = $guestPath; SizeBytes = 0
                            HostPath = $null; Status = "copy_failed"
                        }
                    }
                }
                else {
                    $files += [PSCustomObject]@{
                        Filename = $destName; OriginalPath = $guestPath; SizeBytes = 0
                        HostPath = $null; Status = "not_found"
                    }
                }
            }
            catch {
                $files += [PSCustomObject]@{
                    Filename = $destName; OriginalPath = $guestPath; SizeBytes = 0
                    HostPath = $null; Status = "error: $_"
                }
            }
            $index++
        }
        $status = "copied"
    }
    catch {
        $status = "error: $_"
    }
    finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }

    return [PSCustomObject]@{
        VMName             = $VMName
        HostDestinationDir = $HostDestinationDir
        Status             = $status
        Files              = $files
    }
}

function Get-SandboxVMThumbnail {
    <#
    .SYNOPSIS
        Host-side VM console screenshot via Hyper-V's own WMI thumbnail API
        (the same mechanism Hyper-V Manager uses for VM thumbnails). No
        guest code, no PowerShell Direct, no credentials -- works
        regardless of guest session state and doesn't interfere with
        PowerShell Direct (a separate VMBus channel).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [int]$WidthPixels = 320,

        [Parameter(Mandatory = $false)]
        [int]$HeightPixels = 240
    )

    try {
        $cs = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$VMName'"
        if (-not $cs) { throw "VM '$VMName' not found via WMI (root\virtualization\v2)" }

        # The settings-data association returns one instance per snapshot
        # plus the live VM -- must filter to the realized (live) one or we
        # could capture a stale snapshot's thumbnail instead.
        $settingsData = Get-CimAssociatedInstance -InputObject $cs -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData |
            Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' } |
            Select-Object -First 1
        if (-not $settingsData) { throw "Could not resolve the live Msvm_VirtualSystemSettingData for '$VMName'" }

        $vsms = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
        $result = Invoke-CimMethod -InputObject $vsms -MethodName GetVirtualSystemThumbnailImage -Arguments @{
            TargetSystem = $settingsData
            WidthPixels  = [uint16]$WidthPixels
            HeightPixels = [uint16]$HeightPixels
        }

        if ($result.ReturnValue -eq 4096) {
            # Async job path -- poll JobState (3=Starting, 4=Running,
            # 7=Completed per the standard CIM_ConcreteJob enumeration)
            # until done. NOTE: unverified whether ImageData is populated
            # the same way once the job completes vs. the synchronous
            # (ReturnValue=0) path -- flagged as an open risk in the plan,
            # first real VM run is the validation gate for this branch.
            $job = [wmi]$result.Job
            while ($job.JobState -eq 3 -or $job.JobState -eq 4) {
                Start-Sleep -Milliseconds 100
                $job = [wmi]$result.Job
            }
            if ($job.JobState -ne 7) {
                throw "Thumbnail job did not complete successfully (JobState=$($job.JobState))"
            }
        }
        elseif ($result.ReturnValue -ne 0) {
            throw "GetVirtualSystemThumbnailImage failed with ReturnValue=$($result.ReturnValue)"
        }

        $imageData = $result.ImageData
        if (-not $imageData -or $imageData.Count -eq 0) {
            throw "No image data returned"
        }

        # ImageData is raw RGB565 (16bpp packed, little-endian, no header) --
        # unpack into a 24bpp Bitmap and save as PNG.
        Add-Type -AssemblyName System.Drawing
        $bmp = New-Object System.Drawing.Bitmap($WidthPixels, $HeightPixels, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
        $rect = New-Object System.Drawing.Rectangle(0, 0, $WidthPixels, $HeightPixels)
        $bmpData = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)

        $stride = $bmpData.Stride
        $outBytes = New-Object byte[] ($stride * $HeightPixels)

        for ($y = 0; $y -lt $HeightPixels; $y++) {
            for ($x = 0; $x -lt $WidthPixels; $x++) {
                $srcIndex = ($y * $WidthPixels + $x) * 2
                if ($srcIndex + 1 -ge $imageData.Count) { continue }
                $pixel = [uint16]$imageData[$srcIndex] -bor ([uint16]$imageData[$srcIndex + 1] -shl 8)
                $r5 = ($pixel -shr 11) -band 0x1F
                $g6 = ($pixel -shr 5) -band 0x3F
                $b5 = $pixel -band 0x1F
                $r8 = ($r5 -shl 3) -bor ($r5 -shr 2)
                $g8 = ($g6 -shl 2) -bor ($g6 -shr 4)
                $b8 = ($b5 -shl 3) -bor ($b5 -shr 2)
                # Format24bppRgb's in-memory byte order is B,G,R per pixel.
                $dstIndex = $y * $stride + $x * 3
                $outBytes[$dstIndex]     = [byte]$b8
                $outBytes[$dstIndex + 1] = [byte]$g8
                $outBytes[$dstIndex + 2] = [byte]$r8
            }
        }

        [System.Runtime.InteropServices.Marshal]::Copy($outBytes, 0, $bmpData.Scan0, $outBytes.Length)
        $bmp.UnlockBits($bmpData)

        $destDir = Split-Path -Parent $OutputPath
        if ($destDir -and -not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        $bmp.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()

        $size = (Get-Item $OutputPath).Length
        return [PSCustomObject]@{
            Status       = "captured"
            OutputPath   = $OutputPath
            WidthPixels  = $WidthPixels
            HeightPixels = $HeightPixels
            SizeBytes    = $size
        }
    }
    catch {
        return [PSCustomObject]@{
            Status       = "error: $_"
            OutputPath   = $OutputPath
            WidthPixels  = $WidthPixels
            HeightPixels = $HeightPixels
            SizeBytes    = 0
        }
    }
}

function Invoke-GuestPython {
    <#
    .SYNOPSIS
        Run a python script that lives in the guest agent dir (resolves the
        guest python the same way telemetry init does). Returns exit code +
        combined stdout/stderr. Used for one-off provisioning steps.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $true)][string]$ScriptName,
        [Parameter(Mandatory = $false)][string]$ScriptArgs = "",
        [Parameter(Mandatory = $false)][string]$AgentDir = "C:\SandboxAgent",
        [Parameter(Mandatory = $false)][string]$CredentialUsername,
        [Parameter(Mandatory = $false)][string]$CredentialPassword
    )
    Assert-VMExists -VMName $VMName | Out-Null
    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $scriptBlock = {
        param($agentDir, $scriptName, $scriptArgs)
        $python = Join-Path $agentDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) {
            $python = 'C:\Python311\python.exe'
            if (-not (Test-Path $python)) {
                $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
                if (-not $python) { throw "Python not found in VM" }
            }
        }
        $script = Join-Path $agentDir $scriptName
        if ($scriptArgs) { $argList = $scriptArgs.Split(' ') } else { $argList = @() }
        # 2>&1 keeps guest stderr out of the native-command error channel that
        # PowerShell Direct would otherwise turn into a fatal NativeCommandError.
        $out = & $python $script @argList 2>&1 | Out-String
        return @{ ExitCode = $LASTEXITCODE; Output = $out }
    }
    $invokeArgs = @{ VMName = $VMName; ScriptBlock = $scriptBlock; ArgumentList = $AgentDir, $ScriptName, $ScriptArgs }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Restart-SandboxGuest {
    <#
    .SYNOPSIS
        Reboot the guest OS and wait until PowerShell Direct responds again --
        needed so a boot autologger (ETW-Ti) actually starts before we
        re-capture the golden snapshot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $false)][string]$CredentialUsername,
        [Parameter(Mandatory = $false)][string]$CredentialPassword,
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 300
    )
    Assert-VMExists -VMName $VMName | Out-Null
    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword

    # Capture the guest's current boot time so we can confirm a GENUINE reboot
    # (a soft reboot keeps the Hyper-V VM "Running", and PowerShell Direct can
    # answer during the shutdown window -- so "does it respond" isn't enough;
    # we must see LastBootUpTime advance).
    $bootBeforeArgs = @{ VMName = $VMName; ScriptBlock = { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }; ErrorAction = 'Stop' }
    if ($cred) { $bootBeforeArgs['Credential'] = $cred }
    $bootBefore = [datetime](Invoke-Command @bootBeforeArgs)

    $rebootArgs = @{ VMName = $VMName; ScriptBlock = { Restart-Computer -Force } }
    if ($cred) { $rebootArgs['Credential'] = $cred }
    try { Invoke-Command @rebootArgs -ErrorAction SilentlyContinue | Out-Null } catch { }

    Start-Sleep -Seconds 25  # let the OS actually begin shutting down

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 5
        try {
            $probeArgs = @{ VMName = $VMName; ScriptBlock = { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }; ErrorAction = 'Stop' }
            if ($cred) { $probeArgs['Credential'] = $cred }
            $bootNow = [datetime](Invoke-Command @probeArgs)
            if ($bootNow -gt $bootBefore) {
                # Fresh boot confirmed; give services (autologger) a moment to settle.
                Start-Sleep -Seconds 10
                return [PSCustomObject]@{ VMName = $VMName; Status = "rebooted"; ReadyAfterSeconds = [int]$timer.Elapsed.TotalSeconds }
            }
        } catch { }
    }
    throw "Timeout waiting for VM '$VMName' to complete a fresh boot."
}

function Recapture-SandboxSnapshot {
    <#
    .SYNOPSIS
        Replace the golden snapshot in place with the VM's current (running,
        saved) state -- new-then-swap so a failure can never leave the VM with
        no snapshot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $false)][string]$SnapshotName = "SANDBOX-CLEAN"
    )
    Assert-VMExists -VMName $VMName | Out-Null

    $existing = Get-VMSnapshot -VMName $VMName -Name $SnapshotName -ErrorAction SilentlyContinue
    if (-not $existing) {
        throw "Snapshot '$SnapshotName' does not exist; refusing to recapture (create it with Ensure-Snapshot first)."
    }

    # Save running state so the checkpoint captures the autologger session in
    # memory (it only exists after a boot).
    $vm = Get-VM -Name $VMName
    if ($vm.State -ne "Off") { Stop-VM -Name $VMName -Save -Force }

    $temp = "$SnapshotName" + "-PROVISION"
    $stale = Get-VMSnapshot -VMName $VMName -Name $temp -ErrorAction SilentlyContinue
    if ($stale) { Remove-VMSnapshot -VMName $VMName -Name $temp; Start-Sleep -Seconds 3 }

    # Create + verify the replacement BEFORE touching the old one. Surface
    # the real Checkpoint-VM error instead of swallowing it (the previous
    # "if (-not $new)" path reported nothing actionable). Checkpoint-VM can
    # return before the snapshot is queryable -- poll for visibility.
    try {
        Checkpoint-VM -Name $VMName -SnapshotName $temp -ErrorAction Stop
    } catch {
        throw "Checkpoint-VM failed for replacement '$temp': $($_.Exception.Message)"
    }
    $new = $null
    $visTimer = [Diagnostics.Stopwatch]::StartNew()
    while (-not $new -and $visTimer.Elapsed.TotalSeconds -lt 120) {
        Start-Sleep -Seconds 3
        $new = Get-VMSnapshot -VMName $VMName -Name $temp -ErrorAction SilentlyContinue
    }
    if (-not $new) {
        throw "Checkpoint-VM returned but snapshot '$temp' never became visible; original '$SnapshotName' left intact."
    }

    Remove-VMSnapshot -VMName $VMName -Name $SnapshotName
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-VMSnapshot -VMName $VMName -Name $SnapshotName -ErrorAction SilentlyContinue) -and $timer.Elapsed.TotalSeconds -lt 180) {
        Start-Sleep -Seconds 3  # wait for the parent-merge to finish before renaming
    }
    Rename-VMSnapshot -VMName $VMName -Name $temp -NewName $SnapshotName
    return [PSCustomObject]@{ VMName = $VMName; SnapshotName = $SnapshotName; Status = "recaptured" }
}

# --- Interactive console support (docs/interactive-console-streaming.md) ---

function Invoke-ConsoleInputServerStart {
    <#
    .SYNOPSIS
        Start the guest console-input server INSIDE the interactive session:
        a scheduled task as the logged-on user with an interactive token.
        PSDirect sessions are non-interactive (verified 2026-09-03), so input
        for the visible desktop must be executed by a process in that session;
        the server listens on the named pipe sandbox_console_in (pipes are
        session-independent kernel objects).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $false)][string]$CredentialUsername,
        [Parameter(Mandatory = $false)][string]$CredentialPassword,
        [Parameter(Mandatory = $false)][string]$AgentDir = "C:\SandboxAgent",
        [Parameter(Mandatory = $false)][int]$ReadyTimeoutSeconds = 15
    )

    $scriptBlock = {
        param($agentDir, $userName, $readyTimeout)
        $server = Join-Path $agentDir 'console_input_server.ps1'
        if (-not (Test-Path $server)) { throw "console_input_server.ps1 not found at $server" }
        $ready = Join-Path $agentDir 'console_input_server.ready'
        Remove-Item $ready -Force -ErrorAction SilentlyContinue

        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$server`""
        $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName 'SandboxConsoleInput' -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName 'SandboxConsoleInput'

        $wait = [System.Diagnostics.Stopwatch]::StartNew()
        while ($wait.Elapsed.TotalSeconds -lt $readyTimeout) {
            if (Test-Path $ready) {
                return [PSCustomObject]@{ Status = 'ready'; Task = 'SandboxConsoleInput'; ReadyFile = $ready }
            }
            Start-Sleep -Milliseconds 500
        }
        # Not ready: report task state for diagnosis (LastTaskResult nonzero = the server died at start)
        $info = Get-ScheduledTask -TaskName 'SandboxConsoleInput' | Get-ScheduledTaskInfo
        return [PSCustomObject]@{ Status = 'not_ready'; LastTaskResult = $info.LastTaskResult; LastRunTime = $info.LastRunTime }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{ VMName = $VMName; ScriptBlock = $scriptBlock; ArgumentList = @($AgentDir, $CredentialUsername, $ReadyTimeoutSeconds) }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-ConsoleInputServerStop {
    <#
    .SYNOPSIS
        Stop the guest console-input server: ask it to quit via the pipe
        (graceful), then stop+unregister the scheduled task regardless.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $false)][string]$CredentialUsername,
        [Parameter(Mandatory = $false)][string]$CredentialPassword
    )

    $scriptBlock = {
        try {
            $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'sandbox_console_in', [System.IO.Pipes.PipeDirection]::Out)
            $client.Connect(1500)
            $writer = New-Object System.IO.StreamWriter($client)
            $writer.AutoFlush = $true
            $writer.WriteLine('{"action":"quit"}')
            $writer.Flush(); Start-Sleep -Milliseconds 300
            $writer.Dispose(); $client.Dispose()
        } catch { }
        Stop-ScheduledTask -TaskName 'SandboxConsoleInput' -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName 'SandboxConsoleInput' -Confirm:$false -ErrorAction SilentlyContinue
        return [PSCustomObject]@{ Status = 'stopped' }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{ VMName = $VMName; ScriptBlock = $scriptBlock }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Invoke-SampleExecutionInteractive {
    <#
    .SYNOPSIS
        Launch the sample on the VISIBLE console session via a scheduled task
        (interactive token as the logged-on user), so UI-driven samples
        (message boxes, installers) render on the desktop the browser console
        shows. Mirrors Invoke-SampleExecution's result shape so executor.py
        treats it interchangeably, with two deliberate differences:
        process dumps are not taken (documented gap) and stdout/stderr are
        captured to files by the guest launcher (agent/windows/
        interactive_launcher.ps1) and read back here.
        Blocks until the sample exits or the timeout kills it, exactly like
        Invoke-SampleExecution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$VMName,
        [Parameter(Mandatory = $false)][string]$SamplePathInVM,
        [Parameter(Mandatory = $false)][string]$LauncherPath,
        [Parameter(Mandatory = $false)][string]$LauncherArguments,
        [Parameter(Mandatory = $false)][string]$WorkingDirectory,
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 120,
        [Parameter(Mandatory = $false)][switch]$BehavioralTracing,
        [Parameter(Mandatory = $false)][string]$MonitorDllPath,
        [Parameter(Mandatory = $false)][string]$MonitorLoaderPath,
        [Parameter(Mandatory = $false)][string]$MonitorPidFile,
        [Parameter(Mandatory = $false)][string]$AgentDir = "C:\SandboxAgent",
        [Parameter(Mandatory = $false)][string]$CredentialUsername,
        [Parameter(Mandatory = $false)][string]$CredentialPassword
    )

    $scriptBlock = {
        param($launcherPath, $arguments, $workingDirectory, $timeoutSeconds, $behavioralTracing, $monitorDllPath, $monitorLoaderPath, $monitorPidFile, $agentDir, $userName)

        # Local copy (Invoke-SampleExecution's identically-named helper is
        # scoped to ITS guest scriptblock; scriptblocks share nothing).
        function Format-CapturedOutput($text, $max) {
            if ($null -eq $text) { return "" }
            if ($text.Length -gt $max) {
                return $text.Substring(0, $max) + "`n...(truncated, $($text.Length) total chars)"
            }
            return $text
        }

        $runDir = Join-Path $agentDir 'interactive_run'
        if (Test-Path $runDir) { Remove-Item $runDir -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Force -Path $runDir | Out-Null
        $launcherScript = Join-Path $agentDir 'interactive_launcher.ps1'
        if (-not (Test-Path $launcherScript)) { throw "interactive_launcher.ps1 not found at $launcherScript" }

        # Spec file, not task command line: arbitrary sample arguments survive
        # scheduled-task quoting untouched.
        $spec = [PSCustomObject]@{
            launcher_path       = $launcherPath
            arguments           = $arguments
            working_directory   = $workingDirectory
            timeout_seconds     = $timeoutSeconds
            behavioral_tracing  = [bool]$behavioralTracing
            monitor_dll_path    = $monitorDllPath
            monitor_loader_path = $monitorLoaderPath
            monitor_pid_file    = $monitorPidFile
        }
        $spec | ConvertTo-Json -Compress | Set-Content -Path (Join-Path $runDir 'launch_spec.json') -Encoding ascii

        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcherScript`" -WorkDir `"$runDir`""
        $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName 'SandboxInteractiveRun' -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName 'SandboxInteractiveRun'

        $resultPath = Join-Path $runDir 'launch_result.json'
        $stdoutPath = Join-Path $runDir 'stdout.txt'
        $stderrPath = Join-Path $runDir 'stderr.txt'
        try {
            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while (-not (Test-Path $resultPath) -and $deadline.Elapsed.TotalSeconds -lt ($timeoutSeconds + 60)) {
                Start-Sleep -Seconds 1
            }
            if (-not (Test-Path $resultPath)) {
                throw "interactive launcher produced no result within $($timeoutSeconds + 60)s"
            }
            $result = Get-Content $resultPath -Raw | ConvertFrom-Json
            $stdoutText = if (Test-Path $stdoutPath) { [System.IO.File]::ReadAllText($stdoutPath) } else { '' }
            $stderrText = if (Test-Path $stderrPath) { [System.IO.File]::ReadAllText($stderrPath) } else { '' }
            if ($result.TimedOut) { $stderrText = "Process did not exit within timeout`n" + $stderrText }

            return [PSCustomObject]@{
                ProcessId               = $result.ProcessId
                Started                 = $true
                Path                    = $launcherPath
                LauncherPath            = $launcherPath
                ExitCode                = $result.ExitCode
                Stdout                  = Format-CapturedOutput $stdoutText 65536
                Stderr                  = Format-CapturedOutput $stderrText 65536
                TimedOut                = [bool]$result.TimedOut
                ProcessDumps            = @()
                BehavioralTracingActive = [bool]$result.BehavioralTracingActive
                Interactive             = $true
            }
        } finally {
            Stop-ScheduledTask -TaskName 'SandboxInteractiveRun' -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'SandboxInteractiveRun' -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    $invokeArgs = @{
        VMName      = $VMName
        ScriptBlock = $scriptBlock
        ArgumentList = @($LauncherPath, $LauncherArguments, $WorkingDirectory, $TimeoutSeconds,
                         $BehavioralTracing.IsPresent, $MonitorDllPath, $MonitorLoaderPath, $MonitorPidFile,
                         $AgentDir, $CredentialUsername)
    }
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

$script:InstrumentationProbe = {
    <#
    Shared instrumentation-health probe. Runs ON the analysis machine,
    whatever it is: in-process for local mode (Get-LocalSandboxStatus), via
    PSDirect Invoke-Command inside the guest for hyperv mode
    (Get-GuestHealth). Must stay self-contained (no calls to functions in
    this script -- it is remoted). Every check is defensive: a broken probe
    reports $false, never throws.

    defender_rtp is guest-relevant: on a detonation VM realtime protection
    must be OFF (samples must run); the dashboard renders it inverted.
    #>
    $sysmon = $false
    try {
        $svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
               Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1
        $sysmon = [bool]$svc
    } catch {}

    $agentDir = 'C:\SandboxAgent'
    $agentPresent = [bool](Test-Path $agentDir)
    $dlls = $false
    if ($agentPresent) {
        $dlls = [bool]((Test-Path (Join-Path $agentDir 'monitor_x64.dll')) -and
                       (Test-Path (Join-Path $agentDir 'monitor_x86.dll')) -and
                       (Test-Path (Join-Path $agentDir 'monitor_loader.exe')))
    }

    $guardian = $false
    try {
        $gsvc = Get-CimInstance Win32_SystemDriver -Filter "Name='SandboxGuard'" -ErrorAction SilentlyContinue
        $guardian = [bool]($gsvc -and $gsvc.State -eq 'Running')
    } catch {}

    $secureBoot = $false
    try {
        # Throws on non-UEFI / unsupported platforms -> treat as off
        $secureBoot = [bool](Confirm-SecureBootUEFI)
    } catch { $secureBoot = $false }

    $defenderRtp = $false
    try {
        $defenderRtp = [bool](Get-MpComputerStatus).RealTimeProtectionEnabled
    } catch {}

    $osCaption = ''
    $osBuild = ''
    try {
        $probeOs = Get-CimInstance Win32_OperatingSystem
        $osCaption = $probeOs.Caption
        $osBuild = $probeOs.BuildNumber
    } catch {}

    return [PSCustomObject]@{
        Checks = [PSCustomObject]@{
            sysmon          = $sysmon
            agent_dir       = $agentPresent
            monitor_dlls    = $dlls
            guardian_driver = $guardian
            secure_boot     = $secureBoot
            defender_rtp    = $defenderRtp
        }
        System = [PSCustomObject]@{
            Hostname = $env:COMPUTERNAME
            OS       = $osCaption
            Build    = $osBuild
        }
    }
}

function Get-GuestHealth {
    <#
    .SYNOPSIS
        Instrumentation health of the Hyper-V analysis GUEST (hyperv-mode
        counterpart of Get-LocalSandboxStatus): runs the shared
        $script:InstrumentationProbe inside the VM via PSDirect. Read-only
        and defensive -- VM off or any PSDirect failure yields Checks=$null
        plus a ChecksError string; never throws. Consumed by
        HyperVManager.get_status (30s TTL cache) for the dashboard's
        "Analysis Environment" card.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    $result = [PSCustomObject]@{ Checks = $null; GuestSystem = $null; ChecksError = $null }
    try {
        $vm = Assert-VMExists -VMName $VMName
        if ($vm.State -ne 'Running') {
            $result.ChecksError = "VM is $($vm.State)"
            return $result
        }
        $invokeArgs = @{ VMName = $VMName; ScriptBlock = $script:InstrumentationProbe }
        $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
        if ($cred) { $invokeArgs['Credential'] = $cred }
        $probe = Invoke-AnalysisCommand $invokeArgs
        if ($probe) {
            $result.Checks = $probe.Checks
            $result.GuestSystem = $probe.System
        }
    } catch {
        $result.ChecksError = $_.Exception.Message
    }
    return $result
}

function Get-TelemetryTail {
    <#
    .SYNOPSIS
        Incremental tail of a telemetry JSONL file (live run streaming).
        Reads from byte -Offset to EOF (cap 256 KB per call) and returns the
        new offset. The collector holds the file open, so FileShare ReadWrite
        is mandatory. Runs in the guest (hyperv mode) or in-process (local
        mode) via the standard Invoke-AnalysisCommand seam.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [long]$Offset = 0,

        [Parameter(Mandatory = $false)]
        [string]$CredentialUsername,

        [Parameter(Mandatory = $false)]
        [string]$CredentialPassword
    )

    $tailScript = {
        param($TailPath, $TailOffset)
        if (-not (Test-Path $TailPath)) {
            return [PSCustomObject]@{ Offset = 0; Text = '' }
        }
        $fs = $null
        try {
            $fs = [System.IO.File]::Open($TailPath, [System.IO.FileMode]::Open,
                                         [System.IO.FileAccess]::Read,
                                         [System.IO.FileShare]::ReadWrite)
            if ($TailOffset -gt $fs.Length) { $TailOffset = 0 }  # rotated/truncated
            $fs.Position = $TailOffset
            $cap = 262144
            $toRead = [Math]::Min($cap, $fs.Length - $TailOffset)
            $buf = New-Object byte[] $toRead
            $read = $fs.Read($buf, 0, $toRead)
            $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)
            return [PSCustomObject]@{ Offset = $TailOffset + $read; Text = $text }
        } finally {
            if ($fs) { $fs.Dispose() }
        }
    }

    $invokeArgs = @{ VMName = $VMName; ScriptBlock = $tailScript; ArgumentList = @($Path, $Offset) }
    $cred = New-VmCredential -Username $CredentialUsername -Password $CredentialPassword
    if ($cred) { $invokeArgs['Credential'] = $cred }
    return Invoke-AnalysisCommand $invokeArgs
}

function Get-FleetVMs {
    <#
    .SYNOPSIS
        Host-side inventory of ALL Hyper-V VMs (fleet page). Read-only,
        no guest contact: name, power state, uptime, first IPv4. The
        orchestrator merges this with the hyperv.vms credential registry.
    #>
    [CmdletBinding()]
    param()

    $vms = @(Get-VM | ForEach-Object {
        $ip = (Get-VMNetworkAdapter -VMName $_.Name).IPAddresses |
              Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
              Select-Object -First 1
        [PSCustomObject]@{
            Name      = $_.Name
            State     = $_.State.ToString()
            Uptime    = $_.Uptime.ToString()
            IPAddress = $ip
        }
    })
    # Caller collects with @(...) and serializes via -InputObject (piping an
    # array into ConvertTo-Json wraps it in {value,Count} -- PS5.1 quirk).
    return $vms
}

function Get-LocalSandboxStatus {
    <#
    .SYNOPSIS
        Local-mode environment status: instrumentation health of THIS
        machine instead of VM state. Consumed by the orchestrator's
        /api/vm/status endpoint (dashboard "Analysis Environment" card).
        Runs the shared $script:InstrumentationProbe in-process; local mode
        surfaces 5 of the 6 checks (defender_rtp is guest-relevant).
    #>
    [CmdletBinding()]
    param()

    $probe = & $script:InstrumentationProbe

    $uptime = ''
    try {
        $uptime = ((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString('d\.hh\:mm\:ss')
    } catch {}

    return [PSCustomObject]@{
        VMName      = 'local'
        State       = 'Running'
        Uptime      = $uptime
        IPAddress   = '127.0.0.1'
        Mode        = 'local'
        LocalSystem = $probe.System
        Checks      = [PSCustomObject]@{
            sysmon          = $probe.Checks.sysmon
            agent_dir       = $probe.Checks.agent_dir
            monitor_dlls    = $probe.Checks.monitor_dlls
            guardian_driver = $probe.Checks.guardian_driver
            secure_boot     = $probe.Checks.secure_boot
        }
    }
}

# --- Entrypoint for CLI usage from Python orchestrator ---
if ($args.Count -gt 0) {
    # -LocalMode (appended by hyperv.py::LocalTransport._run_ps as a bare
    # switch) is a GLOBAL flag, not a function parameter -- strip it before
    # splatting the remaining args into the dispatched function.
    $filteredArgs = @($args | Where-Object { "$_" -ne '-LocalMode' })
    if ($filteredArgs.Count -lt $args.Count) { $script:LocalMode = $true }
    $command = $filteredArgs[0]
    if ($filteredArgs.Count -gt 1) {
        $remainingArgs = $filteredArgs[1..($filteredArgs.Count - 1)]
    }
    else {
        $remainingArgs = @()
    }

    switch ($command) {
        "Test-Prerequisites"      { Test-SandboxPrerequisites @remainingArgs | ConvertTo-Json }
        "Ensure-Snapshot"         { Ensure-SandboxSnapshot @remainingArgs | ConvertTo-Json }
        "Restore-Snapshot"        { Restore-SandboxSnapshot @remainingArgs | ConvertTo-Json }
        "Start-VM"                { Start-SandboxVM @remainingArgs | ConvertTo-Json }
        "Stop-VM"                 { Stop-SandboxVM @remainingArgs | ConvertTo-Json }
        "Get-Status"              { Get-SandboxVMStatus @remainingArgs | ConvertTo-Json }
        "Get-LocalStatus"         { Get-LocalSandboxStatus | ConvertTo-Json -Depth 5 }
        "Get-FleetVMs"            { $r = @(Get-FleetVMs); ConvertTo-Json -InputObject $r -Depth 5 }
        "Get-TelemetryTail"       { Get-TelemetryTail @remainingArgs | ConvertTo-Json -Depth 5 }
        "Get-GuestHealth"         { Get-GuestHealth @remainingArgs | ConvertTo-Json -Depth 5 }
        "Copy-Sample"             { Copy-SampleToVM @remainingArgs | ConvertTo-Json }
        "Copy-SampleFolder"       { Copy-SampleFolderToVM @remainingArgs | ConvertTo-Json }
        "Execute-Sample"          { Invoke-SampleExecution @remainingArgs | ConvertTo-Json -Depth 5 }
        "Copy-Agent"              { Copy-AgentToVM @remainingArgs | ConvertTo-Json }
        "Telemetry-Init"          { Invoke-TelemetryInit @remainingArgs | ConvertTo-Json }
        "Telemetry-Collect"       { Invoke-TelemetryCollect @remainingArgs | ConvertTo-Json }
        "Copy-Telemetry"          { Copy-TelemetryFromVM @remainingArgs | ConvertTo-Json }
        "NetworkCapture-Start"    { Invoke-NetworkCaptureStart @remainingArgs | ConvertTo-Json }
        "NetworkCapture-Stop"     { Invoke-NetworkCaptureStop @remainingArgs | ConvertTo-Json }
        "Apitrace-Start"          { Invoke-ApitraceStart @remainingArgs | ConvertTo-Json }
        "Apitrace-Stop"           { Invoke-ApitraceStop @remainingArgs | ConvertTo-Json }
        "Guardian-Start"          { Invoke-GuardianStart @remainingArgs | ConvertTo-Json }
        "Guardian-Stop"           { Invoke-GuardianStop @remainingArgs | ConvertTo-Json }
        "Copy-NetworkCapture"     { Copy-NetworkCaptureFromVM @remainingArgs | ConvertTo-Json }
        "Get-Thumbnail"           { Get-SandboxVMThumbnail @remainingArgs | ConvertTo-Json }
        "Copy-ProcessDumps"       { Copy-ProcessDumpsFromVM @remainingArgs | ConvertTo-Json -Depth 5 }
        "Copy-DroppedFiles"       { Copy-DroppedFilesFromVM @remainingArgs | ConvertTo-Json -Depth 5 }
        "Copy-SandboxArchive"     { Copy-SandboxArchiveFromVM @remainingArgs | ConvertTo-Json -Depth 5 }
        "Clear-SandboxArchive"    { Clear-SandboxArchive @remainingArgs | ConvertTo-Json -Depth 5 }
        "Invoke-GuestPython"      { Invoke-GuestPython @remainingArgs | ConvertTo-Json -Depth 5 }
        "Restart-Guest"           { Restart-SandboxGuest @remainingArgs | ConvertTo-Json }
        "Recapture-Snapshot"      { Recapture-SandboxSnapshot @remainingArgs | ConvertTo-Json }
        "Console-InputServer-Start" { Invoke-ConsoleInputServerStart @remainingArgs | ConvertTo-Json }
        "Console-InputServer-Stop"  { Invoke-ConsoleInputServerStop @remainingArgs | ConvertTo-Json }
        "Execute-Sample-Interactive" { Invoke-SampleExecutionInteractive @remainingArgs | ConvertTo-Json -Depth 5 }
        default                   { throw "Unknown command: $command" }
    }
}
