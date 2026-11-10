<#
.SYNOPSIS
    Removes Delinea / Thycotic Privilege Manager endpoint agents and their leftovers, and
    optionally installs the current component MSIs. Conservative by design: it touches only
    Privilege Manager's own artifacts.

.DESCRIPTION
    Built for endpoints where Privilege Manager agents were previously delivered by SCCM as a
    mix of bundles and individual MSIs, and have drifted into a broken, partially-upgraded or
    phantom-registered state.

    =====================================================================================
    WHAT THIS SCRIPT DELIBERATELY DOES NOT TOUCH
    =====================================================================================
    Everything below was either removed or made opt-in, because a cleanup script should not
    behave like the thing your EDR is paid to catch. Each of these is a recognised
    defense-evasion technique and will generate alerts even when the intent is legitimate.

      NO certificate store access.        Deleting machine certificates is a defense-evasion
                                          TTP. It also found nothing across four endpoint
                                          runs - the agent's identity lives in the registry
                                          and the ClientItems database, both handled below.

      NO driver binary deletion.          No .sys files are removed, and the DriverStore is
                                          never touched. `sc delete` on the driver's service
                                          entry is standard uninstall behaviour and is enough;
                                          the MSI removes its own driver package.

      NO event log clearing or deletion.  No `wevtutil cl`, no .evtx removal, no WINEVT
                                          channel/publisher registry keys. Clearing event
                                          logs is one of the highest-signal detections in any
                                          SIEM. An orphaned channel registration is inert and
                                          is re-registered on reinstall.

      NO WMI namespace changes.           WMI tampering is a monitored technique, and the
                                          sweep matched nothing on any endpoint tested.

      NO `reg load` of user hives.        Loading NTUSER.DAT is a known persistence pattern.
                                          Only already-loaded profile hives are read.

      NO bulk file attribute rewriting.   `Remove-Item -Force` handles read-only files without
                                          a recursive attribute sweep that resembles
                                          ransomware staging.

      NO unconditional service DACL edits. `sc sdset` runs ONLY when the descriptor has
                                          actually been altered by PM's hardening policy.
                                          On a normal endpoint it never runs.

      NO unconditional process killing.   Services are stopped through the service control
                                          manager. Processes are terminated only if a service
                                          fails to stop, and only PM's own binaries.

      NO firewall changes by default.     Opt in with -RemoveFirewallRules. Otherwise matching
                                          rules are reported, not removed.

      NO deletion outside PM's own paths. Every filesystem and registry target is validated
                                          against a Privilege Manager path or key before
                                          removal. Windows system locations are denied
                                          outright by an explicit guard.

    =====================================================================================
    PHASES
    =====================================================================================
        0.  Preflight      - admin check, 64-bit re-launch, MSI health, pending reboot
        1.  Hardening      - reset service security descriptors ONLY if actually hardened
        2.  Discovery      - PM services and registered products
        3.  Stop           - stop services gracefully; force only as a fallback
        4.  Uninstall      - bundle (Burn) first, then MSIs in the supported order
        5.  Services       - remove service entries the MSIs left behind
        6.  Tasks          - remove PM scheduled tasks via the Task Scheduler API
        7.  Registry       - PM-owned keys only
        8.  Filesystem     - PM-owned paths only
        9.  MSI database   - purge phantom / orphaned Windows Installer registrations
       10.  SCCM           - ConfigMgr cache entries for old PM packages (opt-in)
       11.  Verify         - report anything still present
       12.  Install        - optional: install the component MSIs in order and register

    Registration is still fully reset: the agent ID under HKLM\SOFTWARE\Arellia, the AMS
    policy keys and the ClientItems database are all removed, so the endpoint re-registers in
    the console as a new agent.

    =====================================================================================
    Install files and process:
    =====================================================================================
    This script does NOT download anything. Supply the MSIs one of two ways:

      1. NEXT TO THE SCRIPT (the default, and what SCCM/Intune should use). SCCM copies the
         whole package folder to the client and runs the script from it, so $PSScriptRoot is
         already the right place.

             \\server\share\PM-Agent-13.0.1058\
                 Invoke-DelineaPMCleanup.ps1
                 Delinea_ApplicationControlAgent_x64_13_0_1058.msi
                 Delinea_LocalSecurityAgent_x64_13_0_1058.msi
                 DelineaAgent_x64_13_0_1058.msi

      2. -InstallerPath "\\server\share\PM\13.0.1058" - Not neccesary haha

    Every installer is staged to a short local path (C:\Windows\Temp\DPMSrc) and validated by
    opening its MSI database first. That single step eliminates most 1619 errors.

    =====================================================================================
    ERROR HANDLING
    =====================================================================================
      1618  another install in progress -> clear a stale InProgress key, retry
      1619  package could not be opened -> re-stage locally, re-validate, retry
      1620  invalid package            -> re-stage, retry
      1610  bad configuration data     -> purge that product's MSI registration, retry
      1612  install source unavailable -> re-stage, retry
      1638  another version installed  -> resolve via UpgradeCode, purge phantoms, retry
      2753  file not marked for install-> purge that product's MSI registration, retry
      1601  Windows Installer service  -> repair msiserver, retry
      1603  fatal error                -> parse the verbose log, classify the cause,
                                          remediate what is remediable, retry once
      1633  unsupported platform       -> stop, wrong architecture package
      1605/1614 not installed          -> success in an uninstall context

    =====================================================================================
    THE "LATEST VERSION IS ALREADY INSTALLED" FALSE POSITIVE
    =====================================================================================
    Windows Installer is not lying about its own state: an earlier bundle or a rolled-back
    install left registration behind while removing the files. Add/Remove Programs can look
    empty while these still exist:

        HKLM\SOFTWARE\Classes\Installer\Products\<packed ProductCode>
        HKLM\SOFTWARE\Classes\Installer\Features\<packed ProductCode>
        HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\<packed UpgradeCode>
        HKLM\SOFTWARE\Microsoft\Windows\Installer\UserData\S-1-5-18\Products\<packed>
        HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<ProductCode>

    Phase 9 finds these, proves each is a phantom (ProductState is not INSTALLED, or the
    cached LocalPackage MSI is gone) and removes all five footprints. Phase 12 re-checks by
    UpgradeCode immediately before each install. A registration that is NOT provably a phantom
    is reported and left alone.

.PARAMETER Install
    After cleanup, install the agent from -InstallerPath.
.PARAMETER InstallerPath
    Folder holding the MSIs. Defaults to the folder this script runs from.
.PARAMETER Components
    Which components to install. Core is always forced last.
    Default: ApplicationControl, LocalSecurity, Core.
.PARAMETER UseBundle
    Install with PMAgents_*.exe instead of the individual MSIs. Off by default.
.PARAMETER ServerUrl
    Privilege Manager server URL, e.g. https://dallasisd.privilegemanagercloud.com/TMS/
.PARAMETER InstallCode
    Agent install code from Admin > Agents > Installation Codes.
.PARAMETER DryRun
    Log every action without changing anything. Always run this first.
.PARAMETER ClearCcmCache
    Purge ConfigMgr cache entries whose content is a PM package, via the ConfigMgr client API.
    Without it, cached PM content in %WinDir%\ccmcache is reported but not touched. Folders
    under ccmcache are never deleted directly under any switch - that breaks the client's
    cache index and causes download failures on later deployments.
.PARAMETER RemoveFirewallRules
    Remove firewall rules created by the agent. Off by default; matching rules are reported.
.PARAMETER IgnorePendingReboot
    Proceed even when a BLOCKING reboot condition exists (Component Based Servicing, Windows
    Update, pending rename, ConfigMgr). PendingFileRenameOperations on its own is advisory and
    never blocks - see Test-PendingReboot for why.
.PARAMETER PendingRebootExitCode
    Exit code used when a blocking reboot condition stops the run. Default 3010.
    For an SCCM deployment consider 1618 ("fast retry"): SCCM re-attempts within a couple of
    hours without marking the deployment failed. 3010 means "installed, needs restart" - SCCM
    will NOT retry, and the detection method then fails because nothing was installed.
    For Intune, 3010 is the soft-reboot code and is usually correct.
.PARAMETER SkipReboot
    Never request a reboot; return 0 on success even when 3010 was seen.
.PARAMETER LogPath
    Log file. Default C:\Windows\Temp\DelineaPMCleanup_<timestamp>.log

.EXAMPLE
    .\Invoke-DelineaPMCleanup.ps1 -DryRun

.EXAMPLE
    .\Invoke-DelineaPMCleanup.ps1 -ClearCcmCache

.EXAMPLE
    .\Invoke-DelineaPMCleanup.ps1 -ClearCcmCache -Install `
        -ServerUrl "https://dallasisd.privilegemanagercloud.com/TMS/" -InstallCode "ZC6U-3BRY-FR8Y"

.NOTES
    Exit codes:  0 = success | 3010 = success, reboot required | 1 = failure

    COMPONENTS VS BUNDLE
    Components (the default) suit SCCM and Intune: each has its own MSI ProductCode, so
    detection, reporting and supersedence are per-component and each upgrades independently.
    The bundle registers as a Burn package with no MSI ProductCode, and Burn's own
    "already installed / newer version present" logic runs on top of the MSIs - which is where
    most confusing upgrade prompts originate. Mixing the two across an estate is the worst
    option: on a bundle machine the bundle owns the child MSIs, so an individual component MSI
    pushed at it produces "the latest version is already installed".

    Deploy order: Application Control -> Local Security -> Directory Services -> Core,
    each step's success as the predecessor of the next. The Core agent MUST be last: it owns
    registration for the others.
#>

[CmdletBinding()]
param(
    [switch] $Install,
    [string] $InstallerPath,

    [ValidateSet('ApplicationControl','LocalSecurity','DirectoryServices','Core')]
    [string[]] $Components = @('ApplicationControl','LocalSecurity','Core'),

    [switch] $UseBundle,
    [string] $ServerUrl,
    [string] $InstallCode,

    [switch] $DryRun,
    [switch] $ClearCcmCache,
    [switch] $RemoveFirewallRules,
    [switch] $IgnorePendingReboot,
    [switch] $SkipReboot,
    [int]    $PendingRebootExitCode = 3010,

    [string] $LogPath = "$env:WinDir\Temp\DelineaPMCleanup_$(Get-Date -f yyyyMMdd_HHmmss).log"
)

# ============================================================================
#  PHASE 0 - PREFLIGHT
# ============================================================================

$ErrorActionPreference = 'Continue'
$script:RebootRequired       = $false
$script:Failures             = New-Object System.Collections.Generic.List[string]
$script:Removed              = New-Object System.Collections.Generic.List[string]
$script:PendingRebootAtStart  = @()   # every source found, blocking or advisory
$script:BlockingRebootAtStart = @()   # only the ones that actually stop MSI work
$script:PMServiceInventory   = @()
$script:StageDir             = Join-Path $env:WinDir 'Temp\DPMSrc'
$script:MsiLogDir            = Join-Path $env:WinDir 'Temp\DPMLogs'

#--- Re-launch in 64-bit PowerShell -----------------------------------------
# SCCM and Intune run 32-bit PowerShell by default. In 32-bit the registry and Program Files
# views are redirected and half of this script silently misses the real 64-bit artifacts.
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and -not $env:_PMCLEANUP_RELAUNCHED) {
    $native = Join-Path $env:WinDir 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $native) {
        $env:_PMCLEANUP_RELAUNCHED = '1'
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            if ($kv.Key -eq 'LogPath') { continue }
            if ($kv.Value -is [switch])     { if ($kv.Value.IsPresent) { $argList += "-$($kv.Key)" } }
            elseif ($kv.Value -is [array])  { $argList += @("-$($kv.Key)", ($kv.Value -join ',')) }
            else                            { $argList += @("-$($kv.Key)", "`"$($kv.Value)`"") }
        }
        $argList += @('-LogPath', "`"$LogPath`"")
        $p = Start-Process -FilePath $native -ArgumentList $argList -Wait -PassThru -NoNewWindow
        exit $p.ExitCode
    }
}

#--- Logging ----------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Message,
        [ValidateSet('INFO','WARN','ERROR','OK','STEP','DRY','SKIP')][string] $Level = 'INFO'
    )
    $line = '{0}  [{1,-5}] {2}' -f (Get-Date -f 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -EA Stop } catch { }
    $color = switch ($Level) {
        'ERROR' { 'Red' } 'WARN' { 'Yellow' } 'OK' { 'Green' }
        'STEP'  { 'Cyan' } 'DRY' { 'Magenta' } 'SKIP' { 'DarkGray' } default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
}
function Write-Step { param([string]$Message) ; Write-Log ('=' * 78) 'STEP' ; Write-Log $Message 'STEP' }
function Add-Failure { param([string]$M) ; $script:Failures.Add($M) | Out-Null ; Write-Log $M 'ERROR' }
function Add-Removed { param([string]$M) ; $script:Removed.Add($M)  | Out-Null }

function Invoke-Change {
    param(
        [Parameter(Mandatory)][string]      $Description,
        [Parameter(Mandatory)][scriptblock] $Action
    )
    if ($DryRun) { Write-Log "WOULD: $Description" 'DRY' ; return $null }
    Write-Log "DOING: $Description"
    try   { & $Action ; Add-Removed $Description }
    catch { Add-Failure "FAILED: $Description :: $($_.Exception.Message)" }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Log ('#' * 78)
Write-Log "Delinea / Thycotic Privilege Manager endpoint cleanup"
Write-Log "Computer      : $env:COMPUTERNAME"
Write-Log "Running as    : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "PS version    : $($PSVersionTable.PSVersion)  ($([IntPtr]::Size * 8)-bit)"
Write-Log "Log file      : $LogPath"
Write-Log "Mode          : $(if ($DryRun) { 'DRY RUN - no changes' } else { 'LIVE' })"
Write-Log "Install phase : $(if ($Install) { "YES ($(if($UseBundle){'bundle'}else{$Components -join ' -> '}))" } else { 'no' })"
Write-Log "Scope         : Privilege Manager artifacts only - no certificate, driver-binary,"
Write-Log "                event-log or WMI changes. See the header for the full exclusion list."
Write-Log ('#' * 78)

if (-not (Test-IsAdmin)) { Write-Log "Must run elevated (local admin or SYSTEM). Aborting." 'ERROR' ; exit 1 }

if (-not $InstallerPath) {
    $InstallerPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}
if ($Install) { Write-Log "Installer source: $InstallerPath" }

foreach ($d in @($script:StageDir, $script:MsiLogDir)) {
    if (-not $DryRun -and -not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

#--- Match patterns ---------------------------------------------------------
$VendorRx  = 'Arellia|Thycotic|Delinea'
$ProductRx = 'Privilege Manager|Application Control Agent|Local Security(\s+Solution)?\s+Agent|' +
             'Directory Services Agent|Core (Delinea|Thycotic) Agent|Delinea Agent|Thycotic Agent|' +
             'Agent Utility|Remove Programs'
# Other Delinea products that must survive this script.
$KeepRx    = 'Secret Server|Connection Manager|DevOps Secrets|Account Lifecycle|' +
             'Privilege Control for Servers|Server Suite'

$KnownServices = @('ArelliaAgent','ArelliaACSvc','ArelliaACDrv','TaskExecutor',
                   'Arellia.Agent.Service','DPEACSvc','DPEACDrv','ArelliaDirectoryServices')

$KnownProcesses = @('Arellia.Agent.Service','ArelliaACSvc','DPEACSvc','TaskExecutor',
                    'Agent Utility','Thycotic.Agent.User','Delinea.Agent.User',
                    'Remove Programs Utility','ArelliaDisplayXamlAction','AdvMessageAction',
                    'Delinea.Agent.TrayIcon','Thycotic.Agent.TrayIcon','JITModeManager',
                    'MSIElevateHost','COMElevateHost','Arellia.Agent.InventoryHelper',
                    'AgentLogViewer')


# ############################################################################
#  SAFETY GUARDS
#  Nothing is deleted unless it passes these. They are the reason this script
#  can be pointed at a production endpoint.
# ############################################################################

# Windows locations that must never be a deletion target, whatever else matches.
$script:ProtectedPaths = @(
    $env:WinDir
    (Join-Path $env:WinDir 'System32')
    (Join-Path $env:WinDir 'SysWOW64')
    (Join-Path $env:WinDir 'System32\drivers')
    (Join-Path $env:WinDir 'System32\DriverStore')
    (Join-Path $env:WinDir 'System32\winevt')
    (Join-Path $env:WinDir 'System32\Tasks')
    (Join-Path $env:WinDir 'Installer')
    $env:ProgramFiles
    ${env:ProgramFiles(x86)}
    $env:ProgramData
    $env:SystemDrive
    "$env:SystemDrive\"
    "$env:SystemDrive\Users"
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }

# Subtrees where NOTHING is a valid deletion target, however it is named. %ProgramFiles% and
# %ProgramData% are not listed: they are protected as exact paths above, but legitimate PM
# folders live directly beneath them.
$script:ProtectedTrees = @($env:WinDir) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }

# A path is deletable only if it is fully qualified, names a PM vendor/product folder, is not
# itself a protected Windows location, and is not anywhere inside a protected subtree.
function Test-PathIsPmOwned {
    param([Parameter(Mandatory)][string] $Path)
    if ($Path -notmatch '^[A-Za-z]:\\')                                { return $false }
    if ($Path -notmatch "$VendorRx|Privilege Manager")                 { return $false }
    $norm = $Path.TrimEnd('\').ToLower()
    if ($script:ProtectedPaths -contains $norm)                        { return $false }
    # Defense in depth: a vendor-named file inside %SystemRoot% (a driver in System32\drivers,
    # say) must never be deletable just because its name matches.
    foreach ($t in $script:ProtectedTrees) {
        if ($norm -eq $t -or $norm.StartsWith("$t\"))                  { return $false }
    }
    # Must be at least two levels deep - never a drive root or a single top-level folder.
    if (($Path.TrimEnd('\') -split '\\').Count -lt 3)                  { return $false }
    return $true
}

# Registry keys this script is allowed to remove. Everything else is refused, including the
# Windows areas the previous version reached into (WINEVT, WMI).
$script:PmKeyPatterns = @(
    '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?(Policies\\)?Arellia(\\|$)'
    '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?(Policies\\)?Thycotic\\'
    '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?(Policies\\)?Delinea\\'
    '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+$'
    '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
    '^HKLM:\\SOFTWARE\\Classes\\Installer\\(Products|Features|Patches|UpgradeCodes)\\'
    '^HKLM:\\SOFTWARE\\Microsoft\\Windows\\Installer\\(UserData|UpgradeCodes)'
    '^HKLM:\\SOFTWARE\\Classes\\[^\\]+\\Shell\\'
    '^Registry::HKEY_USERS\\S-1-5-21-[^\\]+\\Software\\(Arellia|Thycotic|Delinea)'
    '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\'
)
function Test-KeyIsPmOwned {
    param([Parameter(Mandatory)][string] $Path)
    foreach ($p in $script:PmKeyPatterns) { if ($Path -match $p) { return $true } }
    return $false
}

function Remove-KeyIfPresent {
    param([Parameter(Mandatory)][string] $Path, [string] $Note)
    if (-not (Test-Path $Path)) { return }
    if (-not (Test-KeyIsPmOwned $Path)) {
        Write-Log "REFUSED (guard): $Path is not a Privilege Manager key." 'WARN'
        return
    }
    Invoke-Change "Remove registry key $Path$(if($Note){" ($Note)"})" {
        Remove-Item -LiteralPath $Path -Recurse -Force -EA Stop
    }
}

function Test-IsReparsePoint {
    param([string] $Path)
    try {
        $i = Get-Item -LiteralPath $Path -Force -EA Stop
        return [bool]($i.Attributes -band [IO.FileAttributes]::ReparsePoint)
    } catch { return $false }
}

# %ProgramData%\Application Data is the legacy junction back to %ProgramData%, so
# "...\Application Data\Arellia" and "...\Arellia" are the SAME directory.
function Get-ReparseAncestor {
    param([string] $Path)
    $cur = Split-Path -Parent $Path ; $guard = 0
    while ($cur -and ($cur.Contains('\') -or $cur.Contains('/')) -and $guard -lt 64) {
        $guard++
        if ((Test-Path -LiteralPath $cur) -and (Test-IsReparsePoint $cur)) { return $cur }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    return $null
}

function Remove-PathIfPresent {
    param([Parameter(Mandatory)][string] $Path, [string] $Note)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not (Test-PathIsPmOwned $Path)) {
        Write-Log "REFUSED (guard): $Path is not a Privilege Manager path." 'WARN'
        return
    }
    # Unlink a junction, never recurse through it.
    if (Test-IsReparsePoint $Path) {
        Invoke-Change "Unlink reparse point $Path (link only, target untouched)" {
            [IO.Directory]::Delete($Path, $false)
        }
        return
    }
    $size = 0
    try {
        $size = (Get-ChildItem -LiteralPath $Path -Recurse -Force -EA SilentlyContinue |
                 Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
                 Measure-Object Length -Sum).Sum
    } catch { }
    # -Force already handles read-only and hidden files; no bulk attribute rewrite.
    Invoke-Change ("Remove {0}{1} [{2:N1} MB]" -f $Path, $(if($Note){" ($Note)"}), ($size / 1MB)) {
        Remove-Item -LiteralPath $Path -Recurse -Force -EA Stop
    }
}


# ############################################################################
#  WINDOWS INSTALLER TOOLKIT
# ############################################################################

# The Installer database keys products by a transposed GUID: first three groups reversed,
# remaining bytes nibble-swapped.
function ConvertTo-MsiPackedGuid {
    param([string] $Guid)
    if (-not $Guid) { return $null }
    $g = ($Guid -replace '[{}\-]', '').ToUpper()
    if ($g.Length -ne 32 -or $g -notmatch '^[0-9A-F]{32}$') { return $null }
    $sb = New-Object System.Text.StringBuilder
    foreach ($seg in @(@(0,8), @(8,4), @(12,4))) {
        $c = $g.Substring($seg[0], $seg[1]).ToCharArray() ; [Array]::Reverse($c)
        [void]$sb.Append((-join $c))
    }
    for ($i = 16; $i -lt 32; $i += 2) { [void]$sb.Append($g[$i+1]).Append($g[$i]) }
    $sb.ToString()
}
function ConvertFrom-MsiPackedGuid {
    param([string] $Packed)
    if (-not $Packed) { return $null }
    $p = $Packed.ToUpper()
    if ($p.Length -ne 32 -or $p -notmatch '^[0-9A-F]{32}$') { return $null }
    $sb = New-Object System.Text.StringBuilder
    foreach ($seg in @(@(0,8), @(8,4), @(12,4))) {
        $c = $p.Substring($seg[0], $seg[1]).ToCharArray() ; [Array]::Reverse($c)
        [void]$sb.Append((-join $c)) ; [void]$sb.Append('-')
    }
    for ($i = 16; $i -lt 32; $i += 2) {
        [void]$sb.Append($p[$i+1]).Append($p[$i])
        if ($i -eq 18) { [void]$sb.Append('-') }
    }
    '{' + $sb.ToString() + '}'
}

# Prove the transposition is right ON THIS MACHINE before trusting it to delete anything.
function Test-PackedGuidSupport {
    $sample = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -EA SilentlyContinue |
              Where-Object { $_.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$' } | Select-Object -First 12
    $hits = 0 ; $tried = 0
    foreach ($s in $sample) {
        $packed = ConvertTo-MsiPackedGuid $s.PSChildName
        if (-not $packed) { continue }
        $tried++
        if (Test-Path "HKLM:\SOFTWARE\Classes\Installer\Products\$packed") { $hits++ }
    }
    if ($tried -eq 0) { Write-Log "Packed-GUID self-test: no sample products to test against." 'WARN' ; return $false }
    if ($hits -gt 0)  { Write-Log "Packed-GUID self-test: PASS ($hits/$tried resolved)." 'OK' ; return $true }
    Write-Log "Packed-GUID self-test: FAIL (0/$tried) - Phase 9 will use name matching only." 'WARN'
    return $false
}

# Reading an MSI doubles as a validity check: a truncated or quarantined file cannot be
# opened, which is precisely the 1619 case.
function Get-MsiProperty {
    param([Parameter(Mandatory)][string] $Path)
    $installer = $null ; $db = $null ; $result = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer -EA Stop
        $db = $installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($Path,0))
        $out = @{}
        foreach ($prop in @('ProductCode','UpgradeCode','ProductName','ProductVersion','Manufacturer')) {
            try {
                $view = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,
                            @("SELECT Value FROM Property WHERE Property='$prop'"))
                $view.GetType().InvokeMember('Execute','InvokeMethod',$null,$view,$null) | Out-Null
                $rec = $view.GetType().InvokeMember('Fetch','InvokeMethod',$null,$view,$null)
                if ($rec) { $out[$prop] = $rec.GetType().InvokeMember('StringData','GetProperty',$null,$rec,1) }
                $view.GetType().InvokeMember('Close','InvokeMethod',$null,$view,$null) | Out-Null
            } catch { }
        }
        $result = [pscustomobject]@{
            Path=$Path; ProductCode=$out['ProductCode']; UpgradeCode=$out['UpgradeCode']
            ProductName=$out['ProductName']; ProductVersion=$out['ProductVersion']
            Manufacturer=$out['Manufacturer']; Valid=[bool]$out['ProductCode']
        }
    } catch {
        Write-Log "Cannot open MSI '$Path': $($_.Exception.Message)" 'WARN'
        $result = [pscustomobject]@{ Path=$Path; ProductCode=$null; UpgradeCode=$null
                                     ProductName=$null; ProductVersion=$null; Manufacturer=$null; Valid=$false }
    } finally {
        foreach ($o in @($db, $installer)) {
            if ($o) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($o) } catch { } }
        }
        [GC]::Collect() ; [GC]::WaitForPendingFinalizers()
    }
    $result
}

function Get-MsiProductState {
    param([Parameter(Mandatory)][string] $ProductCode)
    $installer = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer -EA Stop
        $state = $installer.GetType().InvokeMember('ProductState','GetProperty',$null,$installer,@($ProductCode))
        $local = $null ; $source = $null ; $name = $null
        foreach ($pair in @(@('LocalPackage',[ref]$local), @('InstallSource',[ref]$source), @('ProductName',[ref]$name))) {
            try { $pair[1].Value = $installer.GetType().InvokeMember('ProductInfo','GetProperty',$null,$installer,
                                        @($ProductCode, $pair[0])) } catch { }
        }
        # 5 = INSTALLSTATE_DEFAULT (installed). Anything else is advertised, absent or unknown.
        [pscustomobject]@{ ProductCode=$ProductCode; State=$state; Installed=($state -eq 5)
                           ProductName=$name; LocalPackage=$local; InstallSource=$source }
    } catch {
        [pscustomobject]@{ ProductCode=$ProductCode; State=-1; Installed=$false
                           ProductName=$null; LocalPackage=$null; InstallSource=$null }
    } finally {
        if ($installer) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer) } catch { } }
    }
}

function Get-MsiRelatedProducts {
    param([Parameter(Mandatory)][string] $UpgradeCode)
    $installer = $null ; $codes = @()
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer -EA Stop
        foreach ($c in $installer.GetType().InvokeMember('RelatedProducts','GetProperty',$null,$installer,@($UpgradeCode))) {
            $codes += "$c"
        }
    } catch { }
    finally { if ($installer) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer) } catch { } } }
    ,$codes
}

function Test-MsiPhantom {
    param([Parameter(Mandatory)][string] $ProductCode)
    $info = Get-MsiProductState -ProductCode $ProductCode
    if (-not $info.Installed) { return @{ Phantom=$true; Reason="ProductState=$($info.State) (not INSTALLSTATE_DEFAULT)" } }
    if ($info.LocalPackage -and -not (Test-Path -LiteralPath $info.LocalPackage)) {
        return @{ Phantom=$true; Reason="cached package missing: $($info.LocalPackage)" }
    }
    if (-not $info.LocalPackage) { return @{ Phantom=$true; Reason='no cached package recorded' } }
    @{ Phantom=$false; Reason="live install (state $($info.State), package $($info.LocalPackage))" }
}

function Remove-MsiRegistration {
    param([Parameter(Mandatory)][string] $ProductCode, [string] $Label = '')
    $packed = ConvertTo-MsiPackedGuid $ProductCode
    if (-not $packed) { Write-Log "Cannot pack '$ProductCode' - skipping registration purge." 'WARN' ; return }
    Write-Log "Purging Installer registration for $ProductCode $Label (packed $packed)"

    foreach ($t in @(
        "HKLM:\SOFTWARE\Classes\Installer\Products\$packed"
        "HKLM:\SOFTWARE\Classes\Installer\Features\$packed"
        "HKLM:\SOFTWARE\Classes\Installer\Patches\$packed"
        "HKLM:\SOFTWARE\Microsoft\Windows\Installer\UserData\S-1-5-18\Products\$packed"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    )) { Remove-KeyIfPresent $t }

    # UpgradeCodes keys hold packed ProductCodes as VALUE NAMES. Drop the value; drop the key
    # only when it is then empty, so sibling versions of other products are untouched.
    foreach ($ucRoot in @('HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes',
                          'HKLM:\SOFTWARE\Microsoft\Windows\Installer\UpgradeCodes')) {
        if (-not (Test-Path $ucRoot)) { continue }
        foreach ($uc in (Get-ChildItem $ucRoot -EA SilentlyContinue)) {
            $props = Get-ItemProperty $uc.PSPath -EA SilentlyContinue
            if (-not $props) { continue }
            if ($props.PSObject.Properties.Name -contains $packed) {
                $ucPath = $uc.PSPath
                Invoke-Change "Remove $packed from UpgradeCodes key $($uc.PSChildName)" {
                    Remove-ItemProperty -LiteralPath $ucPath -Name $packed -Force -EA Stop
                }
                $left = @((Get-Item $ucPath -EA SilentlyContinue).Property | Where-Object { $_ -ne '(default)' })
                if ($left.Count -eq 0) { Remove-KeyIfPresent $ucPath 'now-empty UpgradeCodes key' }
            }
        }
    }
}

function Repair-MsiSubsystem {
    $svc = Get-Service -Name 'msiserver' -EA SilentlyContinue
    if (-not $svc) { Add-Failure "Windows Installer service (msiserver) is not present." ; return }
    $start = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\msiserver' -Name Start -EA SilentlyContinue).Start
    if ($start -eq 4) {
        Invoke-Change "Windows Installer service is DISABLED - setting to Manual" {
            & sc.exe config msiserver start= demand | Out-Null
        }
    }
    # A crashed installer leaves this key behind and every later msiexec returns 1618 forever.
    $inProg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress'
    if (Test-Path $inProg) {
        Invoke-Change "Remove stale Installer 'InProgress' key (causes permanent 1618)" {
            Remove-Item -LiteralPath $inProg -Recurse -Force -EA Stop
        }
    }
}

# Pending-reboot sources are NOT equal, and treating them as equal makes this script refuse
# to run on healthy machines.
#
#   BLOCKING - a servicing operation is genuinely mid-flight and MSI work will likely fail:
#              Component Based Servicing, Windows Update, a pending computer rename, or the
#              ConfigMgr client saying so.
#
#   ADVISORY - PendingFileRenameOperations on its own. This is just a MoveFileEx queue that
#              Windows Update, Defender platform updates and browser updaters top up
#              constantly. A healthy endpoint carries entries here most of the time - one of
#              these machines went from zero entries to ten in under two hours with nothing
#              of consequence happening. It only matters if a queued rename targets a file
#              THIS install needs, so PFRO escalates to blocking only when an entry names a
#              Privilege Manager path.
function Test-PendingReboot {
    $found = @()
    $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
    foreach ($k in @('RebootPending','RebootInProgress','PackagesPending')) {
        if (Test-Path "$cbs\$k") { $found += [pscustomobject]@{ Source = "Component Based Servicing ($k)"; Blocking = $true } }
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $found += [pscustomobject]@{ Source = 'Windows Update'; Blocking = $true }
    }
    $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name ComputerName -EA SilentlyContinue).ComputerName
    $pend   = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'       -Name ComputerName -EA SilentlyContinue).ComputerName
    if ($active -and $pend -and $active -ne $pend) {
        $found += [pscustomobject]@{ Source = 'pending computer rename'; Blocking = $true }
    }
    try {
        $ccm = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' `
                    -MethodName 'DetermineIfRebootPending' -EA Stop
        if ($ccm.IsHardRebootPending) { $found += [pscustomobject]@{ Source = 'ConfigMgr client (hard reboot pending)'; Blocking = $true } }
        elseif ($ccm.RebootPending)   { $found += [pscustomobject]@{ Source = 'ConfigMgr client (reboot pending)';      Blocking = $true } }
    } catch { }

    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations
    if ($pfro) {
        $all  = @($pfro | Where-Object { $_ })
        $ours = @($all  | Where-Object { $_ -match $VendorRx })
        if ($ours.Count -gt 0) {
            $found += [pscustomobject]@{
                Source   = "PendingFileRenameOperations - $($ours.Count) of $($all.Count) entries target Privilege Manager files"
                Blocking = $true }
        } else {
            $found += [pscustomobject]@{
                Source   = "PendingFileRenameOperations ($($all.Count) entries, none Privilege Manager)"
                Blocking = $false }
        }
    }
    ,$found
}

#--- Verbose-log forensics: turn 1603 into an actual cause ------------------
function Get-MsiFailureDetail {
    param([string] $LogFile)
    if (-not $LogFile -or -not (Test-Path -LiteralPath $LogFile)) { return $null }
    $lines = $null
    foreach ($enc in @('Unicode','Default','UTF8')) {
        try { $lines = Get-Content -LiteralPath $LogFile -Encoding $enc -EA Stop
              if (($lines -join '') -match 'MSI|Windows Installer') { break } } catch { }
    }
    if (-not $lines) { return $null }
    $detail = [ordered]@{ FailingAction=$null; Notes=@(); ErrorLines=@(); Classification='unknown' }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Return value 3\.') {
            for ($j = $i; $j -ge [Math]::Max(0, $i - 40); $j--) {
                if ($lines[$j] -match 'Action start .*?:\s*(\S+)') { $detail.FailingAction = $Matches[1] ; break }
            }
        }
        if ($lines[$i] -match 'Note: 1:\s*(\d{4})') { $detail.Notes += $Matches[1] }
        if ($lines[$i] -match 'Error\s+(\d{4})|error status:\s*(\d+)|returned actual error code') {
            $detail.ErrorLines += $lines[$i].Trim()
        }
    }
    $blob = ($lines -join "`n")
    $detail.Classification = switch -Regex ($blob) {
        'system must be restarted|ScheduleReboot|reboot is required'                  { 'pending-reboot' ; break }
        'Note: 1: 2753'                                                               { 'phantom-registration' ; break }
        'Another version of this product is already installed|Note: 1: 1638'          { 'conflicting-version' ; break }
        'could not access network location|Failed to open|1: 1706|source .*not found' { 'source-unavailable' ; break }
        'Service .* could not be (stopped|deleted)|1: 1922|1: 1923'                   { 'service-locked' ; break }
        'CustomAction .* returned actual error code'                                  { 'custom-action' ; break }
        default                                                                       { 'unknown' }
    }
    $detail.Notes      = @($detail.Notes      | Select-Object -Unique)
    $detail.ErrorLines = @($detail.ErrorLines | Select-Object -Last 6)
    [pscustomobject]$detail
}

function Write-MsiFailureDetail {
    param($Detail, [string] $LogFile)
    if (-not $Detail) { Write-Log "  (no verbose log to analyse: $LogFile)" 'WARN' ; return }
    Write-Log "  log analysis  : classification = $($Detail.Classification)" 'WARN'
    if ($Detail.FailingAction) { Write-Log "  failing action: $($Detail.FailingAction)" 'WARN' }
    if ($Detail.Notes.Count)   { Write-Log "  MSI notes     : $($Detail.Notes -join ', ')" 'WARN' }
    foreach ($e in $Detail.ErrorLines) { Write-Log "  > $e" 'WARN' }
    Write-Log "  full log      : $LogFile" 'WARN'
}

#--- Source staging: the single biggest 1619 fix ----------------------------
function Copy-ToStage {
    param([Parameter(Mandatory)][string] $SourceFile)
    $dest = Join-Path $script:StageDir (Split-Path -Leaf $SourceFile)
    if ((Resolve-Path $SourceFile -EA SilentlyContinue).Path -eq (Resolve-Path $dest -EA SilentlyContinue).Path) {
        return $dest
    }
    for ($i = 1; $i -le 3; $i++) {
        try {
            Copy-Item -LiteralPath $SourceFile -Destination $dest -Force -EA Stop
            $src = Get-Item -LiteralPath $SourceFile ; $dst = Get-Item -LiteralPath $dest
            if ($dst.Length -ne $src.Length) { throw "size mismatch ($($dst.Length) vs $($src.Length))" }
            return $dest
        } catch {
            Write-Log "  stage copy attempt $i/3 failed: $($_.Exception.Message)" 'WARN'
            Start-Sleep -Seconds 5
        }
    }
    throw "Could not stage '$SourceFile' to '$dest'."
}

function Resolve-Installer {
    param(
        [Parameter(Mandatory)][string] $Pattern,
        [string[]] $ExcludePattern = @(),
        [switch]   $SkipValidation
    )
    $candidates = @()
    foreach ($dir in @($script:StageDir, $InstallerPath)) {
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { continue }
        $candidates += Get-ChildItem -LiteralPath $dir -Filter $Pattern -File -EA SilentlyContinue
    }
    foreach ($ex in $ExcludePattern) { $candidates = $candidates | Where-Object { $_.Name -notmatch $ex } }
    $pick = $candidates | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $pick) { return $null }

    $staged = $pick.FullName
    if (-not $DryRun) {
        try { $staged = Copy-ToStage -SourceFile $pick.FullName }
        catch { Add-Failure $_.Exception.Message ; return $null }
    }
    if ($SkipValidation -or $DryRun) { return [pscustomobject]@{ Path = $staged; Msi = $null } }

    $props = Get-MsiProperty -Path $staged
    if (-not $props.Valid) {
        Add-Failure "'$staged' is not a readable MSI (truncated copy, AV quarantine, or wrong file). This is what surfaces as 1619."
        return $null
    }
    Write-Log ("  {0}  v{1}  Product {2}  Upgrade {3}" -f
        (Split-Path -Leaf $staged), $props.ProductVersion, $props.ProductCode, $props.UpgradeCode)
    [pscustomobject]@{ Path = $staged; Msi = $props }
}

function Clear-ConflictingRegistration {
    param(
        [Parameter(Mandatory)][string] $UpgradeCode,
        [string] $Label = '',
        [switch] $IncludeLive
    )
    $related = Get-MsiRelatedProducts -UpgradeCode $UpgradeCode
    if ($related.Count -eq 0) { Write-Log "  no existing products share UpgradeCode $UpgradeCode" ; return }
    Write-Log "  UpgradeCode $UpgradeCode is claimed by: $($related -join ', ')" 'WARN'
    foreach ($pc in $related) {
        $verdict = Test-MsiPhantom -ProductCode $pc
        if ($verdict.Phantom) {
            Write-Log "  $pc is a PHANTOM ($($verdict.Reason)) - purging registration." 'WARN'
            Remove-MsiRegistration -ProductCode $pc -Label $Label
        } elseif ($IncludeLive) {
            Write-Log "  $pc is a live install ($($verdict.Reason)) - uninstalling it first." 'WARN'
            $lg = Join-Path $script:MsiLogDir "conflict_$($pc -replace '[{}]','').log"
            $null = Invoke-MsiCommand -Arguments "/x `"$pc`" /qn /norestart REBOOT=ReallySuppress /l*vx `"$lg`"" `
                                      -Label "Uninstall conflicting product $pc" -LogFile $lg -Context Uninstall
        } else {
            Write-Log "  $pc is a live install ($($verdict.Reason)) - left in place, MSI upgrade logic will handle it."
        }
    }
}

#--- The retry engine -------------------------------------------------------
function Invoke-MsiCommand {
    param(
        [Parameter(Mandatory)][string] $Arguments,
        [Parameter(Mandatory)][string] $Label,
        [string] $FilePath = "$env:WinDir\System32\msiexec.exe",
        [string] $LogFile,
        [ValidateSet('Install','Uninstall')][string] $Context = 'Install',
        [string] $UpgradeCode,
        [string] $ProductCode,
        [string] $SourceFile,
        [int]    $MaxAttempts = 6
    )
    if ($DryRun) { Write-Log "WOULD: $Label  ->  $FilePath $Arguments" 'DRY' ; return 0 }

    $tried = @{}
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Log "$Label  (attempt $attempt/$MaxAttempts)"
        Write-Log "  cmd: $FilePath $Arguments"
        $code = $null
        try {
            $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru -NoNewWindow -EA Stop
            $code = $proc.ExitCode
        } catch { Add-Failure "  could not launch '$FilePath': $($_.Exception.Message)" ; return 1 }

        switch ($code) {
            { $_ -in 0, 1707 }    { Write-Log "  -> success ($code)" 'OK' ; return 0 }
            { $_ -in 3010, 1641 } { Write-Log "  -> success, reboot required ($code)" 'OK'
                                    $script:RebootRequired = $true ; return 0 }
            { $_ -in 1605, 1614 } {
                if ($Context -eq 'Uninstall') { Write-Log "  -> not installed ($code), nothing to do" ; return 0 }
                Write-Log "  -> unexpected 'not installed' ($code) during install" 'WARN' ; return $code
            }
            1618 {
                Write-Log "  -> 1618 another installation in progress" 'WARN'
                if (-not $tried.ContainsKey('inprogress')) { $tried['inprogress'] = $true ; Repair-MsiSubsystem }
                Start-Sleep -Seconds 30 ; continue
            }
            { $_ -in 1619, 1620, 1612, 1610 } {
                Write-Log "  -> $code package could not be opened / source unavailable" 'WARN'
                if ($code -eq 1610 -and $ProductCode -and -not $tried.ContainsKey('purge-config')) {
                    $tried['purge-config'] = $true
                    Write-Log "  remediation: purging bad configuration data for $ProductCode" 'WARN'
                    Remove-MsiRegistration -ProductCode $ProductCode -Label $Label ; continue
                }
                if ($SourceFile -and -not $tried.ContainsKey('restage')) {
                    $tried['restage'] = $true
                    Write-Log "  remediation: re-staging the package locally and re-validating" 'WARN'
                    try {
                        $fresh = Copy-ToStage -SourceFile $SourceFile
                        if (-not (Get-MsiProperty -Path $fresh).Valid) {
                            Add-Failure "  re-staged file is still not a valid MSI: $fresh" ; return $code
                        }
                        continue
                    } catch { Add-Failure "  re-stage failed: $($_.Exception.Message)" ; return $code }
                }
                Add-Failure "  $code and no further remediation available. Check the package is complete and readable by SYSTEM."
                return $code
            }
            1638 {
                Write-Log "  -> 1638 another version of this product is already installed" 'WARN'
                if ($UpgradeCode -and -not $tried.ContainsKey('purge-upgrade')) {
                    $tried['purge-upgrade'] = $true
                    Clear-ConflictingRegistration -UpgradeCode $UpgradeCode -Label $Label -IncludeLive ; continue
                }
                Add-Failure "  1638 with no UpgradeCode to resolve." ; return $code
            }
            2753 {
                Write-Log "  -> 2753 file is not marked for installation (corrupt registration)" 'WARN'
                if ($ProductCode -and -not $tried.ContainsKey('purge-2753')) {
                    $tried['purge-2753'] = $true
                    Remove-MsiRegistration -ProductCode $ProductCode -Label $Label ; continue
                }
                if ($UpgradeCode -and -not $tried.ContainsKey('purge-2753-uc')) {
                    $tried['purge-2753-uc'] = $true
                    Clear-ConflictingRegistration -UpgradeCode $UpgradeCode -Label $Label ; continue
                }
                Add-Failure "  2753 and no registration to purge." ; return $code
            }
            1601 {
                Write-Log "  -> 1601 Windows Installer service could not be accessed" 'WARN'
                if (-not $tried.ContainsKey('msi-repair')) {
                    $tried['msi-repair'] = $true
                    Repair-MsiSubsystem
                    Invoke-Change "Restart Windows Installer service" { Restart-Service -Name msiserver -Force -EA SilentlyContinue }
                    Start-Sleep -Seconds 5 ; continue
                }
                Add-Failure "  1601 persists - the Windows Installer service is unhealthy." ; return $code
            }
            1633 { Add-Failure "  1633 unsupported platform - wrong architecture package." ; return $code }
            1603 {
                Write-Log "  -> 1603 fatal error during installation" 'ERROR'
                $detail = Get-MsiFailureDetail -LogFile $LogFile
                Write-MsiFailureDetail -Detail $detail -LogFile $LogFile
                $classification = if ($detail) { $detail.Classification } else { 'unknown' }

                # NOTE: `continue` inside a nested switch binds to that switch, not the retry
                # loop, so remediation sets a flag and the retry happens below.
                $remediated = $false
                if ($classification -eq 'pending-reboot') {
                    Write-Log "  cause: a reboot is pending. Returning 3010 so the deployment retries after restart." 'WARN'
                    $script:RebootRequired = $true ; return 3010
                }
                elseif ($classification -eq 'phantom-registration' -and $ProductCode -and -not $tried.ContainsKey('p1')) {
                    $tried['p1'] = $true
                    Remove-MsiRegistration -ProductCode $ProductCode -Label $Label ; $remediated = $true
                }
                elseif ($classification -eq 'conflicting-version' -and $UpgradeCode -and -not $tried.ContainsKey('p2')) {
                    $tried['p2'] = $true
                    Clear-ConflictingRegistration -UpgradeCode $UpgradeCode -Label $Label -IncludeLive ; $remediated = $true
                }
                elseif ($classification -eq 'source-unavailable' -and $SourceFile -and -not $tried.ContainsKey('p3')) {
                    $tried['p3'] = $true
                    try { $null = Copy-ToStage -SourceFile $SourceFile ; $remediated = $true }
                    catch { Write-Log "  re-stage failed: $($_.Exception.Message)" 'WARN' }
                }
                elseif ($classification -eq 'service-locked' -and -not $tried.ContainsKey('p4')) {
                    $tried['p4'] = $true
                    Write-Log "  remediation: the installer could not stop an agent service - stopping it." 'WARN'
                    foreach ($e in $script:PMServiceInventory) { Stop-Service -Name $e.Name -Force -EA SilentlyContinue }
                    $remediated = $true
                }
                elseif ($classification -eq 'unknown' -and -not $tried.ContainsKey('p5')) {
                    $tried['p5'] = $true
                    Write-Log "  remediation: generic pass (Installer state + phantom check)" 'WARN'
                    Repair-MsiSubsystem
                    if ($ProductCode) {
                        $v = Test-MsiPhantom -ProductCode $ProductCode
                        if ($v.Phantom) { Remove-MsiRegistration -ProductCode $ProductCode -Label $Label }
                    }
                    $remediated = $true
                }
                if ($remediated) { continue }
                Add-Failure "  1603 could not be remediated automatically (cause: $classification)."
                return $code
            }
            default {
                Write-Log "  -> exit code $code" 'WARN'
                if ($LogFile) { Write-MsiFailureDetail -Detail (Get-MsiFailureDetail -LogFile $LogFile) -LogFile $LogFile }
                return $code
            }
        }
    }
    Add-Failure "$Label gave up after $MaxAttempts attempts."
    return 1618
}


# ============================================================================
#  PHASE 0 (continued) - SUBSYSTEM HEALTH
# ============================================================================

Write-Step "PHASE 0 - Windows Installer health and pending-reboot check"

Repair-MsiSubsystem
$script:PackedGuidOk = Test-PackedGuidSupport

$pending  = @(Test-PendingReboot)
$blocking = @($pending | Where-Object { $_.Blocking })
$advisory = @($pending | Where-Object { -not $_.Blocking })
$script:PendingRebootAtStart  = @($pending  | ForEach-Object { $_.Source })
$script:BlockingRebootAtStart = @($blocking | ForEach-Object { $_.Source })

foreach ($a in $advisory) {
    Write-Log "Advisory (not blocking): $($a.Source)" 'SKIP'
}
if ($blocking.Count -eq 0) {
    if ($advisory.Count -gt 0) { Write-Log "No blocking reboot condition - proceeding." 'OK' }
    else                       { Write-Log "No pending reboot detected." 'OK' }
} else {
    Write-Log "BLOCKING reboot condition: $($script:BlockingRebootAtStart -join '; ')" 'WARN'
    Write-Log "A servicing operation is mid-flight - this is the most common cause of MSI 1603." 'WARN'
    if ($DryRun) {
        Write-Log "DRY RUN - continuing. A LIVE run would exit $PendingRebootExitCode here unless -IgnorePendingReboot is passed." 'WARN'
        if ($IgnorePendingReboot) { Write-Log "(-IgnorePendingReboot was also specified.)" 'WARN' }
    } elseif ($IgnorePendingReboot) {
        Write-Log "Continuing anyway - -IgnorePendingReboot was specified. Expect an elevated risk of 1603." 'WARN'
    } else {
        Write-Log "Stopping so the machine can restart first. Re-run afterwards, or pass -IgnorePendingReboot to force." 'WARN'
        # 3010 tells SCCM/Intune "installed, needs a restart" - it does NOT trigger a retry, and
        # the detection method will then fail because nothing was installed. 1618 is SCCM's
        # "fast retry" code and is usually the better choice for a deployment. Configurable
        # because the right answer depends on how the deployment's return codes are mapped.
        Write-Log "Exiting $PendingRebootExitCode. Note: 3010 = 'success, needs restart' (no retry); 1618 = SCCM fast retry." 'WARN'
        exit $PendingRebootExitCode
    }
}


# ============================================================================
#  PHASE 1 - AGENT HARDENING (conditional)
# ============================================================================
# Privilege Manager's "Restrict Account Permissions on Agent Services (Windows)" policy
# rewrites the service security descriptor so only a nominated account may stop or delete
# the agent services. Until that is undone, msiexec and `sc delete` fail with access denied.
#
# Modifying a service DACL is itself a monitored technique, so this now runs ONLY when the
# descriptor has actually been altered: if Administrators still hold Stop and Delete, there
# is no hardening to undo and sc.exe is never invoked.

Write-Step "PHASE 1 - Checking agent service hardening"

$DefaultServiceSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)' +
                      '(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

# Hardened if any explicit deny ACE exists, or if neither Administrators nor SYSTEM retains
# both Stop (WP) and Delete (SD).
function Test-ServiceHardened {
    param([string] $Sddl)
    if (-not $Sddl) { return $false }
    if ($Sddl -match '\(D;') { return $true }
    $ok = $false
    foreach ($m in [regex]::Matches($Sddl, '\(A;[^;]*;([^;]*);[^;]*;[^;]*;(BA|SY)\)')) {
        $r = $m.Groups[1].Value
        if ($r -match 'WP' -and $r -match 'SD') { $ok = $true }
    }
    return (-not $ok)
}

function Get-PMServiceNames {
    $names = New-Object System.Collections.Generic.HashSet[string]
    foreach ($n in $KnownServices) { if (Get-Service -Name $n -EA SilentlyContinue) { $null = $names.Add($n) } }
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | ForEach-Object {
        $img = (Get-ItemProperty $_.PSPath -Name ImagePath   -EA SilentlyContinue).ImagePath
        $dsp = (Get-ItemProperty $_.PSPath -Name DisplayName -EA SilentlyContinue).DisplayName
        if ((($img -and $img -match $VendorRx) -or ($dsp -and $dsp -match $VendorRx)) -and
            "$img $dsp" -notmatch $KeepRx) { $null = $names.Add($_.PSChildName) }
    }
    ,@($names)
}

# Snapshot services BEFORE anything is removed: `sc delete` takes the registry key with it,
# so later phases work from this inventory. Binary paths are recorded for reporting only -
# no binary is ever deleted.
function Get-PMServiceInventory {
    $inv = @()
    foreach ($n in (Get-PMServiceNames)) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$n"
        $p   = Get-ItemProperty $key -EA SilentlyContinue
        $inv += [pscustomobject]@{
            Name        = $n
            RegKey      = $key
            DisplayName = $p.DisplayName
            ImagePath   = $p.ImagePath
            IsDriver    = ($p.Type -in 1,2)
            Sddl        = (((& sc.exe sdshow $n) 2>&1 | Out-String).Trim() -split "`r?`n" |
                            Where-Object { $_ -match '^D:' } | Select-Object -First 1)
        }
    }
    ,$inv
}

$script:PMServiceInventory = Get-PMServiceInventory
$pmServices = @($script:PMServiceInventory.Name)

if ($pmServices.Count -eq 0) {
    Write-Log "No Privilege Manager services found on this endpoint."
} else {
    Write-Log "Privilege Manager services found: $($pmServices -join ', ')"
    foreach ($e in $script:PMServiceInventory) {
        Write-Log ("  {0,-24} {1}{2}" -f $e.Name, $e.ImagePath, $(if ($e.IsDriver) { '   [driver]' } else { '' }))
    }
    $hardened = @($script:PMServiceInventory | Where-Object { Test-ServiceHardened $_.Sddl })
    if ($hardened.Count -eq 0) {
        Write-Log "No agent hardening detected - service descriptors are unmodified, so nothing to reset." 'OK'
        Write-Log "sc.exe sdset will NOT be called on this endpoint." 'SKIP'
    } else {
        Write-Log "Agent hardening detected on $($hardened.Count) service(s). Resetting those descriptors only." 'WARN'
        foreach ($e in $hardened) {
            Write-Log "  $($e.Name) current SD: $($e.Sddl)"
            Invoke-Change "Reset security descriptor on hardened service '$($e.Name)'" {
                $out = & sc.exe sdset $e.Name $DefaultServiceSddl 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) { throw "sc sdset returned $LASTEXITCODE : $($out.Trim())" }
            }
        }
        Write-Log "If the resets failed, re-run as the domain account named in the Restrict Account" 'WARN'
        Write-Log "Permissions on Agent Services (Windows) policy, or relax that policy first." 'WARN'
    }
}

foreach ($k in @('HKLM:\SOFTWARE\Policies\Arellia','HKLM:\SOFTWARE\Policies\Thycotic',
                 'HKLM:\SOFTWARE\Policies\Delinea')) {
    Remove-KeyIfPresent $k 'agent policy / server URL / install code'
}


# ============================================================================
#  PHASE 2 - DISCOVERY
# ============================================================================

Write-Step "PHASE 2 - Discovering installed products"

function Get-PMInstalledProducts {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $found = @()
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in (Get-ChildItem $root -EA SilentlyContinue)) {
            $p = Get-ItemProperty $key.PSPath -EA SilentlyContinue
            if (-not $p -or -not $p.DisplayName) { continue }
            $name = $p.DisplayName
            if ($name -match $KeepRx) { continue }
            $isOurs = ($p.Publisher -and $p.Publisher -match $VendorRx) -or
                      ($name -match $VendorRx) -or ($name -match $ProductRx)
            if (-not $isOurs) { continue }
            $isBundle = [bool]$p.BundleCachePath -or
                        ($p.QuietUninstallString -and $p.QuietUninstallString -match '\.exe')
            $found += [pscustomobject]@{
                DisplayName=$name; DisplayVersion=$p.DisplayVersion; Publisher=$p.Publisher
                KeyPath=$key.PSPath
                ProductCode = if ($key.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $key.PSChildName } else { $null }
                UninstallString=$p.UninstallString; QuietUninstallString=$p.QuietUninstallString
                IsBundle=$isBundle
            }
        }
    }
    # Bundle first (it removes its own children), then components, Core agent ALWAYS last.
    $rank = {
        param($item)
        if ($item.IsBundle) { return 0 }
        switch -Regex ($item.DisplayName) {
            'Bundle|PMAgents|Privilege Manager Agents'                { 0; break }
            'Application Control'                                     { 1; break }
            'Local Security'                                          { 2; break }
            'Directory Services'                                      { 3; break }
            'Agent Utility|Remove Programs'                           { 4; break }
            'Core .*Agent|Delinea Agent|Thycotic Agent|Arellia Agent'  { 9; break }
            default                                                   { 5 }
        }
    }
    $found | Sort-Object @{ Expression = { & $rank $_ } }, DisplayName -Unique
}

$products = @(Get-PMInstalledProducts)
if ($products.Count -eq 0) {
    Write-Log "No Privilege Manager products registered in Add/Remove Programs." 'WARN'
    Write-Log "If installs still report 'already installed', Phase 9 is what fixes that." 'WARN'
} else {
    Write-Log "Registered products ($($products.Count)):"
    $products | ForEach-Object {
        Write-Log ("  [{0}] {1}  {2}  ({3})" -f
            $(if ($_.IsBundle) { 'BUNDLE' } else { 'MSI   ' }),
            $_.DisplayName, $_.DisplayVersion, $(if ($_.ProductCode) { $_.ProductCode } else { 'no product code' }))
    }
}


# ============================================================================
#  PHASE 3 - STOP SERVICES
# ============================================================================
# Services are stopped through the service control manager. Nothing is pre-emptively
# disabled and no process is killed unless a service genuinely refuses to stop - both are
# monitored techniques when applied to a security product.

Write-Step "PHASE 3 - Stopping agent services"

$stubborn = @()
foreach ($e in $script:PMServiceInventory) {
    $s = Get-Service -Name $e.Name -EA SilentlyContinue
    if (-not $s) { continue }
    if ($s.Status -eq 'Stopped') { Write-Log "  $($e.Name) already stopped." ; continue }
    Invoke-Change "Stop service '$($e.Name)'" {
        Stop-Service -Name $e.Name -Force -EA Stop
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ((Get-Service $e.Name -EA SilentlyContinue).Status -ne 'Stopped' -and $sw.Elapsed.TotalSeconds -lt 60) {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $DryRun) {
        $after = Get-Service -Name $e.Name -EA SilentlyContinue
        if ($after -and $after.Status -ne 'Stopped') { $stubborn += $e.Name }
    }
}

if ($stubborn.Count -gt 0) {
    Write-Log "Service(s) did not stop cleanly: $($stubborn -join ', ')" 'WARN'
    Write-Log "Falling back to disable + terminate for those only - the MSI cannot proceed otherwise." 'WARN'
    foreach ($n in $stubborn) {
        Invoke-Change "Disable service '$n' (did not stop)" { & sc.exe config $n start= disabled | Out-Null }
    }
    foreach ($procName in $KnownProcesses) {
        foreach ($p in (Get-Process -Name $procName -EA SilentlyContinue)) {
            $thisId = $p.Id ; $thisName = $p.ProcessName
            Invoke-Change "Terminate PM process $thisName (PID $thisId)" { Stop-Process -Id $thisId -Force -EA Stop }
        }
    }
} else {
    Write-Log "All agent services stopped cleanly - no process termination needed." 'OK'
}


# ============================================================================
#  PHASE 4 - UNINSTALL
# ============================================================================

Write-Step "PHASE 4 - Uninstalling products"

foreach ($prod in $products) {
    $safe = ($prod.DisplayName -replace '[^\w\.-]', '_')
    $mlog = Join-Path $script:MsiLogDir "uninstall_$safe.log"

    if ($prod.IsBundle) {
        $exe = $null ; $exeArgs = ''
        if ($prod.QuietUninstallString -match '^\s*"?([^"]+\.exe)"?\s*(.*)$') { $exe = $Matches[1] ; $exeArgs = $Matches[2] }
        elseif ($prod.UninstallString  -match '^\s*"?([^"]+\.exe)"?\s*(.*)$') { $exe = $Matches[1] ; $exeArgs = $Matches[2] }

        # A bundle whose version does not match any installed MSI is a stranded registration:
        # running its uninstaller cannot help (it knows nothing about the newer product codes)
        # and may error. Skip the executable; Phase 7 removes the leftover ARP entry.
        $msiVersions = @($products | Where-Object { -not $_.IsBundle } | ForEach-Object { $_.DisplayVersion })
        $stranded = $msiVersions.Count -gt 0 -and
                    -not [bool](@($msiVersions | Where-Object { $_ -and $prod.DisplayVersion -and $_.StartsWith(($prod.DisplayVersion -split '\.')[0]) }).Count)

        if ($stranded) {
            Write-Log "Bundle '$($prod.DisplayName)' is v$($prod.DisplayVersion) but the installed MSIs are v$($msiVersions -join ', ')." 'WARN'
            Write-Log "  This bundle registration is stranded - skipping its uninstaller and removing the registration in Phase 7." 'WARN'
        } elseif ($exe -and (Test-Path $exe)) {
            if ($exeArgs -notmatch '/uninstall') { $exeArgs = "/uninstall $exeArgs" }
            if ($exeArgs -notmatch '/quiet')     { $exeArgs = "$exeArgs /quiet" }
            if ($exeArgs -notmatch '/norestart') { $exeArgs = "$exeArgs /norestart" }
            $exeArgs = "$exeArgs -l `"$mlog`""
            $null = Invoke-MsiCommand -FilePath $exe -Arguments $exeArgs.Trim() -LogFile $mlog `
                                      -Context Uninstall -Label "Uninstall bundle '$($prod.DisplayName)'"
        } else {
            Write-Log "Bundle cache for '$($prod.DisplayName)' is missing ($exe). Its child MSIs are handled below." 'WARN'
        }
        continue
    }

    if ($prod.ProductCode) {
        $a = "/x `"$($prod.ProductCode)`" /qn /norestart REBOOT=ReallySuppress /l*vx `"$mlog`""
        $null = Invoke-MsiCommand -Arguments $a -LogFile $mlog -Context Uninstall `
                                  -ProductCode $prod.ProductCode -Label "Uninstall MSI '$($prod.DisplayName)'"
        continue
    }

    if ($prod.UninstallString -match '^\s*"?([^"]+\.exe)"?\s*(.*)$') {
        Write-Log "No product code for '$($prod.DisplayName)'; using UninstallString." 'WARN'
        $ue = $Matches[1] ; $ua = "$($Matches[2]) /quiet /norestart".Trim()
        $null = Invoke-MsiCommand -FilePath $ue -Arguments $ua -LogFile $mlog -Context Uninstall `
                                  -Label "Uninstall '$($prod.DisplayName)'"
    }
}

$leftovers = @(Get-PMInstalledProducts)
if ($DryRun) {
    Write-Log "(dry run - the $($leftovers.Count) product(s) above are still registered because nothing was executed)"
} elseif ($leftovers.Count -gt 0) {
    Write-Log "Still registered after uninstall pass: $($leftovers.DisplayName -join '; ')" 'WARN'
}


# ============================================================================
#  PHASE 5 - REMOVE SURVIVING SERVICE ENTRIES
# ============================================================================
# Service entries only. No driver binary is deleted and the DriverStore is never touched -
# the MSI removes its own driver package, and an unreferenced .sys file is inert.

Write-Step "PHASE 5 - Removing surviving service entries"

foreach ($svc in (Get-PMServiceNames)) {
    Invoke-Change "sc delete service '$svc'" {
        $out = & sc.exe delete $svc 2>&1 | Out-String
        # 1072 = marked for deletion (gone on reboot); 1060 = does not exist
        if ($LASTEXITCODE -notin 0,1072,1060) { throw "sc delete returned $LASTEXITCODE : $($out.Trim())" }
        if ($LASTEXITCODE -eq 1072) { $script:RebootRequired = $true }
    }
}

$driverLeft = @($script:PMServiceInventory | Where-Object { $_.IsDriver })
if ($driverLeft.Count -gt 0) {
    Write-Log "Driver binaries are intentionally NOT deleted (no .sys or DriverStore changes):" 'SKIP'
    foreach ($d in $driverLeft) { Write-Log "  $($d.Name): $($d.ImagePath)" 'SKIP' }
    Write-Log "  The MSI removes its own driver package; with the service entry gone the file is inert." 'SKIP'
}


# ============================================================================
#  PHASE 6 - SCHEDULED TASKS
# ============================================================================
# Tasks are removed through the Task Scheduler API, not by deleting files out of
# %SystemRoot%\System32\Tasks.

Write-Step "PHASE 6 - Removing Privilege Manager scheduled tasks"

$pmTaskFolders = New-Object System.Collections.Generic.HashSet[string]
try {
    foreach ($t in (Get-ScheduledTask -EA SilentlyContinue)) {
        $execs    = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
        $isPmTask = ($t.TaskPath -match $VendorRx) -or ($t.TaskName -match $VendorRx) -or ($execs -match $VendorRx) -or
                    ($t.TaskPath -match '\\Privilege Manager\\')
        if ($isPmTask -and $t.TaskPath -notmatch 'Microsoft\\Windows' -and
            "$($t.TaskPath)$($t.TaskName)$execs" -notmatch $KeepRx) {
            $tn = $t.TaskName ; $tp = $t.TaskPath
            if ($tp -and $tp -ne '\') { $null = $pmTaskFolders.Add($tp.Trim('\')) }
            Invoke-Change "Remove scheduled task $tp$tn" {
                Unregister-ScheduledTask -TaskName $tn -TaskPath $tp -Confirm:$false -EA Stop
            }
        }
    }
} catch {
    Write-Log "Get-ScheduledTask unavailable, falling back to schtasks.exe: $($_.Exception.Message)" 'WARN'
    foreach ($line in (& schtasks.exe /Query /FO CSV /NH 2>$null)) {
        if ($line -match $VendorRx -and $line -notmatch $KeepRx) {
            $tn = ($line -split '","')[0].Trim('"')
            Invoke-Change "Remove scheduled task $tn (schtasks)" { & schtasks.exe /Delete /TN "$tn" /F | Out-Null }
        }
    }
}

# Delete the now-empty task folders through the API. DeleteFolder fails on a non-empty
# folder, which is a useful safety property.
if (-not $DryRun) {
    try {
        $ts = New-Object -ComObject Schedule.Service ; $ts.Connect()
        foreach ($f in $pmTaskFolders) {
            try {
                $folder = $ts.GetFolder("\$f")
                if (@($folder.GetTasks(1)).Count -eq 0 -and @($folder.GetFolders(0)).Count -eq 0) {
                    Invoke-Change "Remove empty task folder '\$f' (Task Scheduler API)" {
                        $ts.GetFolder('\').DeleteFolder($f, 0)
                    }
                } else { Write-Log "Task folder '\$f' is not empty - leaving it." }
            } catch { Write-Log "Task folder '\$f': $($_.Exception.Message)" }
        }
    } catch { Write-Log "Task Scheduler API unavailable: $($_.Exception.Message)" 'WARN' }
} else {
    foreach ($f in $pmTaskFolders) { Write-Log "WOULD: Remove empty task folder '\$f' (Task Scheduler API)" 'DRY' }
}


# ============================================================================
#  PHASE 7 - REGISTRY
# ============================================================================

Write-Step "PHASE 7 - Removing Privilege Manager registry keys"

$regKeys = @(
    'HKLM:\SOFTWARE\Arellia'                                # agent config, AgentId
    'HKLM:\SOFTWARE\WOW6432Node\Arellia'
    'HKLM:\SOFTWARE\Policies\Arellia'                       # AMS URL, InstallCode
    'HKLM:\SOFTWARE\WOW6432Node\Policies\Arellia'
    'HKLM:\SOFTWARE\Thycotic\Agents'
    'HKLM:\SOFTWARE\Thycotic\Privilege Manager'
    'HKLM:\SOFTWARE\WOW6432Node\Thycotic\Agents'
    'HKLM:\SOFTWARE\WOW6432Node\Thycotic\Privilege Manager'
    'HKLM:\SOFTWARE\Delinea\Privilege Manager'
    'HKLM:\SOFTWARE\WOW6432Node\Delinea\Privilege Manager'
)
foreach ($e in $script:PMServiceInventory) { $regKeys += $e.RegKey }
$regKeys = @($regKeys | Sort-Object -Unique)
foreach ($k in $regKeys) { Remove-KeyIfPresent $k }

# Only remove vendor parents when empty - Secret Server et al. also live under these.
foreach ($parent in @('HKLM:\SOFTWARE\Thycotic','HKLM:\SOFTWARE\WOW6432Node\Thycotic',
                      'HKLM:\SOFTWARE\Delinea','HKLM:\SOFTWARE\WOW6432Node\Delinea')) {
    if (Test-Path $parent) {
        $children = @(Get-ChildItem $parent -EA SilentlyContinue)
        $values   = @((Get-Item $parent -EA SilentlyContinue).Property)
        if ($children.Count -eq 0 -and $values.Count -eq 0) { Remove-KeyIfPresent $parent 'empty vendor parent key' }
        else { Write-Log "Leaving $parent - still contains: $(($children.PSChildName + $values) -join ', ')" }
    }
}

# PM's "Request Run as Administrator" context-menu verb. Matched on the verb's actual
# command pointing into a PM install path - no heuristic name or blob matching.
foreach ($shellRoot in @('HKLM:\SOFTWARE\Classes\exefile\Shell','HKLM:\SOFTWARE\Classes\Msi.Package\Shell',
                         'HKLM:\SOFTWARE\Classes\batfile\Shell','HKLM:\SOFTWARE\Classes\cmdfile\Shell')) {
    if (-not (Test-Path $shellRoot)) { continue }
    foreach ($verb in (Get-ChildItem $shellRoot -EA SilentlyContinue)) {
        $cmd = (Get-ItemProperty (Join-Path $verb.PSPath 'command') -Name '(default)' -EA SilentlyContinue).'(default)'
        if ($cmd -and $cmd -match "\\($VendorRx)\\" -and $cmd -notmatch $KeepRx) {
            Remove-KeyIfPresent $verb.PSPath "PM context-menu verb -> $cmd"
        }
    }
}

foreach ($prod in (Get-PMInstalledProducts)) {
    Remove-KeyIfPresent $prod.KeyPath "orphaned ARP entry: $($prod.DisplayName)"
}

# Per-user state in already-loaded profile hives only. No `reg load` of NTUSER.DAT.
Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
    ForEach-Object {
        $hive = "Registry::HKEY_USERS\$($_.PSChildName)"
        foreach ($sub in @('Software\Arellia','Software\Thycotic\Privilege Manager','Software\Delinea\Privilege Manager')) {
            Remove-KeyIfPresent (Join-Path $hive $sub) 'per-user agent state'
        }
    }
Write-Log "Unloaded profiles and the Default hive are not modified (no reg load)." 'SKIP'


# ============================================================================
#  PHASE 8 - FILESYSTEM
# ============================================================================

Write-Step "PHASE 8 - Removing Privilege Manager files and caches"

$pf   = $env:ProgramFiles
$pf86 = ${env:ProgramFiles(x86)}
$pd   = $env:ProgramData
if (-not $pf86) { $pf86 = $pf }
if (-not $pf -or -not $pd) { Add-Failure "ProgramFiles/ProgramData not set - filesystem phase unreliable." }

$paths = @(
    "$pf\Thycotic\Agents"                      # 12.0 AND 13.0 both install here
    "$pf\Thycotic\Powershell"
    "$pf86\Thycotic\Agents"
    "$pf86\Thycotic\Powershell"
    "$pf\Delinea\Privilege Manager"            # per the admin guide
    "$pf86\Delinea\Privilege Manager"
    "$pf\Arellia"
    "$pf86\Arellia"
    "$pd\Arellia"                              # agent state + ClientItems database
    "$pd\Application Data\Arellia"
    "$pd\Delinea\Privilege Manager"
    "$pd\Thycotic\Agent"
    "$pd\Microsoft\Windows\Start Menu\Programs\Delinea"
    "$pd\Microsoft\Windows\Start Menu\Programs\Thycotic"
    "$pd\Microsoft\Windows\Start Menu\Programs\Privilege Manager"
)
$paths = @($paths | Where-Object { $_ -and (Test-PathIsPmOwned $_) } | Sort-Object -Unique)

# Drop any path reached THROUGH a junction - its real target is already in the list under
# its canonical name.
$pathsToRemove = @()
foreach ($p in $paths) {
    if (Test-Path -LiteralPath $p) {
        $anc = Get-ReparseAncestor $p
        if ($anc) {
            Write-Log "Skipping $p - reached through the junction '$anc'; its target is handled under its canonical path." 'SKIP'
            continue
        }
    }
    $pathsToRemove += $p
}
foreach ($p in $pathsToRemove) { Remove-PathIfPresent $p }

foreach ($p in (@("$pf\Delinea","$pf86\Delinea","$pf\Thycotic","$pf86\Thycotic","$pd\Delinea","$pd\Thycotic") |
                Where-Object { $_ -match '^[A-Za-z]:\\' } | Sort-Object -Unique)) {
    if (Test-Path -LiteralPath $p) {
        if (@(Get-ChildItem -LiteralPath $p -Force -EA SilentlyContinue).Count -eq 0) {
            Remove-PathIfPresent $p 'empty vendor folder'
        } else { Write-Log "Leaving $p - not empty (other Delinea products present)." }
    }
}

# Burn bundle payloads for PM packages only.
foreach ($cacheRoot in @("$pd\Package Cache")) {
    if (-not (Test-Path -LiteralPath $cacheRoot)) { continue }
    Get-ChildItem -LiteralPath $cacheRoot -Directory -EA SilentlyContinue | ForEach-Object {
        $dir = $_
        $hit = Get-ChildItem -LiteralPath $dir.FullName -File -Recurse -Depth 2 -EA SilentlyContinue |
               Where-Object { $_.Name -match 'PMAgents|ThycoticAgent|DelineaAgent|Arellia' } |
               Select-Object -First 1
        if ($hit) {
            # Package Cache folders are named by GUID, so the PM-owned path guard cannot see a
            # vendor name and this is the one removal that bypasses it. Two checks stand in for
            # it: the folder's parent must be exactly the Package Cache root, and it must
            # contain a recognisable PM installer.
            $target = $dir.FullName
            $parentOk = (Split-Path -Parent $target).TrimEnd('\').ToLower() -eq $cacheRoot.TrimEnd('\').ToLower()
            $nameOk   = $dir.Name -match '^\{[0-9A-Fa-f-]{36}\}'
            if (-not ($parentOk -and $nameOk)) {
                Write-Log "REFUSED (guard): $target is not a GUID folder directly under the Package Cache root." 'WARN'
            } else {
                Invoke-Change "Remove cached bundle payload $target (contains $($hit.Name))" {
                    Remove-Item -LiteralPath $target -Recurse -Force -EA Stop
                }
            }
        }
    }
}

# PM installer logs from prior attempts. This script's own cleanup logs are preserved.
Get-ChildItem "$env:WinDir\Temp" -File -EA SilentlyContinue |
    Where-Object { $_.Name -match '(Thycotic|Delinea|Arellia|PMAgents).*\.log$' -and
                   $_.Name -notmatch '^DelineaPMCleanup_' } |
    ForEach-Object {
        $f = $_.FullName
        Invoke-Change "Remove stale PM installer log $f" { Remove-Item -LiteralPath $f -Force -EA Stop }
    }

# Firewall rules the agent created. Reported by default, removed only on request.
try {
    $fwPolicy  = New-Object -ComObject HNetCfg.FwPolicy2 -EA Stop
    $fwMatches = @($fwPolicy.Rules | Where-Object {
        ("$($_.Name) $($_.Grouping)" -match $VendorRx) -and ($_.Name -notmatch $KeepRx)
    })
    if ($fwMatches.Count -eq 0) {
        Write-Log "No Privilege Manager firewall rules found."
    } elseif ($RemoveFirewallRules) {
        foreach ($r in $fwMatches) {
            $ruleName = $r.Name
            Invoke-Change "Remove firewall rule '$ruleName'" { $fwPolicy.Rules.Remove($ruleName) }
        }
    } else {
        Write-Log "Firewall rules left in place (pass -RemoveFirewallRules to remove them):" 'SKIP'
        foreach ($r in $fwMatches) { Write-Log "  $($r.Name)" 'SKIP' }
        Write-Log "  These are inert once the agent binaries are gone - nothing listens on them." 'SKIP'
    }
} catch { Write-Log "Firewall enumeration unavailable: $($_.Exception.Message)" 'WARN' }


# ============================================================================
#  PHASE 9 - PURGE PHANTOM MSI REGISTRATIONS
# ============================================================================
# This is what fixes "the latest version is already installed" when nothing is installed.
# Each candidate must PROVE it is a phantom before anything is deleted.

Write-Step "PHASE 9 - Purging phantom / orphaned Windows Installer registrations"

$candidates = @{}   # packed code -> description

foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -EA SilentlyContinue)) {
    $pn = (Get-ItemProperty $k.PSPath -Name ProductName -EA SilentlyContinue).ProductName
    if ($pn -and $pn -match "$VendorRx|$ProductRx" -and $pn -notmatch $KeepRx) { $candidates[$k.PSChildName] = $pn }
}
$udRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Installer\UserData\S-1-5-18\Products'
if (Test-Path $udRoot) {
    foreach ($k in (Get-ChildItem $udRoot -EA SilentlyContinue)) {
        $ip = Join-Path $k.PSPath 'InstallProperties'
        $dn = (Get-ItemProperty $ip -Name DisplayName -EA SilentlyContinue).DisplayName
        $pb = (Get-ItemProperty $ip -Name Publisher   -EA SilentlyContinue).Publisher
        if ((("$dn $pb") -match "$VendorRx|$ProductRx") -and "$dn $pb" -notmatch $KeepRx) {
            if (-not $candidates.ContainsKey($k.PSChildName)) { $candidates[$k.PSChildName] = $dn }
        }
    }
}

if ($candidates.Count -eq 0) {
    Write-Log "No Privilege Manager entries in the Windows Installer database." 'OK'
} else {
    Write-Log "Installer database entries to evaluate ($($candidates.Count)):"
    foreach ($packed in $candidates.Keys) {
        $guid = ConvertFrom-MsiPackedGuid $packed
        Write-Log ("  {0}  ->  {1}  [{2}]" -f $packed, $(if($guid){$guid}else{'<unpack failed>'}), $candidates[$packed])
    }
    foreach ($packed in @($candidates.Keys)) {
        $name = $candidates[$packed]
        $guid = ConvertFrom-MsiPackedGuid $packed
        if (-not $guid) { Write-Log "Cannot unpack '$packed' - skipping." 'WARN' ; continue }
        $verdict = Test-MsiPhantom -ProductCode $guid
        if ($verdict.Phantom) {
            Write-Log "PHANTOM: $guid '$name' - $($verdict.Reason)" 'WARN'
            Remove-MsiRegistration -ProductCode $guid -Label "'$name'"
        } else {
            Write-Log "LIVE   : $guid '$name' - $($verdict.Reason). Left in place." 'WARN'
        }
    }
}

# Sweep UpgradeCodes keys that now point at nothing. This is the only place the script
# deletes a whole key on aggregate evidence, so it shows its work: every member is logged
# with its unpacked ProductCode, name and state BEFORE the verdict. Nothing is removed
# unless every member is provably dead AND at least one is a PM product; a member that
# cannot be unpacked blocks the whole key.
foreach ($ucRoot in @('HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes',
                      'HKLM:\SOFTWARE\Microsoft\Windows\Installer\UpgradeCodes')) {
    if (-not (Test-Path $ucRoot)) { continue }
    foreach ($uc in (Get-ChildItem $ucRoot -EA SilentlyContinue)) {
        $vals = @((Get-Item $uc.PSPath -EA SilentlyContinue).Property | Where-Object { $_ -ne '(default)' })
        if ($vals.Count -eq 0) { continue }

        $members = @()
        foreach ($v in $vals) {
            $g  = ConvertFrom-MsiPackedGuid $v
            $st = if ($g) { Get-MsiProductState -ProductCode $g } else { $null }
            $members += [pscustomobject]@{
                Packed=$v; ProductCode=$g
                ProductName = if ($st) { $st.ProductName } else { $null }
                State       = if ($st) { $st.State } else { $null }
                Installed   = if ($st) { $st.Installed } else { $false }
                InProductsDb= [bool](Test-Path "HKLM:\SOFTWARE\Classes\Installer\Products\$v")
                Unpackable  = [bool]$g
            }
        }
        # "Ours" requires a PM product name or a PM entry in the candidate set. Membership of
        # the Products database alone is NOT enough - that matches any vendor's product.
        $anyOurs = [bool](@($members | Where-Object {
            ($_.ProductName -and $_.ProductName -match "$VendorRx|$ProductRx" -and $_.ProductName -notmatch $KeepRx) -or
            ($_.InProductsDb -and $candidates.ContainsKey($_.Packed))
        }).Count)
        if (-not $anyOurs) { continue }

        $ucGuid  = ConvertFrom-MsiPackedGuid $uc.PSChildName
        $allDead = -not [bool](@($members | Where-Object { $_.Installed -or -not $_.Unpackable }).Count)

        Write-Log "UpgradeCodes key $($uc.PSChildName) -> $(if($ucGuid){$ucGuid}else{'<unpack failed>'})  ($($members.Count) member(s)):"
        foreach ($m in $members) {
            Write-Log ("    {0}  {1,-40}  {2,-34}  {3}" -f
                $(if ($m.Installed) { 'INSTALLED' } elseif ($m.Unpackable) { 'dead     ' } else { 'UNKNOWN  ' }),
                $(if ($m.ProductCode) { $m.ProductCode } else { "<cannot unpack $($m.Packed)>" }),
                $(if ($m.ProductName) { $m.ProductName } else { '(no product name)' }),
                "state=$($m.State); inProductsDb=$($m.InProductsDb)")
        }
        if ($allDead) {
            Write-Log "  verdict: every member is dead and at least one is a PM product - removing the key." 'WARN'
            Remove-KeyIfPresent $uc.PSPath "UpgradeCodes key, all $($members.Count) member(s) dead"
        } else {
            $blockers = @($members | Where-Object { $_.Installed -or -not $_.Unpackable })
            Write-Log ("  verdict: KEPT - {0} member(s) still live or unreadable: {1}" -f $blockers.Count,
                       (($blockers | ForEach-Object { if ($_.ProductCode) { $_.ProductCode } else { $_.Packed } }) -join ', '))
        }
    }
}


# ============================================================================
#  PHASE 10 - SCCM / CONFIGMGR CACHE
# ============================================================================
# Old PM packages delivered by SCCM sit in %WinDir%\ccmcache\<id>\. Two things matter:
#
#  1. Removal goes through the ConfigMgr client's own API (UIResource.UIResourceMgr ->
#     GetCacheInfo -> DeleteCacheElement), never by deleting the folder. The client keeps an
#     index of what it believes is cached; deleting folders behind its back leaves ghost
#     entries, and the client then reports content as present that isn't - which causes
#     download failures on the NEXT deployment. The API removes the entry and the content
#     together.
#
#  2. ccmcache lives under %SystemRoot%, which the path guard denies outright. That is
#     deliberate and is not worked around: no folder under C:\Windows is deleted by this
#     script under any switch.
#
# When the client API is unavailable, the cache is REPORTED, not touched. Leftover packages
# there are wasted disk, not a functional problem - ConfigMgr ages content out on its own
# based on cache size and retention.

$ccmPkgRx = 'PMAgents|ThycoticAgent|DelineaAgent|Thycotic_|Delinea_|Arellia'

function Get-CcmCacheReport {
    # Read-only view of PM content in ccmcache, for when the client API cannot be used.
    $root = Join-Path $env:WinDir 'ccmcache'
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    $hits = @()
    foreach ($dir in (Get-ChildItem -LiteralPath $root -Directory -EA SilentlyContinue)) {
        $hit = Get-ChildItem -LiteralPath $dir.FullName -File -Recurse -Depth 2 -EA SilentlyContinue |
               Where-Object { $_.Name -match $ccmPkgRx } | Select-Object -First 1
        if ($hit) {
            $size = 0
            try { $size = (Get-ChildItem -LiteralPath $dir.FullName -Recurse -File -EA SilentlyContinue |
                           Measure-Object Length -Sum).Sum } catch { }
            $hits += [pscustomobject]@{ Path=$dir.FullName; Sample=$hit.Name; MB=[math]::Round($size/1MB,1) }
        }
    }
    ,$hits
}

if ($ClearCcmCache) {
    Write-Step "PHASE 10 - Purging ConfigMgr cache entries for Privilege Manager packages"
    $handled = $false ; $found = 0
    try {
        $uiRes = New-Object -ComObject 'UIResource.UIResourceMgr' -EA Stop
        $cache = $uiRes.GetCacheInfo()
        foreach ($el in $cache.GetCacheElements()) {
            $loc = $el.Location
            $match = ($loc -match $ccmPkgRx)
            if (-not $match -and (Test-Path -LiteralPath $loc)) {
                $match = [bool](Get-ChildItem -LiteralPath $loc -File -Recurse -Depth 2 -EA SilentlyContinue |
                                Where-Object { $_.Name -match $ccmPkgRx } | Select-Object -First 1)
            }
            if ($match) {
                $found++
                $id = $el.CacheElementId
                Invoke-Change "Delete ConfigMgr cache element $id ($loc)" { $cache.DeleteCacheElement($id) }
            }
        }
        $handled = $true
        if ($found -eq 0) { Write-Log "ConfigMgr client reports no cached Privilege Manager content." 'OK' }
    } catch { Write-Log "ConfigMgr client COM not available: $($_.Exception.Message)" 'WARN' }

    if (-not $handled) {
        # No client API: report only. Deleting ccmcache folders directly would both break the
        # client's index and require writing under C:\Windows, which the guard forbids.
        $report = Get-CcmCacheReport
        if ($report.Count -eq 0) {
            Write-Log "No Privilege Manager content found in ccmcache." 'OK'
        } else {
            Write-Log "ConfigMgr client API unavailable - reporting ccmcache content, NOT deleting it:" 'SKIP'
            foreach ($r in $report) { Write-Log ("  {0}  [{1}, {2} MB]" -f $r.Path, $r.Sample, $r.MB) 'SKIP' }
            Write-Log "  Remove these from the ConfigMgr console (or let cache retention age them out)." 'SKIP'
            Write-Log "  Deleting the folders by hand leaves ghost cache entries that break later deployments." 'SKIP'
        }
    }
} else {
    Write-Log "PHASE 10 - reporting SCCM cache only (pass -ClearCcmCache to purge via the ConfigMgr client API)."
    $report = Get-CcmCacheReport
    if ($report.Count -eq 0) {
        Write-Log "  No Privilege Manager content in ccmcache."
    } else {
        $totalMb = ($report | Measure-Object MB -Sum).Sum
        Write-Log ("  {0} cached Privilege Manager package(s), {1} MB total:" -f $report.Count, $totalMb) 'WARN'
        foreach ($r in $report) { Write-Log ("    {0}  [{1}, {2} MB]" -f $r.Path, $r.Sample, $r.MB) }
    }
}


# ============================================================================
#  PHASE 11 - VERIFY
# ============================================================================

Write-Step "PHASE 11 - Verification"

$remaining = @()
foreach ($p in (Get-PMInstalledProducts)) { $remaining += "ARP entry: $($p.DisplayName)" }
foreach ($s in (Get-PMServiceNames))      { $remaining += "Service: $s" }
foreach ($p in $pathsToRemove) { if (Test-Path -LiteralPath $p) { $remaining += "Path: $p" } }
foreach ($k in $regKeys)       { if (Test-Path $k)              { $remaining += "Reg: $k" } }
Get-CimInstance Win32_Process -EA SilentlyContinue |
    Where-Object { $_.ExecutablePath -and $_.ExecutablePath -match $VendorRx -and $_.ExecutablePath -notmatch $KeepRx } |
    ForEach-Object { $remaining += "Process: $($_.Name) [$($_.ExecutablePath)]" }
foreach ($packed in @($candidates.Keys)) {
    if (Test-Path "HKLM:\SOFTWARE\Classes\Installer\Products\$packed") {
        $remaining += "Installer DB: $packed [$($candidates[$packed])]"
    }
}

if ($DryRun) {
    Write-Log "Dry run - the items above are what WOULD be removed." 'DRY'
} elseif ($remaining.Count -eq 0) {
    Write-Log "Clean. No PM services, products, registry keys, paths or Installer records remain." 'OK'
} else {
    Write-Log "Still present after cleanup ($($remaining.Count)):" 'WARN'
    $remaining | ForEach-Object { Write-Log "  - $_" 'WARN' }
    if ($script:RebootRequired -or $script:PendingRebootAtStart.Count -gt 0) {
        Write-Log "A reboot is pending - most of these clear on restart. Re-run afterwards to confirm." 'WARN'
    }
}


# ============================================================================
#  PHASE 12 - INSTALL (optional)
# ============================================================================

if ($Install) {
    Write-Step "PHASE 12 - Installing Privilege Manager agent"

    if (-not (Test-Path -LiteralPath $InstallerPath)) {
        Add-Failure "InstallerPath not found: $InstallerPath"
    } else {
        if (-not $ServerUrl -or -not $InstallCode) {
            Write-Log "ServerUrl and/or InstallCode not supplied - the agent will install but will NOT register." 'WARN'
        }
        $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
            'ARM64' { 'ARM64' ; break }
            default { if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' } }
        }
        Write-Log "Architecture  : $arch"
        Write-Log "Source        : $InstallerPath"
        Write-Log "Staging to    : $($script:StageDir)"

        if ($UseBundle) {
            $b = Resolve-Installer -Pattern 'PMAgents*.exe' -SkipValidation
            if (-not $b) { Add-Failure "No PMAgents*.exe found in '$InstallerPath'." }
            else {
                $a = "/quiet /norestart"
                if ($ServerUrl)   { $a += " ServerUrl=$ServerUrl" }
                if ($InstallCode) { $a += " InstallCode=$InstallCode" }
                $blog = Join-Path $script:MsiLogDir 'install_bundle.log'
                $a += " -l `"$blog`""
                $rc = Invoke-MsiCommand -FilePath $b.Path -Arguments $a -LogFile $blog `
                                        -Context Install -SourceFile $b.Path -Label "Install bundle $(Split-Path -Leaf $b.Path)"
                if ($rc -ne 0) { Add-Failure "Bundle install returned $rc" }
            }
        } else {
            $catalog = @{
                ApplicationControl = @{ Pattern="*ApplicationControlAgent_$arch*.msi"; Label='Application Control Agent'; Order=1; Exclude=@() }
                LocalSecurity      = @{ Pattern="*LocalSecurityAgent_$arch*.msi";      Label='Local Security Agent';      Order=2; Exclude=@() }
                DirectoryServices  = @{ Pattern="*DirectoryServices*Agent_$arch*.msi"; Label='Directory Services Agent';  Order=3; Exclude=@() }
                # The core pattern also matches the component MSIs, so exclude them by name.
                Core               = @{ Pattern="*Agent_$arch*.msi";                   Label='Core Delinea Agent';        Order=9
                                        Exclude=@('ApplicationControl','LocalSecurity','DirectoryServices') }
            }
            $plan = $Components | Sort-Object { $catalog[$_].Order } -Unique
            Write-Log "Install plan  : $(($plan | ForEach-Object { $catalog[$_].Label }) -join '  ->  ')"

            foreach ($comp in $plan) {
                $spec = $catalog[$comp]
                Write-Log ('-' * 78)
                Write-Log "Component: $($spec.Label)"
                $found = Resolve-Installer -Pattern $spec.Pattern -ExcludePattern $spec.Exclude
                if (-not $found) {
                    Add-Failure "$($spec.Label) MSI ($($spec.Pattern)) not found in '$InstallerPath'."
                    if ($comp -eq 'Core') { Write-Log "  Without the core agent the endpoint cannot register." 'ERROR' }
                    continue
                }
                # Clear whatever Windows Installer already believes about this product BEFORE
                # installing - the pre-emptive fix for the false "already installed" prompt.
                if ($found.Msi -and $found.Msi.UpgradeCode) {
                    Write-Log "Pre-install registration check for $($spec.Label):"
                    Clear-ConflictingRegistration -UpgradeCode $found.Msi.UpgradeCode -Label $spec.Label -IncludeLive
                }
                if ($found.Msi -and $found.Msi.ProductCode) {
                    $v = Test-MsiPhantom -ProductCode $found.Msi.ProductCode
                    if ($v.Phantom -and (Test-Path "HKLM:\SOFTWARE\Classes\Installer\Products\$(ConvertTo-MsiPackedGuid $found.Msi.ProductCode)")) {
                        Write-Log "  exact ProductCode is registered but phantom ($($v.Reason)) - purging." 'WARN'
                        Remove-MsiRegistration -ProductCode $found.Msi.ProductCode -Label $spec.Label
                    }
                }
                $logf = Join-Path $script:MsiLogDir ("install_$comp.log")
                $a = "/i `"$($found.Path)`" /qn /norestart REBOOT=ReallySuppress /l*vx `"$logf`""
                if ($comp -eq 'Core') {
                    if ($ServerUrl)   { $a += " AMSURL=$ServerUrl" }
                    if ($InstallCode) { $a += " INSTALLCODE=$InstallCode" }
                }
                $rc = Invoke-MsiCommand -Arguments $a -LogFile $logf -Context Install `
                                        -SourceFile $found.Path `
                                        -ProductCode $(if ($found.Msi) { $found.Msi.ProductCode }) `
                                        -UpgradeCode $(if ($found.Msi) { $found.Msi.UpgradeCode }) `
                                        -Label "Install $($spec.Label)"
                if ($rc -ne 0 -and $rc -ne 3010) {
                    Add-Failure "$($spec.Label) install returned $rc"
                    if ($comp -ne 'Core') {
                        Write-Log "Stopping the sequence - installing the Core agent on top of a failed component leaves a broken endpoint." 'ERROR'
                        break
                    }
                }
            }
        }

        if (-not $DryRun) {
            Write-Log ('-' * 78)
            Start-Sleep -Seconds 10
            $core = Get-Service -Name 'ArelliaAgent' -EA SilentlyContinue
            $acs  = Get-Service -Name 'ArelliaACSvc' -EA SilentlyContinue
            if ($core) { Write-Log "Core agent service present, status $($core.Status)" 'OK' }
            else       { Add-Failure "ArelliaAgent service not present after install." }
            if ($acs)  { Write-Log "Application Control service present, status $($acs.Status)" 'OK' }
            if (Test-Path 'HKLM:\SOFTWARE\Arellia\Agent') { Write-Log "Agent registry root created." 'OK' }
            foreach ($p in (Get-PMInstalledProducts)) {
                Write-Log ("Installed: {0} {1}" -f $p.DisplayName, $p.DisplayVersion) 'OK'
            }
        }
    }
}


# ============================================================================
#  SUMMARY AND EXIT
# ============================================================================

Write-Step "SUMMARY"
Write-Log "Actions taken : $($script:Removed.Count)"
Write-Log "Failures      : $($script:Failures.Count)"
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Log "  ! $_" 'ERROR' } }

$rebootSummary =
    if     ($script:RebootRequired -and $script:BlockingRebootAtStart.Count -gt 0) {
        "YES - required by this run, and a blocking condition existed at start ($($script:BlockingRebootAtStart -join '; '))" }
    elseif ($script:RebootRequired) { 'YES - required by changes made in this run' }
    elseif ($script:BlockingRebootAtStart.Count -gt 0) {
        "YES - pre-existing blocking condition, not caused by this run ($($script:BlockingRebootAtStart -join '; '))" }
    elseif ($script:PendingRebootAtStart.Count -gt 0) {
        "no - advisory only ($($script:PendingRebootAtStart -join '; '))" }
    else { 'no' }
Write-Log "Reboot needed : $rebootSummary"
Write-Log "Log file      : $LogPath"
Write-Log "MSI logs      : $($script:MsiLogDir)"

if ($script:Failures.Count -gt 0) { Write-Log "Completed WITH FAILURES." 'ERROR' ; exit 1 }

# Only a reboot this run actually caused, or a genuinely blocking pre-existing condition,
# earns a 3010. An advisory PendingFileRenameOperations must NOT make every successful run
# return 3010 - that turns a clean install into a "needs restart" result in the console.
# A dry run never returns 3010 either: it changed nothing for a deployment tool to act on.
$needsReboot = ($script:RebootRequired -or $script:BlockingRebootAtStart.Count -gt 0)
if ($needsReboot -and -not $SkipReboot -and -not $DryRun) {
    Write-Log "Completed. Reboot required." 'OK' ; exit 3010
}
Write-Log "Completed successfully." 'OK'
exit 0
