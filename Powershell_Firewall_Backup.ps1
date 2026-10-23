function Invoke-FirewallBackup {
    <#
    .SYNOPSIS
        Backs up or restores the Windows Firewall configuration.
    .DESCRIPTION
        Uses 'netsh advfirewall export/import' to save or restore all firewall rules
        and profile settings (.wfw file). Requires Administrator rights.
        Restoring REPLACES the entire current firewall policy.
    .PARAMETER Output
        Directory to save the backup in. Created if missing. Defaults to the current directory.
    .PARAMETER Restore
        Path to a .wfw backup file to restore.
    .EXAMPLE
        Invoke-FirewallBackup -Output C:\Backups
    .EXAMPLE
        Invoke-FirewallBackup -Restore C:\Backups\fw_backup_20261013_101500.wfw -WhatIf
    #>
    [CmdletBinding(DefaultParameterSetName = 'Backup', SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName = 'Backup', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Output = (Get-Location).Path,

        [Parameter(ParameterSetName = 'Restore', Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Restore
    )

    # netsh advfirewall import/export requires administrator rights
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Error "Run this as Administrator."; return }

    if ($PSCmdlet.ParameterSetName -eq 'Restore') {
        # ---- RESTORE ----
        $file = (Resolve-Path $Restore).Path
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Replace firewall policy with $file")) {
            Write-Verbose "Importing firewall policy from $file"
            netsh advfirewall import "$file" | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Host "Firewall configuration restored from $file" }
            else { Write-Error "Restore failed (netsh exit code $LASTEXITCODE)." }
        }
    }
    else {
        # ---- BACKUP ----
        if (-not (Test-Path $Output)) {
            Write-Verbose "Creating directory $Output"
            New-Item -ItemType Directory -Path $Output -Force | Out-Null
        }
        $dir  = (Resolve-Path $Output).Path
        $file = Join-Path $dir ("fw_backup_{0}.wfw" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Write-Verbose "Exporting firewall policy to $file"
        netsh advfirewall export "$file" | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host "Firewall configuration backed up to $file" }
        else { Write-Error "Backup failed (netsh exit code $LASTEXITCODE)." }
    }
}