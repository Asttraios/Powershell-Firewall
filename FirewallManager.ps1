#Requires -RunAsAdministrator
param (
    # Przelacznik uzywany przez Harmonogram Zadan Windows do aktualizacji w tle (omija menu)
    [switch]$AutoUpdateProfile
)

# ==========================================
# KONFIGURACJA LOGOWANIA I BASELINE
# ==========================================
$ScriptPath = If ($PSCommandPath) { $PSCommandPath } Else { Join-Path (Get-Location).Path "FirewallManager.ps1" }
$ScriptDir = Split-Path -Path $ScriptPath -Parent
$LogPath = Join-Path $ScriptDir "firewall_audit.log"
$BaselinePath = Join-Path $ScriptDir "firewall_baseline.json"

function Write-FirewallLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $logEntry = "[$timestamp] [$Level] [$user] - $Message"
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

# ==========================================
# 1. FUNKCJE ZARZADZANIA REGULAMI
# ==========================================

function Add-BlockedPort {
    param (
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [ValidateSet("TCP", "UDP")]
        [string]$Protocol = "TCP",

        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction = "Inbound",

        [ValidateSet("Public", "Private", "Domain")]
        [string]$ProfileGroup = "Public"
    )

    $groupName = "PowershellFirewall_$ProfileGroup"
    $ruleName = "PF_${ProfileGroup}_BlockPort_${Protocol}_${Port}_${Direction}"
    $displayName = "PF [$ProfileGroup] Blocking Port $Port ($Protocol - $Direction)"

    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRule) {
        Write-Warning "Firewall Rule '$ruleName' already exists!"
        return
    }

    $ruleParams = @{
        Name        = $ruleName
        DisplayName = $displayName
        Group       = $groupName
        Direction   = $Direction
        Action      = "Block"
        Protocol    = $Protocol
        LocalPort   = $Port
        Profile     = "Any"
        Enabled     = "False"
        ErrorAction = "Stop"
    }

    try {
        New-NetFirewallRule @ruleParams | Out-Null
        Write-Host "[SUCCESS] Port $Port added to '$groupName' ($Protocol, direction: $Direction)." -ForegroundColor Green
        Write-FirewallLog -Message "Added blocked port rule: $ruleName (Port $Port, $Protocol)" -Level "INFO"
    }
    catch {
        Write-Host "[ERROR] Failed to add port $Port to '$groupName': $($_.Exception.Message)" -ForegroundColor Red
        Write-FirewallLog -Message "Failed to add blocked port rule $ruleName : $($_.Exception.Message)" -Level "ERROR"
    }
}

function Add-BlockedIP {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,

        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction = "Inbound",

        [ValidateSet("Public", "Private", "Domain")]
        [string]$ProfileGroup = "Public"
    )

    $groupName = "PowershellFirewall_$ProfileGroup"
    $safeIPName = $IPAddress -replace '/', '_'
    $ruleName = "PF_${ProfileGroup}_BlockIP_${safeIPName}_${Direction}"
    $displayName = "PF [$ProfileGroup] Blocking IP $IPAddress ($Direction)"

    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRule) {
        Write-Warning "Firewall Rule '$ruleName' already exists!"
        return
    }

    $ruleParams = @{
        Name          = $ruleName
        DisplayName   = $displayName
        Group         = $groupName
        Direction     = $Direction
        Action        = "Block"
        RemoteAddress = $IPAddress
        Profile       = "Any"
        Enabled       = "False"
        ErrorAction   = "Stop"
    }

    try {
        New-NetFirewallRule @ruleParams | Out-Null
        Write-Host "[SUCCESS] IP address $IPAddress added to '$groupName' (direction: $Direction)." -ForegroundColor Green
        Write-FirewallLog -Message "Added blocked IP rule: $ruleName (IP $IPAddress)" -Level "INFO"
    }
    catch {
        Write-Host "[ERROR] Failed to add IP $IPAddress to '$groupName': $($_.Exception.Message)" -ForegroundColor Red
        Write-FirewallLog -Message "Failed to add blocked IP rule $ruleName : $($_.Exception.Message)" -Level "ERROR"
    }
}

function Update-FirewallRulesByProfile {
    $connectionProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue

    if ($null -eq $connectionProfiles) {
        Write-Warning "No active network connection profile found."
        return
    }

    if ($connectionProfiles.NetworkCategory -contains "Public") {
        $activeProfile = "Public"
    }
    elseif ($connectionProfiles.NetworkCategory -contains "Private") {
        $activeProfile = "Private"
    }
    else {
        $activeProfile = "Domain"
    }

    $allProfiles = @("Public", "Private", "Domain")

    foreach ($profileName in $allProfiles) {
        $groupName = "PowershellFirewall_$profileName"
        $rulesInGroup = Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue

        if ($null -ne $rulesInGroup) {
            if ($profileName -eq $activeProfile) {
                Set-NetFirewallRule -Group $groupName -Enabled "True"
                Write-Host "[ACTIVE] Rule set '$groupName' is now ENABLED." -ForegroundColor Green
            }
            else {
                Set-NetFirewallRule -Group $groupName -Enabled "False"
                Write-Host "[INACTIVE] Rule set '$groupName' is now DISABLED." -ForegroundColor Gray
            }
        }
    }
    Write-FirewallLog -Message "Updated firewall rule states according to active profile ($activeProfile)" -Level "INFO"
}

function Register-FirewallProfileTask {
    $taskName = "PF_AutoProfileSwitch"

    try {
        # Nasluch na EventID 10000 (Polaczono), 10001 (Rozlaczono) oraz 4004 (Zmiana kategorii sieci Public/Private/Domain)
        $cimTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
        $trigger = New-CimInstance -CimClass $cimTriggerClass -ClientOnly
        $trigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">
    <Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000 or EventID=10001 or EventID=10002)]]</Select>
  </Query>
</QueryList>
"@
        $trigger.Enabled = $true

        # Uruchomienie skryptu z flaga -AutoUpdateProfile (omija petle menu!)
        $actionArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -AutoUpdateProfile"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $actionArgs

        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Principal $principal -Force -ErrorAction Stop | Out-Null
        Write-Host "[SUCCESS] Automat przelaczania profili ($taskName) zostal wlaczony w Harmonogramie Zadan." -ForegroundColor Green
        Write-FirewallLog -Message "Registered Scheduled Task '$taskName' for automatic profile switching." -Level "INFO"
    }
    catch {
        Write-Host "[ERROR] Nie udalo sie zarejestrowac zadania: $($_.Exception.Message)" -ForegroundColor Red
        Write-FirewallLog -Message "Failed to register Scheduled Task '$taskName': $($_.Exception.Message)" -Level "ERROR"
    }
}

function Unregister-FirewallProfileTask {
    $taskName = "PF_AutoProfileSwitch"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "[CLEANUP] Automat przelaczania profili ($taskName) zostal wylaczony i usuniety." -ForegroundColor Yellow
        Write-FirewallLog -Message "Unregistered Scheduled Task '$taskName'." -Level "INFO"
    }
    else {
        Write-Warning "Zadanie '$taskName' nie jest obecnie zarejestrowane w systemie."
    }
}

function Import-RulesFromCsv {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path $CsvPath)) {
        Write-Warning "CSV file not found at path: $CsvPath"
        Write-FirewallLog -Message "CSV import failed. File not found: $CsvPath" -Level "WARN"
        return
    }

    $rulesList = Import-Csv -Path $CsvPath

    foreach ($item in $rulesList) {
        if ($item.Type -eq "Port") {
            Add-BlockedPort -Port ([int]$item.Target) -Protocol $item.Protocol -Direction $item.Direction -ProfileGroup $item.ProfileGroup
        }
        elseif ($item.Type -eq "IP") {
            Add-BlockedIP -IPAddress $item.Target -Direction $item.Direction -ProfileGroup $item.ProfileGroup
        }
    }

    Update-FirewallRulesByProfile
    Write-FirewallLog -Message "Successfully imported firewall rules from CSV file: $CsvPath" -Level "INFO"
}

function Remove-PFRules {
    param (
        [string]$RuleName,
        [switch]$All
    )

    if ($All) {
        $rules = Get-NetFirewallRule -Name "PF_*" -ErrorAction SilentlyContinue
        if ($null -ne $rules) {
            Remove-NetFirewallRule -Name "PF_*"
            Write-Host "[CLEANUP] All 'PF_*' firewall rules have been removed." -ForegroundColor Yellow
            Write-FirewallLog -Message "Removed all 'PF_*' firewall rules." -Level "WARN"
        }
        else {
            Write-Warning "No 'PF_*' rules found to remove."
        }
    }
    elseif ($RuleName) {
        $rule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
        if ($null -ne $rule) {
            Remove-NetFirewallRule -Name $RuleName
            Write-Host "[REMOVED] Firewall rule '$RuleName' has been removed." -ForegroundColor Yellow
            Write-FirewallLog -Message "Removed firewall rule: $RuleName" -Level "INFO"
        }
        else {
            Write-Warning "Firewall rule '$RuleName' does not exist."
        }
    }
}

function Invoke-FirewallBackup {
    [CmdletBinding(DefaultParameterSetName = 'Backup', SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName = 'Backup', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Output = (Get-Location).Path,

        [Parameter(ParameterSetName = 'Restore', Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Restore
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Error "Run this as Administrator."; return }

    if ($PSCmdlet.ParameterSetName -eq 'Restore') {
        $file = (Resolve-Path $Restore).Path
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Replace firewall policy with $file")) {
            Write-Verbose "Importing firewall policy from $file"
            netsh advfirewall import "$file" | Out-Null
            if ($LASTEXITCODE -eq 0) { 
                Write-Host "[SUCCESS] Zapora zostala pomyslnie przywrocona z pliku: $file" -ForegroundColor Green 
                Write-FirewallLog -Message "Restored firewall policy from file $file" -Level "INFO"
            }
            else { 
                Write-Error "Restore failed (netsh exit code $LASTEXITCODE)." 
                Write-FirewallLog -Message "Failed to restore policy from $file" -Level "ERROR"
            }
        }
    }
    else {
        if (-not (Test-Path $Output)) {
            Write-Verbose "Creating directory $Output"
            New-Item -ItemType Directory -Path $Output -Force | Out-Null
        }
        $dir  = (Resolve-Path $Output).Path
        $file = Join-Path $dir ("fw_backup_{0}.wfw" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Write-Verbose "Exporting firewall policy to $file"
        netsh advfirewall export "$file" | Out-Null
        if ($LASTEXITCODE -eq 0) { 
            Write-Host "[SUCCESS] Kopia zapasowa zapory zostala zapisana w: $file" -ForegroundColor Green 
            Write-FirewallLog -Message "Created firewall backup file $file" -Level "INFO"
        }
        else { 
            Write-Error "Backup failed (netsh exit code $LASTEXITCODE)." 
            Write-FirewallLog -Message "Failed to create backup at $Output" -Level "ERROR"
        }
    }
}

# ==========================================
# 2. FUNKCJE AUDYTU I BASELINE
# ==========================================

function Save-FirewallBaseline {
    param([string]$Path = $BaselinePath)
    
    $rules = Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Profile, Direction, Action, LocalPort, RemoteAddress
    $rules | ConvertTo-Json -Depth 4 | Set-Content -Path $Path
    
    Write-Host "[SUCCESS] Zapisano nowa migawke baseline w: $Path" -ForegroundColor Green
    Write-FirewallLog -Message "Saved new firewall baseline snapshot to $Path" -Level "INFO"
}

function Test-FirewallIntegrity {
    param([string]$Path = $BaselinePath)

    if (-not (Test-Path $Path)) {
        Write-Warning "Plik baseline nie istnieje. Utworz najpierw migawke wzorcowa."
        return
    }

    $baselineRules = Get-Content -Path $Path -Raw | ConvertFrom-Json
    $currentRules = Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Profile, Direction, Action, LocalPort, RemoteAddress

    $baselineDict = @{}
    foreach ($r in $baselineRules) { $baselineDict[$r.Name] = $r }

    $currentDict = @{}
    foreach ($r in $currentRules) { $currentDict[$r.Name] = $r }

    $added = @()
    $removed = @()
    $modified = @()

    foreach ($name in $currentDict.Keys) {
        if (-not $baselineDict.ContainsKey($name)) {
            $added += $currentDict[$name]
        } else {
            $b = $baselineDict[$name]
            $c = $currentDict[$name]
            if ($b.Enabled -ne $c.Enabled -or $b.Action -ne $c.Action) {
                $modified += [PSCustomObject]@{
                    Name      = $name
                    OldStatus = "Enabled=$($b.Enabled), Action=$($b.Action)"
                    NewStatus = "Enabled=$($c.Enabled), Action=$($c.Action)"
                }
            }
        }
    }

    foreach ($name in $baselineDict.Keys) {
        if (-not $currentDict.ContainsKey($name)) {
            $removed += $baselineDict[$name]
        }
    }

    if ($added.Count -eq 0 -and $removed.Count -eq 0 -and $modified.Count -eq 0) {
        Write-Host "[OK] Nie wykryto zadnych nieautoryzowanych zmian. Konfiguracja jest zgodna z baseline." -ForegroundColor Green
        Write-FirewallLog -Message "Integrity check passed. No changes detected." -Level "INFO"
    } else {
        Write-Host "[ALERT] WYKRYTO NIEAUTORYZOWANE ZMIANY W ZAPORZE" -ForegroundColor Red
        
        if ($added.Count -gt 0) {
            Write-Host "`n--- NOWE REGULY ($($added.Count)) ---" -ForegroundColor Yellow
            $added | Format-Table Name, DisplayName, Enabled, Direction -AutoSize
        }
        if ($removed.Count -gt 0) {
            Write-Host "`n--- USUNIETE REGULY ($($removed.Count)) ---" -ForegroundColor Red
            $removed | Format-Table Name, DisplayName, Enabled, Direction -AutoSize
        }
        if ($modified.Count -gt 0) {
            Write-Host "`n--- ZMODYFIKOWANE REGULY ($($modified.Count)) ---" -ForegroundColor Magenta
            $modified | Format-Table -AutoSize
        }

        Write-FirewallLog -Message "Integrity breach! Added: $($added.Count), Removed: $($removed.Count), Modified: $($modified.Count)" -Level "WARN"
    }
}

function Get-SuspiciousFirewallEvents {
    param([int]$Hours = 24)
    
    $startTime = (Get-Date).AddHours(-$Hours)
    Write-Host "Analizowanie Dziennika Zdarzen Windows z ostatnich $Hours godzin..." -ForegroundColor Cyan
    
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Security", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        Id        = 4946, 4947, 4948, 2004, 2005, 2006, 2099
        StartTime = $startTime
    } -ErrorAction SilentlyContinue

    if (-not $events) {
        Write-Host "Brak zdarzen modyfikacji zapory w Dzienniku Zdarzen w podanym okresie." -ForegroundColor Gray
        return
    }

    $results = foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $eventData = @{}
        foreach ($data in $xml.Event.EventData.Data) {
            if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
        }

        $ruleName = $eventData['RuleName']
        if (-not $ruleName) { $ruleName = $eventData['RuleId'] }
        if (-not $ruleName) { $ruleName = "N/A" }

        $user = $eventData['SubjectUserName']
        $userSid = $eventData['SubjectUserSid']
        if (-not $user) { $user = $evt.UserId }

        $isBuiltInSystemRule = ($ruleName -like "@FirewallAPI.dll*" -or 
                                $ruleName -like "@%SystemRoot%*" -or 
                                $ruleName -like "MSDTC*" -or 
                                $ruleName -like "CDPSvc*")

        $isSystemAccount = ($userSid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -or 
                            $user -like 'NT AUTHORITY*' -or 
                            $user -like '*$')

        $isScriptRule = ($ruleName -like "PF_*")

        if (-not $isBuiltInSystemRule) {
            $isSuspicious = (-not $isScriptRule) -and (-not $isSystemAccount)

            [PSCustomObject]@{
                TimeCreated = $evt.TimeCreated
                EventID     = $evt.Id
                User        = $user
                RuleName    = $ruleName
                Suspicious  = $isSuspicious
            }
        }
    }

    if ($results) {
        Write-Host "`n=== DETEKCJA ZMIAN W DZIENNIKU WINDOWS ===" -ForegroundColor Yellow
        $results | Format-Table TimeCreated, EventID, User, RuleName, Suspicious -AutoSize

        $suspiciousRules = $results | Where-Object { $_.Suspicious -eq $true }
        if ($suspiciousRules) {
            foreach ($sRule in $suspiciousRules) {
                Write-FirewallLog -Message "UNAUTHORIZED USER CHANGE DETECTED: Rule '$($sRule.RuleName)' by user '$($sRule.User)'" -Level "WARN"
            }
        }
    } else {
        Write-Host "Wszystkie zarejestrowane zdarzenia to automatyczne modyfikacje wbudowane Windows." -ForegroundColor Gray
    }
}

# ==========================================
# OBSLUGA AUTOMATYCZNEGO WYZWALACZA W TLE
# ==========================================
if ($AutoUpdateProfile) {
    Update-FirewallRulesByProfile
    exit
}

# ==========================================
# 3. HELPERY MENU
# ==========================================

function Read-Choice {
    param(
        [string]$Prompt,
        [string[]]$ValidOptions,
        [string]$DefaultOption
    )
    
    do {
        $inputVal = Read-Host "$Prompt [$($ValidOptions -join '/')]"
        if ([string]::IsNullOrWhiteSpace($inputVal)) {
            $inputVal = $DefaultOption
        }
        $match = $ValidOptions | Where-Object { $_ -eq $inputVal.Trim() }
    } until ($null -ne $match)
    
    return $match
}

# ==========================================
# 4. INTERAKTYWNA PETLA MENU
# ==========================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] Uruchom ten skrypt jako Administrator!" -ForegroundColor Red
    Exit
}

do {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "    ZARZADZANIE ZAPORA FIREWALL POWERSHELL  " -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host " 1. Utworz kopie zapasowa konfiguracji (Backup)"
    Write-Host " 2. Przywroc konfiguracje z pliku (Restore)"
    Write-Host " 3. Dodaj regule blokujaca port (Add-BlockedPort)"
    Write-Host " 4. Dodaj regule blokujaca IP (Add-BlockedIP)"
    Write-Host " 5. Importuj reguly z pliku CSV (Import-RulesFromCsv)"
    Write-Host " 6. Usun regule lub wyczysc reguly PF_* (Remove-PFRules)"
    Write-Host " 7. Przelacz reguly wg profilu / Konfiguruj Automat (Event Trigger)"
    Write-Host " 8. Wyswietl utworzone reguly PF_*"
    Write-Host " -------------------------------------------" -ForegroundColor DarkGray
    Write-Host " 9. Zapisz nowa migawke wzorcowa (Save Baseline)" -ForegroundColor Yellow
    Write-Host " 10. Wykryj nieautoryzowane zmiany (Test Integrity)" -ForegroundColor Yellow
    Write-Host " 11. Analizuj Dziennik Zdarzen Windows" -ForegroundColor Yellow
    Write-Host " 0. Wyjscie"
    Write-Host "=============================================" -ForegroundColor Cyan
    
    $choice = Read-Host "Wybierz opcje (0-11)"

    switch ($choice) {
        "1" {
            Write-Host "`n--- TWORZENIE KOPII ZAPASOWEJ ---" -ForegroundColor Yellow
            $outPath = Read-Host "Podaj sciezke zapisu [Domyslnie: biezacy katalog]"
            if ([string]::IsNullOrWhiteSpace($outPath)) {
                Invoke-FirewallBackup
            } else {
                Invoke-FirewallBackup -Output $outPath
            }
            Pause
        }
        "2" {
            Write-Host "`n--- PRZYWRACANIE KONFIGURACJI ---" -ForegroundColor Yellow
            $filePath = Read-Host "Podaj pelna sciezke do pliku .wfw"
            if (Test-Path $filePath -PathType Leaf) {
                Invoke-FirewallBackup -Restore $filePath
            } else {
                Write-Host "[ERROR] Podany plik nie istnieje." -ForegroundColor Red
            }
            Pause
        }
        "3" {
            Write-Host "`n--- DODAWANIE REGULY BLOKOWANIA PORTU ---" -ForegroundColor Yellow
            [int]$port = Read-Host "Podaj numer portu (np. 80, 443)"
            if ($port -gt 0) {
                $protocol = Read-Choice -Prompt "Protokol" -ValidOptions @("TCP", "UDP") -DefaultOption "TCP"
                $direction = Read-Choice -Prompt "Kierunek" -ValidOptions @("Inbound", "Outbound") -DefaultOption "Inbound"
                $profile = Read-Choice -Prompt "Profil" -ValidOptions @("Public", "Private", "Domain") -DefaultOption "Public"
                
                Add-BlockedPort -Port $port -Protocol $protocol -Direction $direction -ProfileGroup $profile
            } else {
                Write-Host "[ERROR] Niepoprawny numer portu." -ForegroundColor Red
            }
            Pause
        }
        "4" {
            Write-Host "`n--- DODAWANIE REGULY BLOKOWANIA ADRESU IP ---" -ForegroundColor Yellow
            $ip = Read-Host "Podaj adres IP lub podsiec (np. 192.168.1.50 lub 10.0.0.0/24)"
            if (-not [string]::IsNullOrWhiteSpace($ip)) {
                $direction = Read-Choice -Prompt "Kierunek" -ValidOptions @("Inbound", "Outbound") -DefaultOption "Inbound"
                $profile = Read-Choice -Prompt "Profil" -ValidOptions @("Public", "Private", "Domain") -DefaultOption "Public"
                
                Add-BlockedIP -IPAddress $ip -Direction $direction -ProfileGroup $profile
            } else {
                Write-Host "[ERROR] Adres IP nie moze byc pusty." -ForegroundColor Red
            }
            Pause
        }
        "5" {
            Write-Host "`n--- IMPORT REGUL Z PLIKU CSV ---" -ForegroundColor Yellow
            $csv = Read-Host "Podaj sciezke do pliku CSV"
            if (-not [string]::IsNullOrWhiteSpace($csv)) {
                Import-RulesFromCsv -CsvPath $csv
            } else {
                Write-Host "[ERROR] Sciezka nie moze byc pusta." -ForegroundColor Red
            }
            Pause
        }
        "6" {
            Write-Host "`n--- USUWANIE REGUL ZAPORY ---" -ForegroundColor Yellow
            Write-Host "1. Usun pojedyncza regule po nazwie"
            Write-Host "2. Wyczysc WSZYSTKIE reguly z prefiksem PF_*"
            $subChoice = Read-Host "Wybierz opcje (1-2)"
            
            if ($subChoice -eq "1") {
                $rName = Read-Host "Podaj dokladna nazwe reguly (Nazwa systemowa, np. PF_Public_BlockPort_TCP_80_Inbound)"
                if (-not [string]::IsNullOrWhiteSpace($rName)) {
                    Remove-PFRules -RuleName $rName
                }
            }
            elseif ($subChoice -eq "2") {
                $confirm = Read-Host "Czy na pewno chcesz usunac wszystkie reguly PF_*? [y/N]"
                if ($confirm -eq "y" -or $confirm -eq "Y") {
                    Remove-PFRules -All
                } else {
                    Write-Host "Anulowano czyszczenie regul." -ForegroundColor Gray
                }
            }
            Pause
        }
        "7" {
            Write-Host "`n--- ZARZADZANIE PROFILEM I AUTOMATYZACJA ---" -ForegroundColor Yellow
            Write-Host "1. Przelacz reguly teraz wg aktywnego profilu (Update-FirewallRulesByProfile)"
            Write-Host "2. WLACZ automatyczne przelaczanie w tle (Harmonogram Zadan - Event Trigger)"
            Write-Host "3. WYLACZ automatyczne przelaczanie w tle (Usun zadanie)"
            $profChoice = Read-Host "Wybierz opcje (1-3)"

            if ($profChoice -eq "1") {
                Update-FirewallRulesByProfile
            }
            elseif ($profChoice -eq "2") {
                Register-FirewallProfileTask
            }
            elseif ($profChoice -eq "3") {
                Unregister-FirewallProfileTask
            }
            Pause
        }
        "8" {
            Write-Host "`n--- LISTA REGUL FIREWALL (PF_*) ---" -ForegroundColor Yellow
            $rules = Get-NetFirewallRule -Name "PF_*" -ErrorAction SilentlyContinue
            if ($rules) {
                $rules | Select-Object Name, DisplayName, Group, Enabled, Direction, Action | Format-Table -AutoSize
            } else {
                Write-Host "Nie znaleziono zarejestrowanych regul z prefiksem PF_*." -ForegroundColor Gray
            }
            Pause
        }
        "9" {
            Write-Host "`n--- TWORZENIE MIGAWKI WZORCOWEJ (BASELINE) ---" -ForegroundColor Yellow
            Save-FirewallBaseline
            Pause
        }
        "10" {
            Write-Host "`n--- SPRAWDZANIE INTEGRALNOSCI REGUL ---" -ForegroundColor Yellow
            Test-FirewallIntegrity
            Pause
        }
        "11" {
            Write-Host "`n--- ANALIZA DZIENNIKA ZDARZEN WINDOWS ---" -ForegroundColor Yellow
            $hours = Read-Host "Z ilu ostatnich godzin wyswietlic zdarzenia? [Domyslnie: 24]"
            if ([string]::IsNullOrWhiteSpace($hours)) { $hours = 24 }
            Get-SuspiciousFirewallEvents -Hours ([int]$hours)
            Pause
        }
        "0" {
            Write-Host "`nZamykanie..." -ForegroundColor Gray
        }
        default {
            Write-Host "`nNieprawidlowy wybor, sprobuj ponownie." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} until ($choice -eq "0")