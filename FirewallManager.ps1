#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Zaawansowany menedzer Zapory Windows z obsluga profilowania sieci, kopii zapasowych, audytu integralnosci oraz automatyzacji zdarzeniowej.

.DESCRIPTION
    Skrypt PowerShell 'FirewallManager.ps1' zapewnia kompleksowe srodowisko do zarzadzania zapora sieciowa w systemie Windows.
    
    Glowne funkcjonalnosci obejmuja:
    - Dodawanie i usuwanie dedykowanych regul blokujacych porty (TCP/UDP) oraz adresy IP/podsieci (oznaczonych prefiksem 'PF_*').
    - Masowy import definicji regul z plikow CSV.
    - Kontekstowe wlaczanie/wylaczanie grup regul w zaleznosci od aktywnego profilu polaczenia (Public, Private, Domain).
    - Automatyzacje przelaczania profili w tle za pomoca Harmonogramu Zadan.
    - Eksport i przywracanie pelnej polisy Zapory do/z plikow .wfw za pomoca netsh.
    - Tworzenie migawki wzorcowej i weryfikacje integralnosci pod katem nieautoryzowanych zmian.
    - Analize Dziennika Zdarzen Windows pod katem zmian regul wykonanych poza skryptem.
    - Rejestracje wszystkich operacji w pliku 'firewall_audit.log'.

.PARAMETER AutoUpdateProfile
    Przelacznik uzywany przez wyzwalacz zdarzen w Harmonogramie Zadan Windows. Uruchamia wylacznie funkcje aktualizacji regul wedlug aktywnej sieci w tle i natychmiast konczy dzialanie skryptu bez wyswietlania menu interaktywnego.

.PARAMETER ShowHelp
    Wyswietla szczegolowa dokumentacje i pomoc dla skryptu, a nastepnie konczy jego dzialanie. Obsluguje aliasy: -h oraz -help.

.EXAMPLE
    .\FirewallManager.ps1
    Uruchamia skrypt w interaktywnym trybie menu konsolowego (wymagane uprawnienia Administratora).

.EXAMPLE
    .\FirewallManager.ps1 -AutoUpdateProfile
    Wykonuje cicha aktualizacje stanu regul na podstawie aktualnie polaczonej sieci i konczy dzialanie.

.EXAMPLE
    .\FirewallManager.ps1 -h
    Wyswietla opis skryptu, dostepne parametry oraz przyklady uzycia.

.NOTES
    Wymagania: Windows PowerShell 5.1 / PowerShell 7+ uruchomiony z uprawnieniami Administratora.
#>

param (
    # Przelacznik uzywany przez Harmonogram Zadan Windows do aktualizacji w tle
    [switch]$AutoUpdateProfile,

    # Przelacznik wyswietlajacy pomoc (-h, --help, -help)
    [Alias('h', 'help')]
    [switch]$ShowHelp
)

# Jezeli uzytkownik wywolal skrypt z parametrem pomocy, wyswietl pomoc i zakoncz dzialanie
if ($ShowHelp) {
    Get-Help $PSCommandPath -Detailed
    exit
}

# ==========================================
# KONFIGURACJA LOGOWANIA I BASELINE
# ==========================================
$ScriptPath = If ($PSCommandPath) { $PSCommandPath } Else { Join-Path (Get-Location).Path "FirewallManager.ps1" }
$ScriptDir = Split-Path -Path $ScriptPath -Parent
$LogPath = Join-Path $ScriptDir "firewall_audit.log"
$BaselinePath = Join-Path $ScriptDir "firewall_baseline.json"
$BackupDir = Join-Path $ScriptDir "FWbackup"

function Write-FirewallLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $rawUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $user = if ($rawUser -match '\\') { $rawUser.Split('\')[-1] } else { $rawUser }
    if ([string]::IsNullOrWhiteSpace($user)) { $user = $env:USERNAME }

    $paddedLevel = $Level.PadRight(5)

    $logEntry = "$timestamp | $paddedLevel | $user | $Message"
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

# ==========================================
# 1. FUNKCJE ZARZADZANIA REGULAMI
# ==========================================

function Add-BlockedRule {
    <#
    .SYNOPSIS
        Tworzy regule blokujaca port, adres IP lub kombinacje obu parametrow.
    #>
    param (
        [Parameter(Mandatory = $false)]
        [int]$Port = 0,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?)?$')]
        [string]$IPAddress = "",

        [ValidateSet("TCP", "UDP")]
        [string]$Protocol = "TCP",

        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction = "Inbound",

        [ValidateSet("Public", "Private", "Domain")]
        [string]$ProfileGroup = "Public"
    )

    $hasPort = ($Port -gt 0 -and $Port -le 65535)
    $hasIP   = (-not [string]::IsNullOrWhiteSpace($IPAddress))

    # 1. Walidacja: uzytkownik musi podac przynajmniej Port lub IP
    if (-not $hasPort -and -not $hasIP) {
        Write-Warning "You must specify at least a Port (-Port) or an IP Address (-IPAddress)!"
        return
    }

    $groupName = "PowershellFirewall_$ProfileGroup"
    $safeIPName = $IPAddress -replace '/', '_'

    # 2. Dynamiczne generowanie nazwy reguly oraz opisu (3 scenariusze)
    if ($hasPort -and $hasIP) {
        $ruleName    = "PF_${ProfileGroup}_Block_${Protocol}_${Port}_IP_${safeIPName}_${Direction}"
        $displayName = "PF [$ProfileGroup] Blocking Port $Port ($Protocol) & IP $IPAddress ($Direction)"
        $targetDesc  = "Port $Port ($Protocol) and IP $IPAddress"
    }
    elseif ($hasPort) {
        $ruleName    = "PF_${ProfileGroup}_BlockPort_${Protocol}_${Port}_${Direction}"
        $displayName = "PF [$ProfileGroup] Blocking Port $Port ($Protocol - $Direction)"
        $targetDesc  = "Port $Port ($Protocol)"
    }
    else {
        $ruleName    = "PF_${ProfileGroup}_BlockIP_${safeIPName}_${Direction}"
        $displayName = "PF [$ProfileGroup] Blocking IP $IPAddress ($Direction)"
        $targetDesc  = "IP address $IPAddress"
    }

    # 3. Sprawdzenie, czy regula juz istnieje w systemie
    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRule) {
        Write-Warning "Firewall Rule '$ruleName' already exists!"
        return
    }

    # 4. Bazowe parametry reguly
    $ruleParams = @{
        Name        = $ruleName
        DisplayName = $displayName
        Group       = $groupName
        Direction   = $Direction
        Action      = "Block"
        Profile     = "Any"
        Enabled     = "False"
        ErrorAction = "Stop"
    }

    # Dolaczanie parametrow specyficznych dla Portu i/lub IP
    if ($hasPort) {
        $ruleParams["Protocol"]  = $Protocol
        $ruleParams["LocalPort"] = $Port
    }
    if ($hasIP) {
        $ruleParams["RemoteAddress"] = $IPAddress
    }

    # 5. Utworzenie reguly w zaporze i zapis do logow
    try {
        New-NetFirewallRule @ruleParams | Out-Null
        Write-Host "[SUCCESS] Blocked $targetDesc in '$groupName' (direction: $Direction)." -ForegroundColor Green
        Write-FirewallLog -Message "Added block rule: $ruleName ($targetDesc, $Direction)" -Level "INFO"
    }
    catch {
        Write-Host "[ERROR] Failed to add rule for $targetDesc to '$groupName': $($_.Exception.Message)" -ForegroundColor Red
        Write-FirewallLog -Message "Failed to add block rule $ruleName : $($_.Exception.Message)" -Level "ERROR"
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

        # Uruchomienie skryptu z flaga -AutoUpdateProfile
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
        # Obsluga nowego formatu CSV (kolumny: Port, IPAddress, Protocol, Direction, ProfileGroup)
        if ($item.PSObject.Properties.Name -contains "Port" -or $item.PSObject.Properties.Name -contains "IPAddress") {
            $portVal = if ([string]::IsNullOrWhiteSpace($item.Port)) { 0 } else { [int]$item.Port }
            $protVal = if ([string]::IsNullOrWhiteSpace($item.Protocol) -or $item.Protocol -eq "Any") { "TCP" } else { $item.Protocol }
            
            Add-BlockedRule -Port $portVal -IPAddress $item.IPAddress -Protocol $protVal -Direction $item.Direction -ProfileGroup $item.ProfileGroup
        }
        # Kompatybilnosc wsteczna ze starym formatem CSV (kolumny: Type, Target...)
        elseif ($item.Type -eq "Port") {
            Add-BlockedRule -Port ([int]$item.Target) -Protocol $item.Protocol -Direction $item.Direction -ProfileGroup $item.ProfileGroup
        }
        elseif ($item.Type -eq "IP") {
            Add-BlockedRule -IPAddress $item.Target -Direction $item.Direction -ProfileGroup $item.ProfileGroup
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
        [string]$Output = $BackupDir,

        [Parameter(ParameterSetName = 'Restore', Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Restore
    )

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

    $eventList = foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $eventData = @{}
        foreach ($data in $xml.Event.EventData.Data) {
            if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
        }

        $ruleName = $eventData['RuleName']
        if (-not $ruleName) { $ruleName = $eventData['RuleId'] }
        if ([string]::IsNullOrWhiteSpace($ruleName) -or $ruleName -eq "-") { continue }

        $isBuiltInSystemRule = ($ruleName -like "@*" -or 
                                $ruleName -like "{*" -or 
                                $ruleName -like "*Defender*" -or 
                                $ruleName -like "*WinDefend*" -or 
                                $ruleName -like "*Microsoft Edge*" -or 
                                $ruleName -like "*Microsoft Store*" -or
                                $ruleName -like "*Microsoft Teams*" -or
                                $ruleName -like "*Windows Web Experience Pack*" -or
                                $ruleName -like "*Microsoft 365*" -or
                                $ruleName -like "*Games*" -or
                                $ruleName -like "*Xbox*" -or
                                $ruleName -like "*Widgets*" -or
                                $ruleName -like "*ProductPkgDisplayName*" -or
                                $ruleName -like "*Font Driver Host*" -or 
                                $ruleName -like "*mDNS*" -or 
                                $ruleName -like "MSDTC*" -or 
                                $ruleName -like "CDPSvc*" -or 
                                $ruleName -like "WCN*" -or 
                                $ruleName -like "CoreNet*" -or 
                                $ruleName -match '^[0-9a-fA-F]{8}-' -or 
                                $ruleName -match '^\d+$')

        if ($isBuiltInSystemRule) { continue }

        $user = $eventData['SubjectUserName']
        $domain = $eventData['SubjectDomainName']
        $userSid = $eventData['SubjectUserSid']

        if ($user -and $domain -and $user -ne "-") {
            $user = "$domain\$user"
        } elseif (-not $user -or $user -eq "-") {
            if ($evt.UserId) {
                try {
                    $user = ([System.Security.Principal.SecurityIdentifier]$evt.UserId).Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $user = $evt.UserId.Value
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($user) -or $user -eq "-") {
            $user = "SYSTEM / Automatyczne"
        }

        $isSystemAccount = ($userSid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -and $user -eq "SYSTEM / Automatyczne")
        if ($isSystemAccount) { continue }

        $isScriptRule = ($ruleName -like "PF_*" -or $ruleName -like "PF [*]" -or $ruleName -like "PF[*]")
        $source = if ($isScriptRule) { "Skrypt (PF)" } else { "GUI / Manualna" }

        $action = switch ($evt.Id) {
            4946 { "Dodano regule" }
            2004 { "Dodano regule" }
            4947 { "Zmodyfikowano regule" }
            2005 { "Zmodyfikowano regule" }
            4948 { "Usunieto regule" }
            2006 { "Usunieto regule" }
            2099 { "Zmiana stanu zapory" }
            default { "Modyfikacja ($($evt.Id))" }
        }

        [PSCustomObject]@{
            TimeCreated = $evt.TimeCreated
            Action      = $action
            Zrodlo      = $source
            User        = $user
            RuleName    = $ruleName
            IsManual    = (-not $isScriptRule)
            EventID     = $evt.Id
        }
    }

    if ($eventList) {
        Write-Host "`n=== HISTORIA ZMIAN W ZAPORZE ===" -ForegroundColor Yellow
        $eventList | Format-Table TimeCreated, Action, Zrodlo, User, RuleName -AutoSize

        $manualChanges = $eventList | Where-Object { $_.IsManual -eq $true }
        if ($manualChanges) {
            foreach ($mRule in $manualChanges) {
                Write-FirewallLog -Message "MANUAL/GUI CHANGE: $($mRule.Action) '$($mRule.RuleName)' (User: $($mRule.User))" -Level "WARN"
            }
        }
    } else {
        Write-Host "`n[OK] Brak akcji skryptu ani zmian uzytkownika w tym okresie." -ForegroundColor Green
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
# 4. PETLA MENU
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
    Write-Host " 1. Utworz kopie zapasowa konfiguracji"
    Write-Host " 2. Przywroc konfiguracje z pliku"
    Write-Host " 3. Dodaj regule blokujaca port/IP/port + IP"
    Write-Host " 4. Importuj reguly z pliku CSV"
    Write-Host " 5. Usun regule lub wyczysc reguly PF_*"
    Write-Host " 6. Przelacz reguly wg profilu / Konfiguruj Automat"
    Write-Host " 7. Wyswietl utworzone reguly PF_*"
    Write-Host " -------------------------------------------" -ForegroundColor DarkGray
    Write-Host " 8. Zapisz nowa migawke wzorcowa" -ForegroundColor Yellow
    Write-Host " 9. Wykryj nieautoryzowane zmiany" -ForegroundColor Yellow
    Write-Host " 10. Analizuj Dziennik Zdarzen Windows" -ForegroundColor Yellow
    Write-Host " 0. Wyjscie"
    Write-Host "=============================================" -ForegroundColor Cyan
    
    $choice = Read-Host "Wybierz opcje (0-10)"

    switch ($choice) {
        "1" {
            Write-Host "`n--- TWORZENIE KOPII ZAPASOWEJ ---" -ForegroundColor Yellow
            $outPath = Read-Host "Podaj sciezke zapisu [Domyslnie: $BackupDir]"
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
            Write-Host "`n--- DODAWANIE REGULY BLOKUJACEJ (PORT / IP / OBA) ---" -ForegroundColor Yellow
            $portInput = Read-Host "Podaj numer portu (np. 80, 443) [Wcisnij Enter, aby pominac]"
            $ipInput   = Read-Host "Podaj adres IP lub podsiec (np. 10.0.0.0/24) [Wcisnij Enter, aby pominac]"

            $portVal = if ([string]::IsNullOrWhiteSpace($portInput)) { 0 } else { [int]$portInput }
            
            if ($portVal -gt 0 -or (-not [string]::IsNullOrWhiteSpace($ipInput))) {
                $protocol = "TCP"
                if ($portVal -gt 0) {
                    $protocol = Read-Choice -Prompt "Protokol" -ValidOptions @("TCP", "UDP") -DefaultOption "TCP"
                }
                $direction = Read-Choice -Prompt "Kierunek" -ValidOptions @("Inbound", "Outbound") -DefaultOption "Inbound"
                $profile   = Read-Choice -Prompt "Profil" -ValidOptions @("Public", "Private", "Domain") -DefaultOption "Public"

                Add-BlockedRule -Port $portVal -IPAddress $ipInput -Protocol $protocol -Direction $direction -ProfileGroup $profile
            } else {
                Write-Host "[ERROR] Musisz podac przynajmniej numer portu lub adres IP." -ForegroundColor Red
            }
            Pause
        }
        "4" {
            Write-Host "`n--- IMPORT REGUL Z PLIKU CSV ---" -ForegroundColor Yellow
            $csv = Read-Host "Podaj sciezke do pliku CSV"
            if (-not [string]::IsNullOrWhiteSpace($csv)) {
                Import-RulesFromCsv -CsvPath $csv
            } else {
                Write-Host "[ERROR] Sciezka nie moze byc pusta." -ForegroundColor Red
            }
            Pause
        }
        "5" {
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
        "6" {
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
        "7" {
            Write-Host "`n--- LISTA REGUL FIREWALL (PF_*) ---" -ForegroundColor Yellow
            $rules = Get-NetFirewallRule -Name "PF_*" -ErrorAction SilentlyContinue
            if ($rules) {
                $rules | Select-Object Name, DisplayName, Group, Enabled, Direction, Action | Format-Table -AutoSize
            } else {
                Write-Host "Nie znaleziono zarejestrowanych regul z prefiksem PF_*." -ForegroundColor Gray
            }
            Pause
        }
        "8" {
            Write-Host "`n--- TWORZENIE MIGAWKI WZORCOWEJ (BASELINE) ---" -ForegroundColor Yellow
            Save-FirewallBaseline
            Pause
        }
        "9" {
            Write-Host "`n--- SPRAWDZANIE INTEGRALNOSCI REGUL ---" -ForegroundColor Yellow
            Test-FirewallIntegrity
            Pause
        }
        "10" {
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