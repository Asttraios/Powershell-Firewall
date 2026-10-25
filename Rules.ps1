#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Modul zarzadzania regulami zapory Windows (Podpunkty A oraz B).
.DESCRIPTION
    Skrypt odpowiada za dodawanie i usuwanie regul blokujacych porty oraz adresy IP,
    importowanie zestawow regul z pliku CSV oraz kontekstowe przelaczanie grup regul
    w zaleznosci od aktywnego profilu sieciowego (Public, Private, Domain).
    
    Wykorzystane cmdlety z modulu NetSecurity / NetConnection:
    - New-NetFirewallRule
    - Get-NetFirewallRule
    - Set-NetFirewallRule
    - Remove-NetFirewallRule
    - Get-NetConnectionProfile
#>

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

    # 1. Automatyczne generowanie nazwy z prefiksem PF_ oraz nazwa zestawu
    $groupName = "PowershellFirewall_$ProfileGroup"
    $ruleName = "PF_${ProfileGroup}_BlockPort_${Protocol}_${Port}_${Direction}"
    $displayName = "PF [$ProfileGroup] Blocking Port $Port ($Protocol - $Direction)"

    # 2. Sprawdzenie, czy regula juz istnieje w systemie
    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRule) {
        Write-Warning "Firewall Rule '$ruleName' already exists!"
        return
    }

    # 3. Utworzenie reguly firewalla przypisanej do odpowiedniej grupy
    New-NetFirewallRule -Name $ruleName `
                        -DisplayName $displayName `
                        -Group $groupName `
                        -Direction $Direction `
                        -Action Block `
                        -Protocol $Protocol `
                        -LocalPort $Port `
                        -Profile Any `
                        -Enabled False | Out-Null

    Write-Host "[SUCCESS] Port $Port added to '$groupName' ($Protocol, direction: $Direction)." -ForegroundColor Green
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

    # 1. Automatyczne generowanie nazwy z prefiksem PF_ oraz nazwa zestawu
    $groupName = "PowershellFirewall_$ProfileGroup"
    $safeIPName = $IPAddress -replace '/', '_'
    $ruleName = "PF_${ProfileGroup}_BlockIP_${safeIPName}_${Direction}"
    $displayName = "PF [$ProfileGroup] Blocking IP $IPAddress ($Direction)"

    # 2. Sprawdzenie, czy regula juz istnieje w systemie
    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRule) {
        Write-Warning "Firewall Rule '$ruleName' already exists!"
        return
    }

    # 3. Utworzenie reguly firewalla przypisanej do odpowiedniej grupy
    New-NetFirewallRule -Name $ruleName `
                        -DisplayName $displayName `
                        -Group $groupName `
                        -Direction $Direction `
                        -Action Block `
                        -RemoteAddress $IPAddress `
                        -Profile Any `
                        -Enabled False | Out-Null

    Write-Host "[SUCCESS] IP address $IPAddress added to '$groupName' (direction:$Direction)." -ForegroundColor Green
}

function Update-FirewallRulesByProfile {
    # 1. Pobranie aktualnego profilu polaczenia sieciowego
    $connectionProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue

    if ($null -eq $connectionProfiles) {
        Write-Warning "No active network connection profile found!"
        return
    }

    # 2. Ustalenie docelowego zestawu na podstawie kategorii sieci (priorytet dla najbardziej restrykcyjnej)
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

    # 3. Przelaczanie grup regul (wlaczenie aktywnej grupy, wylaczenie pozostalych)
    foreach ($profileName in $allProfiles) {
        $groupName = "PowershellFirewall_$profileName"
        $rulesInGroup = Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue

        if ($null -ne $rulesInGroup) {
            if ($profileName -eq $activeProfile) {
                Set-NetFirewallRule -Group $groupName -Enabled True
                Write-Host "[ACTIVE] Rule set '$groupName' is now ENABLED." -ForegroundColor Green
            }
            else {
                Set-NetFirewallRule -Group $groupName -Enabled False
                Write-Host "[INACTIVE] Rule set '$groupName' is now DISABLED." -ForegroundColor Gray
            }
        }
    }
}

function Import-RulesFromCsv {
    <#
    .SYNOPSIS
        Wczytuje i tworzy reguly zapory masowo z pliku CSV, a nastepnie aktywuje odpowiedni profil.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path $CsvPath)) {
        Write-Warning "CSV file not found at path: $CsvPath"
        return
    }

    $rulesList = Import-Csv -Path $CsvPath

    foreach ($item in $rulesList) {
        if ($item.Type -eq "Port") {
            Add-BlockedPort -Port ([int]$item.Target) `
                            -Protocol $item.Protocol `
                            -Direction $item.Direction `
                            -ProfileGroup $item.ProfileGroup
        }
        elseif ($item.Type -eq "IP") {
            Add-BlockedIP -IPAddress $item.Target `
                          -Direction $item.Direction `
                          -ProfileGroup $item.ProfileGroup
        }
    }

    # Automatyczne przelaczenie stanu regul po zaimportowaniu
    Update-FirewallRulesByProfile
}

function Remove-PFRules {
    <#
    .SYNOPSIS
        Usuwa pojedyncza regule po nazwie lub czysci wszystkie reguly stworzone przez projekt.
    #>
    param (
        [string]$RuleName,
        [switch]$All
    )

    if ($All) {
        $rules = Get-NetFirewallRule -Name "PF_*" -ErrorAction SilentlyContinue
        if ($null -ne $rules) {
            Remove-NetFirewallRule -Name "PF_*"
            Write-Host "[CLEANUP] All 'PF_*' firewall rules have been removed." -ForegroundColor Yellow
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
        }
        else {
            Write-Warning "Firewall rule '$RuleName' does not exist!"
        }
    }
}

# Przydatne komendy
# =========================================================================
# Wszystkie reguly projektu na raz: Get-NetFirewallRule -Name "PF_*"
# Reguly sieci Private:             Get-NetFirewallRule -Group "PowershellFirewall_Private"
# Reguly sieci Public:              Get-NetFirewallRule -Group "PowershellFirewall_Public"
# Reguly sieci Domain:              Get-NetFirewallRule -Group "PowershellFirewall_Domain"
# Import z pliku CSV:               Import-RulesFromCsv -CsvPath ".\rules_config.csv"
# Usuniecie wszystkich naszych regul: Remove-PFRules -All
