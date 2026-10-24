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

#Wszystkie reguly na raz: Get-NetFirewallRule -Name "PF_*"
#reguly sieci private: Get-NetFirewallRule -Group "PowershellFirewall_Private"
#reguly sieci public: Get-NetFirewallRule -Group "PowershellFirewall_Public"
#reguly sieci domain: Get-NetFirewallRule -Group "PowershellFirewall_Domain"