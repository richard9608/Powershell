function GetUser_Info2 {
    param (
        [string]$Username
    )

    if (-not $Username) {
        $Username = Read-Host "Please enter the username to query"
    }

    $Username = $Username.Trim().ToLower()

    try {
        $user = Get-ADUser -Identity $Username -Properties *
    }
    catch {
        Write-Host "User '$Username' not found. Please check the username and try again." -ForegroundColor Red
        return
    }

    $targetAddressCleaned = $user.targetAddress -replace '(?i)smtp:'

    $user | Format-List Name,
    HomeDirectory,
    @{Label = 'targetAddress'; Expression = { $targetAddressCleaned } },
    ExtensionAttribute1,
    PrimaryGroup

    if ($user.proxyAddresses) {
        $emailList = ($user.proxyAddresses | Sort-Object) -replace '(?i)smtp:'
        Write-Host "`nEmail Addresses:" -ForegroundColor Cyan
        $emailList | ForEach-Object { Write-Host $_ }
    }

    if ($user.MemberOf) {
        Write-Host "`nMemberOf:" -ForegroundColor Cyan
        $user.MemberOf | Sort-Object | ForEach-Object {
            $_.Split(',')[0] | Write-Host
        }
    }
}

function FindAccount3 {
    param(
        [string]$firstname,
        [string]$lastname
    )

    $DC = @(
        "mdotgbfrdc1.ad.mdot.mdstate",
        "MAABWIDC1.maa.ad.mdot.mdstate",
        "TSOGBDC1.mdothq.ad.mdot.mdstate",
        "MDTAICCDC01.mdta.ad.mdot.mdstate",
        "MPADMTENTDC01.mpa.ad.mdot.mdstate",
        "MTACWDRDC1.mtant1.ad.mdot.mdstate",
        "MVAWSDC1.mvant1.ad.mdot.mdstate",
        "SHAGBDC1.shacadd.ad.mdot.mdstate"
    )

    $results = foreach ($server in $DC) {
        Get-ADUser -LDAPFilter "(&(givenname=$firstname*)(sn=$lastname*))" -Server $server -Properties Department |
            Select-Object Name, SamAccountName, Department
    }

    $results | Sort-Object SamAccountName | Format-Table -AutoSize
}

# ===== AUTO EXECUTION BLOCK =====
# You can call either function manually OR uncomment below to run something on load

# Example: Uncomment to auto run user info prompt
# GetUser_Info2

# Example: Uncomment to auto search by name
# FindAccount3 -firstname 'John' -lastname 'Doe'
