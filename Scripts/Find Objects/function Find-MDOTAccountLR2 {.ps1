<#
.SYNOPSIS
    Find-MDOTAccount is valid' for finding MDOT accounts by name or username.
.PARAMETER ByName
    Use this switch to search by first and last name.
.PARAMETER ByUser
    Use this switch to search by username.                  
.DESCRIPTION
    This function searches for MDOT accounts in Active Directory.
.NOTES
    This function is not supported in Linux.
.LINK
    https://example.com/Find-MDOTAccount
.EXAMPLE
    Find-MDOTAccount -ByName "John" "Doe"
    This command searches for MDOT accounts with the first name "John" and last name "Doe". 
#>

function Find-MDOTAccountLR2 {
    [CmdletBinding()]
    param (
        [switch]$ByName,
        [switch]$ByUser,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    if ($ByName) {
        if ($Args.Count -lt 2) {
            Write-Host "Usage: Find-MDOTAccount -ByName FirstName LastName"
            return
        }
        $firstname = $Args[0].Trim()
        $lastname = $Args[1].Trim()
        $LDAP = "(&(givenname=$firstname*)(sn=$lastname*))"
    }
    elseif ($ByUser) {
        if ($Args.Count -lt 1) {
            Write-Host "Usage: Find-MDOTAccount -ByUser UserName"
            return
        }
        $user = $Args[0].Trim()
        $LDAP = "(samaccountname=$user*)"
    }
    else {
        Write-Host "You must specify either -ByName or -ByUser"
        return
    }

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

    $result = $DC | ForEach-Object {
        Get-ADUser -LDAPFilter $LDAP -Server $_ -Properties Department, Office, Description |
            Sort-Object SamAccountName |
            Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description
        }

        # Display the count
        $count = $result.Count
        Write-Host "`nNumber of results found: $count`n" -ForegroundColor Yellow

        $result | Format-Table -AutoSize
    }
