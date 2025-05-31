function Find-ADUserByFullName {
    param (
        [string[]]$FullNames
    )

    $DomainControllers = @(
        "mdotgbfrdc1.ad.mdot.mdstate",
        "MAABWIDC1.maa.ad.mdot.mdstate",
        "TSOGBDC1.mdothq.ad.mdot.mdstate",
        "MDTAICCDC01.mdta.ad.mdot.mdstate",
        "MPADMTENTDC01.mpa.ad.mdot.mdstate",
        "MTACWDRDC1.mtant1.ad.mdot.mdstate",
        "MVAWSDC1.mvant1.ad.mdot.mdstate",
        "SHAGBDC1.shacadd.ad.mdot.mdstate"
    )

    foreach ($fullname in $FullNames) {
        # Parse into First and Last Name
        $parts = $fullname -split '\s+', 2
        if ($parts.Count -eq 2) {
            $first = $parts[0]
            $last = $parts[1]
        }
        else {
            Write-Warning "⚠️ Could not parse name: '$fullname'"
            continue
        }

        $found = $false

        foreach ($dc in $DomainControllers) {
            try {
                $result = Get-ADUser -LDAPFilter "(&(givenName=$first*)(sn=$last*))" -Server $dc -Properties SamAccountName, EmailAddress, Department, Office |
                    Select-Object SamAccountName, GivenName, Surname, EmailAddress, Department, Office

                if ($result) {
                    Write-Host "✅ Match for '$fullname' on ${dc}:"
                    $result | Format-Table -AutoSize
                    $found = $true
                    break
                }
            }
            catch {
                Write-Warning "❌ Error querying DC '$dc': $_"
            }
        }

        if (-not $found) {
            Write-Warning "⚠️ No match found for '$fullname' on any DC"
        }
    }
}


# Example usage:
# You can replace the names in the array with the ones you want to search for
$names = @(
    "Keith Thomas",
    "Carol Diserio",
    "Nicholas Zito",
    "Nickos Routzounis",
    "Terence Wright",
    "Christopher Saunders",
    "Scott Heaps",
    "John Goudy",
    "Scott Simons"
)

$names.Count 

# This will search for the users in the specified domain controllers
# and display their details if found.
Find-ADUserByFullName -FullNames $names
