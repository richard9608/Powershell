# Find-MDOTAccount.ps1
# This script searches for MDOT accounts based on either first/last name or username.   
#without username logic 

function Find-MDOTAccount {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        # Parameter set for searching by first/last name
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [string]$FirstName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [string]$LastName,

        # Parameter set for searching by username
        [Parameter(Mandatory = $true, ParameterSetName = 'ByUser')]
        [string]$User
    )

    # List of domain controllers
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

    # Choose LDAP filter based on which parameter set was used
    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        $LDAP = "(&(givenname=$FirstName*)(sn=$LastName*))"
    } elseif ($PSCmdlet.ParameterSetName -eq 'ByUser') {
        $LDAP = "(samaccountname=$User*)"
    }

    # Search all DCs and collect results
    $result = $DC | ForEach-Object {
        Get-ADUser -LDAPFilter $LDAP -Server $_ -Properties Department, Office, Description |
            Sort-Object SamAccountName |
            Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description
    }
    $result | Format-Table -AutoSize
}


