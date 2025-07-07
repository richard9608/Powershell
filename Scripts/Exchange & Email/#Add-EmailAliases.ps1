#Add-EmailAliases.ps1
# This script adds email aliases to an Active Directory user.   
# It checks for existing aliases and only adds those that are not already present.
# Requires the ActiveDirectory module to be installed and imported.
# Usage: Add-EmailAliases -User 'username' -Aliases @('alias1', 'alias2', ...)
# Requires PowerShell 5.1 or later
# Ensure the ActiveDirectory module is available
# Ensure you have the necessary permissions to modify user attributes in Active Directory
# Requires the ActiveDirectory module
# Example usage:
# Import-Module ActiveDirectory
# $aliases = @(
#     'KSpiker@sha.maryland.gov',
#     'KSpiker.consultant@mdot.maryland.gov',
#     'KSpiker@mdot.maryland.gov',
#     'KSpiker@mdot.state.md.us',
#     'KSpiker@sha.state.md.us'
# )
# Add-EmailAliases -User 'jdoe' -Aliases $aliases



Import-Module ActiveDirectory

function Add-EmailAliases {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $User,

        [Parameter(Mandatory)]
        [string[]] $Aliases
    )

    # Get existing proxyAddresses (lower-case for comparison)
    $current = @((Get-ADUser -Identity $User -Properties proxyAddresses).proxyAddresses) |
               ForEach-Object { $_ }

    # Build list of smtp: entries that don’t already exist
    $newValues = $Aliases | ForEach-Object {
        $entry = "smtp:$($_)"
        if ($entry -notin $current) { $entry }
    }

    if ($newValues) {
        # -Add will append, not replace
        Set-ADUser -Identity $User -Add @{ proxyAddresses = $newValues }
        Write-Host "Added $($newValues.Count) new alias(es) to $User."
    }
    else {
        Write-Host "No new aliases to add for $User."
    }
}


# Example usage:
# $aliases = @(
#     'KSpiker@sha.maryland.gov',
#     'KSpiker.consultant@mdot.maryland.gov',
#     'KSpiker@mdot.maryland.gov',
#     'KSpiker@mdot.state.md.us',
#     'KSpiker@sha.state.md.us'
# )
# Add-EmailAliases -User 'jdoe' -Aliases $aliases
# Example usage:
# $aliases = @(
#     'KSpiker@sha.maryland.gov',
#     'KSpiker.consultant@mdot.maryland.gov',
#     'KSpiker@mdot.maryland.gov',
#     'KSpiker@mdot.state.md.us',
#     'KSpiker@sha.state.md.us'
# )
# Add-EmailAliases -User 'jdoe' -Aliases $aliases                   










 Set-ADUser KMyers4 -Replace `
    @{ proxyAddresses = @(
        'smtp:KMyers4@sha.maryland.gov',
        'smtp:KMyers4.consultant@mdot.maryland.gov',
        'smtp:KMyers4@mdot.maryland.gov',
        'smtp:KMyers4@mdot.state.md.us',
        'smtp:KMyers4@sha.state.md.us'
    )
    }   