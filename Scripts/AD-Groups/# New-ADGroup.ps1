# New-ADGroup


<#
.SYNOPSIS
    Creates a new Active Directory group with specified properties.

.DESCRIPTION
    This function wraps the New-ADGroup cmdlet to create a new AD group with the given name, description, path, scope, and category.

.PARAMETER Name
    The name of the new Active Directory group.
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [string]$GroupScope = 'Global',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Security', 'Distribution')]
        [string]$GroupCategory = 'Security'
    )
    The distinguished name (DN) of the container or organizational unit (OU) where the group will be created.

.PARAMETER GroupScope
    The scope of the group (e.g., Global, Universal, DomainLocal). Default is 'Global'.

.PARAMETER GroupCategory
    The category of the group (e.g., Security, Distribution). Default is 'Security'.

.EXAMPLE
    New-ADGroupLR -Name "MyGroup" -Description "Test group" -Path "OU=Groups,DC=domain,DC=com"

#>
function New-ADGroupLR {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$GroupScope = 'Global',
        [string]$GroupCategory = 'Security'
    )
    
    New-ADGroup -Name $Name `
    -DisplayName $Name `
    -GroupScope $GroupScope `
    -GroupCategory $GroupCategory `
    -Description $Description `
    -Path $Path -Verbose
}
