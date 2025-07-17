function Set-IcaclsPermission {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Switch]$ReadWrite,
        [Switch]$Modify,
        [Switch]$Full,
        [Switch]$Remove
    )

    # Ensure exactly one switch is specified
    $count = @($ReadWrite, $Modify, $Full, $Remove) | Where-Object { $_ } | Measure-Object
    if ($count.Count -ne 1) {
        Throw "Specify exactly one action switch: -ReadWrite, -Modify, -Full or -Remove."
    }

    if ($ReadWrite) {
        icacls $Path /grant "$User:(R,W)"
    }
    elseif ($Modify) {
        icacls $Path /grant "$User:(M)"
    }
    elseif ($Full) {
        icacls $Path /grant "$User:(F)"
    }
    elseif ($Remove) {
        icacls $Path /remove "$User"
    }
}
