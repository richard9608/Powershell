<# This PowerShell function generates a password based on the current date.
# The password format is: Prefix + FullMonthName + Day (no leading zero) + Year + Suffix.   
# Today’s password (e.g. if today is May 28, 2025):

# Example usage:
New-MDOTSHAPassword
# → MDOTSHAMay282025@

# For a specific date:
New-MDOTSHAPassword -Date (Get-Date '2025-04-15')
# → MDOTSHAApril152025@

# Different suffix:
New-MDOTSHAPassword -Suffix '!'
# → MDOTSHAMay282025!

# Different prefix entirely (if you ever need):
New-MDOTSHAPassword -Prefix 'XYZ123' -Date (Get-Date '2025-12-01') -Suffix '#'
# → XYZ123December12025#
#>


function New-MDOTSHAPasswordLR {
    [CmdletBinding()]
    param (
        [string]  $Prefix = 'MDOTSHA', # fixed text at the start
        [datetime]$Date = (Get-Date), # today’s date by default
        [string]  $Suffix = '@'                      # symbol at the end
    )
    # Format as FullMonthName + Day (no leading zero) + Year
    $datePart = $Date.ToString('MMMMdyyyy')
    # Combine and output
    "$Prefix$($datePart)$Suffix"
}

#--------------------------------------------------------------------------------------------
function New-MDOTSHAPasswordLR {
    [CmdletBinding()]
    param(
        [string]   $Prefix = 'MDOTSHA', # fixed text at the start
        [datetime] $Date = (Get-Date), # today’s date by default
        [string]   $Suffix = '@'                       # symbol at the end
    )

    # 1) Build the plain-text password
    $datePart = $Date.ToString('MMMMdyyyy')           # e.g. "May282025"
    $plain = "$Prefix$($datePart)$Suffix"          # e.g. "MDOTSHAMay282025@"

    # 2) Convert it into a SecureString and return
    return (ConvertTo-SecureString $plain -AsPlainText -Force)
}
