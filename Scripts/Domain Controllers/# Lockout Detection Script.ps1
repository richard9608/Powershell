# Lockout Detection Script
# This script checks for user account lockouts across all domain controllers
# in the last few days and outputs relevant information.
# Requires the Active Directory module
Import-Module ActiveDirectory
# Ensure the script is run with appropriate permissions
if (-not (Get-Module -Name ActiveDirectory)) {
    Write-Host "Active Directory module is not available. Please run this script on a domain controller or a machine with RSAT installed." -ForegroundColor Red
    exit
}   
# Define the user and the number of days to look back
# Change the user and days as needed

$User = "JMaynard"  # Change to your locked-out user
$DaysBack = 3   # Increase search window
$DCs = Get-ADDomainController -Filter *

foreach ($DC in $DCs) {
    Write-Host "`nSearching $($DC.HostName)..." -ForegroundColor Cyan
    try {
        $events = Get-WinEvent -ComputerName $DC.HostName -FilterHashtable @{
            LogName = 'Security'
            ID      = 4740
            StartTime = (Get-Date).AddDays(-$DaysBack)
        } -ErrorAction Stop

        foreach ($event in $events) {
            if ($event.Message -match $User) {
                Write-Host "🔒 Found lockout on: $($event.TimeCreated) at $($DC.HostName)" -ForegroundColor Yellow
                Write-Host $event.Message
            }
        }
    } catch {
        Write-Host "❌ Failed to query $($DC.HostName): $_" -ForegroundColor Red
    }
}
