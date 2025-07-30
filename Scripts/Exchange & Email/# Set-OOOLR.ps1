# Set-OOOLR.ps1
# Set Out of Office (OOO) for a user in Exchange Online
Function Set-OOOLR {
    [CmdletBinding()]
    param ()

    $UserEmail = Read-Host "Enter user's username (email or alias)"
    
    # Start time = Now
    $Start = Get-Date

    # Ask for end time
    $End = Read-Host "Enter OOO end date/time (e.g., 07/29/2025 12:00AM)"
    $Message = Read-Host "Enter OOO message (used for both internal and external)"

    Set-MailboxAutoReplyConfiguration -Identity $UserEmail `
        -AutoReplyState Scheduled  `
        -StartTime $Start `
        -EndTime (Get-Date $End) `
        -InternalMessage $Message `
        -ExternalMessage $Message
}
