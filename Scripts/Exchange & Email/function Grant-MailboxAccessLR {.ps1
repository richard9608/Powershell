function Grant-MailboxAccessLR {
    [CmdletBinding()]
    param (
        [string]$TargetMailbox,
        [string]$Delegate,
        [switch]$FullAccess,
        [switch]$SendAs,
        [switch]$SendOnBehalf
    )

    # Prompt if not provided
    if (-not $TargetMailbox) {
        $TargetMailbox = Read-Host "Enter the **user ID** of the target mailbox (e.g., jdoe)"
    }

    if (-not $Delegate) {
        $Delegate = Read-Host "Enter the **user ID** of the delegate (e.g., msmith)"
    }

    # Ensure exactly one access switch is selected
    $accessOptions = @($FullAccess, $SendAs, $SendOnBehalf) | Where-Object { $_ }
    if ($accessOptions.Count -ne 1) {
        Write-Error "Please specify exactly one permission switch: -FullAccess, -SendAs, or -SendOnBehalf."
        return
    }

    if ($FullAccess) {
        Add-MailboxPermission -Identity $TargetMailbox -User $Delegate -AccessRights FullAccess -InheritanceType All
        Write-Host "✅ Granted FullAccess to '$Delegate' on mailbox '$TargetMailbox'"
    }
    elseif ($SendAs) {
        Add-RecipientPermission -Identity $TargetMailbox -Trustee $Delegate -AccessRights SendAs
        Write-Host "✅ Granted SendAs permission to '$Delegate' on mailbox '$TargetMailbox'"
    }
    elseif ($SendOnBehalf) {
        Set-Mailbox -Identity $TargetMailbox -GrantSendOnBehalfTo @{Add = $Delegate}
        Write-Host "✅ Granted SendOnBehalfTo permission to '$Delegate' on mailbox '$TargetMailbox'"
    }
}
