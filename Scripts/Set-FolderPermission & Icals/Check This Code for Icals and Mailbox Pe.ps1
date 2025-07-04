Check This Code for Icals and Mailbox Permissions Management



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
#--------------------------------------------------------------------------------------------


function Manage-MailboxPermission {
    [CmdletBinding(DefaultParameterSetName = 'Add')]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Mailbox,

        [Parameter(Mandatory=$true)]
        [string] $User,

        [Parameter(ParameterSetName='Add', Mandatory=$true)]
        [switch] $Add,

        [Parameter(ParameterSetName='Remove', Mandatory=$true)]
        [switch] $Remove
    )

    begin {
        # Ensure you're connected
        if (-not (Get-PSSession | Where-Object { $_.ComputerName -like 'outlook.office365.com' })) {
            Connect-ExchangeOnline -ErrorAction Stop
        }
    }

    process {
        switch ($PsCmdlet.ParameterSetName) {
            'Add' {
                Add-MailboxPermission `
                    -Identity $Mailbox `
                    -User $User `
                    -AccessRights FullAccess `
                    -InheritanceType All `
                    -ErrorAction Stop

                Write-Host "Added FullAccess for $User on $Mailbox." -ForegroundColor Green

                # Confirm
                Get-MailboxPermission -Identity $Mailbox |
                    Where-Object { $_.User -eq $User } |
                    Format-Table User, AccessRights -AutoSize
            }

            'Remove' {
                Remove-MailboxPermission `
                    -Identity $Mailbox `
                    -User $User `
                    -AccessRights FullAccess `
                    -Confirm:$false `
                    -ErrorAction Stop

                Write-Host "Removed FullAccess for $User on $Mailbox." -ForegroundColor Yellow
            }
        }
    }

    end {
        # Optional: disconnect when done
        # Disconnect-ExchangeOnline -Confirm:$false
    }
}

<#
.SYNOPSIS
    Adds or removes FullAccess mailbox permissions.

.EXAMPLE
    Manage-MailboxPermission -Mailbox "TargetMailbox" -User "DelegateUser" -Add

.EXAMPLE
    Manage-MailboxPermission -Mailbox "TargetMailbox" -User "DelegateUser" -Remove
#>


