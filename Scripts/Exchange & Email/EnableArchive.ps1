EnableArchive

<#
.SYNOPSIS
    This script enables the archive for a remote mailbox in Exchange.

.DESCRIPTION
    This script connects to an Exchange server, checks if a remote mailbox archive is enabled
    for a specified user, and enables it if not. It uses Kerberos authentication and requires 
    the user to have the necessary permissions.

.PARAMETER UserId
    The user ID (alias, email, or UPN) for which to check and enable the remote mailbox archive. 
    If not provided, the script will prompt for it.
#>


function EnableArchive {
    param (
        [string]$UserId
    )

    # Define credential storage path
    $CredentialPath = "$env:USERPROFILE\exchangeCred.xml"

    # Check if the credentials file exists
    if (Test-Path $CredentialPath) {
        Write-Host "Loading credentials from $CredentialPath"
        $UserCredential = Import-CliXml -Path $CredentialPath
    }
    else {
        Write-Error "Credentials file not found at '$CredentialPath'. Use `Get-Credential | Export-CliXml` to store credentials."
        return
    }

    # Exchange Server URI
    $ExchangeServer = "http://mdotgbexch1/PowerShell/"

    # Create session with Exchange
    try {
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ExchangeServer -Authentication Kerberos -Credential $UserCredential
        Import-PSSession $Session -DisableNameChecking -AllowClobber | Out-Null
        Write-Host "Connected to Exchange successfully."
    }
    catch {
        Write-Error "Failed to create a session: $($_.Exception.Message)"
        return
    }

    try {
        # Ensure AD server settings allow full forest view
        Set-ADServerSettings -ViewEntireForest $True -ErrorAction Stop

        # If no user ID is provided, prompt for one
        if (-not $UserId) {
            $UserId = Read-Host -Prompt "Enter the User ID for which to check and enable the remote mailbox archive"
        }

        # Get the remote mailbox
        $RemoteMailbox = Get-RemoteMailbox -Identity $UserId -ErrorAction Stop

        if ($RemoteMailbox.ArchiveStatus -eq "Active") {
            Write-Host "Archive is already enabled for $UserId."
        }
        else {
            Write-Host "Enabling archive for $UserId..."
            Enable-RemoteMailbox -Identity $UserId -Archive -ErrorAction Stop
            Write-Host "Archive has been enabled for $UserId."
        }
    }
    catch {
        Write-Error "Failed to retrieve or update the remote mailbox for user $($UserId): $($_.Exception.Message)"
    }
    finally {
        # Cleanup session
        if ($Session) {
            Remove-PSSession $Session
            Write-Host "Session closed."
        }
    }
}
