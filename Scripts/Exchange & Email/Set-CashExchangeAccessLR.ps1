

function Set-CashExchangeAccess {
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param (
        [Parameter(Mandatory)]
        [string]$UserID,

        [Parameter(ParameterSetName = 'Enable')]
        [switch]$Enable,

        [Parameter(ParameterSetName = 'Disable')]
        [switch]$Disable
    )

    # Helper: Check if Exchange session is already connected
    function Ensure-ExchangeConnection {
        try {
            # Try a simple ExchangeOnline cmdlet to test connection
            Get-OrganizationConfig -ErrorAction Stop | Out-Null
            Write-Host "`n[✔] Exchange Online session already connected." -ForegroundColor Green
        } catch {
            Write-Host "`n[INFO] Connecting to Exchange Online..." -ForegroundColor Cyan
            Connect-ExchangeOnline 
        }
    }

    # Ensure connected to Exchange Online
    Ensure-ExchangeConnection

    $Identity = "$UserID@mdot.state.md.us"

    if ($Enable) {
        Write-Host "`n[SELECT LICENSE TYPE]" -ForegroundColor Cyan
        Write-Host "1. G5 (Full access)"
        Write-Host "2. F3 (Limited access)"
        $choice = Read-Host "Enter your choice (1 or 2)"

        switch ($choice) {
            "1" { $LicenseType = "G5" }
            "2" { $LicenseType = "F3" }
            default {
                Write-Warning "Invalid selection. Please enter 1 for G5 or 2 for F3."
                return
            }
        }

        Write-Host "`n[INFO] Enabling access for $UserID using license type: $LicenseType" -ForegroundColor Cyan

        switch ($LicenseType) {
            "G5" {
                Set-CASMailbox -Identity $Identity `
                    -ActiveSyncEnabled $true `
                    -MAPIEnabled $true `
                    -EwsEnabled $true `
                    -ImapEnabled $true `
                    -PopEnabled $true `
                    -OWAEnabled $true
                Write-Host "[SUCCESS] All client access protocols enabled for G5." -ForegroundColor Green
            }
            "F3" {
                Set-CASMailbox -Identity $Identity `
                    -ActiveSyncEnabled $false `
                    -MAPIEnabled $false `
                    -EwsEnabled $true `
                    -ImapEnabled $false `
                    -PopEnabled $false `
                    -OWAEnabled $true
                Write-Host "[SUCCESS] Limited access protocols enabled for F3." -ForegroundColor Green
            }
        }
    }

    elseif ($Disable) {
        Write-Host "`n[INFO] Disabling select access for $UserID..." -ForegroundColor Yellow
        Set-CASMailbox -Identity $Identity `
            -ActiveSyncEnabled $false `
            -OWAEnabled $false
        Write-Host "[SUCCESS] Access disabled." -ForegroundColor Green
    }

    else {
        Write-Warning "Please specify either -Enable or -Disable."
    }
}
