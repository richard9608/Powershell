  
function Set-ExitUserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the username (SamAccountName) or Distinguished Name of the account")]
        [string]$Username,

        [Parameter(Mandatory = $false, HelpMessage = "Specify whether to disable and hide the user account")]
        [switch]$DisableAndHide,

        [Parameter(Mandatory = $false, HelpMessage = "Specify whether to perform the exit procedure for the user account")]
        [switch]$ExitProcedure
    )

    # Trim spaces and ensure consistent casing for the username
    $Username = $Username.Trim()

    # Validate username format
    if ($Username -notmatch '^[a-zA-Z0-9._-]+$') {
        Write-Host "Invalid username format. Please provide a valid SamAccountName or distinguished name." -ForegroundColor Red
        return
    }

    try {
        # Get the user object with all properties
        $user = Get-ADUser -Identity $Username -Properties *

        if ($DisableAndHide) {
            Disable-ADAccount -Identity $Username -ErrorAction Stop
            Write-Host "The user account '$Username' has been successfully disabled." -ForegroundColor Green

            Set-ADUser -Identity $Username -Replace @{msExchHideFromAddressLists = $true } -ErrorAction Stop
            Write-Host "The user account '$Username' has been hidden from the Global Address List (GAL)." -ForegroundColor Yellow

            $user = Get-ADUser -Identity $Username -Properties Enabled, msExchHideFromAddressLists
            Write-Host "Verification:" -ForegroundColor Cyan
            Write-Host "Account Enabled: $($user.Enabled)" -ForegroundColor White
            Write-Host "Hidden from GAL: $($user.msExchHideFromAddressLists)" -ForegroundColor White
        }
        elseif ($ExitProcedure) {
            $TargetOU = "OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate"
            Write-Host "The user will be moved to the following OU: $TargetOU" -ForegroundColor Cyan

            $SRNumber = Read-Host "Enter SR number"
            $date = (Get-Date).ToShortDateString()
            $AdditionalDescription = "Disabled $date SR#$SRNumber LR2.".Replace("  ", " ").Trim()

            # Output to console and copy to clipboard
            Write-Output $AdditionalDescription
            $AdditionalDescription | Set-Clipboard
            Write-Output "The exit description has been copied to the clipboard."

            $userDetails = Get-ADUser -Identity $Username -Properties MemberOf, HomeDirectory, Description, DistinguishedName -ErrorAction SilentlyContinue
            if (-not $userDetails) {
                Write-Host "User $Username not found in Active Directory." -ForegroundColor Red
                return
            }

            Write-Host "User $Username found, proceeding..." -ForegroundColor Green

            $groups = $userDetails.MemberOf
            $homeDirectory = $userDetails.HomeDirectory
            $currentDescription = $userDetails.Description
            $distinguishedName = $userDetails.DistinguishedName

            $outputFilePath = "$env:USERPROFILE\Desktop\UserDetails_$Username.txt"
            try {
                Add-Content -Path $outputFilePath -Value "User: $Username"
                Add-Content -Path $outputFilePath -Value "HomeDirectory: $homeDirectory"
                Add-Content -Path $outputFilePath -Value "`nGroups:`n"
                foreach ($group in $groups) {
                    Add-Content -Path $outputFilePath -Value $group
                }
                notepad $outputFilePath
            }
            catch {
                Write-Host "Failed to write user details to file or open with Notepad: $_" -ForegroundColor Yellow
            }

            $removeHomeDirectory = Read-Host "Do you want to remove the HomeDirectory for this user? (Y/N)"
            if ($removeHomeDirectory -eq 'Y' -or $removeHomeDirectory -eq 'y') {
                try {
                    Set-ADUser -Identity $Username -HomeDirectory $null
                    Write-Host "HomeDirectory removed for user $Username." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to remove HomeDirectory for ${Username}: $_" -ForegroundColor Red
                }
            }

            try {
                Disable-ADAccount -Identity $Username
                Write-Host "User account for $Username has been disabled." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to disable user account for ${Username}: $_" -ForegroundColor Red
            }

            try {
                Move-ADObject -Identity $distinguishedName -TargetPath $TargetOU
                Write-Host "User $Username moved to OU: $TargetOU." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to move user $Username to the specified OU: $_" -ForegroundColor Red
            }

            $newDescription = "$currentDescription - $AdditionalDescription"
            try {
                Set-ADUser -Identity $Username -Description $newDescription
                Write-Host "Description updated for user $Username." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to update description for ${Username}: $_" -ForegroundColor Red
            }

            foreach ($group in $groups) {
                try {
                    if ($group -notlike "*Domain Users*") {
                        Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
                        Write-Host "Removed $Username from group $group." -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "Failed to remove ${Username} from group ${group}: $_" -ForegroundColor Red
                }
            }

            Write-Host "Operation completed for user $Username." -ForegroundColor Green
        }
        else {
            $targetAddressCleaned = if ($user.targetAddress) {
                $user.targetAddress -replace '(?i)smtp:', ''
            }
            else {
                $null
            }

            $user | Format-List `
                Name, `
                EmployeeID, `
                Description, `
                OfficePhone, `
                Office, `
                StreetAddress, `
                DisplayName, `
                Enabled, `
                LockedOut, `
                HomeDirectory, `
                EmailAddress, `
                userPrincipalName, `
            @{label = 'targetAddress'; expression = { $targetAddressCleaned } }, `
                ExtensionAttribute1, `
                AccountExpirationDate, `
                msExchHideFromAddressLists

            if ($user.proxyAddresses) {
                Write-Host "`nEmail Addresses:" -ForegroundColor Cyan
                $user.proxyAddresses | ForEach-Object { Write-Host $_ }
            }

            if ($user.MemberOf) {
                Write-Host "`nMemberOf:" -ForegroundColor Cyan
                $user.MemberOf | Sort-Object | ForEach-Object {
                    try {
                        $_.Split(',')[0].Replace("CN=", "")
                    }
                    catch {
                        Write-Host "Error processing group: $_" -ForegroundColor Red
                    }
                }
            }
        }
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
    }
}
