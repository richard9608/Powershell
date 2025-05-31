
function Manage-UserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the username (SamAccountName) or Distinguished Name of the account")]
        [string]$Username,

        [Parameter(Mandatory = $false, HelpMessage = "Specify whether to disable and hide the user account")]
        [switch]$DisableAndHide
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
            # Disable the user account
            Disable-ADAccount -Identity $Username -ErrorAction Stop
            Write-Host "The user account '$Username' has been successfully disabled." -ForegroundColor Green

            # Hide the user from the Global Address List (GAL)
            Set-ADUser -Identity $Username -Replace @{msExchHideFromAddressLists = $true } -ErrorAction Stop
            Write-Host "The user account '$Username' has been hidden from the Global Address List (GAL)." -ForegroundColor Yellow

            # Verify the changes
            $user = Get-ADUser -Identity $Username -Properties Enabled, msExchHideFromAddressLists
            Write-Host "Verification:" -ForegroundColor Cyan
            Write-Host "Account Enabled: $($user.Enabled)" -ForegroundColor White
            Write-Host "Hidden from GAL: $($user.msExchHideFromAddressLists)" -ForegroundColor White
        }
        else {
            # Clean up the targetAddress by removing any smtp: or SMTP: prefix
            $targetAddressCleaned = if ($user.targetAddress) {
                $user.targetAddress -replace '(?i)smtp:', ''
            }
            else {
                $null
            }

            # Display user properties
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

            # Process and organize email addresses
            if ($user.proxyAddresses) {
                Write-Host "`nEmail Addresses:" -ForegroundColor Cyan
                $user.proxyAddresses | ForEach-Object { Write-Host $_ }
            }

            # Display group memberships
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


function ExitDescriptLR2 {
    # Prompt the user for input only when the function is called
    $date = (Get-Date).ToShortDateString()
    $srNumber = Read-Host "Enter SR number"
    
    # Generate the output string without any extra spaces
    $output = "Disabled $date SR#$srNumber LR2.".Replace("  ", " ").Trim()
    
    # Output to console
    Write-Output $output
    
    # Copy to clipboard
    $output | Set-Clipboard
    
    Write-Output "The output has been copied to the clipboard."
    function Manage-UserAccount {
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
                # Disable the user account
                Disable-ADAccount -Identity $Username -ErrorAction Stop
                Write-Host "The user account '$Username' has been successfully disabled." -ForegroundColor Green

                # Hide the user from the Global Address List (GAL)
                Set-ADUser -Identity $Username -Replace @{msExchHideFromAddressLists = $true } -ErrorAction Stop
                Write-Host "The user account '$Username' has been hidden from the Global Address List (GAL)." -ForegroundColor Yellow

                # Verify the changes
                $user = Get-ADUser -Identity $Username -Properties Enabled, msExchHideFromAddressLists
                Write-Host "Verification:" -ForegroundColor Cyan
                Write-Host "Account Enabled: $($user.Enabled)" -ForegroundColor White
                Write-Host "Hidden from GAL: $($user.msExchHideFromAddressLists)" -ForegroundColor White
            }
            elseif ($ExitProcedure) {
                # Hardcoded target OU
                $TargetOU = "OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate"
                Write-Host "The user will be moved to the following OU: $TargetOU" -ForegroundColor Cyan

                # Prompt for the SR number
                $SRNumber = Read-Host "Enter SR number"
                $date = (Get-Date).ToShortDateString()
                $AdditionalDescription = "Disabled $date SR#$SRNumber LR2."

                # Check if the user exists in Active Directory
                $userDetails = Get-ADUser -Identity $Username -Properties MemberOf, HomeDirectory, Description, DistinguishedName -ErrorAction SilentlyContinue

                if (-not $userDetails) {
                    Write-Host "User $Username not found in Active Directory." -ForegroundColor Red
                    return
                }

                Write-Host "User $Username found, proceeding..." -ForegroundColor Green

                # Retrieve necessary properties from $userDetails
                $groups = $userDetails.MemberOf
                $homeDirectory = $userDetails.HomeDirectory
                $currentDescription = $userDetails.Description
                $distinguishedName = $userDetails.DistinguishedName

                # Step 1: Save user details (groups and home directory) to a text file
                $outputFilePath = "$env:USERPROFILE\Desktop\UserDetails_$Username.txt"
                try {
                    Add-Content -Path $outputFilePath -Value "User: $Username"
                    Add-Content -Path $outputFilePath -Value "HomeDirectory: $homeDirectory"
                    Add-Content -Path $outputFilePath -Value "`nGroups:`n"

                    foreach ($group in $groups) {
                        Add-Content -Path $outputFilePath -Value $group
                    }

                    # Optional: Open the output file with Notepad
                    notepad $outputFilePath
                }
                catch {
                    Write-Host "Failed to write user details to file or open with Notepad: $_" -ForegroundColor Yellow
                }

                # Step 2: Prompt to remove the HomeDirectory
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

                # Step 3: Disable the user account
                try {
                    Disable-ADAccount -Identity $Username
                    Write-Host "User account for $Username has been disabled." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to disable user account for ${Username}: $_" -ForegroundColor Red
                }

                # Step 4: Move the user to the hardcoded target OU
                try {
                    Move-ADObject -Identity $distinguishedName -TargetPath $TargetOU
                    Write-Host "User $Username moved to OU: $TargetOU." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to move user $Username to the specified OU: $_" -ForegroundColor Red
                }

                # Step 5: Update the user description
                $newDescription = "$currentDescription - $AdditionalDescription"
                try {
                    Set-ADUser -Identity $Username -Description $newDescription
                    Write-Host "Description updated for user $Username." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to update description for ${Username}: $_" -ForegroundColor Red
                }

                # Step 6: Remove all group memberships except default groups (e.g., Domain Users)
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
                # Clean up the targetAddress by removing any smtp: or SMTP: prefix
                $targetAddressCleaned = if ($user.targetAddress) {
                    $user.targetAddress -replace '(?i)smtp:', ''
                }
                else {
                    $null
                }

                # Display user properties
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

                # Process and organize email addresses
                if ($user.proxyAddresses) {
                    Write-Host "`nEmail Addresses:" -ForegroundColor Cyan
                    $user.proxyAddresses | ForEach-Object { Write-Host $_ }
                }

                # Display group memberships
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



