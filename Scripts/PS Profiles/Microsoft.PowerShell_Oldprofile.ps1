


#--------------------------------------------------------------------------------------------

function Set-UserInGAL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

[Parameter(Mandatory = $true)]
        [bool]$Hide
    )

    try {
        # Determine action based on the $Hide parameter
        $action = if ($Hide) { "Hiding" } else { "Unhiding" }
        $value = if ($Hide) { $true } else { $false }

        # Apply the change
        Set-ADUser -Identity $User -Replace @{msExchHideFromAddressLists = $value}

        Write-Host "$action user '$User' from the GAL." -ForegroundColor Green
    }
    catch {
        Write-Host "Error modifying user '$User': $_" -ForegroundColor Red
    }
}


#--------------------------------------------------------------------------------------------
function ResourceExitProcedure {
    
    # Prompt for the username
    $Username = (Read-Host ("Enter the username"))

    # Hardcoded target OU
    $TargetOU = "OU=Resource Inactive,OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate"
    Write-Host "The user will be moved to the following OU: $TargetOU" -ForegroundColor Cyan

    # Prompt for the additional description
    $AdditionalDescription = (Read-Host "Enter the additional description (e.g., Disabled 10/16/2024 SR123456)")

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
    } catch {
        Write-Host "Failed to write user details to file or open with Notepad: $_" -ForegroundColor Yellow
    }

    # Step 2: Prompt to remove the HomeDirectory
    $removeHomeDirectory = Read-Host "Do you want to remove the HomeDirectory for this user? (Y/N)"
    if ($removeHomeDirectory -eq 'Y' -or $removeHomeDirectory -eq 'y') {
        try {
            Set-ADUser -Identity $Username -HomeDirectory $null
            Write-Host "HomeDirectory removed for user $Username." -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove HomeDirectory for ${Username}: $_" -ForegroundColor Red
        }
    }

    # Step 3: Disable the user account
    try {
        Disable-ADAccount -Identity $Username
        Write-Host "User account for $Username has been disabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable user account for ${Username}: $_" -ForegroundColor Red
    }

    # Step 4: Move the user to the hardcoded target OU
    try {
        Move-ADObject -Identity $distinguishedName -TargetPath $TargetOU
        Write-Host "User $Username moved to OU: $TargetOU." -ForegroundColor Green
    } catch {
        Write-Host "Failed to move user $Username to the specified OU: $_" -ForegroundColor Red
    }

    # Step 5: Update the user description
    $newDescription = "$currentDescription - $AdditionalDescription"
    try {
        Set-ADUser -Identity $Username -Description $newDescription
        Write-Host "Description updated for user $Username." -ForegroundColor Green
    } catch {
        Write-Host "Failed to update description for ${Username}: $_" -ForegroundColor Red
    }

    # Step 6: Remove all group memberships except default groups (e.g., Domain Users)
    foreach ($group in $groups) {
        try {
            if ($group -notlike "*Domain Users*") {
                Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
                Write-Host "Removed $Username from group $group." -ForegroundColor Green
            }
        } catch {
            Write-Host "Failed to remove ${Username} from group ${group}: $_" -ForegroundColor Red
        }
    }

    Write-Host "Operation completed for user $Username." -ForegroundColor Green
}


#--------------------------------------------------------------------------------------------
function Findaccount3 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$firstname,

        [Parameter(Mandatory)]
        [string]$lastname
    )

    # List of Domain Controllers
    $DCs = @(
        "mdotgbfrdc1.ad.mdot.mdstate",
        "MAABWIDC1.maa.ad.mdot.mdstate",
        "TSOGBDC1.mdothq.ad.mdot.mdstate",
        "MDTAICCDC01.mdta.ad.mdot.mdstate",
        "MPADMTENTDC01.mpa.ad.mdot.mdstate",
        "MTACWDRDC1.mtant1.ad.mdot.mdstate",
        "MVAWSDC1.mvant1.ad.mdot.mdstate",
        "SHAGBDC1.shacadd.ad.mdot.mdstate"
    )

    $allResults = @()

    foreach ($dc in $DCs) {
        Write-Verbose "Testing connectivity to $dc on port 389..."
        $test = Test-NetConnection -ComputerName $dc -Port 389 -WarningAction SilentlyContinue

        if ($test.TcpTestSucceeded) {
            Write-Verbose "Connected to $dc. Querying AD..."
            try {
                $results = Get-ADUser -LDAPFilter "(&(givenname=$firstname*)(sn=$lastname*))" `
                                        -Server $dc `
                                        -Properties Department, Office, Description, Enabled `
                                        -ErrorAction Stop

                if ($results) {
                    # Sort and select desired properties
                    $selected = $results | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description
                    $allResults += $selected
                }
            }
            catch {
                Write-Warning ("Error querying {0}: {1}" -f $dc, $_.Exception.Message)
            }
        }
        else {
            Write-Warning "Cannot connect to $dc on port 389. Skipping..."
        }
    }

    if ($allResults.Count -gt 0) {
        $allResults | Format-Table -AutoSize
    }
    else {
        Write-Host "No results found or unable to query any Domain Controller." -ForegroundColor Yellow
    }
}


#--------------------------------------------------------------------------------------------
function psremote {
param([string]$pcname)
if ((Get-Service WinRM -ComputerName $pcname).Status -eq "stopped") {
    Set-Service WinRM -Status Running -StartupType Automatic -ComputerName $pcname}
$session=New-PSSession -ComputerName $pcname
Enter-PSSession -Session $session}


#--------------------------------------------------------------------------------------------
function Get-MailboxPermissionsSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$MailboxName,

        [string]$CsvPath
    )

    # Create a custom object to store all permissions
    $Results = @()

    # 1. Check Full Access Permissions
    $FullAccess = Get-MailboxPermission -Identity $MailboxName | Where-Object {$_.AccessRights -contains "FullAccess"}
    foreach ($perm in $FullAccess) {
        $Results += [PSCustomObject]@{
            PermissionType = "Full Access"
            User           = $perm.User
            AccessRights   = $perm.AccessRights -join ", "
            IsInherited    = $perm.IsInherited
        }
    }

    # 2. Check Send As Permissions
    $SendAs = Get-RecipientPermission -Identity $MailboxName | Where-Object {$_.AccessRights -contains "SendAs"}
    foreach ($perm in $SendAs) {
        $Results += [PSCustomObject]@{
            PermissionType = "Send As"
            User           = $perm.Trustee
            AccessRights   = $perm.AccessRights -join ", "
            IsInherited    = $perm.IsInherited
        }
    }

    # 3. Check Send on Behalf Permissions
    $SendOnBehalf = (Get-Mailbox -Identity $MailboxName).GrantSendOnBehalfTo
    foreach ($user in $SendOnBehalf) {
        $Results += [PSCustomObject]@{
            PermissionType = "Send on Behalf"
            User           = $user.Name
            AccessRights   = "Send on Behalf"
            IsInherited    = "False"
        }
    }

    # 4. Check Booking Delegates (if it is a resource mailbox)
    $CalendarProcessing = Get-CalendarProcessing -Identity $MailboxName -ErrorAction SilentlyContinue
    if ($CalendarProcessing) {
        foreach ($delegate in $CalendarProcessing.ResourceDelegates) {
            $Results += [PSCustomObject]@{
                PermissionType = "Booking Delegate"
                User           = $delegate
                AccessRights   = "Booking Delegate"
                IsInherited    = "False"
            }
        }
    }

    # Output results
    if ($CsvPath) {
        $Results | Export-Csv -Path $CsvPath -NoTypeInformation
        Write-Host "Results exported to $CsvPath" -ForegroundColor Green
    } else {
        $Results | Format-Table -AutoSize
    }
}



#--------------------------------------------------------------------------------------------
function Reset-and-Apply_ADGroupsFromTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TemplateUser,

        [Parameter(Mandatory = $true)]
        [string[]]$TargetUsers
    )

    # Import Active Directory module
    Import-Module ActiveDirectory -ErrorAction Stop

    # Get Template User's Group Memberships
    Write-Verbose "Retrieving group memberships for the template user: ${TemplateUser}"
    $TemplateGroups = Get-ADUser -Identity $TemplateUser -Properties MemberOf | Select-Object -ExpandProperty MemberOf

    if (-not $TemplateGroups) {
        Write-Error "The template user '${TemplateUser}' does not belong to any groups. Exiting function."
        return
    }

    Write-Verbose "Template user '${TemplateUser}' is a member of the following groups:"
    $TemplateGroups | ForEach-Object { Write-Verbose $_ }

    # Process each target user
    foreach ($TargetUser in $TargetUsers) {
        Write-Verbose "Processing target user: ${TargetUser}"

        # Get the target user's current group memberships
        $TargetGroups = Get-ADUser -Identity $TargetUser -Properties MemberOf | Select-Object -ExpandProperty MemberOf

        if ($TargetGroups) {
            Write-Verbose "Current groups for ${TargetUser}:"
            $TargetGroups | ForEach-Object { Write-Verbose $_ }

            # Remove target user from all groups except "Domain Users"
            foreach ($Group in $TargetGroups) {
                if ($Group -notlike "*Domain Users*") {
                    Write-Verbose "Removing ${TargetUser} from group: $Group"
                    Remove-ADGroupMember -Identity $Group -Members $TargetUser -Confirm:$false
                } else {
                    Write-Verbose "Skipping mandatory group: $Group"
                }
            }
        } else {
            Write-Verbose "The target user '${TargetUser}' does not belong to any groups."
        }

        # Add the target user to the template user's groups
        foreach ($Group in $TemplateGroups) {
            Write-Verbose "Adding ${TargetUser} to group: $Group"
            Add-ADGroupMember -Identity $Group -Members $TargetUser -Confirm:$false
        }

        Write-Verbose "Finished processing user: ${TargetUser}"
    }

    Write-Verbose "Function execution completed successfully."
}


#--------------------------------------------------------------------------------------------


function GetUser_Info2 {
    param (
        [string]$Username
    )

    # If no username is provided, prompt the user
    if (-not $Username) {
        $Username = Read-Host "Please enter the username to query"
    }

    # Trim spaces and ensure consistent casing for the username
    $Username = $Username.Trim().ToLower()

    # Get the user object with all properties
    try {
        $user = Get-ADUser -Identity $Username -Properties *
    } catch {
        Write-Host "User '$Username' not found. Please check the username and try again." -ForegroundColor Red
        return
    }

    # Clean up the targetAddress by removing any smtp: or SMTP: prefix
    $targetAddressCleaned = $user.targetAddress -replace '(?i)smtp:', ''

    # Display user properties
    $user | fl Name, EmployeeID, Description, OfficePhone, Office, StreetAddress, DisplayName, Enabled, LockedOut, `
        HomeDirectory, EmailAddress, userPrincipalName, `
        @{label='targetAddress';expression={$targetAddressCleaned}}, `
        ExtensionAttribute1, AccountExpirationDate, DistinguishedName, `
        PrimaryGroup, msExchArchiveName, msExchHideFromAddressLists

    # Process and organize email addresses
    if ($user.proxyAddresses) {
        $emailList = ($user.proxyAddresses | Sort-Object) -replace '(?i)smtp:', '' 
        Write-Host "`nEmail Addresses:" -ForegroundColor Cyan
        $emailList | ForEach-Object { Write-Host $_ }
    }

    # Organize MemberOf attribute (groups the user is a member of)
    if ($user.MemberOf) {
        Write-Host "`nMemberOf:" -ForegroundColor Cyan
        $user.MemberOf | Sort-Object | ForEach-Object {
            $_.Split(',')[0].Replace("CN=", "")
        }
    }
}

#--------------------------------------------------------------------------------------------
function Find-UserAccount {
    [CmdletBinding()]
    param(
        [string]$FirstName,
        [string]$LastName
    )
    
    # Ensure the script is run interactively if parameters are not provided
    if (-not $FirstName) {
        $FirstName = Read-Host "Enter the user's First Name (or partial First Name)"
    }
    if (-not $LastName) {
        $LastName = Read-Host "Enter the user's Last Name (or partial Last Name)"
    }

    # Define the list of domain controllers to query
    $DCs = @(
        'mdotgbfrdc1.ad.mdot.mdstate',
        'MAABWIDC1.maa.ad.mdot.mdstate',
        'TSOGBDC1.mdothq.ad.mdot.mdstate',
        'MDTAICCDC01.mdta.ad.mdot.mdstate',
        'MPADMTENTDC01.mpa.ad.mdot.mdstate',
        'MTACWDRDC1.mtant1.ad.mdot.mdstate',
        'MVAWSDC1.mvant1.ad.mdot.mdstate',
        'SHAGBDC1.shacadd.ad.mdot.mdstate'
    )

    # Initialize a collection to store the query results
    $Results = @()

    # Create the output directory if it doesn't exist
    $OutputDirectory = "$HOME\Documents\Find-UserAccount"
    if (-not (Test-Path -Path $OutputDirectory)) {
        Write-Verbose "Creating output directory: $OutputDirectory"
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    # Define the output CSV file path
    $OutputCsv = "$OutputDirectory\Find-UserAccount-Results.csv"

    # Logging the start of the process
    Write-Host "Starting to query domain controllers for accounts with FirstName '$FirstName' and LastName '$LastName'..." -ForegroundColor Cyan

    # Loop through each domain controller
    foreach ($DC in $DCs) {
        Write-Host "Querying domain controller: $DC" -ForegroundColor Cyan
        Write-Verbose "Using LDAPFilter: (&(givenname=$FirstName*)(sn=$LastName*))"

        try {
            # Query the domain controller using the provided FirstName and LastName
            $QueryResult = Get-ADUser -LDAPFilter "(&(givenname=$FirstName*)(sn=$LastName*))" -Server $DC -Properties Company, Department, Enabled, SamAccountName, DisplayName, DistinguishedName, EmployeeID

            if ($QueryResult) {
                Write-Host "Successfully retrieved $(($QueryResult | Measure-Object).Count) result(s) from $DC." -ForegroundColor Green
                Write-Verbose "Appending results from $DC to the results collection."

                # Add the results to the collection
                $Results += $QueryResult |
                    Select-Object Company, Department, Enabled, SamAccountName, Name, GivenName, Surname, DisplayName, DistinguishedName, EmployeeID
            } else {
                Write-Host "No results found on domain controller $DC." -ForegroundColor Yellow
            }
        } catch {
            # Log errors for this domain controller
            $ErrorMessage = $_.Exception.Message
            Write-Host "Failed to query domain controller ${DC}: ${ErrorMessage}" -ForegroundColor Red
            Write-Verbose "Error details: $ErrorMessage"
        }
    }

    # Display and export the results
    if ($Results) {
        Write-Host "Displaying $(($Results | Measure-Object).Count) result(s):" -ForegroundColor Cyan

        # Explicitly include EmployeeID in the output table
        $Results | Format-Table Company, Department, Enabled, SamAccountName, Name, GivenName, Surname, DisplayName, EmployeeID, DistinguishedName -AutoSize

        # Export to CSV
        Write-Host "Exporting results to CSV: $OutputCsv" -ForegroundColor Green
        Write-Verbose "Exporting $(($Results | Measure-Object).Count) results to $OutputCsv"
        $Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
        Write-Host "Export complete. File saved to $OutputCsv" -ForegroundColor Green
    } else {
        Write-Host "No accounts found matching the criteria." -ForegroundColor Yellow
    }
}




#--------------------------------------------------------------------------------------------

function Get-UserByEIN {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$EIN  # The Employee Identification Number to search for
    )

    # Import the Active Directory module
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    try {
        # Search for the user with the provided EIN
        $User = Get-ADUser -Filter {employeeID -eq $EIN} -Properties employeeID, DisplayName, SamAccountName, EmailAddress

        if ($User) {
            Write-Host "User found:" -ForegroundColor Green
            Write-Host "--------------------------"
            Write-Host "Display Name     : $($User.DisplayName)"
            Write-Host "SAM Account Name : $($User.SamAccountName)"
            Write-Host "E-mail Address   : $($User.EmailAddress)"
            Write-Host "Employee ID      : $($User.employeeID)"
        } else {
            Write-Host "No user found with EIN: $EIN" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "An error occurred while searching for the user." -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}

#--------------------------------------------------------------------------------------------
function grpmem {
param([string]$a)
Get-ADGroupMember $a|sort name|select -ExpandProperty name}


#--------------------------------------------------------------------------------------------
function Find-NextSamAccountName {
    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $true)]
        [string]$Name
    )

    # List of Domain Controllers
    $DCs = @(
        'mdotgbfrdc1.ad.mdot.mdstate',
        'MAABWIDC1.maa.ad.mdot.mdstate',
        'TSOGBDC1.mdothq.ad.mdot.mdstate',
        'MDTAICCDC01.mdta.ad.mdot.mdstate',
        'MPADMTENTDC01.mpa.ad.mdot.mdstate',
        'MTACWDRDC1.mtant1.ad.mdot.mdstate',
        'MVAWSDC1.mvant1.ad.mdot.mdstate',
        'SHAGBDC1.shacadd.ad.mdot.mdstate'
    )

    # Collect all samAccountName values from all Domain Controllers
    $allSamAccountNames = foreach ($DC in $DCs) {
        try {
            Get-ADUser -LDAPFilter "(samaccountname=$Name*)" -Server $DC -Properties SamAccountName |
            Select-Object -ExpandProperty SamAccountName
        } catch {
            Write-Verbose "Failed to query DC: $DC. Error: $_"
        }
    }

    # Ensure unique results
    $allSamAccountNames = $allSamAccountNames | Sort-Object -Unique

    # Debugging: Output all found SamAccountNames
    Write-Output "Found SamAccountNames: $($allSamAccountNames -join ', ')"

    # Determine the next available SamAccountName
    $numericSuffix = 1
    $baseName = $Name

    while ($allSamAccountNames -contains "$baseName$numericSuffix") {
        $numericSuffix++
    }

    # Output the next available name
    Write-Output "The next available SamAccountName is: $baseName$numericSuffix"
}



#--------------------------------------------------------------------------------------------
function Find-Account {
    [CmdletBinding()]
    param(
        [string]$FirstName,
        [string]$LastName
    )

    # Ensure the script is run interactively if parameters are not provided
    if (-not $FirstName) {
        $FirstName = Read-Host "Enter the user's First Name (or partial First Name)"
    }
    if (-not $LastName) {
        $LastName = Read-Host "Enter the user's Last Name (or partial Last Name)"
    }

    # Define the list of domain controllers to query
    $DCs = @(
        'mdotgbfrdc1.ad.mdot.mdstate',
        'MAABWIDC1.maa.ad.mdot.mdstate',
        'TSOGBDC1.mdothq.ad.mdot.mdstate',
        'MDTAICCDC01.mdta.ad.mdot.mdstate',
        'MPADMTENTDC01.mpa.ad.mdot.mdstate',
        'MTACWDRDC1.mtant1.ad.mdot.mdstate',
        'MVAWSDC1.mvant1.ad.mdot.mdstate',
        'SHAGBDC1.shacadd.ad.mdot.mdstate'
    )

    # Initialize a collection to store the query results
    $Results = @()

    # Create the output directory if it doesn't exist
    $OutputDirectory = "$HOME\Documents\Find-Account"
    if (-not (Test-Path -Path $OutputDirectory)) {
        Write-Verbose "Creating output directory: $OutputDirectory"
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    # Define the output CSV file path
    $OutputCsv = "$OutputDirectory\Find-Account-Results.csv"

    # Logging the start of the process
    Write-Host "Starting to query domain controllers for accounts with FirstName '$FirstName' and LastName '$LastName'..." -ForegroundColor Cyan

    # Loop through each domain controller
    foreach ($DC in $DCs) {
        Write-Host "Querying domain controller: $DC" -ForegroundColor Cyan
        Write-Verbose "Using LDAPFilter: (&(givenname=$FirstName*)(sn=$LastName*))"

        try {
            # Query the domain controller using the provided FirstName and LastName
            $QueryResult = Get-ADUser -LDAPFilter "(&(givenname=$FirstName*)(sn=$LastName*))" -Server $DC -Properties Company, Department, Enabled, SamAccountName, DisplayName, DistinguishedName
            
            if ($QueryResult) {
                Write-Host "Successfully retrieved $(($QueryResult | Measure-Object).Count) result(s) from $DC." -ForegroundColor Green
                Write-Verbose "Appending results from $DC to the results collection."

                # Add the results to the collection
                $Results += $QueryResult |
                    Select-Object Company, Department, Enabled, SamAccountName, Name, GivenName, Surname, DisplayName, DistinguishedName
            } else {
                Write-Host "No results found on domain controller $DC." -ForegroundColor Yellow
            }
        } catch {
            # Log errors for this domain controller
            $ErrorMessage = $_.Exception.Message
            Write-Host "Failed to query domain controller ${DC}: ${ErrorMessage}" -ForegroundColor Red
            Write-Verbose "Error details: $ErrorMessage"
        }
    }

    # Display and export the results
    if ($Results) {
        Write-Host "Displaying $(($Results | Measure-Object).Count) result(s):" -ForegroundColor Cyan
        $Results | Format-Table -AutoSize

        # Export to CSV
        Write-Host "Exporting results to CSV: $OutputCsv" -ForegroundColor Green
        Write-Verbose "Exporting $(($Results | Measure-Object).Count) results to $OutputCsv"
        $Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
        Write-Host "Export complete. File saved to $OutputCsv" -ForegroundColor Green
    } else {
        Write-Host "No accounts found matching the criteria." -ForegroundColor Yellow
    }
}






#--------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------



function remmobile {
param([string]$user)
"`nRemoving Active sync devices....`n"
Get-MobileDeviceStatistics -Mailbox $user|select -exp Identity|Remove-MobileDevice -Confirm:$false
"`nDisabling OWA and Active Sync in Exchange....`n"
Set-CASMailbox $user -ActiveSyncEnabled:$false -OWAEnabled:$false
Get-CASMailbox $user|Ft -AutoSize}

#--------------------------------------------------------------------------------------------


function autoreply {
param([string]$user)
"I am no longer employed by MDOT. All inquiries should be e-mailed to $((Get-ADUser $user).GivenName+" "+$((Get-ADUser $user).SurName)) at $((Get-ADUser $user -Properties *).emailaddress). Thank you."|Set-Clipboard}
#--------------------------------------------------------------------------------------------
function userid {
$a=(read-host "FirstName?");$b=(read-host "LastName?")
($a+" "+$b) -replace '(\w)\w+\s(\w+)','$1$2'}
#--------------------------------------------------------------------------------------------
function ooo {
param([Parameter(mandatory=$true)]
[string]$user,
[Parameter(mandatory=$true)]
[string]$poc)
Set-MailboxAutoReplyConfiguration $user `
-AutoReplyState Scheduled `
-StartTime $(get-date) `
-EndTime $([datetime]$end=(read-host "end date");$end) `
-InternalMessage "I am no longer employed by MDOT. All inquiries should be e-mailed to $((Get-ADUser $poc).GivenName+" "+$((Get-ADUser $poc).SurName)) at $((Get-ADUser $poc -Properties *).emailaddress). Thank you." `
-ExternalMessage "I am no longer employed by MDOT. All inquiries should be e-mailed to $((Get-ADUser $poc).GivenName+" "+$((Get-ADUser $poc).SurName)) at $((Get-ADUser $poc -Properties *).emailaddress). Thank you." `
-ExternalAudience All
Get-MailboxAutoReplyConfiguration $user|fl AutoReplyState,StartTime,EndTime,InternalMessage,ExternalMessage}
#--------------------------------------------------------------------------------------------
function pw {
param([switch]$ent,
[switch]$adm,
[switch]$mgr,
[switch]$dmz,
[switch]$email,
[switch]$pfile,
[switch]$rt,
[switch]$red)
$entpw=@{pw='B@ltimorian36@!'}
$admpw=@{pw='B@ltimorian36@!'}
$mgrpw=@{pw='tot@1C0ntro!'}
$dmzpw=@{pw='KlwUkeGe&2ef'}
$mail=@{id='LRichardson2@mdot.state.md.us'}
$file=@{pw='@H$0!tn3Tpw$'}
$root=@{pw='@DBr00t@dm1n'}
$redhat=@{pw='B@ltimorian33@!'}
if ($ent){$entpw.pw|Set-Clipboard}
elseif ($adm){$admpw.pw|Set-Clipboard}
elseif ($mgr){$mgrpw.pw|Set-Clipboard}
elseif ($dmz){$dmzpw.pw|Set-Clipboard}
elseif ($email){$mail.id|Set-Clipboard}
elseif ($pfile){$file.pw|Set-Clipboard}
elseif ($rt){$root.pw|Set-Clipboard}
elseif ($red){$redhat.pw|Set-Clipboard}}
#--------------------------------------------------------------------------------------------
function Accesslist {
param([Parameter(mandatory=$true)]
[string]$path)
$a=(get-acl $path).path
"`nPath: $($a -replace '.+::')"
(get-acl $path).Access|ft -AutoSize IdentityReference,IsInherited,FileSystemRights}
#--------------------------------------------------------------------------------------------
#Traverse Permissions


function traverse {
param([parameter(mandatory, Position=0)]
[string]$user,
[parameter(mandatory, Position=1)]
[string]$path)
$acl=get-acl $path
$identity="SHACADD\$user"
[System.Security.AccessControl.FileSystemRights]$rights=@("ReadAndExecute")
[System.Security.AccessControl.InheritanceFlags]$inher=@("None")
[System.Security.AccessControl.PropagationFlags]$prop="None"
[System.Security.AccessControl.AccessControlType]$type="Allow"
$object=$identity,$rights,$inher,$prop,$type
$newacl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
$acl.AddAccessRule($newacl)
Set-Acl $path -AclObject $acl}
#--------------------------------------------------------------------------------------------
function removepermission {
param([parameter(mandatory, Position=0)]
[string]$person,
[parameter(mandatory, Position=1)]
[string]$path)
$folder=get-acl $path
foreach ($acl in $folder.Access) {
$user = $acl.IdentityReference.Value
if ($user -match "SHACADD\\$person") {
$folder.RemoveAccessRule($acl)}} 
Set-Acl $path -AclObject $folder}
#--------------------------------------------------------------------------------------------
function addpermission1 {
param([parameter(mandatory, Position=0)]
[string]$user,
[parameter(mandatory, Position=1)]
[string]$path,
[parameter(mandatory, Position=2)]
[ValidateSet("ReadAndExecute","Modify")]
[string[]]$permission)
$acl=get-acl $path
$identity="SHACADD\$user"
[System.Security.AccessControl.FileSystemRights]$rights=@($permission)
[System.Security.AccessControl.InheritanceFlags]$inher=@("ContainerInherit","ObjectInherit")
[System.Security.AccessControl.PropagationFlags]$prop="None"
[System.Security.AccessControl.AccessControlType]$type="Allow"
$object=$identity,$rights,$inher,$prop,$type
$newacl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
$acl.AddAccessRule($newacl)
Set-Acl $path -AclObject $acl}
#--------------------------------------------------------------------------------------------
#Check User permissions to File Path


function access {
param([parameter(mandatory=$true)]
[string]$user,
[parameter(mandatory=$true)]
[string]$path)
[string[]]$acl=get-acl $path|select -Expand access|select -expand identityreference
$acl=$acl -replace '.+\\'
$a=get-acl $path|select -expand access|ft IdentityReference,FileSystemRights
$acl|%{if($_ -match $user){"$_ has explicit rights."}
elseif((Get-ADGroup $_)-and(Get-ADGroupMember $_|? name -match $user)){
"$user is a member of $_";$a|? IdentityReference -Match $_}
else {end}}2>$null}

#--------------------------------------------------------------------------------------------

function addPermission {
param([parameter(mandatory, Position=0)]
[string]$user,
[parameter(mandatory, Position=1)]
[string]$path,
[parameter(mandatory, Position=2)]
[ValidateSet("ReadAndExecute","Modify","Fullcontrol")]
[string[]]$permission)
$acl=get-acl $path
$identity="SHACADD\$user"
[System.Security.AccessControl.FileSystemRights]$rights=@($permission)
[System.Security.AccessControl.InheritanceFlags]$inher=@("ContainerInherit","ObjectInherit")
[System.Security.AccessControl.PropagationFlags]$prop="None"
[System.Security.AccessControl.AccessControlType]$type="Allow"
$object=$identity,$rights,$inher,$prop,$type
$newacl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
$acl.AddAccessRule($newacl)
Set-Acl $path -AclObject $acl}
#--------------------------------------------------------------------------------------------
#First Version For the transfer Script Josh did

function fix {
param([parameter(mandatory=$true)]
[string]$template=(read-host "Provide the template Account"),
[parameter(mandatory=$true)]
[string]$targetuser=(read-host "Provide the User Account"))
(get-aduser $a -Properties *).description|%{Set-ADUser $b -Description $_}
(get-aduser $a -Properties *).StreetAddress|%{Set-ADUser $b -StreetAddress $_}
(get-aduser $a -Properties *).office|%{Set-ADUser $b -Office $_}
(get-aduser $a -Properties *).pobox|%{Set-ADUser $b -pobox $_}
(get-aduser $a -Properties *).city|%{Set-ADUser $b -city $_}
(get-aduser $a -Properties *).postalcode|%{Set-ADUser $b -postalcode $_}}
#--------------------------------------------------------------------------------------------

function acl1 {
param([string]$a)
get-acl $a|select @{l="path";e={$([string]$b=$_.path;$b=$b -replace '.+::',"";
$b)}} -ExpandProperty access|ft filesystemrights,isinherited,identityreference -GroupBy path}
#--------------------------------------------------------------------------------------------
function acl2 {
param([string]$a)
get-acl $a|select @{l="path";e={$([string]$b=$_.path;$b=$b -replace '.+::',"";
$b)}},owner -ExpandProperty access|ft owner,filesystemrights,isinherited,identityreference -GroupBy path}
#--------------------------------------------------------------------------------------------
function finduser {
param([string]$a)
Get-ADUser -LDAPFilter "(name=$a*)" -Properties *|fl displayname,name,employeeid}
#--------------------------------------------------------------------------------------------
function newuser {
param([string]$a)
@"
Name:`t`t`t`t$((Get-ADUser $a -Properties *).displayname)
Username:`t`t`t$((Get-ADUser $a -Properties *).name)
PW:`t`t`t`tMdot@Jun212022
Email:`t`t`t`t$((Get-ADUser $a -Properties *).emailaddress)
Microsoft Sign-in:`t`t$((Get-ADUser $a -Properties *).userprincipalname)
"@}
#--------------------------------------------------------------------------------------------
#Hide User In GAL

function HideUser {
param([string]$user)
Set-ADUser $user -Add @{msExchHideFromAddressLists=$true}}
#--------------------------------------------------------------------------------------------
function getuser {
param($a)
Get-ADUser $a -Properties *|fl Name,displayname,Enabled,Created,Lockedout,Homedirectory,Office,OfficePhone,Employeeid,emailaddress,AccountExpirationDate,Description,ExtensionAttribute1,ExtensionAttribute5,DistinguishedName,PrimaryGroup
$b="$((Get-ADUser $a -Properties *|sort proxyaddresses).proxyaddresses|select-string '@')"
$b=$b.Replace("smtp:","")
$b=$b.Replace("SMTP:","")
$b=$b.split()
$b=$b|sort
$b}
#--------------------------------------------------------------------------------------------
function delsheet {
param($a)
$add=[PSCustomObject]@{
email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
first_name=(Get-ADUser $a -properties *).GivenName;
last_name=(Get-ADUser $a -properties *).Surname;
'OU' =(Read-Host "OU");
'Deletion Date'=(get-date).ToShortDateString();
'EIN#'=(Get-ADUser $a -properties *).EmployeeID;
'SR#'=(Read-Host "SR#");
'Worked By'=(Read-Host "Worked By (userid)")}
$add|Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Deletes_2025.csv" -Append -NoTypeInformation}

#--------------------------------------------------------------------------------------------
function addsheet {
param($a)
$add=[PSCustomObject]@{
email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
first_name=(Get-ADUser $a -properties *).GivenName;
last_name=(Get-ADUser $a -properties *).Surname;
group_name="SHA";
OU=$(read-host "which OU?")
'Creation Date'=(get-date).ToShortDateString();
'Notes'="";
'EIN?'=(Get-ADUser $a -properties *).EmployeeID
'SR#'=(read-host "SR#")
"Worked By"=(read-host "Worked by (your userid)")}
$add|Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Adds_2025.csv" -Append}
#--------------------------------------------------------------------------------------------
function AddFMT {
param($a)
$add=[PSCustomObject]@{
email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
first_name=(Get-ADUser $a -properties *).GivenName;
last_name=(Get-ADUser $a -properties *).Surname;
group_name="SHA";
OU=$(read-host "which OU?");
'Creation Date'=(get-date).ToShortDateString();
'Notes'="";
'EIN?'=(Get-ADUser $a -properties *).EmployeeID}
$add|Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_FMT_Adds_2025.csv" -Append}
#--------------------------------------------------------------------------------------------
function updatesheet {
param([string]$old,[string]$new)
$add=[PSCustomObject]@{
current_email=(Get-ADUser $old -properties *).EmailAddress;
current_first_name=(Get-ADUser $old).GivenName;
current_last_name=(Get-ADUser $old).SurName;
current_group_name="SHA";
new_email=(Get-ADUser $new -properties *).emailaddress;
new_first_name=(Get-ADUser $new -properties *).GivenName;
new_last_name=(Get-ADUser $new -properties *).SurName;
new_group_name="SHA";
notes=(read-host "Notes")}
$add|Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Updates_2025.csv" -Append}
#--------------------------------------------------------------------------------------------
#Maximo Template 

function NewUserReply {
param([string]$user,[string]$pw=(read-host "Password"))
Get-ADUser $user -Properties *|fl @{l='UserID';e={$_.Name}},
@{l="Password";e={$pw}},
@{l='Email';e={$_.emailaddress}},
@{l='Microsoft UserName';e={$($a=$_.proxyaddresses[1];$a=$a -replace 'smtp:';$a)}}}
#--------------------------------------------------------------------------------------------
function LitSheet {
param($a)
$add=[PSCustomObject]@{
email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
first_name=(Get-ADUser $a -properties *).GivenName;
last_name=(Get-ADUser $a -properties *).Surname;
'Litigation Hold or Proxy Needed?'=$(read-host "Describe litigation");
'User Disabled Date'=(get-date).ToShortDateString()
'Worked by'=$(read-host "Worked by")}
$add|Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Litigation_Hold.csv" -Append}
#--------------------------------------------------------------------------------------------
#Remove M:Drive from Server and Clear Homedirectory
function remdir {
param([string]$user,[string]$path)
rm $path -Force -Recurse;Set-ADUser $user -Clear Homedirectory,HomeDrive}
#--------------------------------------------------------------------------------------------
function exitdesc {
param([string]$user)
$desc=(Get-ADUser $user -Properties *).description
Set-ADUser $user -Description $("$desc"+" "+"- Disabled $(
(get-date).ToShortDateString()) SR#$(read-host 'SR#') JG")}
#--------------------------------------------------------------------------------------------
function dismove {
param([string]$a)
Disable-ADAccount $a
[string]$b=(get-aduser $a).DistinguishedName
Move-ADObject -Identity $b -TargetPath 'OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate'}
#--------------------------------------------------------------------------------------------

function newmail {
param([string]$a)
@"
`$UserCredential = Get-Credential
`$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch1/PowerShell/ -Authentication Kerberos
Import-PSSession `$Session -disablenamechecking
set-ADServerSettings -viewentireforest `$True
Enable-RemoteMailbox $a -RemoteRoutingAddress "$a@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
"@|Set-Clipboard}
#--------------------------------------------------------------------------------------------

function MDWare {
start-job {Robocopy /TEE /R:0 /W:0 "\\SHAHANPCE11063\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\RShirk1 qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\RShirk1.txt
Robocopy /TEE /R:0 /W:0 "\\SHAOMTPCE16232\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\sclark qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\sclark.txt
Robocopy /TEE /R:0 /W:0 "\\SHAHANPCE10271\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\VVadakoot qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\VVaddakot.txt}}
#--------------------------------------------------------------------------------------------
function add-alias {
param([string]$a) Set-ADUser $a -Clear proxyAddresses
sleep -Seconds 5
Set-ADUser $a -EmailAddress "$a@mdot.maryland.gov"
Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+"@mdot.maryland.gov"),
$('smtp:'+$a+"@mdot.state.md.us"),
$('smtp:'+$a+"@mdotgov.mail.onmicrosoft.com"),
$('smtp:'+$a+"@sha.maryland.gov"),
$('smtp:'+$a+"@sha.state.md.us")}}
#--------------------------------------------------------------------------------------------
function vminfo {
param([string]$a)
Get-ADComputer $a|select -ExpandProperty DNSHostName
GET-VM $a|fl Name,Folder,NumCpu,CoresPerSocket,MemoryGB,VMHost
"`nOperating System:"
Get-VMGuest $a|select VmName,IPAddress,OSFullName
"`nUUID:"
Get-WmiObject win32_computersystemproduct -ComputerName SHAHQ22OHDAPP1|ft UUID -HideTableHeaders
"`nDisks:"
Get-VMGuest SHAHQ22OHDAPP1|select -ExpandProperty disks
"`nDatastore:"
Get-Datastore -RelatedObject $a|select Datacenter,Name,FreeSpaceGB,CapacityGB
"`nVirtual Network:"
Get-NetworkAdapter -VM $a|select NetworkName}
#--------------------------------------------------------------------------------------------
function remove-alias {
param([string]$a) Set-ADUser $a -Clear proxyAddresses
sleep -Seconds 3
Set-ADUser $a -EmailAddress "$a@mdot.state.md.us"
Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+'@mdot.state.md.us'),$('smtp:'+$a+'@mdotgov.mail.onmicrosoft.com')}}
#--------------------------------------------------------------------------------------------
function Transfer-LR {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetUser,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplateUser
    )

    try {
        # Get template user details
        Write-Verbose "Fetching attributes for template user: $TemplateUser"
        $templateUserData = Get-ADUser -Identity $TemplateUser -Properties Description, Office, StreetAddress, POBox, City, PostalCode, HomeDirectory, DistinguishedName
        if (-not $templateUserData) {
            throw "Template user '$TemplateUser' not found in Active Directory."
        }

        # Get target user details
        $targetUserData = Get-ADUser -Identity $TargetUser -Properties DistinguishedName
        if (-not $targetUserData) {
            throw "Target user '$TargetUser' not found in Active Directory."
        }

        # Update attributes
        Write-Verbose "Updating target user's attributes..."
        Set-ADUser -Identity $TargetUser `
            -Description $templateUserData.Description `
            -Office $templateUserData.Office `
            -StreetAddress $templateUserData.StreetAddress `
            -POBox $templateUserData.POBox `
            -City $templateUserData.City `
            -PostalCode $templateUserData.PostalCode -Verbose

        # Set Home Directory
        if ($templateUserData.HomeDirectory) {
            $homeDirBase = [System.IO.Path]::GetDirectoryName($templateUserData.HomeDirectory)
            $newHomeDirectory = "$homeDirBase\$TargetUser"
            Write-Verbose "Setting home directory: $newHomeDirectory"

            if (-not (Test-Path -Path $newHomeDirectory)) {
                New-Item -Path $newHomeDirectory -ItemType Directory -Force | Out-Null
            }

            Set-ADUser -Identity $TargetUser -HomeDirectory $newHomeDirectory -HomeDrive "M" -Verbose
        }
        else {
            Write-Warning "Template user has no HomeDirectory. Skipping this step."
        }

        # Wait for changes to apply
        Start-Sleep -Seconds 4

        # Compare and transfer group memberships
        Write-Verbose "Comparing and transferring group memberships..."
        $targetGroups = groups $TargetUser
        $templateGroups = groups $TemplateUser

        # Identify missing groups
        $missingGroups = Compare-Object -ReferenceObject $templateGroups -DifferenceObject $targetGroups |
                         Where-Object { $_.SideIndicator -eq '<=' } |
                         Select-Object -ExpandProperty InputObject

        if ($missingGroups) {
            Write-Verbose "Adding missing groups..."
            foreach ($group in $missingGroups) {
                try {
                    Add-ADGroupMember -Identity $group -Members $TargetUser -Verbose
                }
                catch {
                    Write-Warning "Failed to add $TargetUser to $group. Error: $_"
                }
            }
        }
        else {
            Write-Output "No missing groups."
        }

        # Move target user to template's OU
        Write-Verbose "Moving user to template's OU..."
        $destinationOU = ($templateUserData.DistinguishedName -split ",", 2)[1]
        if ($targetUserData.DistinguishedName) {
            Move-ADObject -Identity $targetUserData.DistinguishedName -TargetPath $destinationOU -Verbose
        }
        else {
            Write-Warning "Could not determine target user's DN. Skipping move."
        }

        Write-Output "User '$TargetUser' successfully transferred and moved to '$destinationOU'."

        # Final group comparison
        Write-Verbose "Final group comparison after updates:"
        Compare-Object -ReferenceObject (groups $TemplateUser) -DifferenceObject (groups $TargetUser) -IncludeEqual

    }
    catch {
        Write-Error "An error occurred: $_"
    }
}


#--------------------------------------------------------------------------------------------

function Transfer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Template,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $templateUser = Get-ADUser -Identity $Template -Properties Description, Office, StreetAddress, POBox, City, PostalCode, HomeDirectory, MemberOf

    if (-not $templateUser) {
        Write-Error "Template user '$Template' not found."
        return
    }

    Set-ADUser -Identity $Target `
        -Description $templateUser.Description `
        -Office $templateUser.Office `
        -StreetAddress $templateUser.StreetAddress `
        -POBox $templateUser.POBox `
        -City $templateUser.City `
        -PostalCode $templateUser.PostalCode `
        -Verbose

    if ($templateUser.HomeDirectory) {
        $folder = $templateUser.HomeDirectory -replace '(.+\\).+', "`$1$Target"

        if (-not (Test-Path $folder)) {
            Write-Host "`nFolder does not exist... Creating Folder"
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }

        Set-ADUser -Identity $Target -HomeDirectory $folder -HomeDrive "M" -Verbose
    }

    Start-Sleep -Seconds 4

    $targetUser = Get-ADUser -Identity $Target
    if ($targetUser) {
        Move-ADObject -Identity $targetUser.DistinguishedName -TargetPath $Destination
    } else {
        Write-Error "Target user '$Target' not found."
        return
    }

    $targetGroups = (Get-ADUser -Identity $Target -Properties MemberOf).MemberOf
    $templateGroups = $templateUser.MemberOf

    Compare-Object -ReferenceObject $targetGroups -DifferenceObject $templateGroups -IncludeEqual |
        ForEach-Object {
            if ($_.SideIndicator -eq "=>") {
                Write-Host "User '$Target' is missing group: $($_.InputObject) - Adding..."
                Add-ADGroupMember -Identity $_.InputObject -Members $Target
            } elseif ($_.SideIndicator -eq "<=") {
                Write-Host "User '$Target' has extra group: $($_.InputObject) - Removing..."
                Remove-ADGroupMember -Identity $_.InputObject -Members $Target -Confirm:$false
            }
        }

    Write-Host "`nUser '$Target' successfully transferred."
}

#--------------------------------------------------------------------------------------------

function transferinOU {
param([Parameter(mandatory=$true)]
[string]$target,
[Parameter(mandatory=$true)]
[String]$template)
Set-ADUser $target -Description $((Get-ADUser $template -Properties *).description) `
-StreetAddress $((Get-ADUser $template -Properties *).streetaddress) `
-POBox $((Get-ADUser $template -Properties *).pobox) `
-City $((Get-ADUser $template -Properties *).city) `
-Officephone $(Read-Host "Enter New Phone Number") `
-PostalCode $((Get-ADUser $template -Properties *).postalcode) -Verbose
$destination=$([string]$a=(Get-ADUser $template).distinguishedname;$a=$a -replace '.+TEMPLATE,(.+)','$1';$a)
Move-ADObject -Identity (Get-ADUser $target).distinguishedname -TargetPath $destination}


#--------------------------------------------------------------------------------------------


function portsec {
param([string]$mac,[string]$int)
"sh port-security address | i ($mac)
sh mac address-table | i ($mac)
sh port-security address | i ($int )
sh mac address-table | i ($int )
sh int $int status
"|set-clipboard}
#--------------------------------------------------------------------------------------------
function clear-port {
param([string]$int)
"clear port-security sticky int $int"|set-clipboard}
#--------------------------------------------------------------------------------------------
function salesforce {
param([string]$a)
Add-ADPrincipalGroupMembership $a -MemberOf SHASalesforceAzure_SSO
start-sleep -seconds 3
groups $a|select-string SHASalesforceAzure_SSO}
#--------------------------------------------------------------------------------------------
function add-alias2 {
param([string]$a) Set-ADUser $a -Clear proxyAddresses
sleep -Seconds 5
Set-ADUser $a -EmailAddress "$a.consultant@mdot.maryland.gov"
Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+".consultant@mdot.maryland.gov"),
$('Smtp:'+$a+"@mdot.maryland.gov"),
$('smtp:'+$a+"@mdot.state.md.us"),
$('smtp:'+$a+"@mdotgov.mail.onmicrosoft.com"),
$('smtp:'+$a+"@sha.maryland.gov"),
$('smtp:'+$a+"@sha.state.md.us")}}
#--------------------------------------------------------------------------------------------
function Server {
param([string]$pc)
Get-ADComputer $pc -Properties *|select Enabled,Name,SAMAccountName,Created,Modified,DNSHostName,DistinguishedName
Resolve-DnsName $pc 2>$null|ft Name,IP4Address -AutoSize}
#--------------------------------------------------------------------------------------------

#This Script for Consultant converting to EIN Users @mdot.maryland.gov


function add-alias3 {
param([string]$a) Set-ADUser $a -Clear proxyAddresses
sleep -Seconds 5
Set-ADUser $a -EmailAddress "$a@mdot.maryland.gov"
Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+"t@mdot.maryland.gov"),
$('smtp:'+$a+".consultant@mdot.maryland.gov"),
$('smtp:'+$a+"@mdot.state.md.us"),
$('smtp:'+$a+"@mdotgov.mail.onmicrosoft.com"),
$('smtp:'+$a+"@sha.maryland.gov"),
$('smtp:'+$a+"@sha.state.md.us")}}
#--------------------------------------------------------------------------------------------
#move to OU container based off of the Template

function moveuser {
param([parameter(mandatory=$true)]
[string]$targetuser,
[parameter(mandatory=$true)]
[string]$template)
$target=(Get-ADUser $targetuser).distinguishedname
$destination=$([string]$a=(Get-ADUser $template).distinguishedname;$a=$a -replace 'CN=\w+,(.+)','$1';$a)
Move-ADObject -Identity $target -TargetPath $destination}

#--------------------------------------------------------------------------------------------

function defender {
param([parameter(mandatory=$true)]
[string]$pc)
Get-WinEvent `
-FilterHashtable @{providername="*firewall*";id=2011;starttime=$((get-date).AddDays(-30))} `
-ComputerName $pc 2>$null|fl TimeCreated,MachineName,Providername,ID,Message}
#--------------------------------------------------------------------------------------------
function patchfilter {
param([parameter(mandatory=$true)]
[string]$pc)
invoke-command -ComputerName $pc {
New-NetFirewallRule -Name IvantiPatch `
-DisplayName IvantiPatch `
-Direction Inbound `
-Enabled "True" `
-Action Allow `
-Program "C:\windows\propatches\scheduler\stschedex.exe" `
-Profile Domain `
-Protocol TCP `
-LocalPort 5120 -Verbose}}
#--------------------------------------------------------------------------------------------
function getdisk {
param([string]$pc)
Get-WmiObject Win32_DiskPartition -ComputerName $pc|
SORT Name|ft SystemName,BootPartition,Name,Type,PrimaryPartition,
@{label="Size";exp={$($b=$_.size/1073741824;$b=[System.Convert]::ToInt16($b);"$b GB")}}}
#--------------------------------------------------------------------------------------------
function Allconnections {
param([string]$pc)
invoke-command -ComputerName $pc {function connectinfo {
$a=Get-NetTCPConnection|? {
$_.RemoteAddress -ne '0.0.0.0' -and 
$_.RemoteAddress -ne '127.0.0.1' -and 
$_.RemoteAddress -ne '::' -and 
$_.State -eq "Established" -or 
$_.State -eq "CloseWait"}|sort State,RemoteAddress
$a|ft CreationTime,OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State -AutoSize
[Int32[]]$b=$a.OwningProcess
$z=[psobject[]]$b|%{Get-WmiObject win32_process -Filter "processid=$_"|select ProcessId,Name,Commandline}
$z|fl 2>$null}connectinfo}}
#--------------------------------------------------------------------------------------------
function CheckTCP {
param([parameter(mandatory=$true)]
[string]$pc)
invoke-command -ComputerName $pc {function connectinfo {
$a=Get-NetTCPConnection|? {
$_.State -eq "established" -and `
$_.LocalAddress -ne '0.0.0.0' -and `
$_.LocalAddress -ne '127.0.0.1'-and `
$_.LocalAddress -notmatch '::'}|sort State,RemoteAddress
$a|select State,LocalAddress,LocalPort,RemoteAddress -Unique|ft -AutoSize
[Int32[]]$b=$a.OwningProcess
$z=[psobject[]]$b|%{Get-WmiObject win32_process -Filter "processid=$_"|select ProcessId,Name,Commandline}
$z|fl 2>$null}connectinfo 2>$null}}
#--------------------------------------------------------------------------------------------
function lockout {
param([string]$a)
get-winevent -FilterHashtable @{
logname="security";
id=4740} `
-ComputerName shahqdc3|? message -match $a|
SELECT -first 1|fl TimeCreated,MachineName,ProviderName,Id,Message
get-winevent -FilterHashtable @{
logname="security";
id=4740} `
-ComputerName shagbdc1|? message -match $a|
SELECT -first 1|fl TimeCreated,MachineName,ProviderName,Id,Message}
#--------------------------------------------------------------------------------------------
function checktimeout {
$a=Get-NetTCPConnection|? {
$_.RemoteAddress -ne '0.0.0.0' -and
$_.RemoteAddress -ne '127.0.0.1' -and
$_.RemoteAddress -ne '::' -or
$_.State -eq "CloseWait" -or $_.State -eq "TimeWait"}|sort State,RemoteAddress
$a|ft CreationTime,State,OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort -AutoSize
$a=$a|sort OwningProcess|select -ExpandProperty owningprocess -Unique
$b=$a|%{Get-WmiObject win32_process -Filter "processid=$_"|select PSComputername,ProcessID,Name,Commandline}
$b}
#--------------------------------------------------------------------------------------------
function TCPConnection {
param([string]$pc)
Invoke-Command -ComputerName $pc {
Get-NetTCPConnection -State Established -AppliedSetting Datacenter,Internet|
sort OwningProcess,RemoteAddress|? LocalAddress -ne ::1|
ft -AutoSize LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
$a=(Get-NetTCPConnection -State Established -AppliedSetting Datacenter,Internet|
sort OwningProcess,RemoteAddress|? LocalAddress -ne ::1).OwningProcess
$a=$a|select -Unique
$a=$a|%{Get-WmiObject win32_process -Filter "processid=$_"|select Name,ProcessID,CommandLine}
$a|fl}}
#--------------------------------------------------------------------------------------------
Function CheckCentracs {
"`nConnections from:`r"
Write-Host 'SHAHQATMSCS1 [10.92.178.213]' -ForegroundColor Red
"`rto`r"
Write-Host 'SHAHQATMSFS1 [10.92.178.215]' -ForegroundColor Blue
$a=(Get-WmiObject win32_process -Filter 'name="devicemanager.exe"' -ComputerName SHAHQATMSCS1).ProcessID
$b=(Get-WmiObject win32_process -Filter 'name="devicemanager.exe"' -ComputerName SHAHQATMSCS1).Path
"`nThe program '$b' is using process id $a on SHAHQATMSCS1`n"
Get-Service CentracsDeviceManager -ComputerName SHAHQATMSCS1|select MachineName,StartType,Status,Name,DisplayName|ft -AutoSize
Invoke-Command -ComputerName SHAHQATMSCS1 {
Get-NetTCPConnection|?{$_.RemoteAddress -eq '10.92.178.215'}|ft LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess}
"`nConnections from:`r"
Write-Host 'SHAHQATMSFS1 [10.92.178.215]' -ForegroundColor Blue
"`rto`r"
Write-Host "SHAHQATMSCS1 [10.92.178.213]" -ForegroundColor Red
$d=(Get-WmiObject win32_process -Filter 'name="Core.exe"' -ComputerName SHAHQATMSFS1).ProcessID
$e=(Get-WmiObject win32_process -Filter 'name="Core.exe"' -ComputerName SHAHQATMSFS1).Path
"`nThe program '$e' is using process id $d on SHAHQATMSFS1`n"
Get-Service CentracsCore -ComputerName SHAHQATMSFS1|select MachineName,StartType,Status,Name,DisplayName|ft -AutoSize
Invoke-Command -ComputerName SHAHQATMSFS1 {
Get-NetTCPConnection|? {$_.RemoteAddress -eq '10.92.178.213'}|ft -Autosize LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess}
Write-Host "Note:`rIf no connections are displayed between the servers, please reboot SHAHQATMSFS1" -ForegroundColor Green}

#--------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------
function Copy-ADUserGroupMemberships {
    <#
    .SYNOPSIS
    Copies group memberships from one Active Directory (AD) user to another.

    .DESCRIPTION
    This function retrieves all the groups a source user is a member of and adds a target user to those groups.
    It validates the existence of both users before proceeding.

    .PARAMETER SourceUser
    The SamAccountName of the source user whose group memberships will be copied.

.PARAMETER TargetUser
    The SamAccountName of the target user who will be added to the source user's groups.

    .EXAMPLE
    Copy-ADUserGroupMemberships -SourceUser "jdoe" -TargetUser "asmith"

    This will copy all group memberships from user `jdoe` to user `asmith`.

    .NOTES
    Ensure you have administrative privileges to run this function.
    The Active Directory module must be installed and imported.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string]$SourceUser,

        [Parameter(Mandatory, Position = 1)]
        [string]$TargetUser
    )

    # Import the Active Directory module (ensure the RSAT:AD module is installed)
    Import-Module ActiveDirectory -ErrorAction Stop

    # Validate the existence of the source and target users
    try {
        $sourceUserObject = Get-ADUser -Identity $SourceUser -Properties MemberOf -ErrorAction Stop
        $targetUserObject = Get-ADUser -Identity $TargetUser -ErrorAction Stop
    } catch {
        Write-Error "Error: One of the users was not found. Please ensure the usernames are correct. $_"
        return
    }

    # Retrieve the groups the source user is a member of
    $sourceGroups = $sourceUserObject.MemberOf

    if ($sourceGroups.Count -eq 0) {
        Write-Warning "The source user '$SourceUser' is not a member of any groups."
        return
    }

    Write-Host "Found $($sourceGroups.Count) groups for user '$SourceUser'. Adding memberships to '$TargetUser'..." -ForegroundColor Cyan

    # Loop through the groups and add the target user to each group
    foreach ($group in $sourceGroups) {
        try {
            Add-ADGroupMember -Identity $group -Members $TargetUserObject -ErrorAction Stop
            Write-Host "Added '$TargetUser' to group '$group' successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to add '$TargetUser' to group '$group'. Error: $_"
        }
    }

    Write-Host "Memberships from '$SourceUser' have been successfully added to '$TargetUser'." -ForegroundColor Cyan
}

#--------------------------------------------------------------------------------------------
function add-alias2 {
param([string]$a) Set-ADUser $a -Clear proxyAddresses
sleep -Seconds 5
Set-ADUser $a -EmailAddress "$a.consultant@mdot.maryland.gov"
Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+".consultant@mdot.maryland.gov"),
$('Smtp:'+$a+"@mdot.maryland.gov"),
$('smtp:'+$a+"@mdot.state.md.us"),
$('smtp:'+$a+"@mdotgov.mail.onmicrosoft.com"),
$('smtp:'+$a+"@sha.maryland.gov"),
$('smtp:'+$a+"@sha.state.md.us")}}


#----------------------------------------------------------------------------------------

# Set the value of msExchHideFromAddressLists to Replace @{msExchHideFromAddressLists=$false}
function hideuser {
param([string]$user)
Set-ADUser $user -Add @{msExchHideFromAddressLists=$true}}


#--------------------------------------------------------------------------------------------
function findaccount2 {
param([string]$user)
$DC="mdotgbfrdc1.ad.mdot.mdstate",
"MAABWIDC1.maa.ad.mdot.mdstate",
"TSOGBDC1.mdothq.ad.mdot.mdstate",
"MDTAICCDC01.mdta.ad.mdot.mdstate",
"MPADMTENTDC01.mpa.ad.mdot.mdstate",
"MTACWDRDC1.mtant1.ad.mdot.mdstate",
"MVAWSDC1.mvant1.ad.mdot.mdstate",
"SHAGBDC1.shacadd.ad.mdot.mdstate"
$result=$DC|%{Get-ADUser -LDAPFilter "(samaccountname=$user*)" -Server $_ -Properties Department,Office,Description|sort SamAccountName|select Department,Enabled,SamAccountName,GivenName,SurName,Office,Description}
$result|ft -AutoSize}
#--------------------------------------------------------------------------------------------

# Function to Search First and Last Name

function findaccount1 {
param([string]$firstname,[string]$lastname)
$DC="mdotgbfrdc1.ad.mdot.mdstate",
"MAABWIDC1.maa.ad.mdot.mdstate",
"TSOGBDC1.mdothq.ad.mdot.mdstate",
"MDTAICCDC01.mdta.ad.mdot.mdstate",
"MPADMTENTDC01.mpa.ad.mdot.mdstate",
"MTACWDRDC1.mtant1.ad.mdot.mdstate",
"MVAWSDC1.mvant1.ad.mdot.mdstate",
"SHAGBDC1.shacadd.ad.mdot.mdstate"
$result=$DC|%{Get-ADUser -LDAPFilter "(&(givenname=$firstname*)(sn=$lastname*))" -Server $_ -Properties Department,Office,Description|sort SamAccountName|select Department,Enabled,SamAccountName,GivenName,SurName,Office,Description}
$result|ft -AutoSize}
#--------------------------------------------------------------------------------------------


# Define the AddPermission function.
function AddPermission {
    # Function to add specific permissions to a file or folder for a user.

    # Prompt the user interactively for each required input parameter.
    param(
        [parameter(Mandatory)]
        [string]$user = $(Read-Host "Enter the username (e.g., domain\username)"),

        [parameter(Mandatory)]
        [string]$path = $(Read-Host "Enter the full file or folder path (e.g., C:\example)"),

        [parameter(Mandatory)]
        [ValidateSet("ReadAndExecute", "Modify", "Fullcontrol")]
        [string[]]$permission = $(Read-Host "Enter the permission level (ReadAndExecute, Modify, Fullcontrol)")
    )

    # Step 1: Retrieve the current Access Control List (ACL) for the path.
    $acl = Get-Acl $path

    # Step 2: Define the identity (user or group name) for whom permissions will be granted.
    $identity = $user

    # Step 3: Map the provided permission to a FileSystemRights object.
    [System.Security.AccessControl.FileSystemRights]$rights = @($permission)

    # Step 4: Specify inheritance flags for applying the permission to subfolders and files.
    [System.Security.AccessControl.InheritanceFlags]$inher = @("ContainerInherit", "ObjectInherit")

    # Step 5: Set propagation flags (how permissions are passed down).
    [System.Security.AccessControl.PropagationFlags]$prop = "None"

    # Step 6: Define the access type (Allow or Deny).
    [System.Security.AccessControl.AccessControlType]$type = "Allow"

    # Step 7: Create a FileSystemAccessRule object to represent the new access rule.
    $object = $identity, $rights, $inher, $prop, $type
    $newacl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object

    # Step 8: Add the new access rule to the current ACL.
    $acl.AddAccessRule($newacl)

    # Step 9: Apply the updated ACL to the file or folder.
    Set-Acl $path -AclObject $acl

    # Provide confirmation to the user.
    Write-Host "Permission '$($permission)' has been successfully applied for user '$($user)' on path '$($path)'" -ForegroundColor Green
}

# This ensures the script runs only when explicitly called.
# If the script is executed directly, it will provide an option to call the function.
if ($MyInvocation.InvocationName -eq ".\$(Split-Path -Leaf $MyInvocation.MyCommand.Path)") {
    Write-Host "This script has been loaded. You can now invoke 'AddPermission' manually to use it." -ForegroundColor Yellow
}



#--------------------------------------------------------------------------------------------


function Get-ACLDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    if (-not $Path) {
        $Path = Read-Host -Prompt "Enter the file or folder path for which you want to retrieve ACL details"
    }

    if (-not (Test-Path -Path $Path)) {
        Write-Error "The specified path '$Path' does not exist. Please provide a valid path."
        return
    }

    try {
        $ACL = Get-Acl -Path $Path
    } catch {
        Write-Error "Failed to retrieve ACL details for the path '$Path'. Error: $_"
        return
    }

    $ProcessedACL = $ACL.Access | ForEach-Object {
        [PSCustomObject]@{
            Path                = $Path
            FileSystemRights    = ($_.FileSystemRights -join ", ")
            IsInherited         = $_.IsInherited
            IdentityReference   = $_.IdentityReference
        }
    }

    # Display in PowerShell without truncation
    Write-Host "Displaying ACL details in PowerShell:" -ForegroundColor Yellow
    $ProcessedACL | Format-Table -Wrap -AutoSize

    # Set default output path
    $DefaultOutputPath = "C:\Users\LRichardson2_adm\Documents\ACLDetails.csv"

    $OutputPath = Read-Host -Prompt "Enter the full path for the CSV output file (press Enter to use default: $DefaultOutputPath)"
    if (-not $OutputPath) {
        $OutputPath = $DefaultOutputPath
    }

    if (Test-Path -Path $OutputPath) {
        try {
            $fileStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $fileStream.Close()
        } catch {
            Write-Warning "The file '$OutputPath' is currently in use by another process. Please close the file and try again."
            return
        }
    }

    try {
        $ProcessedACL | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        Write-Host "ACL details successfully exported to '$OutputPath'" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export ACL details to the CSV file. Error: $_"
    }
}


#--------------------------------------------------------------------------------------------


function Move-ADObjectPrompt {
    <#
    .SYNOPSIS
    Moves an Active Directory object to a specified Organizational Unit (OU).

    .DESCRIPTION
    This function prompts for the current Distinguished Name (DN) of an object
    and the target OU path, and then uses the Move-ADObject cmdlet to move the object.

    .EXAMPLE
    Move-ADObjectPrompt
    # Prompts interactively for the DN and target OU, then moves the object.
    #>

    [CmdletBinding()]
    param ()

    # Prompt for the current Distinguished Name (DN) of the object
    $currentDN = Read-Host "Enter the current Distinguished Name (DN) of the object (e.g., CN=John Smith,OU=Users,DC=example,DC=com)"

    # Prompt for the target OU
    $targetPath = Read-Host "Enter the Distinguished Name (DN) of the target OU (e.g., OU=IT,DC=example,DC=com)"

    # Perform the move operation
    try {
        Move-ADObject -Identity $currentDN -TargetPath $targetPath -Confirm:$false -ErrorAction Stop
        Write-Host "Successfully moved the object to $targetPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to move the object. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}


#--------------------------------------------------------------------------------------------

function GetUser_Info {
    # Prompt for username when the function is called
    $a = Read-Host "Please enter the username to query"
    
    # Trim spaces and ensure consistent casing for the username
    $a = $a.Trim().ToLower()

    # Get the user object with all properties
    try {
        $user = Get-ADUser -Identity $a -Properties *
    } catch {
        Write-Host "User not found. Please check the username and try again." -ForegroundColor Red
        return
    }

    # Clean up the targetAddress by removing any smtp: or SMTP: prefix
    $targetAddressCleaned = $user.targetAddress -replace '(?i)smtp:', ''

    # Display user properties - Only AD value for msExchHideFromAddressLists
    $user | fl Name,EmployeeID,Description,OfficePhone,Office,StreetAddress,DisplayName,Enabled,LockedOut,HomeDirectory,EmailAddress,userPrincipalName,@{label='targetAddress';expression={$targetAddressCleaned}},ExtensionAttribute1,AccountExpirationDate,DistinguishedName,PrimaryGroup,msExchArchiveName,msExchHideFromAddressLists 

    # Process and organize email addresses, remove smtp: and SMTP:
    $b = "$(($user | Sort-Object proxyAddresses).proxyAddresses | Select-String '@')"
    $b = $b -replace '(?i)smtp:', '' # Case-insensitive removal of smtp and SMTP
    $b = $b.Split() | Sort-Object
    $b | ForEach-Object { $_ } # Output the cleaned email addresses

    # Organize MemberOf attribute (groups the user is a member of)
    if ($user.MemberOf) {
        Write-Host "`nMemberOf:" -ForegroundColor Cyan
        $user.MemberOf | Sort-Object | ForEach-Object {
            # Extract only the CN (Common Name) of each group
            $_.Split(',')[0].Replace("CN=", "")
        }
    }
}


#--------------------------------------------------------------------------------------------

function Process-MultipleADUserExits {
    param (
        [Parameter(Mandatory = $false)]
        [string]$CSVPath,  # Path to your CSV file

        [string]$TargetOU = "OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate"  # Default target OU
    )

    # Prompt for CSV path if not provided
    if (-not $CSVPath) {
        $CSVPath = Read-Host "Please enter the full path to your CSV file"
    }

    # Check if the CSV file exists
    if (-not (Test-Path $CSVPath)) {
        Write-Host "The CSV file at path $CSVPath does not exist or cannot be accessed. Please provide a valid file." -ForegroundColor Red
        return
    }

    # Create a log file to track operations
    $logFile = "$env:USERPROFILE\Desktop\Process-MultipleADUserExits_Log.txt"
    try {
        New-Item -Path $logFile -ItemType File -Force | Out-Null
        Write-Host "Log file created at: $logFile" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create log file: $_" -ForegroundColor Red
        return
    }

    # Function for logging
    function Write-Log {
        param (
            [string]$Message,
            [string]$LogType = "INFO"
        )
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "$timestamp [$LogType] $Message"
        Add-Content -Path $logFile -Value $logEntry
        Write-Host $logEntry
    }

    # Import the CSV
    $users = Import-Csv -Path $CSVPath
    Write-Log "Imported CSV file with $($users.Count) users."

    foreach ($user in $users) {
        $Username = $user.Username
        $AdditionalDescription = $user.AdditionalDescription

        Write-Log "Processing user: $Username"
        Write-Host "Processing user: $Username" -ForegroundColor Cyan

        # Check if the user exists in Active Directory
        $userDetails = Get-ADUser -Identity $Username -Properties MemberOf, HomeDirectory, Description, DistinguishedName -ErrorAction SilentlyContinue

        if (-not $userDetails) {
            Write-Log "User $Username not found in Active Directory." "ERROR"
            Write-Host "User $Username not found in Active Directory." -ForegroundColor Red
            continue
        }

        Write-Log "User $Username found in Active Directory."
        Write-Host "User $Username found, proceeding..." -ForegroundColor Green

        # Retrieve necessary properties
        $groups = $userDetails.MemberOf
        $homeDirectory = $userDetails.HomeDirectory
        $currentDescription = $userDetails.Description
        $distinguishedName = $userDetails.DistinguishedName

        # Step 1: Save user details (groups and home directory) to a text file
        $outputDirectory = "$env:USERPROFILE\Desktop\UserDetails"
        if (-not (Test-Path $outputDirectory)) {
            New-Item -ItemType Directory -Path $outputDirectory | Out-Null
        }

        $outputFilePath = "$outputDirectory\UserDetails_${Username}.txt"
        try {
            Set-Content -Path $outputFilePath -Value "User: ${Username}"
            Add-Content -Path $outputFilePath -Value "DistinguishedName: ${distinguishedName}"
            Add-Content -Path $outputFilePath -Value "HomeDirectory: ${homeDirectory}"
            Add-Content -Path $outputFilePath -Value "`nGroups:`n"

            foreach ($group in $groups) {
                Add-Content -Path $outputFilePath -Value $group
            }

            Write-Log "User details for ${Username} saved to: $outputFilePath"
            Write-Host "User details for ${Username} saved to: $outputFilePath" -ForegroundColor Green
        } catch {
            Write-Log "Failed to save user details for ${Username}: $_" "ERROR"
            Write-Host "Failed to save user details for ${Username}: $_" -ForegroundColor Red
        }

        # Step 2: Remove the HomeDirectory
        try {
            Set-ADUser -Identity $Username -HomeDirectory $null
            Write-Log "HomeDirectory removed for user ${Username}."
            Write-Host "HomeDirectory removed for user ${Username}." -ForegroundColor Green
        } catch {
            Write-Log "Failed to remove HomeDirectory for ${Username}: $_" "ERROR"
            Write-Host "Failed to remove HomeDirectory for ${Username}: $_" -ForegroundColor Red
        }

        # Step 3: Disable the user account
        try {
            Disable-ADAccount -Identity $Username
            Write-Log "User account for ${Username} has been disabled."
            Write-Host "User account for ${Username} has been disabled." -ForegroundColor Green
        } catch {
            Write-Log "Failed to disable user account for ${Username}: $_" "ERROR"
            Write-Host "Failed to disable user account for ${Username}: $_" -ForegroundColor Red
        }

        # Step 4: Move the user to the target OU
        try {
            Move-ADObject -Identity $distinguishedName -TargetPath $TargetOU
            Write-Log "User ${Username} moved to OU: $TargetOU."
            Write-Host "User ${Username} moved to OU: $TargetOU." -ForegroundColor Green
        } catch {
            Write-Log "Failed to move user ${Username} to OU: $_" "ERROR"
            Write-Host "Failed to move user ${Username} to the specified OU: $_" -ForegroundColor Red
        }

        # Step 5: Update the user description
        if ([string]::IsNullOrWhiteSpace($currentDescription)) {
            $newDescription = "$AdditionalDescription"
        } else {
            $newDescription = "$currentDescription - $AdditionalDescription"
        }

        try {
            Set-ADUser -Identity $Username -Description $newDescription
            Write-Log "Description updated for user ${Username}: $newDescription."
            Write-Host "Description updated for user ${Username}: $newDescription" -ForegroundColor Green
        } catch {
            Write-Log "Failed to update description for ${Username}: $_" "ERROR"
            Write-Host "Failed to update description for ${Username}: $_" -ForegroundColor Red
        }

        # Step 6: Remove all group memberships except default groups (e.g., Domain Users)
        foreach ($group in $groups) {
            try {
                if ($group -notlike "*Domain Users*") {
                    Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
                    Write-Log "Removed ${Username} from group ${group}."
                    Write-Host "Removed ${Username} from group ${group}." -ForegroundColor Green
                }
            } catch {
                Write-Log "Failed to remove ${Username} from group ${group}: $_" "ERROR"
                Write-Host "Failed to remove ${Username} from group ${group}: $_" -ForegroundColor Red
            }
        }

        Write-Log "Operation completed for user ${Username}."
        Write-Host "Operation completed for user ${Username}." -ForegroundColor Green
        Write-Host "--------------------------------------------" -ForegroundColor Yellow
    }
}

# Example usage:
# Process-MultipleADUserExits




#--------------------------------------------------------------------------------------------


# Define the function to clear and update an AD user's description
function ClearAndUpdate-ADUserDescription {
    # Prompt for the username (sAMAccountName)
    $username = Read-Host "Enter the username (sAMAccountName) of the user"
    $username = $username.Trim()  # Remove leading/trailing whitespace

    # Attempt to retrieve the user's AD information
    try {
        # Fetch the user with the cleaned username
        $user = Get-ADUser -Identity $username -Properties Description

        if ($null -eq $user) {
            Write-Host "User '$username' not found in Active Directory." -ForegroundColor Red
            return
        }

        # Show the old description (if any)
        $oldDescription = $user.Description
        if (-not [string]::IsNullOrWhiteSpace($oldDescription)) {
            Write-Host "Current description for user '$username': $oldDescription" -ForegroundColor Yellow
        } else {
            Write-Host "The user '$username' has no current description." -ForegroundColor Yellow
        }

        # Prompt for the new description
        $newDescription = Read-Host "Enter the new description for user '$username'"

        # Clear the old description and set the new one
        Set-ADUser -Identity $username -Description $null
        Set-ADUser -Identity $username -Description $newDescription

        # Confirm the change
        Write-Host "The description for user '$username' has been updated successfully." -ForegroundColor Green
    }
    catch {
        # Handle errors
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}

# Ensure the script doesn't run automatically in your profile
if ($MyInvocation.InvocationName -ne ".") {
    Write-Host "Function 'ClearAndUpdate-ADUserDescription' is loaded. Call it manually to execute."
}




#--------------------------------------------------------------------------------------------


function Disable-OutOfOffice {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Enter the email address or username of the user to disable Out of Office.")]
        [string]$UserEmail
    )

    # Import Exchange Online module
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    # Connect to Exchange Online (prompting for credentials if needed)
    Connect-ExchangeOnline

    # If no email is provided, prompt the user for it
    if (-not $UserEmail) {
        $UserEmail = Read-Host -Prompt "Enter the email address or username of the user to disable Out of Office"
    }

    # Display the input for confirmation
    Write-Host "Fetching information for: ${UserEmail}" -ForegroundColor Cyan

    # OPTIONAL: Fetch user info (e.g., display current Out of Office settings)
    try {
        $AutoReplyConfig = Get-MailboxAutoReplyConfiguration -Identity $UserEmail
        Write-Host "Current Out of Office Status for ${UserEmail}:" -ForegroundColor Yellow
        Write-Host "AutoReplyState: $($AutoReplyConfig.AutoReplyState)" -ForegroundColor Green
        Write-Host "Internal Message: $($AutoReplyConfig.InternalMessage)" -ForegroundColor Green
        Write-Host "External Message: $($AutoReplyConfig.ExternalMessage)" -ForegroundColor Green
    } catch {
        Write-Error "Could not retrieve AutoReply settings for ${UserEmail}. Error: $_"
        return
    }

    # Ask for confirmation before disabling Out of Office
    $Confirmation = Read-Host "Do you want to disable Out of Office for ${UserEmail}? (Y/N)"
    if ($Confirmation -ne 'Y' -and $Confirmation -ne 'y') {
        Write-Host "Operation canceled by user." -ForegroundColor Red
        return
    }

    # Disable Out of Office
    try {
        Set-MailboxAutoReplyConfiguration -Identity $UserEmail -AutoReplyState Disabled
        Write-Host "Out of Office has been successfully disabled for ${UserEmail}" -ForegroundColor Green
    } catch {
        Write-Error "Failed to disable Out of Office for ${UserEmail}. Error: $_"
    }

    # Disconnect the session
    Disconnect-ExchangeOnline -Confirm:$false
}


#--------------------------------------------------------------------------------------------



function Get-AutoReplyConfiguration {
    <#
    .SYNOPSIS
    Retrieves the auto-reply (Out of Office) configuration for a user.

    .DESCRIPTION
    This function prompts the user for a username, retrieves the associated email address 
    from Active Directory, and then fetches the auto-reply configuration using the 
    Get-MailboxAutoReplyConfiguration cmdlet.

    .PARAMETER Username
    Optional parameter to specify the username directly. If omitted, the function will prompt.

    .EXAMPLE
    Get-AutoReplyConfiguration
    Prompts for a username and retrieves the auto-reply configuration.

    .EXAMPLE
    Get-AutoReplyConfiguration -Username jdoe
    Retrieves the auto-reply configuration for the user `jdoe`.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Username
    )

    # If no username is provided, prompt the user
    if (-not $Username) {
        $Username = Read-Host "Please enter the username"
    }

    # Retrieve the email address associated with the provided username
    try {
        $User = Get-ADUser -Filter {SamAccountName -eq $Username} -Properties EmailAddress

        if ($null -eq $User) {
            Write-Host "No user found with the username '$Username'. Please check the input and try again." -ForegroundColor Red
            return
        }

        $Email = $User.EmailAddress

        if ($null -eq $Email) {
            Write-Host "No email address found for the username '$Username'. Please ensure the user has an email address." -ForegroundColor Red
            return
        }

        Write-Host "Email address for user '$Username' is: $Email" -ForegroundColor Green

        # Retrieve and display the mailbox auto-reply configuration
        $AutoReplyConfig = Get-MailboxAutoReplyConfiguration -Identity $Email | Format-List AutoReplyState, StartTime, EndTime, InternalMessage, ExternalMessage

        # Output the auto-reply configuration
        $AutoReplyConfig

    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}


#--------------------------------------------------------------------------------------------


function Disable-AndHideUserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the username (SamAccountName) or Distinguished Name of the account to disable and hide")]
        [string]$UserAccount
    )

    Try {
        # Disable the user account
        Disable-ADAccount -Identity $UserAccount -ErrorAction Stop
        Write-Host "The user account '$UserAccount' has been successfully disabled." -ForegroundColor Green

        # Hide the user from the Global Address List (GAL)
        Set-ADUser -Identity $UserAccount -Replace @{msExchHideFromAddressLists=$true} -ErrorAction Stop
        Write-Host "The user account '$UserAccount' has been hidden from the Global Address List (GAL)." -ForegroundColor Yellow

        # Verify the changes
        $user = Get-ADUser -Identity $UserAccount -Properties Enabled, msExchHideFromAddressLists
        Write-Host "Verification:" -ForegroundColor Cyan
        Write-Host "Account Enabled: $($user.Enabled)" -ForegroundColor White
        Write-Host "Hidden from GAL: $($user.msExchHideFromAddressLists)" -ForegroundColor White
    } Catch {
        # Handle errors
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}


#--------------------------------------------------------------------------------------------



function EnableArchive {
    param (
        [string]$UserId
    )

    # Define credential storage path
    $CredentialPath = "C:\Users\LRichardson2_adm\Documents\Credentials.xml"

    # Check if the credentials file exists
    if (Test-Path $CredentialPath) {
        Write-Host "Loading credentials from $CredentialPath"
        $UserCredential = Import-CliXml -Path $CredentialPath
    } else {
        Write-Error "Credentials file not found at '$CredentialPath'. Use Get-Credential | Export-CliXml to store credentials."
        return
    }

    # Exchange Server URI
    $ExchangeServer = "http://mdotgbexch1/PowerShell/"

    # Create session with Exchange
    try {
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ExchangeServer -Authentication Kerberos -Credential $UserCredential
        Import-PSSession $Session -DisableNameChecking -AllowClobber
        Write-Host "Connected to Exchange successfully."
    } catch {
        Write-Error "Failed to create a session: $_"
        return
    }

    try {
        # Ensure AD server settings allow full forest view
        Set-ADServerSettings -ViewEntireForest $True

        # If no user ID is provided, prompt for one
        if (-not $UserId) {
            $UserId = Read-Host -Prompt "Enter the User ID for which to check and enable the remote mailbox archive"
        }

        # Get the remote mailbox
        $RemoteMailbox = Get-RemoteMailbox -Identity $UserId -ErrorAction Stop

        if ($RemoteMailbox.ArchiveStatus -eq "Active") {
            Write-Host "Archive is already enabled for $UserId."
        } else {
            Write-Host "Enabling archive for $UserId..."
            Enable-RemoteMailbox -Identity $UserId -Archive
            Write-Host "Archive has been enabled for $UserId."
        }
    } catch {
        Write-Error "Failed to retrieve or update the remote mailbox for user $UserId: $_"
    } finally {
        # Cleanup session
        if ($Session) {
            Remove-PSSession $Session
            Write-Host "Session closed."
        }
    }
}


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


function Set-ConsultAtt {
    param ()

    $username = (Read-Host "Enter the user's SAM Account Name").Trim()

    if ($username) {
        try {
            # Retrieve the user's current DisplayName
            $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -Properties DisplayName

            if ($null -ne $user) {
                # Extract the base Display Name
                $baseDisplayName = $user.DisplayName

                # Construct the new Display Name
                $newDisplayName = "$baseDisplayName (Consultant)"

                # Update the user's attributes
                Set-ADUser -Identity $username -DisplayName $newDisplayName -Replace @{ExtensionAttribute1 = 'SHA Consultant'}
            }
        } catch {
            # Silently handle errors
            return
        }
    }
}


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

function GetAllUser_Attributes {
    # Prompt the user for input only when the function is explicitly called
    param (
        [string]$Username
    )

    # If no username is provided, prompt for it
    if (-not $Username) {
        $Username = Read-Host "Enter the username of the AD user you want to retrieve all attributes for"
    }

    # Trim whitespace and convert the username to lowercase to make the input case-insensitive
    $Username = $Username.Trim().ToLower()

    # Run the Get-ADUser command with the specified username
    try {
        $user = Get-ADUser -Identity $Username -Properties *  # Retrieves all properties of the user
        Write-Output $user  # Display the user object with all attributes
    } catch {
        Write-Output "User '$Username' not found or an error occurred: $_"
    }
}








#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# Define a function to retrieve user license information and optionally add licenses
function GetUserLicenseInfo {
    param (
        [string]$DisplayName
    )

    # Search for users that match the display name
    $users = Get-MsolUser -SearchString $DisplayName

    # Check if any users were found
    if ($users.Count -eq 0) {
        Write-Output "No users found with the display name '$DisplayName'."
    }
    elseif ($users.Count -eq 1) {
        # If only one user is found, retrieve their UPN
        $user = $users[0]
        Write-Output "Found user: $($user.DisplayName) with UPN: $($user.UserPrincipalName)"
        
        # Retrieve and display license details
        Write-Output "Current licenses for $($user.DisplayName):"
        $user.Licenses | ForEach-Object {
            Write-Output " - $($_.AccountSkuId)"
        }

        # Ask if user wants to add a license
        $addLicense = Read-Host "Would you like to add a license to this user? (y/n)"
        if ($addLicense -eq 'y') {
            # Prompt for licenses to add
            $licensesInput = Read-Host "Enter the licenses to add, separated by commas (e.g., 'ENTERPRISEPREMIUM,POWER_BI_STANDARD')"
            $licensesArray = $licensesInput -split "," | ForEach-Object { $_.Trim() }
            
            # Add each license if not already assigned
            foreach ($license in $licensesArray) {
                if (-not ($user.Licenses.AccountSkuId -contains "$($user.TenantId):$license")) {
                    Write-Output "Adding license $license to user $($user.DisplayName)..."
                    Set-MsolUserLicense -UserPrincipalName $user.UserPrincipalName -AddLicenses "$($user.TenantId):$license"
                    Write-Output "License $license added successfully."
                } else {
                    Write-Output "User already has the license $license."
                }
            }
        } else {
            Write-Output "No licenses were added."
        }
    }
    else {
        # If multiple users are found, display them and prompt to choose one
        Write-Output "Multiple users found with the display name '$DisplayName':"
        $users | ForEach-Object -Begin { $i = 1 } -Process {
            Write-Output "$i. $($_.DisplayName) - $($_.UserPrincipalName)"
            $i++
        }

        # Prompt user to select a specific user
        $selection = Read-Host "Enter the number corresponding to the user you want to view"
        if ([int]::TryParse($selection, [ref]$null) -and $selection -gt 0 -and $selection -le $users.Count) {
            $user = $users[$selection - 1]
            Write-Output "Selected user: $($user.DisplayName) with UPN: $($user.UserPrincipalName)"
            
            # Retrieve and display license details for the selected user
            Write-Output "Current licenses for $($user.DisplayName):"
            $user.Licenses | ForEach-Object {
                Write-Output " - $($_.AccountSkuId)"
            }

            # Ask if user wants to add a license
            $addLicense = Read-Host "Would you like to add a license to this user? (y/n)"
            if ($addLicense -eq 'y') {
                # Prompt for licenses to add
                $licensesInput = Read-Host "Enter the licenses to add, separated by commas (e.g., 'ENTERPRISEPREMIUM,POWER_BI_STANDARD')"
                $licensesArray = $licensesInput -split "," | ForEach-Object { $_.Trim() }
                
                # Add each license if not already assigned
                foreach ($license in $licensesArray) {
                    if (-not ($user.Licenses.AccountSkuId -contains "$($user.TenantId):$license")) {
                        Write-Output "Adding license $license to user $($user.DisplayName)..."
                        Set-MsolUserLicense -UserPrincipalName $user.UserPrincipalName -AddLicenses "$($user.TenantId):$license"
                        Write-Output "License $license added successfully."
                    } else {
                        Write-Output "User already has the license $license."
                    }
                }
            } else {
                Write-Output "No licenses were added."
            }
        } else {
            Write-Output "Invalid selection. Please run the function again and choose a valid user."
        }
    }
}

# Define a wrapper function that prompts for the display name when called
function RequestUserLicenseInfo {
    $displayNameInput = Read-Host "Enter the user's display name or part of it (e.g., 'John Doe')"
    Get-UserLicenseInfo -DisplayName $displayNameInput
}

# Usage:
# To use the script, explicitly call `RequestUserLicenseInfo`.




#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------




function SetAccountExpiration {
    # Prompt for Username and Expiration Date
    $username = Read-Host "Please enter the username"
    $expirationDate = Read-Host "Please enter the expiration date (MM/dd/yyyy)"
    
    # Convert the date to a valid DateTime object
    try {
        $expirationDate = [datetime]::ParseExact($expirationDate, 'MM/dd/yyyy', $null)
    } catch {
        Write-Host "Invalid date format. Please ensure the date is in MM/dd/yyyy format." -ForegroundColor Red
        return  # Return instead of exit to avoid closing the entire session
    }
    
    # Set the account expiration date for the specified user
    try {
        Get-ADUser -Identity $username -ErrorAction Stop | Set-ADAccountExpiration -Date $expirationDate
        Write-Host "The account expiration date for $username has been successfully set to $($expirationDate.ToString('MM/dd/yyyy'))."
    } catch {
        Write-Host "Failed to set the expiration date. Please check the username or date format." -ForegroundColor Red
        return
    }

    # Export results to Notepad
    $result = "Account: $username`nExpiration Date: $($expirationDate.ToString('MM/dd/yyyy'))"
    $result | Out-File -FilePath "$env:TEMP\AccountExpiration.txt"
    notepad.exe "$env:TEMP\AccountExpiration.txt"
}

# The script now only executes when Set-AccountExpiration is called explicitly


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


function User_DesrciptUpd {
    # Prompt for the username and trim any extra spaces
    $username = (Read-Host "Please enter the username (e.g., jdoe)").Trim()

    # Prompt for the Employee ID and trim any extra spaces
    $employeeID = (Read-Host "Please enter the Employee ID").Trim()

    # Prompt for Description and trim any extra spaces
    $description = (Read-Host "Please enter the Description").Trim()

    # Prompt for Office and trim any extra spaces
    $office = (Read-Host "Please enter the Office").Trim()

    # Prompt for Telephone Number (Yes/No) and trim any extra spaces
    $updatePhone = (Read-Host "Would you like to update the telephone number? (Yes/No)").Trim()

    if ($updatePhone -eq "Yes") {
        # Prompt for the telephone number and trim any extra spaces
        $phoneNumber = (Read-Host "Please enter the Telephone Number").Trim()
    } else {
        $phoneNumber = $null  # No update for telephone number
    }

    # Prompt for Address and trim any extra spaces
    $address = (Read-Host "Please enter the Address").Trim()

    # Update the user information in Active Directory
    Set-ADUser -Identity $username `
        -EmployeeID $employeeID `
        -Description $description `
        -Office $office `
        -StreetAddress $address `
        -OfficePhone $phoneNumber

    # Retrieve updated user details
    $userDetails = Get-ADUser -Identity $username -Properties DisplayName, HomeDirectory, Description, Office, OfficePhone, StreetAddress

    # Prepare the output for Notepad
    $output = @"
Display Name: $($userDetails.DisplayName)
Home Directory: $($userDetails.HomeDirectory)
Description: $($userDetails.Description)
Office: $($userDetails.Office)
Office Phone: $($userDetails.OfficePhone)
Address: $($userDetails.StreetAddress)
"@

    # Save the output to a Notepad file
    $filePath = "C:\\Users\\$env:USERNAME\\Documents\\$username-user-details.txt"
    $output | Out-File -FilePath $filePath

    # Open the Notepad file with the saved user details
    Start-Process notepad.exe $filePath
}

# To run the function, type:
# Update-ADUserDetails

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

function Enable_DisableUserAcc {
    # Prompt for the username using Read-Host
    $userName = Read-Host -Prompt "Enter the username to manage (e.g., jdoe)"

    # Prompt the user to choose whether to enable or disable the account
    $action = Read-Host -Prompt "Do you want to 'Enable' or 'Disable' the account? (Enter 'Enable' or 'Disable')"

    # Validate the input
    if ($action -eq 'Enable') {
        # Enable the account
        Enable-ADAccount -Identity $userName
        Write-Host "Account '$userName' has been enabled." -ForegroundColor Green
    }
    elseif ($action -eq 'Disable') {
        # Disable the account
        Disable-ADAccount -Identity $userName
        Write-Host "Account '$userName' has been disabled." -ForegroundColor Green
    }
    else {
        Write-Host "Invalid choice. Please enter either 'Enable' or 'Disable'." -ForegroundColor Yellow
    }

    # Confirm the account status
    $accountStatus = Get-ADUser -Identity $userName -Properties Enabled
    $statusText = if ($accountStatus.Enabled) { 'enabled' } else { 'disabled' }
    Write-Host "The current status of '$userName' is: $statusText" -ForegroundColor Cyan
}

# Ensure that the function is defined in the current session, but not executed


#--------------------------------------------------------------------------------------------

# Function to reset AD account password with random password generation
function Reset_UserPass {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Username
    )

    # Function to generate a random 13-character password
    function New-RandomPassword {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        $password = -join ((1..13) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        return $password
    }

    # Prompt for Username if not provided when the function is called
    if (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Username')) {
        $Username = Read-Host "Please enter the username for the account"
    }

    # Check if the username is not empty
    if (-not [string]::IsNullOrWhiteSpace($Username)) {
        # Generate a random 13-character password
        $newPassword = New-RandomPassword

        try {
            # Reset the user's password in Active Directory
            Set-ADAccountPassword -Identity $Username -Reset -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)

            # Force the user to change their password at next logon
            Set-ADUser -Identity $Username -ChangePasswordAtLogon $true

            # Output the new password to the screen
            Write-Host "The new password for $Username is: $newPassword"
            Write-Host "The user will be prompted to change their password at next logon."
        }
        catch {
            # Handle errors during the password reset process
            Write-Host "An error occurred while resetting the password for $Username. Please check the username and try again." -ForegroundColor Red
        }
    } else {
        # Handle empty username input
        Write-Host "Username cannot be empty." -ForegroundColor Red
    }
}


#--------------------------------------------------------------------------------------------
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
}


#-----------------------------------------------------------------------------------------------------------------


function UpdateADUserDescript {
    # Prompt for the user identity first
    $Identity = Read-Host "Enter the user identity (e.g., JSchreiner)"
    
    # Retrieve the current description from AD
    $CurrentUser = Get-ADUser -Identity $Identity -Properties Description
    
    # Check if the user has a current description
    if ($CurrentUser.Description) {
        Write-Host "The current description for user $Identity is: '$($CurrentUser.Description)'"
    } else {
        Write-Host "The user $Identity does not have a description set."
    }
    
    # Prompt for the new description
    $NewDescription = Read-Host "Enter the new description (e.g., District 5 User - Shop 52 - Disabled <date> <ticket>)"
    
    # Update the AD user with the new description
    Set-ADUser -Identity $Identity -Description $NewDescription
    
    Write-Host "User $Identity has been updated with the new description: $NewDescription"
}

# The function won't run automatically unless explicitly called.
# To run it, call Disable-ADUserWithDescription


#-----------------------------------------------------------------------------------------------------------------


function ExitDesriptJG {echo $(" - Disabled $((get-date).ToShortDateString()) SR#$(read-host "SR number") GR.")}

#-----------------------------------------------------------------------------------------------------------------

`



#-----------------------------------------------------------------------------------------------------------------------	


function RandomPassword {
    param (
        [int]$Length
    )

    # If the Length is not provided as a parameter, prompt the user for it
    if (-not $Length) {
        $Length = Read-Host "Please enter the desired password length (minimum 4)"
    }

    # Ensure the desired length is at least 4 to accommodate one character from each set
    if ($Length -lt 4) {
        throw "Password length must be at least 4."
    }

    # Define the character sets (uppercase, lowercase, digits, special characters)
    $upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $lowerCase = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $numbers = '0123456789'.ToCharArray()
    $specialChars = '!@#$%^&*()-_=+[]{}'.ToCharArray()

    # Combine all character sets
    $allChars = $upperCase + $lowerCase + $numbers + $specialChars

    # Randomly select at least one character from each set to meet complexity requirements
    $password = @()
    $password += $upperCase | Get-Random
    $password += $lowerCase | Get-Random
    $password += $numbers | Get-Random
    $password += $specialChars | Get-Random

    # Fill the remaining characters randomly from the entire character set
    $remainingLength = $Length - $password.Count
    for ($i = 0; $i -lt $remainingLength; $i++) {
        $password += $allChars | Get-Random
    }

    # Shuffle the password to randomize the order
    $shuffledPassword = $password | Sort-Object { Get-Random }

    # Return the password as a string
    return -join $shuffledPassword
}

# Remove any automatic function calls from the script to avoid unintended execution.
# Now the function only runs when you explicitly call it, like this:
# $generatedPassword = RandomPassword
# Write-Output "Your new password is: $generatedPassword"



#-----------------------------------------------------------------------------------------------------------------------	
function LitSheet {
    # Prompt for input when the function is called
    $a = Read-Host "Please enter the username or identity"

    # Attempt to retrieve the AD user object
    $user = Get-ADUser -Identity $a -Properties EmailAddress, GivenName, Surname
    
    # Check if the user was found
    if (-not $user) {
        Write-Host "User not found: $a" -ForegroundColor Red
        return
    }

    # Prepare the email address (removing '.consultant' from the email)
    $email = $user.EmailAddress -replace '\.consultant', ''
    
    # Build the PSCustomObject with the relevant details
    $add = [PSCustomObject]@{
        email      = $email
        first_name = $user.GivenName
        last_name  = $user.Surname
        'Litigation Hold or Proxy Needed?' = (Read-Host "Describe litigation")
        'User Disabled Date' = (Get-Date).ToShortDateString()
        'Worked By' = (Read-Host "Created by?")
    }

    # Ensure the file exists and has headers
    $csvPath = "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Litigation_Hold.csv"
    if (Test-Path $csvPath) {
        # Import existing CSV to get headers
        $existingCsv = Import-Csv -Path $csvPath

        # If the file isn't empty, proceed to match headers
        if ($existingCsv.Count -gt 0) {
            # Get existing headers
            $csvHeaders = $existingCsv[0].PSObject.Properties.Name

            # Add missing properties to the $add object
            foreach ($header in $csvHeaders) {
                if (-not $add.PSObject.Properties[$header]) {
                    # Add missing headers with an empty value
                    Add-Member -InputObject $add -MemberType NoteProperty -Name $header -Value ''
                }
            }
        }
    }

    # Export to CSV
    $add | Export-Csv -Path $csvPath -Append -NoTypeInformation
}

# Now when you just type LitSheet, it will prompt you for the username.

#-----------------------------------------------------------------------------------------------------------------------	


# Function to update the OfficePhone attribute in Active Directory
function Update-OfficePhone {
    # Prompt for the user's SAM account name or user name
    $userName = Read-Host -Prompt "Please enter the SAMAccountName (username) of the user"

    # Prompt for the new office phone number
    $newPhoneNumber = Read-Host -Prompt "Enter the new office phone number"

    # Use Get-ADUser to check if the user exists in Active Directory
    $user = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue

    if ($null -ne $user) {
        # If the user exists, update the OfficePhone attribute using Set-ADUser
        Set-ADUser -Identity $userName -OfficePhone $newPhoneNumber
        Write-Host "Office phone number for $userName successfully updated to $newPhoneNumber"
    } else {
        Write-Host "User '$userName' not found in Active Directory. Please verify the username."
    }
}

# Note: This function will not execute automatically. You must explicitly call 'Update-OfficePhone'.



#-----------------------------------------------------------------------------------------------------------------------	
	function View-ExcelData {
    param (
        [string]$FilePath
    )

    # If no file path is provided, prompt the user
    if (-not $FilePath) {
        $FilePath = Read-Host "Enter the path to the Excel file you want to view"
    }

    # Import the Excel data
    $data = Import-Excel -Path $FilePath

    # Display the data
    $data
}


#-----------------------------------------------------------------------------------------------------------------------	
		function Edit-ExcelData {
    param (
        [string]$FilePath,
        [string]$SheetName = "Sheet1",
        [int]$Row = 1,
        [int]$Column = 1,
        [string]$NewValue
    )

    # If no file path or new value is provided, prompt the user
    if (-not $FilePath) {
        $FilePath = Read-Host "Enter the path to the Excel file you want to edit"
    }
    if (-not $NewValue) {
        $NewValue = Read-Host "Enter the new value for the cell"
    }

    # Import the Excel data
    $data = Import-Excel -Path $FilePath -WorksheetName $SheetName

    # Update the cell
    $data[$Row - 1][$Column - 1] = $NewValue

    # Export the data back to the Excel file
    $data | Export-Excel -Path $FilePath -WorksheetName $SheetName -AutoSize

    Write-Host "Data updated successfully."
}

#-----------------------------------------------------------------------------------------------------------------------	


	function set-autoreply {
	param([string]$a,[datetime]$b=(read-host "Enter the date (must be 4 hours ahead) ex. 12/11/2022 21:00"),[datetime]$c=(read-host "Enter the date (must be 4 hours ahead) ex. 12/11/2022 21:00"),[string]$d,[string]$e)
	Set-MailboxAutoReplyConfiguration $a@mdot.maryland.gov -AutoReplyState Scheduled -StartTime $b -EndTime $c -InternalMessage $d -ExternalMessage $e -ExternalAudience All}

#-----------------------------------------------------------------------------------------------------------------#

function Remmobile {
param([string]$user)
"`nRemoving Active sync devices....`n"
Get-MobileDeviceStatistics -Mailbox $user|select -exp Identity|Remove-MobileDevice -Confirm:$false
"`nDisabling OWA and Active Sync in Exchange....`n"
Set-CASMailbox $user -ActiveSyncEnabled:$false -OWAEnabled:$false
Get-CASMailbox $user|Ft -AutoSize} 
#-----------------------------------------------------------------------------------------------------------------#
function Remove-MobileDevice {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox
    )

    try {
        # Fetch all mobile devices associated with the specified mailbox
        $devices = Get-MobileDevice -Mailbox "$Mailbox@mdot.state.md.us" -ErrorAction Stop

        # Check if any devices were found
        if ($devices) {
            # Loop through each device and remove it without confirmation
            foreach ($device in $devices) {
                Remove-MobileDevice -Identity $device.Identity -Confirm:$false
                Write-Output "Removed device: $($device.Identity)"
            }
        }
        else {
            Write-Output "No mobile devices found for mailbox: $Mailbox"
        }
    }
    catch {
        # Output error message if something goes wrong
        Write-Error "Failed to remove mobile devices for mailbox: $Mailbox. Error: $_"
    }
}




#-----------------------------------------------------------------------------------------------------------------#

<#
	$UserCredential = Get-Credential
	$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
	Import-PSSession $Session -DisableNameChecking
#>

#-----------------------------------------------------------------------------------------------------------------#
	function remove-alias {
	param([string]$a) Set-ADUser $a -Clear proxyAddresses
	sleep -Seconds 3
	Set-ADUser $a -EmailAddress "$a@mdot.state.md.us"
	Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+'@mdot.state.md.us'),$('smtp:'+$a+'@mdotgov.mail.onmicrosoft.com')}}

#-----------------------------------------------------------------------------------------------------------------#
	function remove-groups {
	param([string]$a)
	Get-ADPrincipalGroupMembership $a|select -ExpandProperty name|%{Remove-ADPrincipalGroupMembership $a -MemberOf $_ -Confirm:$false}}

#-----------------------------------------------------------------------------------------------------------------#
function Remove-AllUserGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]${UserName}
    )

    # Fetch the groups the user is a member of
    $Groups = Get-ADPrincipalGroupMembership -Identity ${UserName} | Select-Object -ExpandProperty Name

    if ($Groups.Count -eq 0) {
        Write-Warning "${UserName} is not a member of any groups."
        return
    }

    # Display all groups to be removed
    Write-Host "The following groups will be removed for ${UserName}:" -ForegroundColor Yellow
    $Groups | ForEach-Object { Write-Host "- $_" -ForegroundColor Cyan }

    # Confirm the operation (optional, remove this block if you don't want a confirmation prompt)
    $Confirmation = Read-Host "Are you sure you want to remove ${UserName} from these groups? (Y/N)"
    if ($Confirmation -ne 'Y') {
        Write-Host "Operation canceled." -ForegroundColor Red
        return
    }

    # Remove the user from each group
    foreach ($Group in $Groups) {
        try {
            Remove-ADPrincipalGroupMembership -Identity ${UserName} -MemberOf ${Group} -Confirm:$false -ErrorAction Stop
            Write-Host "Successfully removed ${UserName} from group ${Group}" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to remove ${UserName} from group ${Group}: $_"
        }
    }
}
                                            #-----------------------------------------------------------------------------------------------------------------#

	function getuserjg {
	param($a)
	Get-ADUser $a -Properties *|fl Name,EmployeeID,Description,OfficePhone,Office,StreetAddress,DisplayName,Enabled,Lockedout,Homedirectory,EmailAddress,userPrincipalName,targetAddress,ExtensionAttribute1, AccountExpirationDate,DistinguishedName,PrimaryGroup,msExchArchiveName,MemberOf
	$b="$((Get-ADUser $a -Properties *|sort proxyaddresses).proxyaddresses|select-string '@')"
	$b=$b.Replace("smtp:","")
	$b=$b.Replace("SMTP:","")
	$b=$b.split()
	$b=$b|sort
	$b}

#-----------------------------------------------------------------------------------------------------------------#

	function acl1 {
	param([string]$a)
	get-acl $a|select @{l="path";e={$([string]$b=$_.path;$b=$b -replace '.+::',"";
	$b)}} -ExpandProperty access|ft filesystemrights,isinherited,identityreference -GroupBy path}

#-----------------------------------------------------------------------------------------------------------------#

	function finduser {
	param([string]$a)
	Get-ADUser -LDAPFilter "(name=$a*)" -Properties *|fl displayname,name,employeeid}

#-----------------------------------------------------------------------------------------------------------------#

	function addsheet {
	param($a)
	$add=[PSCustomObject]@{
	email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
	first_name=(Get-ADUser $a -properties *).GivenName;
	last_name=(Get-ADUser $a -properties *).Surname;
	group_name="SHA";
	OU=$(read-host "which OU?")
	'Creation Date'=(get-date).ToShortDateString();
	'Notes'="";
	'EIN?'=(Get-ADUser $a -properties *).EmployeeID
	'SR#'=$(read-host "SR number?")
	'Worked By'=$(read-host "Created by?")}
	$add|Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Adds_2025.csv" -Append}

#-----------------------------------------------------------------------------------------------------------------#

	function addlicense {
	param($a)
	$pathToExcel = '\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\SHA_Licenses.xlsx'
	$add=[PSCustomObject]@{
	email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
	first_name=(Get-ADUser $a -properties *).GivenName;
	last_name=(Get-ADUser $a -properties *).Surname;
	'Creation Date'=(get-date).ToShortDateString();
	'Notes'=$(read-host "F3 or G3?");
	'SR#'=$(read-host "SR number?")
	'Worked By'=$(read-host "Created by?");
	'License Added/Removed'="Added"}

	$add|Export-Excel $pathToExcel -Append }#-Force}
	
#-----------------------------------------------------------------------------------------------------------------#
	


	function add-alias {
	param([string]$a) Set-ADUser $a #-Clear proxyAddresses
	sleep -Seconds 5
	Set-ADUser $a -EmailAddress "$a@mdot.maryland.gov"
	Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+"@mdot.maryland.gov"),
	$('smtp:'+$a+"@mdot.maryland.gov"),
	$('smtp:'+$a+"@mdot.state.md.us"),
	$('smtp:'+$a+"@mdotgov.mail.onmicrosoft.com"),
	$('smtp:'+$a+"@sha.maryland.gov"),
	$('smtp:'+$a+"@sha.state.md.us")}}

#-----------------------------------------------------------------------------------------------------------------#

	function remove-alias {
	param([string]$a) Set-ADUser $a -Clear proxyAddresses
	sleep -Seconds 3
	Set-ADUser $a -EmailAddress "$a@mdot.state.md.us"
	Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+'@mdot.state.md.us'),$('smtp:'+$a+'@mdotgov.mail.onmicrosoft.com')}}

#-----------------------------------------------------------------------------------------------------------------#

	function LitSheetJG {
	param($a)
	$add=[PSCustomObject]@{
	email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
	first_name=(Get-ADUser $a -properties *).GivenName;
	last_name=(Get-ADUser $a -properties *).Surname;
	'Litigation Hold or Proxy Needed?'=$(read-host "Describe litigation");
	'User Disabled Date'=(get-date).ToShortDateString();
	'Worked By'=$(read-host "Created by?")}
	$add|Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Litigation_Hold.csv" -Append}

#-----------------------------------------------------------------------------------------------------------------#

	function delsheetJG {
	param($a)
	$add=[PSCustomObject]@{
	email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
	first_name=(Get-ADUser $a -properties *).GivenName;
	last_name=(Get-ADUser $a -properties *).Surname;
	Notes="";
	'Deletion Date'=(get-date).ToShortDateString();
	'EIN#'=(Get-ADUser $a -properties *).EmployeeID;
	'SR#'=$(read-host "SR number?");
	'Worked By'=$(read-host "Created by?")}
	$add|Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Deletes_2025.csv" -Append}

#-----------------------------------------------------------------------------------------------------------------#

	function ExitDesript {echo $(" - Disabled $((get-date).ToShortDateString()) SR#$(read-host "SR number") GR.")}

#-----------------------------------------------------------------------------------------------------------------#

	function chkprop {
	param([string]$a)
	sl ~\desktop
	get-aduser $a -Properties *|fl > "$a.txt"
	sleep -Seconds 3
	cat "$a.txt"|select-string $a}function remgrp {
	param([string]$a)
	get-adprincipalgroupmembership $a|select -expandproperty name|%{Remove-ADPrincipalGroupMembership $a -memberof $_ -Confirm:$false}}

#-----------------------------------------------------------------------------------------------------------------#

	function fix {
	param($a,$b)
	(get-aduser $a -Properties *).description|%{Set-ADUser $b -Description $_}
	(get-aduser $a -Properties *).StreetAddress|%{Set-ADUser $b -StreetAddress $_}
	(get-aduser $a -Properties *).office|%{Set-ADUser $b -Office $_}
	(get-aduser $a -Properties *).pobox|%{Set-ADUser $b -pobox $_}
	(get-aduser $a -Properties *).city|%{Set-ADUser $b -city $_}
	(get-aduser $a -Properties *).postalcode|%{Set-ADUser $b -postalcode $_}}

#--------------------------------------------------------------------------------------------


	function getgrp {
	param($a)
	Get-ADGroup -LDAPFilter "(name=$($a))" -Properties *|fl Name,Description,Notes,DistinguishedName}

#-----------------------------------------------------------------------------------------------------------------#

function groups {
    param (
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    try {
        # Get all groups the user is a member of
        $groups = Get-ADPrincipalGroupMembership -Identity $User -ErrorAction Stop

        # If groups exist, sort and return them
        if ($groups) {
            return $groups | Sort-Object Name | Select-Object -ExpandProperty Name
        }
        else {
            Write-Output "User '$User' is not a member of any groups."
        }
    }
    catch {
        Write-Warning "Failed to retrieve groups for user '$User'. Error: $_"
    }
}

#-----------------------------------------------------------------------------------------------------------------#

	function newmail {
param([string]$a)
@"
`$UserCredential = Get-Credential
`$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch1/PowerShell/ -Authentication Kerberos
Import-PSSession `$Session -disablenamechecking
set-ADServerSettings -viewentireforest `$True
Enable-RemoteMailbox $a -RemoteRoutingAddress '$a@mdotgov.mail.onmicrosoft.com' -DomainController shahqdc3.shacadd.ad.mdot.mdstate
"@|Set-Clipboard}

#-----------------------------------------------------------------------------------------------------------------#

function License {
param([string]$a)
Get-MgUserLicenseDetail -UserId "$a@mdot.state.md.us"
}



#-----------------------------------------------------------------------------------------------------------------#

function lockout {
 param([string]$a)
 get-winevent -FilterHashtable @{
 logname="security";
 id=4740} `
 -ComputerName shahqdc1|? message -match $a|
 SELECT -first 2|fl TimeCreated,MachineName,ProviderName,Id,Message}

#-----------------------------------------------------------------------------------------------------------------#


function checkSMStran {
	param([string]$a)
Get-Service -DisplayName *sms* -ComputerName SHAGBSMS1|ft -Autosize}
#-----------------------------------------------------------------------------------------------------------------#

function startSMSservice {
	param([string]$a)
Get-Service $a -ComputerName SHAGBSMS1|Start-Service -Verbose}

<#
#Scheduled Task Action
$a = New-ScheduledTaskAction `
-Execute "powershell.exe" `
-Argument "-File C:\Users\grebolledo_ADm\Desktop\MailStopScripts\D7\SHOP74.ps1"
$t=New-ScheduledTaskTrigger -At '08/01/2024 3:30 PM' -Once
$p=New-ScheduledTaskPrincipal -UserId "SHACADD\grebolledo_adm"  -RunLevel Highest
$s=New-ScheduledTaskSettingsSet
$d=New-ScheduledTask -Action $a -Principal $p -Trigger $t -Settings $s
Register-ScheduledTask MailStop_SHOP74 -InputObject $d
#>	

#-----------------------------------------------------------------------------------------------------------------#
function Remove-ConsultantFromDisplayName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$a
	)

        # Retrieve the user based on their a
        $user = Get-AdUser -Filter "SamAccountName -eq '$a'"
		
		$newDisplayName = $user.GivenName + " " + $user.Surname
        
        # Update the user's Display Name
        Set-AdUser -Identity $user -DisplayName $newDisplayName

	Write-Host ("Display Name updated successfully for user $a to:   " + $newDisplayName)

}
         
	
# Usage example:
# Remove-ConsultantFromDisplayName -a "johndoe"

#----------------------------------------------------------------------------------------



function ChangeReplyAddressToMDOTStandard {
	param(
	[string]$a
	) 
	Set-ADUser $a -Clear proxyAddresses
	sleep -Seconds 5
	
	Set-ADUser $a -EmailAddress "$a@mdot.maryland.gov"
	Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+"@mdot.maryland.gov"),
	$('smtp:'+$a+".consultant@mdot.maryland.gov"),
	$('smtp:'+$a+"@mdot.state.md.us"),
	$('smtp:'+$a+"@mdotgov.mail.onmicrosoft.com"),
	$('smtp:'+$a+"@sha.maryland.gov"),
	$('smtp:'+$a+"@sha.state.md.us")
	}
	
		
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------------

function Clear-ADExtensionAttribute1 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$a
    )

    # Import the Active Directory module if it's not already loaded
    if (-not (Get-Module -Name ActiveDirectory)) {
        Import-Module ActiveDirectory
    }

    try {
        # Retrieve the user object
        $User = Get-ADUser -Identity $a -ErrorAction Stop

        # Clear ExtensionAttribute1
        Set-ADUser -Identity $User -Clear ExtensionAttribute1

        Write-Host "ExtensionAttribute1 successfully cleared for $a."
    } catch {
        Write-Host "Error: $_"
    }
}



	
#-------------------------------------------------------------------------------------------------------------------------------------------------------------


function Clear-ADUserExpiration {
    param(
        [string]$a
    )

    # Check if the Active Directory module is available
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Host "Active Directory module not found. Please install the Active Directory module."
        return
    }

    try {
        # Get the user account by a
        $User = Get-ADUser -Filter { SamAccountName -eq $a }

        # Check if the user account exists
        if ($User -eq $null) {
            Write-Host "User account '$a' not found in Active Directory."
            return
        }

        # Clear the expiration date
        Set-ADAccountExpiration -Identity $User -DateTime $null

        Write-Host "Expiration date cleared for user '$a'."

    } catch {
        Write-Host "An error occurred: $_"
    }
}

# Usage example:
# Clear-ADUserExpiration -a "aToClear"

#-------------------------------------------------------------------------------------------------------------------------------------------------------------






function Get-VMUUID {
	 param (
		 [string]$VMName
	 )

	 # Get VM
	 $vm = Get-VM -Name $VMName

	 if ($vm) {
		 # Get VM UUID
		 $vmUUID = $vm.ExtensionData.Config.InstanceUuid

	 # Convert to uppercase
	 $vmUUIDUpper = $vmUUID.ToUpper()

	 # Copy to clipboard
	 $vmUUIDUpper | Set-Clipboard

	 Write-Host "VM UUID (Uppercase) copied to clipboard: $vmUUIDUpper"
	 } else {
		 Write-Host "Virtual machine not found: $VMName"
	 }  
}

#--------------------------------------------------------------------

function Get-VMNetworkReport {
	 param(
		 [string]$VMName
	 )

	 $report = Get-VM $VMName | Get-NetworkAdapter |
		 Select-Object @{
			 N="VM";E={$_.Parent.Name}
		 },
		 @{
			 N="NIC";E={$_.Name}
		 },
		 @{
			 N="Network";E={$_.NetworkName}
		 },
		 MacAddress,
		 @{
			 N='IP';E={
				 $vNIC = $_
				 ($_.Parent.ExtensionData.Guest.Net | Where-Object { $_.MacAddress -eq $vNIC.MacAddress }).IPAddress -join ', '
			 }
		 },
		 @{
			 N='DNS';E={($_.Parent.ExtensionData.Guest.Net.DNSConfig).IPAddress -join ', '}
		 }

	 return $report
 }
 
 #--------------------------------------------------------------------
 
 function Remove-VMFromDomain {
    param (
        [string]$vmName
    )

    # Define the domain
    $domain = "shacadd.ad.mdot.mdstate"

    # Unjoin the virtual machine from the domain
    Remove-Computer -ComputerName $vmName -UnjoinDomainCredential SHACADD\grebolledo_adm -WorkgroupName "WORKGROUP" -Force -Restart
}

# Example usage:
# Remove-VMFromDomain -vmName "YourVMName"

#--------------------------------------------------------------------------------------------

function AddLicense {
    # Import the required module for Excel operations
    Import-Module ImportExcel

    # Define the path to the Excel and CSV files
    $pathToExcel = '\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\SHA_Licenses.xlsx'
    $csvFilePath = "$env:USERPROFILE\Documents\LicenseInfo.csv"

    # Check if the Excel file exists
    if (-not (Test-Path $pathToExcel)) {
        Write-Host "❌ Error: The file path $pathToExcel does not exist."
        return
    }

    # Prompt for the user ID
    $userId = (Read-Host "Enter the user ID")

    # Retrieve AD User information
    $adUser = Get-ADUser -Identity $userId -Properties EmailAddress, GivenName, Surname

    # Error handling: Check if the AD user exists
    if ($null -eq $adUser) {
        Write-Host "User with ID $userId not found in Active Directory." -ForegroundColor Red
        return
    }

    # Process the email address, removing '.consultant'
    $email = $adUser.EmailAddress -replace '\.consultant'

    # Initialize the base custom object with common fields
    $add = @{
        email                = $email
        first_name           = $adUser.GivenName
        last_name            = $adUser.Surname
        License_Type         = Read-Host "Enter License Type (F3 or G3)"
        'SR#'                = Read-Host "Enter SR number"
        Worked_By            = "LRichardson2"
        'License_Added/Removed' = Read-Host "Was the License Added or Removed?"
        Notes                = ""
    }

    # Conditionally set Creation_Date based on user input
    $creationInput = Read-Host "Is there a creation date? (yes/no)"
    if ($creationInput.Trim().ToLower() -eq "yes") {
        $add["Creation_Date"] = (Get-Date).ToShortDateString()  # Set current date if yes
    } else {
        $add["Creation_Date"] = ""  # Leave blank if no
    }

    # Conditionally set Deletion_Date based on user input
    $deletionInput = Read-Host "Is there a deletion date? (yes/no)"
    if ($deletionInput.Trim().ToLower() -eq "yes") {
        $add["Deletion_Date"] = (Get-Date).ToShortDateString()  # Set current date if yes
    } else {
        $add["Deletion_Date"] = ""  # Leave blank if no
    }

    # Convert the hashtable to a PSCustomObject
    $add = [PSCustomObject]$add

    # Display the object for verification before export
    Write-Host "`n--- License Information ---"
    $add | Format-Table -AutoSize

    # Attempt to write the License Information to a CSV file
    try {
        $add | Export-Csv -Path $csvFilePath -NoTypeInformation -Append
        Write-Host "✅ License information saved to $csvFilePath"
    }
    catch {
        Write-Host "❌ Error writing to CSV file: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Open the CSV file in Notepad for review
    Start-Process "notepad.exe" $csvFilePath

    # Try to append the data to the Excel file in the SHA_Licenses worksheet
    try {
        $add | Export-Excel -Path $pathToExcel -WorksheetName 'SHA_Licenses' -Append
        Write-Host "✅ Successfully added license for $($add.email) to SHA_Licenses tab."

        # Optionally verify the data was written correctly
        $excelData = Import-Excel -Path $pathToExcel -WorksheetName 'SHA_Licenses'
        $isAdded = $excelData | Where-Object { $_.email -eq $add.email }

        if ($isAdded) {
            Write-Host "✅ Verification: License for $($add.email) was successfully added."
        } else {
            Write-Host "❌ Verification failed: License for $($add.email) was not added."
        }
    }
    catch {
        Write-Host "❌ Error: Could not save to the Excel file. Check if the file is open or if you have write permissions."
        Write-Host "Details: $($_.Exception.Message)"
    }
}

#--------------------------------------------------------------------------------------------



function ADUserExitProcedure {
    
    # Prompt for the username
    $Username = (Read-Host ("Enter the username"))

    # Hardcoded target OU
    $TargetOU = "OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate"
    Write-Host "The user will be moved to the following OU: $TargetOU" -ForegroundColor Cyan

    # Prompt for the additional description
    $AdditionalDescription = (Read-Host "Enter the additional description (e.g., Disabled 10/16/2024 SR123456)")

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
    } catch {
        Write-Host "Failed to write user details to file or open with Notepad: $_" -ForegroundColor Yellow
    }

    # Step 2: Prompt to remove the HomeDirectory
    $removeHomeDirectory = Read-Host "Do you want to remove the HomeDirectory for this user? (Y/N)"
    if ($removeHomeDirectory -eq 'Y' -or $removeHomeDirectory -eq 'y') {
        try {
            Set-ADUser -Identity $Username -HomeDirectory $null
            Write-Host "HomeDirectory removed for user $Username." -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove HomeDirectory for ${Username}: $_" -ForegroundColor Red
        }
    }

    # Step 3: Disable the user account
    try {
        Disable-ADAccount -Identity $Username
        Write-Host "User account for $Username has been disabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable user account for ${Username}: $_" -ForegroundColor Red
    }

    # Step 4: Move the user to the hardcoded target OU
    try {
        Move-ADObject -Identity $distinguishedName -TargetPath $TargetOU
        Write-Host "User $Username moved to OU: $TargetOU." -ForegroundColor Green
    } catch {
        Write-Host "Failed to move user $Username to the specified OU: $_" -ForegroundColor Red
    }

    # Step 5: Update the user description
    $newDescription = "$currentDescription - $AdditionalDescription"
    try {
        Set-ADUser -Identity $Username -Description $newDescription
        Write-Host "Description updated for user $Username." -ForegroundColor Green
    } catch {
        Write-Host "Failed to update description for ${Username}: $_" -ForegroundColor Red
    }

    # Step 6: Remove all group memberships except default groups (e.g., Domain Users)
    foreach ($group in $groups) {
        try {
            if ($group -notlike "*Domain Users*") {
                Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
                Write-Host "Removed $Username from group $group." -ForegroundColor Green
            }
        } catch {
            Write-Host "Failed to remove ${Username} from group ${group}: $_" -ForegroundColor Red
        }
    }

    Write-Host "Operation completed for user $Username." -ForegroundColor Green
}

# To run the function, just call it in your PowerShell session:
# Disable-ADUserExitProcedure

#--------------------------------------------------------------------------------------------


function Replace-EmailName {
    # Function to replace 'LRichardson2' with user-provided input

    # Prompt user for the replacement text
    $replaceText = Read-Host -Prompt "Enter the replacement text"

    # Validate user input (ensure it's not empty)
    if ([string]::IsNullOrWhiteSpace($replaceText)) {
        Write-Host "Invalid input. Please provide a valid replacement text." -ForegroundColor Red
        return
    }

    # Define the string with email addresses
    $emailAddresses = @'
LRichardson2@mdot.maryland.gov
LRichardson2@mdot.state.md.us
LRichardson2@mdotgov.mail.onmicrosoft.com
LRichardson2@sha.maryland.gov
LRichardson2@sha.state.md.us
'@

    # Perform the replacement (always replace 'LRichardson2')
    $result = $emailAddresses -replace "LRichardson2", $replaceText

    # Output the result
    Write-Output "Updated Email Addresses:"
    Write-Output $result
}

# The function will only execute if explicitly called
Write-Host "The script is loaded. Call the Replace-EmailName function to run." -ForegroundColor Green


#--------------------------------------------------------------------------------------------


function Enable-UserAccount {
    <#
    .SYNOPSIS
    Enables a disabled Active Directory user account.

    .DESCRIPTION
    This function prompts for a username and enables the specified user account
    in Active Directory if it is currently disabled.

    .EXAMPLE
    Enable-UserAccount
    Prompts for a username and enables the account.

    .NOTES
    Ensure you have the necessary permissions and the ActiveDirectory module available.
    #>

    # Prompt for the username of the account to enable
    $Username = Read-Host -Prompt "Enter the username of the account to enable"

    # Check if the username is provided
    if (![string]::IsNullOrWhiteSpace($Username)) {
        try {
            # Try to enable the user account
            Enable-ADAccount -Identity $Username
            Write-Output "User account '$Username' has been enabled successfully."
        }
        catch {
            # Handle any errors
            Write-Output "An error occurred while trying to enable the account '$Username'."
            Write-Output "Error details: $_"
        }
    } else {
        Write-Output "No username was provided. Please run the function again and provide a valid username."
    }
}

# Example usage
# Call the function to enable a user account


#--------------------------------------------------------------------------------------------


# Function to unlock a user account on all Domain Controllers
function Unlock_User_OnAllDCs {

    # Import Active Directory module (only necessary if not already imported)
    Import-Module ActiveDirectory

    # Prompt for username input
    $username = Read-Host "Enter the username (SamAccountName) you want to unlock"

    # Define a default file path for saving the log (you can adjust this path as necessary)
    $logFilePath = "C:\Temp\UnlockResults_$($username)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    # Ensure the directory exists, create if not
    $logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force
    }

    # Initialize the log file with a header
    Add-Content -Path $logFilePath -Value "`nUnlock attempt for user: $username started at $(Get-Date)`n"

    # Get the list of all Domain Controllers
    $domainControllers = Get-ADDomainController -Filter *

    # Loop through each Domain Controller and attempt to unlock the user
    foreach ($dc in $domainControllers) {
        # Write to the console and log which Domain Controller is being checked
        $message = "Attempting to unlock user '$username' on Domain Controller: $($dc.HostName)"
        Write-Host $message
        Add-Content -Path $logFilePath -Value $message

        # Run the unlock account command against the current Domain Controller
        try {
            # Unlock the user account on the current DC
            Unlock-ADAccount -Identity $username -Server $dc.HostName

            $result = "User '$username' successfully unlocked on Domain Controller: $($dc.HostName)"
            Write-Host $result -ForegroundColor Green
            Add-Content -Path $logFilePath -Value $result
        } catch {
            # Handle specific disk space errors and other generic errors
            if ($_.Exception.Message -like "*not enough space*") {
                $errorMessage = "Disk space issue on Domain Controller: $($dc.HostName). Please check disk space and retry."
                Write-Host $errorMessage -ForegroundColor Yellow
            } else {
                $errorMessage = "Error unlocking user '$username' on Domain Controller: $($dc.HostName). Details: $_"
                Write-Host $errorMessage -ForegroundColor Red
            }
            
            # Log the error
            Add-Content -Path $logFilePath -Value $errorMessage
        }
    }

    # Finalize log
    Add-Content -Path $logFilePath -Value "`nUnlock process completed at $(Get-Date)`n"

    # Automatically open the results in Notepad
    Start-Process notepad.exe $logFilePath
}

# Example usage (function is not called automatically)
# UnlockUserOnDCs






#-----------------------------------------------------------------------------------------------------------------------



# Function to check if a user account is locked on all Domain Controllers and log results to Notepad
function AccLockoutCheck {

    # Import Active Directory module (only necessary if not already imported)
    Import-Module ActiveDirectory

    # Prompt for username input
    $username = Read-Host "Enter the username (SamAccountName) you want to check for lockout status"

    # Define a default file path for saving the log (you can adjust this path as necessary)
    $logFilePath = "C:\Temp\LockoutResults_$($username)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    # Ensure the directory exists, create if not
    $logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force
    }

    # Initialize the log file with a header
    Add-Content -Path $logFilePath -Value "`nLockout check for user: $username started at $(Get-Date)`n"

    # Get the list of all Domain Controllers
    $domainControllers = Get-ADDomainController -Filter *

    # Loop through each Domain Controller and check the lockout status
    foreach ($dc in $domainControllers) {
        # Write to the console and log which Domain Controller is being checked
        $message = "Checking lockout status on Domain Controller: $($dc.HostName)"
        Write-Host $message
        Add-Content -Path $logFilePath -Value $message

        # Run the lockout check against the current Domain Controller
        try {
            $user = Get-ADUser -Identity $username -Server $dc.HostName -Properties LockoutTime

            if ($user.LockoutTime -ne $null) {
                $result = "The user account '$username' is LOCKED on Domain Controller: $($dc.HostName) since $($user.LockoutTime)"
            } else {
                $result = "The user account '$username' is NOT LOCKED on Domain Controller: $($dc.HostName)"
            }

            # Output the result to the console and log file
            Write-Host $result
            Add-Content -Path $logFilePath -Value $result
        } catch {
            # Log any errors (e.g., if user not found on a specific Domain Controller)
            $errorMessage = "Error checking Domain Controller: $($dc.HostName). Details: $_"
            Write-Host $errorMessage -ForegroundColor Red
            Add-Content -Path $logFilePath -Value $errorMessage
        }
    }

    # Finalize log
    Add-Content -Path $logFilePath -Value "`nLockout check completed at $(Get-Date)`n"

    # Automatically open the results in Notepad
    Start-Process notepad.exe $logFilePath
}



#--------------------------------------------------------------------------------------------


# Function to Add or Remove a user from Active Directory groups
function Manage-UserGroups {
    # Prompt for the username
    $username = Read-Host "Enter the username (SamAccountName) of the user"

    # Prompt for the operation (Add or Remove)
    $operation = Read-Host "Enter the operation (Add or Remove) for groups"

    # Validate the operation
    if ($operation -notmatch '^(Add|Remove)$') {
        Write-Host "Invalid operation. Please enter 'Add' or 'Remove'." -ForegroundColor Red
        return
    }

    # Prompt for group names (comma-separated) and split into an array
    $groupNamesInput = Read-Host "Enter group names (comma-separated)"
    $groupNames = $groupNamesInput -split ','

    # Trim whitespace from each group name
    $groupNames = $groupNames | ForEach-Object { $_.Trim() }

    # Check if the user exists in Active Directory
    $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue

    if (-not $user) {
        Write-Host "User $username not found in Active Directory." -ForegroundColor Yellow
        return
    }

    foreach ($groupName in $groupNames) {
        # Check if the group exists in Active Directory
        $group = Get-ADGroup -Filter "SamAccountName -eq '$groupName'" -ErrorAction SilentlyContinue

        if (-not $group) {
            Write-Host "Group $groupName does not exist in Active Directory." -ForegroundColor Yellow
            continue
        }

        # Add or Remove the user from the group based on the selected operation
        if ($operation -eq 'Add') {
            try {
                Add-ADGroupMember -Identity $group -Members $user
                Write-Host "Added user $username to group $groupName" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to add user $username to group $groupName. Error: $_" -ForegroundColor Red
            }
        }
        elseif ($operation -eq 'Remove') {
            try {
                Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
                Write-Host "Removed user $username from group $groupName" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to remove user $username from group $groupName. Error: $_" -ForegroundColor Red
            }
        }
    }
}

# Usage Instructions
Write-Host "To manage user groups, call the Manage-UserGroups function." -ForegroundColor Cyan
Write-Host "Example: Manage-UserGroups" -ForegroundColor Cyan






#-----------------------------------------------------------------------------------------------------------------------



# Function to check if a user account is locked on all Domain Controllers and log results to Notepad
function AccLockoutCheck {

    # Import Active Directory module (only necessary if not already imported)
    Import-Module ActiveDirectory

    # Prompt for username input
    $username = Read-Host "Enter the username (SamAccountName) you want to check for lockout status"

    # Define a default file path for saving the log (you can adjust this path as necessary)
    $logFilePath = "C:\Temp\LockoutResults_$($username)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    # Ensure the directory exists, create if not
    $logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force
    }

    # Initialize the log file with a header
    Add-Content -Path $logFilePath -Value "`nLockout check for user: $username started at $(Get-Date)`n"

    # Get the list of all Domain Controllers
    $domainControllers = Get-ADDomainController -Filter *

    # Loop through each Domain Controller and check the lockout status
    foreach ($dc in $domainControllers) {
        # Write to the console and log which Domain Controller is being checked
        $message = "Checking lockout status on Domain Controller: $($dc.HostName)"
        Write-Host $message
        Add-Content -Path $logFilePath -Value $message

        # Run the lockout check against the current Domain Controller
        try {
            $user = Get-ADUser -Identity $username -Server $dc.HostName -Properties LockoutTime

            if ($user.LockoutTime -ne $null) {
                $result = "The user account '$username' is LOCKED on Domain Controller: $($dc.HostName) since $($user.LockoutTime)"
            } else {
                $result = "The user account '$username' is NOT LOCKED on Domain Controller: $($dc.HostName)"
            }

            # Output the result to the console and log file
            Write-Host $result
            Add-Content -Path $logFilePath -Value $result
        } catch {
            # Log any errors (e.g., if user not found on a specific Domain Controller)
            $errorMessage = "Error checking Domain Controller: $($dc.HostName). Details: $_"
            Write-Host $errorMessage -ForegroundColor Red
            Add-Content -Path $logFilePath -Value $errorMessage
        }
    }

    # Finalize log
    Add-Content -Path $logFilePath -Value "`nLockout check completed at $(Get-Date)`n"

    # Automatically open the results in Notepad
    Start-Process notepad.exe $logFilePath
}


#----------------------------------------------------------------------------------


function UpdateEIN {
    # Import the Active Directory module if it's not already loaded
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to load the Active Directory module. Please ensure it is installed and accessible."
        return
    }

    # Prompt for the username
    $username = Read-Host "Enter the username (SamAccountName) of the user"

    # Prompt for the new employee ID
    $newEmployeeID = Read-Host "Enter the new employee ID (leave blank to clear)"

    try {
        # Attempt to get the user by their SamAccountName
        $user = Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction Stop

        if ($user) {
            if ($newEmployeeID) {
                # Update the employeeID attribute
                Set-ADUser -Identity $user -Replace @{employeeID = $newEmployeeID } -ErrorAction Stop
                Write-Output "Updated employeeID for user '$username' to '$newEmployeeID'."
            }
            else {
                # Clear the employeeID attribute if no value is provided
                Set-ADUser -Identity $user -Clear "employeeID" -ErrorAction Stop
                Write-Output "Cleared employeeID for user '$username'."
            }
        }
        else {
            Write-Warning "User not found: $username"
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}



#--------------------------------------------------------------------------------------------

function getconnections {

Get-NetTCPConnection -State Established -AppliedSetting Internet|? LocalAddress -NE '127.0.0.1'

$a=(Get-NetTCPConnection -State Established -AppliedSetting Internet|? LocalAddress -NE '127.0.0.1').OwningProcess

$b=$a|%{Get-Process -Id $_|select StartTime,Name,Id,Path}

$b|ft -AutoSize}
 
#--------------------------------------------------------------------------------------------


function Set-AutoReply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$User,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate
    )

    try {
        # Check if the mailbox exists
        $mailbox = Get-Mailbox -Identity $User -ErrorAction Stop

        # Configure the auto-reply settings
        Set-MailboxAutoReplyConfiguration -Identity $User `
            -AutoReplyState Scheduled `
            -StartTime (Get-Date) `
            -EndTime $EndDate `
            -InternalMessage $Message `
            -ExternalMessage $Message `
            -ExternalAudience All

        # Display the configured settings to the user
        $config = Get-MailboxAutoReplyConfiguration -Identity $User
        Write-Host "Auto-reply has been successfully configured for $User." -ForegroundColor Green
        $config | Format-List AutoReplyState, StartTime, EndTime, InternalMessage, ExternalMessage
    }
    catch [Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException] {
        # Specific error for when the mailbox cannot be found
        Write-Error "The mailbox '$User' could not be found. Please verify the email address and try again."
    }
    catch {
        # General error handling for unexpected issues
        Write-Error "An unexpected error occurred: $_"
    }
}

# Prompt the admin for the username
$username = Read-Host "Enter the username or email address to find the user's information"

# Try to retrieve the user from Active Directory
try {
    # Retrieve the user info using Get-ADUser (requires the Active Directory module)
    $userInfo = Get-ADUser -Identity $username -Properties GivenName, Surname -ErrorAction Stop

    # Extract the user's first and last name
    $fullName = "$($userInfo.GivenName) $($userInfo.Surname)"
    Write-Host "Found user: $fullName" -ForegroundColor Green
}
catch {
    Write-Error "Unable to find user '$username' in Active Directory. Please check the username and try again."
    return
}

# Define the OOO message using the retrieved user's full name
$message = "I am no longer employed by MDOT. All inquiries should be e-mailed to $fullName. Thank you."

# Call the Set-AutoReply function with the retrieved information
Set-AutoReply -User $username `
              -Message $message `
              -EndDate (Get-Date).AddYears(1)  # Set auto-reply for one year




New-PSDrive -Name M -PSProvider FileSystem -Root \\shahqfs1\ADMUsers\OIT\LRichardson2
import-module m:\pcinfo.psm1



Variable
$end="machinename","timecreated","providername","id","message"



#--------------------------------------------------------------------------------------------
# Import the Active Directory module
Import-Module ActiveDirectory

# Define the function
function Copy-Description_OfficePhone_Office_StreetAddress {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://docs.microsoft.com/powershell/module/activedirectory/set-aduser')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceUser,

        [Parameter(Mandatory = $true)]
        [string]$TargetUser
    )

    # Begin verbose logging
    Write-Verbose "Starting the Update-Description_OfficePhone_Office_StreetAddress function."

    # Retrieve the source user properties
    Write-Verbose "Retrieving attributes from source user: $SourceUser"
    $SourceUserProperties = Get-ADUser -Identity $SourceUser -Properties Description, OfficePhone, Office, StreetAddress

    if ($SourceUserProperties -eq $null) {
        Write-Warning "Source user '$SourceUser' not found. Exiting function."
        return
    }

    # Display the retrieved properties for confirmation
    Write-Host "Retrieved the following attributes from the source user:" -ForegroundColor Cyan
    Write-Host "Description: $($SourceUserProperties.Description)"
    Write-Host "Office Phone: $($SourceUserProperties.OfficePhone)"
    Write-Host "Office: $($SourceUserProperties.Office)"
    Write-Host "Street Address: $($SourceUserProperties.StreetAddress)"
    Write-Host "`n"

    # Confirm with the user before proceeding
    $Confirmation = Read-Host -Prompt "Do you want to copy these attributes to the target user? (Yes/No)"
    if ($Confirmation -ne "Yes") {
        Write-Verbose "Operation canceled by user."
        return
    }

    # Update the target user attributes
    if ($PSCmdlet.ShouldProcess($TargetUser, "Copy attributes from $SourceUser")) {
        Write-Verbose "Copying attributes to the target user: $TargetUser"
        Set-ADUser -Identity $TargetUser `
            -Description $SourceUserProperties.Description `
            -OfficePhone $SourceUserProperties.OfficePhone `
            -Office $SourceUserProperties.Office `
            -StreetAddress $SourceUserProperties.StreetAddress -Verbose
        Write-Host "Attributes successfully copied to the target user!" -ForegroundColor Green
    } else {
        Write-Verbose "Operation skipped by user."
    }

    Write-Verbose "Function execution completed."
}

# Prompt the user for input
$SourceUserInput = Read-Host -Prompt "Enter the username of the source user"
$TargetUserInput = Read-Host -Prompt "Enter the username of the target user"

# Call the function with verbose logging
Update-Description_OfficePhone_Office_StreetAddress -SourceUser $SourceUserInput -TargetUser $TargetUserInput -Verbose


#--------------------------------------------------------------------------------------------
  #Variables

$end = "machinename","timecreated","providername","id","message"
$User = "SHACADD\LRichardson2_Adm"
$PWord = (ConvertTo-SecureString -AsPlainText 'PeterPan44S*' -Force)
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$sni = "J'dan Vaughn (Consultant) <JVaughn.consultant@mdot.maryland.gov>; Theophilus Osei-Adu <TOseiAdu@mdot.maryland.gov>; Paulin Ama (Consultant) <PAma.consultant@mdot.maryland.gov>; Lavar Richardson <LRichardson2@mdot.maryland.gov>; Marcus Williams <MWilliams28@mdot.maryland.gov>; Marcus Buckley <MBuckley@mdot.maryland.gov>"
$exit1 = "
1. Account Disabled and moved to inactive users OU
2. Account Hidden from the Global Address Book
3. Security groups documented and removed
4. Active sync and OWA were disabled in Exchange
5. Active sync devices were removed
6. Out of office until $((get-date).AddDays(14).ToShortDateString())."



