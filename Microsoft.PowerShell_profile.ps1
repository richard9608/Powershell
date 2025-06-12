#--------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------
#.Help
<# 
.SYNOPSIS
    Sets the specified permission for a user on a folder.

.DESCRIPTION
    This function modifies the Access Control List (ACL) of a folder to grant the specified permission to a user.

.PARAMETER FolderPath
    The path to the folder on which to set the permission.

.PARAMETER User
    The username or user account to which the permission will be granted.

.PARAMETER Permission
    The level of permission to grant. Valid values are: FullControl, Modify, ReadAndExecute, Read, Write.

.EXAMPLE
    Set-FolderPermission -FolderPath "C:\SharedFolder" -User "DOMAIN\User" -Permission "Read"

.NOTES
    Author: Your Name
    Date: Today's Date
#>
function Set-FolderPermission {
    param (
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [Parameter(Mandatory)]
        [string]$User,

        [Parameter(Mandatory)]
        [ValidateSet("FullControl", "Modify", "ReadAndExecute", "Read", "Write")]
        [string]$Permission
    )

    if (-Not (Test-Path -Path $FolderPath)) {
        Write-Error "Folder path does not exist: $FolderPath"
        return
    }

    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $User,
        $Permission,
        $inheritanceFlags,
        $propagationFlags,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $acl = Get-Acl -Path $FolderPath
    $acl.SetAccessRule($accessRule)

    try {
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-Host "✅ $Permission permission set for $User on $FolderPath"
    }
    catch {
        Write-Error "Failed to set ACL: $_"
    }
}



#--------------------------------------------------------------------------------------------

function groups {
    param([Parameter(mandatory = $true)]
        [string]$user)
    Get-ADPrincipalGroupMembership -Identity $user | Sort-Object name | Select-Object -exp name
}


#--------------------------------------------------------------------------------------------
function findaccount {
    param([string]$user)
    $DC = "mdotgbfrdc1.ad.mdot.mdstate",
    "MAABWIDC1.maa.ad.mdot.mdstate",
    "TSOGBDC1.mdothq.ad.mdot.mdstate",
    "MDTAICCDC01.mdta.ad.mdot.mdstate",
    "MPADMTENTDC01.mpa.ad.mdot.mdstate",
    "MTACWDRDC1.mtant1.ad.mdot.mdstate",
    "MVAWSDC1.mvant1.ad.mdot.mdstate",
    "SHAGBDC1.shacadd.ad.mdot.mdstate"
    $result = $DC | ForEach-Object { Get-ADUser -LDAPFilter "(samaccountname=$user*)" -Server $_ -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description }
    $result | Format-Table -AutoSize
}
 

# --------------------------------------------------------------------

function Add-SHARecord {
    [CmdletBinding()]
    param ()

    # --- Fetch AD User Info ---
    $userId = Read-Host "Enter UserID (sAMAccountName)"
    $adUser = Get-ADUser -Identity $userId -Properties EmailAddress, GivenName, Surname, EmployeeID
    if (-not $adUser) {
        Write-Host "❌ User not found in AD." -ForegroundColor Red
        return
    }

    # --- Ask which records to add ---
    Write-Host "`nWhich record(s) do you want to add? (Enter numbers separated by comma, e.g. 1,2)"
    Write-Host "1. Adds"
    Write-Host "2. FMT"
    Write-Host "3. License"
    $recordTypes = Read-Host "Selection"
    $selected = $recordTypes -split "," | ForEach-Object { $_.Trim() }

    # --- Always collected fields (if needed for any selected sheet) ---
    if ($selected -contains "1" -or $selected -contains "2") {
        $ou = Read-Host "Which OU?"
    }
    if ($selected -contains "1" -or $selected -contains "3") {
        $srNumber = Read-Host "SR#"
    }
    if ($selected -contains "3") {
        $licenseType = Read-Host "Enter License Type (F3 or G3)"
        $addedOrRemoved = Read-Host "Was the License Added or Removed?"
        $creation = Read-Host "Is there a creation date? (yes/no)"
        $creationDate = if ($creation -eq "yes") { (Get-Date).ToShortDateString() } else { "" }
        $deletion = Read-Host "Is there a deletion date? (yes/no)"
        $deletionDate = if ($deletion -eq "yes") { (Get-Date).ToShortDateString() } else { "" }
    }

    # --- Always reused fields ---
    $email = $adUser.EmailAddress -replace '\.consultant'
    $first = $adUser.GivenName
    $last = $adUser.Surname
    $ein = $adUser.EmployeeID
    $workedBy = "LRichardson2"  # Always this value

    # --- Now generate and save each record as needed ---
    if ($selected -contains "1") {
        $add = [PSCustomObject]@{
            email           = $email
            first_name      = $first
            last_name       = $last
            group_name      = "SHA"
            OU              = $ou
            'Creation Date' = (Get-Date).ToShortDateString()
            'Notes'         = ""
            'EIN?'          = $ein
            'SR#'           = $srNumber
            "Worked By"     = $workedBy
        }
        $addsPath = "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Adds_2025.csv"
        $add | Export-Csv -Path $addsPath -NoTypeInformation -Append
        Write-Host "✅ 'Adds' record written."
    }

    if ($selected -contains "2") {
        $fmt = [PSCustomObject]@{
            email           = $email
            first_name      = $first
            last_name       = $last
            group_name      = "SHA"
            OU              = $ou
            'Creation Date' = (Get-Date).ToShortDateString()
            'Notes'         = ""
            'EIN?'          = $ein
        }
        $fmtPath = "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_FMT_Adds_2025.csv"
        $fmt | Export-Csv -Path $fmtPath -NoTypeInformation -Append
        Write-Host "✅ 'FMT' record written."
    }

    if ($selected -contains "3") {
        $lic = [PSCustomObject]@{
            email                   = $email
            first_name              = $first
            last_name               = $last
            License_Type            = $licenseType
            'SR#'                   = $srNumber
            Worked_By               = $workedBy
            'License_Added/Removed' = $addedOrRemoved
            Notes                   = ""
            Creation_Date           = $creationDate
            Deletion_Date           = $deletionDate
        }
        # Write to CSV as before
        $licCsvPath = "$HOME\Documents\LicenseInfo.csv"
        $lic | Export-Csv -Path $licCsvPath -NoTypeInformation -Append
        Write-Host "✅ 'License' record written to CSV."

        # Write to Excel (worksheet SHA_Licenses, hardcoded path)
        $pathToExcel = '\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\SHA_Licenses.xlsx'
        $worksheetName = 'SHA_Licenses'
        $lic | Export-Excel -Path $pathToExcel -WorksheetName $worksheetName -Append
        Write-Host "✅ 'License' record appended to Excel worksheet ($worksheetName)."
    }

    Write-Host "`nAll selected records have been processed."
}

# --------------------------------------------------------------------



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
    }
    catch {
        Write-Host "Error: $_"
    }
}

#--------------------------------------------------------------------------------------------
#Get applications installed on a remote computer that are not Microsoft applications
# This function retrieves a list of installed applications on a remote computer, excluding Microsoft applications.
function getapps2 {
    param([Parameter(mandatory = $true)]
        [string]$ComputerName)
    Invoke-Command $ComputerName { get-package -providername programs |
            Sort-Object name | Where-Object name -notmatch "Microsoft.+" | Select-Object Version, Name } |
            Format-Table Version, Name, PSComputerName -AutoSize
}
#--------------------------------------------------------------------------------------------
#Get applications installed on a remote computer that are Microsoft applications
# This function retrieves a list of installed Microsoft applications on a remote computer.
function getapps {
    param([Parameter(mandatory = $true)]
        [string]$ComputerName)
    Invoke-Command $ComputerName { get-package -providername programs |
            Sort-Object name | Select-Object Version, Name } | Format-Table Version, Name, PSComputerName -AutoSize
}
#--------------------------------------------------------------------------------------------
function Set-EmailName {
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

#--------------------------------------------------------------------------------------------
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
    }
    else {
        Write-Host "User '$userName' not found in Active Directory. Please verify the username."
    }
}

#--------------------------------------------------------------------------------------------
function SetAccountExpiration {
    # Prompt for Username and Expiration Date
    $username = Read-Host "Please enter the username"
    $expirationDate = Read-Host "Please enter the expiration date (MM/dd/yyyy)"
    
    # Convert the date to a valid DateTime object
    try {
        $expirationDate = [datetime]::ParseExact($expirationDate, 'MM/dd/yyyy', $null)
    }
    catch {
        Write-Host "Invalid date format. Please ensure the date is in MM/dd/yyyy format." -ForegroundColor Red
        return  # Return instead of exit to avoid closing the entire session
    }
    
    # Set the account expiration date for the specified user
    try {
        Get-ADUser -Identity $username -ErrorAction Stop | Set-ADAccountExpiration -Date $expirationDate
        Write-Host "The account expiration date for $username has been successfully set to $($expirationDate.ToString('MM/dd/yyyy'))."
    }
    catch {
        Write-Host "Failed to set the expiration date. Please check the username or date format." -ForegroundColor Red
        return
    }

    # Export results to Notepad
    $result = "Account: $username`nExpiration Date: $($expirationDate.ToString('MM/dd/yyyy'))"
    $result | Out-File -FilePath "$env:TEMP\AccountExpiration.txt"
    notepad.exe "$env:TEMP\AccountExpiration.txt"
}

# The script now only executes when Set-AccountExpiration is called explicitly

#--------------------------------------------------------------------------------------------

function groupsLR {
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
#--------------------------------------------------------------------------------------------

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


# Function to Add or Remove a user from Active Directory groups
function Set-ADUserGroups {
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
        email                   = $email
        first_name              = $adUser.GivenName
        last_name               = $adUser.Surname
        License_Type            = Read-Host "Enter License Type (F3 or G3)"
        'SR#'                   = Read-Host "Enter SR number"
        Worked_By               = "LRichardson2"
        'License_Added/Removed' = Read-Host "Was the License Added or Removed?"
        Notes                   = ""
    }

    # Conditionally set Creation_Date based on user input
    $creationInput = Read-Host "Is there a creation date? (yes/no)"
    if ($creationInput.Trim().ToLower() -eq "yes") {
        $add["Creation_Date"] = (Get-Date).ToShortDateString()  # Set current date if yes
    }
    else {
        $add["Creation_Date"] = ""  # Leave blank if no
    }

    # Conditionally set Deletion_Date based on user input
    $deletionInput = Read-Host "Is there a deletion date? (yes/no)"
    if ($deletionInput.Trim().ToLower() -eq "yes") {
        $add["Deletion_Date"] = (Get-Date).ToShortDateString()  # Set current date if yes
    }
    else {
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
        }
        else {
            Write-Host "❌ Verification failed: License for $($add.email) was not added."
        }
    }
    catch {
        Write-Host "❌ Error: Could not save to the Excel file. Check if the file is open or if you have write permissions."
        Write-Host "Details: $($_.Exception.Message)"
    }
}
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
        $templateUserData = Get-ADUser -Identity $TemplateUser -Properties Description, Office, StreetAddress, POBox, City, PostalCode, HomeDirectory, DistinguishedName, MemberOf
        if (-not $templateUserData) {
            throw "Template user '$TemplateUser' not found in Active Directory."
        }

        # Get target user details
        Write-Verbose "Fetching attributes for target user: $TargetUser"
        $targetUserData = Get-ADUser -Identity $TargetUser -Properties DistinguishedName, MemberOf
        if (-not $targetUserData) {
            throw "Target user '$TargetUser' not found in Active Directory."
        }

        # Update target user's attributes
        Write-Verbose "Updating target user's attributes from template..."
        Set-ADUser -Identity $TargetUser `
            -Description $templateUserData.Description `
            -Office $templateUserData.Office `
            -StreetAddress $templateUserData.StreetAddress `
            -POBox $templateUserData.POBox `
            -City $templateUserData.City `
            -PostalCode $templateUserData.PostalCode -Verbose

        # Set Home Directory
        if ($templateUserData.HomeDirectory) {
            $homeDirBase = Split-Path -Path $templateUserData.HomeDirectory -Parent
            $newHomeDirectory = "$homeDirBase\$TargetUser"
            Write-Verbose "Setting home directory: $newHomeDirectory"

            if (-not (Test-Path -Path $newHomeDirectory)) {
                New-Item -Path $newHomeDirectory -ItemType Directory -Force | Out-Null
            }

            Set-ADUser -Identity $TargetUser -HomeDirectory $newHomeDirectory -HomeDrive "M" -Verbose
        }
        else {
            Write-Warning "Template user has no HomeDirectory. Skipping home directory transfer."
        }

        # Wait for changes to apply
        Start-Sleep -Seconds 4

        # Compare and transfer group memberships
        Write-Verbose "Transferring group memberships..."
        $templateGroups = ($templateUserData.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name)
        $targetGroups = ($targetUserData.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name)

        # Identify missing groups
        $missingGroups = $templateGroups | Where-Object { $_ -notin $targetGroups }

        if ($missingGroups) {
            Write-Verbose "Adding target user to missing groups..."
            foreach ($group in $missingGroups) {
                try {
                    Add-ADGroupMember -Identity $group -Members $TargetUser -Verbose
                }
                catch {
                    Write-Warning "Failed to add $TargetUser to group '$group'. Error: $_"
                }
            }
        }
        else {
            Write-Output "No missing groups detected."
        }

        # Move target user to template's OU
        Write-Verbose "Moving user to template's Organizational Unit..."
        $destinationOU = ($templateUserData.DistinguishedName -split ",", 2)[1]
        if ($targetUserData.DistinguishedName) {
            Move-ADObject -Identity $targetUserData.DistinguishedName -TargetPath $destinationOU -Verbose
        }
        else {
            Write-Warning "Could not determine target user's Distinguished Name (DN). Skipping move."
        }

        Write-Output "User '$TargetUser' successfully transferred and moved to '$destinationOU'."

        # Final group comparison
        Write-Verbose "Final group membership comparison after updates:"
        Compare-Object -ReferenceObject $templateGroups -DifferenceObject ($TargetUser | Get-ADUser -Properties MemberOf | Select-Object -ExpandProperty MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name) -IncludeEqual

    }
    catch {
        Write-Error "An error occurred: $_"
    }
}
#--------------------------------------------------------------------------------------------

function ConvertTo-ProperCase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
        [string[]]$InputString
    )

    process {
        $combined = ($InputString -join ' ').ToLower()

        return (
            ($combined -split '\s+') |
                Where-Object { $_.Length -gt 0 } |  # 💥 SKIP empty strings
                ForEach-Object { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }
        ) -join ' '
    }
}

#--------------------------------------------------------------------------------------------

<#
.SYNOPSIS
    Retrieves the last logon details for a given user.
.DESCRIPTION
    Queries Active Directory for user logon data and writes it to a file.
.PARAMETER UserName
    The username (sAMAccountName) of the AD user.
.EXAMPLE
    .\Get-LastLogon.ps1 -UserName "jdoe"
.NOTES
    Author: You
    Date: 2025-04-11
#>
Function Last-Logon {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )
    Get-ADUser -Identity $UserName -Properties * |
        Select-Object Name, DisplayName, UserPrincipalName, Department, Office, whenCreated, LastLogonDate, lastLogon, lastLogoff | Format-List
}

#--------------------------------------------------------------------------------------------


function Add-SalesforceAzure_SSO {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    try {
        # Get the user object with group memberships
        $user = Get-ADUser -Identity $UserName -Properties MemberOf

        # Define target groups
        $targetGroups = @("SHASalesforceAzure_SSO", "SHA_SFDC_SSO")

        # Initialize a list for missing groups
        $groupsToAdd = @()

        foreach ($group in $targetGroups) {
            if (-not ($user.MemberOf -match $group)) {
                $groupsToAdd += $group
            }
        }

        if ($groupsToAdd.Count -gt 0) {
            Add-ADPrincipalGroupMembership -Identity $UserName -MemberOf $groupsToAdd -Verbose
            Write-Host "User '$UserName' added to: $($groupsToAdd -join ', ')"
        }
        else {
            Write-Host "User '$UserName' is already a member of all target groups."
        }
    }
    catch {
        Write-Error "Failed to process user '$UserName': $_"
    }
}

#--------------------------------------------------------------------------------------------
function New-LRRemoteMailbox {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    # Define credential path
    $CredentialPath = "C:\Users\LRichardson2_adm\Documents\Credentials.xml"

    # Load credentials
    if (-not (Test-Path $CredentialPath)) {
        Write-Error "❌ Credentials file not found at '$CredentialPath'. Use `Get-Credential | Export-CliXml -Path '$CredentialPath'` to create it."
        return
    }

    $UserCredential = Import-CliXml -Path $CredentialPath

    try {
        # Create session to Exchange
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange `
            -ConnectionUri http://mdotgbexch1/PowerShell/ `
            -Authentication Kerberos `
            -Credential $UserCredential

        Import-PSSession $Session -DisableNameChecking | Out-Null

        # Ensure AD Server Settings view is expanded
        Set-ADServerSettings -ViewEntireForest $true

        # Enable remote mailbox
        Enable-RemoteMailbox -Identity $Username `
            -RemoteRoutingAddress "$Username@mdotgov.mail.onmicrosoft.com" `
            -DomainController "shahqdc3.shacadd.ad.mdot.mdstate"

        Write-Host "✅ Remote mailbox enabled for '$Username'" -ForegroundColor Green
    }
    catch {
        Write-Error "❌ Failed to enable remote mailbox: $_"
    }
    finally {
        if ($Session) {
            Remove-PSSession $Session
        }
    }
}


#--------------------------------------------------------------------------------------------
function Add-UserToSHAGroup {
    [CmdletBinding()]
    param ()

    # List of available groups
    $groups = @(
        'SHA_G5_Users',
        'SHA_F3_Users',
        'SHASalesforceAzure_SSO',
        'SHA_SFDC_SSO'
    )

    # Prompt for username
    $username = Read-Host "Enter the username (sAMAccountName) to add"

    # Display group options
    Write-Host "`nSelect a group to add '$username' to:`n"
    for ($i = 0; $i -lt $groups.Count; $i++) {
        Write-Host "$($i + 1). $($groups[$i])"
    }

    # Prompt for group selection
    $selection = Read-Host "`nEnter the number of the group (1-$($groups.Count))"

    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $groups.Count) {
        $selectedGroup = $groups[[int]$selection - 1]

        try {
            Add-ADGroupMember -Identity $selectedGroup -Members $username -ErrorAction Stop
            Write-Host "`n✅ User '$username' has been successfully added to group '$selectedGroup'." -ForegroundColor Green
        }
        catch {
            Write-Error "`n❌ Failed to add user '$username' to group '$selectedGroup'. Error: $_"
        }
    }
    else {
        Write-Warning "`n⚠ Invalid selection. Please run the function again and choose a valid number."
    }
}





#--------------------------------------------------------------------------------------------

function defender {
    param([parameter(mandatory = $true)]
        [string]$pc)
    Get-WinEvent `
        -FilterHashtable @{providername = "*firewall*"; id = 2011; starttime = $((get-date).AddDays(-30)) } `
        -ComputerName $pc 2>$null | Format-List TimeCreated, MachineName, Providername, ID, Message
}
#--------------------------------------------------------------------------------------------
function Get-MSLic_Multi {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Usernames
    )

    foreach ($Username in $Usernames) {
        $UPN = "$Username@mdot.state.md.us"
        Write-Host "`nRetrieving license info for $UPN..." -ForegroundColor Cyan

        try {
            Get-MsolUser -UserPrincipalName $UPN |
                Select-Object UserPrincipalName, DisplayName, Licenses |
                Format-List
        }
        catch {
            Write-Warning "Could not retrieve data for '$UPN'."
            Write-Error $_.Exception.Message
        }
    }
}

#--------------------------------------------------------------------------------------------
function Get-MSLic {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $UserPrincipalName = "$Username@mdot.state.md.us"

    try {
        Get-MsolUser -UserPrincipalName $UserPrincipalName |
            Select-Object UserPrincipalName, DisplayName, Licenses |
            Format-List
    }
    catch {
        Write-Warning "Failed to retrieve user information for '$UserPrincipalName'."
        Write-Error $_.Exception.Message
    }
}

#--------------------------------------------------------------------------------------------

function Set-AccountExpiration2 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$ExpirationDate
    )

    # Prompt if parameters are not provided
    if (-not $Username) {
        $Username = Read-Host "Please enter the username"
    }

    if (-not $ExpirationDate) {
        $ExpirationDate = Read-Host "Please enter the expiration date (MM/dd/yyyy)"
    }

    # Validate and convert the date
    try {
        $expirationDateObj = [datetime]::ParseExact($ExpirationDate, 'MM/dd/yyyy', $null)
    }
    catch {
        Write-Host "Invalid date format. Please ensure the date is in MM/dd/yyyy format." -ForegroundColor Red
        return
    }

    # Try to set the expiration date
    try {
        Get-ADUser -Identity $Username -ErrorAction Stop | Set-ADAccountExpiration -Date $expirationDateObj
        Write-Host "The account expiration date for $Username has been successfully set to $($expirationDateObj.ToString('MM/dd/yyyy'))."
    }
    catch {
        Write-Host "Failed to set the expiration date. Please check the username or date format." -ForegroundColor Red
        return
    }

    # Export to notepad
    $result = "Account: $Username`nExpiration Date: $($expirationDateObj.ToString('MM/dd/yyyy'))"
    $result | Out-File -FilePath "$env:TEMP\AccountExpiration.txt"
    notepad.exe "$env:TEMP\AccountExpiration.txt"
}




#--------------------------------------------------------------------------------------------

  
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



#--------------------------------------------------------------------------------------------
function Get-NUAR_SR {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Username
    )

    if (-not $Username) {
        $Username = Read-Host "Enter the username (sAMAccountName) of the user"
    }

    $Username = $Username.Trim()

    if ([string]::IsNullOrWhiteSpace($Username)) {
        Write-Host "Username input is empty or invalid. Please enter a valid sAMAccountName." -ForegroundColor Yellow
        return
    }

    $user = Get-ADUser -Identity $Username -Properties * -ErrorAction SilentlyContinue

    if ($user) {
        $user | Select-Object `
            Name,
        EmployeeID,
        Description,
        OfficePhone,
        Office,
        StreetAddress,
        DisplayName,
        Enabled,
        LockedOut,
        HomeDirectory,
        EmailAddress,
        userPrincipalName,
        ExtensionAttribute1,
        AccountExpirationDate,
        DistinguishedName,
        PrimaryGroup,
        msExchArchiveName,
        msExchHideFromAddressLists |
            Format-List

       
        $groups = Get-ADUser -Identity $Username -Properties MemberOf | Select-Object -ExpandProperty MemberOf

        if ($groups) {
            Write-Host "MemberOf:" -ForegroundColor Green
            $groups | ForEach-Object {
                ($_ -split ',')[0] -replace '^CN=' 
            }
        }
        else {
            Write-Host "MemberOf: None" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "User '$Username' not found in Active Directory." -ForegroundColor Red
    }
}



#--------------------------------------------------------------------------------------------
function Copy-ADUserTemplate {
    <#
    .SYNOPSIS
        Copies user attributes and group memberships from a template Active Directory user to a target user.

    .DESCRIPTION
        Useful for onboarding or standardizing users based on a template account. Includes support for WhatIf and Confirm.

    .PARAMETER TemplateUser
        The sAMAccountName of the template user.

    .PARAMETER TargetUser
        The sAMAccountName of the target user.

    .EXAMPLE
        Copy-ADUserTemplate -TemplateUser "jdoe" -TargetUser "jsmith" -Verbose

    .EXAMPLE
        Copy-ADUserTemplate -TemplateUser "template1" -TargetUser "user2" -WhatIf

    .NOTES
        Compatible with PowerShell 5.1 and Active Directory Module.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplateUser,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetUser
    )

    function Get-UserGroups {
        param (
            [Parameter(Mandatory = $true)]
            [string]$UserName
        )

        try {
            $user = Get-ADUser -Identity $UserName -Properties MemberOf
            return $user.MemberOf | ForEach-Object {
                ($_ -split ',')[0] -replace '^CN='
            }
        }
        catch {
            throw "Error retrieving group memberships for user '$UserName'. Details: $_"
        }
    }

    try {
        Write-Verbose "Fetching attributes for template user: $TemplateUser"
        $templateUserData = Get-ADUser -Identity $TemplateUser -Properties Description, Office, StreetAddress, POBox, City, PostalCode, HomeDirectory
        if (-not $templateUserData) {
            throw "Template user '$TemplateUser' not found."
        }

        Write-Verbose "Verifying existence of target user: $TargetUser"
        $targetUserData = Get-ADUser -Identity $TargetUser
        if (-not $targetUserData) {
            throw "Target user '$TargetUser' not found."
        }

        if ($PSCmdlet.ShouldProcess($TargetUser, "Copy attributes from $TemplateUser")) {
            Write-Verbose "Preparing home directory for target user..."
            $parentDirectory = Split-Path -Path $templateUserData.HomeDirectory
            $targetHomeDirectory = Join-Path -Path $parentDirectory -ChildPath $TargetUser

            Write-Verbose "Copying attributes to target user..."
            Set-ADUser -Identity $TargetUser `
                -Description $templateUserData.Description `
                -Office $templateUserData.Office `
                -StreetAddress $templateUserData.StreetAddress `
                -POBox $templateUserData.POBox `
                -City $templateUserData.City `
                -PostalCode $templateUserData.PostalCode `
                -HomeDirectory $targetHomeDirectory `
                -Verbose
        }

        # Compare and transfer group memberships
        Write-Verbose "Fetching group memberships..."
        $templateGroups = Get-UserGroups -UserName $TemplateUser
        $targetGroups = Get-UserGroups -UserName $TargetUser

        Write-Verbose "Comparing group memberships..."
        $missingGroups = Compare-Object -ReferenceObject $templateGroups -DifferenceObject $targetGroups |
            Where-Object { $_.SideIndicator -eq '<=' } |
            Select-Object -ExpandProperty InputObject

        if ($missingGroups.Count -gt 0) {
            Write-Verbose "Adding missing groups to $TargetUser..."
            foreach ($groupName in $missingGroups) {
                if ($PSCmdlet.ShouldProcess($TargetUser, "Add to group: $groupName")) {
                    try {
                        Add-ADGroupMember -Identity $groupName -Members $TargetUser -Verbose
                    }
                    catch {
                        Write-Warning "Could not add '$TargetUser' to group '$groupName'. Error: $_"
                    }
                }
            }
        }
        else {
            Write-Verbose "No group memberships to add. $TargetUser is already in all required groups."
        }

        Write-Output "✅ Successfully copied attributes and group memberships from $TemplateUser to $TargetUser."
    }
    catch {
        Write-Error "❌ An error occurred: $_"
    }
}




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
        Set-ADUser -Identity $User -Replace @{msExchHideFromAddressLists = $value }

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
        Set-Service WinRM -Status Running -StartupType Automatic -ComputerName $pcname
    }
    $session = New-PSSession -ComputerName $pcname
    Enter-PSSession -Session $session
}


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
    $FullAccess = Get-MailboxPermission -Identity $MailboxName | Where-Object { $_.AccessRights -contains "FullAccess" }
    foreach ($perm in $FullAccess) {
        $Results += [PSCustomObject]@{
            PermissionType = "Full Access"
            User           = $perm.User
            AccessRights   = $perm.AccessRights -join ", "
            IsInherited    = $perm.IsInherited
        }
    }

    # 2. Check Send As Permissions
    $SendAs = Get-RecipientPermission -Identity $MailboxName | Where-Object { $_.AccessRights -contains "SendAs" }
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
    }
    else {
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
                }
                else {
                    Write-Verbose "Skipping mandatory group: $Group"
                }
            }
        }
        else {
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
    }
    catch {
        Write-Host "User '$Username' not found. Please check the username and try again." -ForegroundColor Red
        return
    }

    # Clean up the targetAddress by removing any smtp: or SMTP: prefix
    $targetAddressCleaned = $user.targetAddress -replace '(?i)smtp:', ''

    # Display user properties
    $user | Format-List Name, EmployeeID, Description, OfficePhone, Office, StreetAddress, DisplayName, Enabled, LockedOut, `
        HomeDirectory, EmailAddress, userPrincipalName, `
    @{label = 'targetAddress'; expression = { $targetAddressCleaned } }, `
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
            }
            else {
                Write-Host "No results found on domain controller $DC." -ForegroundColor Yellow
            }
        }
        catch {
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
    }
    else {
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
        $User = Get-ADUser -Filter { employeeID -eq $EIN } -Properties employeeID, DisplayName, SamAccountName, EmailAddress

        if ($User) {
            Write-Host "User found:" -ForegroundColor Green
            Write-Host "--------------------------"
            Write-Host "Display Name     : $($User.DisplayName)"
            Write-Host "SAM Account Name : $($User.SamAccountName)"
            Write-Host "E-mail Address   : $($User.EmailAddress)"
            Write-Host "Employee ID      : $($User.employeeID)"
        }
        else {
            Write-Host "No user found with EIN: $EIN" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "An error occurred while searching for the user." -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}

#--------------------------------------------------------------------------------------------

function getgrp {
    param($a)
    Get-ADGroup -LDAPFilter "(name=$($a))" -Properties * | Format-List Name, Description, Notes, DistinguishedName
}

#--------------------------------------------------------------------------------------------


function grpmem {
    param([string]$a)
    Get-ADGroupMember $a | Sort-Object name | Select-Object -ExpandProperty name
}


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
        }
        catch {
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
            }
            else {
                Write-Host "No results found on domain controller $DC." -ForegroundColor Yellow
            }
        }
        catch {
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
    }
    else {
        Write-Host "No accounts found matching the criteria." -ForegroundColor Yellow
    }
}






#--------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------



function remmobile {
    param([string]$user)
    "`nRemoving Active sync devices....`n"
    Get-MobileDeviceStatistics -Mailbox $user | Select-Object -exp Identity | Remove-MobileDevice -Confirm:$false
    "`nDisabling OWA and Active Sync in Exchange....`n"
    Set-CASMailbox $user -ActiveSyncEnabled:$false -OWAEnabled:$false
    Get-CASMailbox $user | Format-Table -AutoSize
}

#--------------------------------------------------------------------------------------------


function autoreply {
    param([string]$user)
    "I am no longer employed by MDOT. All inquiries should be e-mailed to $((Get-ADUser $user).GivenName+" "+$((Get-ADUser $user).SurName)) at $((Get-ADUser $user -Properties *).emailaddress). Thank you." | Set-Clipboard
}
#--------------------------------------------------------------------------------------------
function userid {
    $a = (read-host "FirstName?"); $b = (read-host "LastName?")
($a + " " + $b) -replace '(\w)\w+\s(\w+)', '$1$2'
}
#--------------------------------------------------------------------------------------------
function ooo {
    param([Parameter(mandatory = $true)]
        [string]$user,
        [Parameter(mandatory = $true)]
        [string]$poc)
    Set-MailboxAutoReplyConfiguration $user `
        -AutoReplyState Scheduled `
        -StartTime $(get-date) `
        -EndTime $([datetime]$end = (read-host "end date"); $end) `
        -InternalMessage "I am no longer employed by MDOT. All inquiries should be e-mailed to $((Get-ADUser $poc).GivenName+" "+$((Get-ADUser $poc).SurName)) at $((Get-ADUser $poc -Properties *).emailaddress). Thank you." `
        -ExternalMessage "I am no longer employed by MDOT. All inquiries should be e-mailed to $((Get-ADUser $poc).GivenName+" "+$((Get-ADUser $poc).SurName)) at $((Get-ADUser $poc -Properties *).emailaddress). Thank you." `
        -ExternalAudience All
    Get-MailboxAutoReplyConfiguration $user | Format-List AutoReplyState, StartTime, EndTime, InternalMessage, ExternalMessage
}
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
    $entpw = @{pw = 'B@ltimorian36@!' }
    $admpw = @{pw = 'PeterPan88S*' }
    $mgrpw = @{pw = 'tot@1C0ntro!' }
    $dmzpw = @{pw = 'KlwUkeGe&2ef' }
    $mail = @{id = 'LRichardson2@mdot.state.md.us' }
    $file = @{pw = '@H$0!tn3Tpw$' }
    $root = @{pw = '@DBr00t@dm1n' }
    $redhat = @{pw = 'B@ltimorian33@!' }
    if ($ent) { $entpw.pw | Set-Clipboard }
    elseif ($adm) { $admpw.pw | Set-Clipboard }
    elseif ($mgr) { $mgrpw.pw | Set-Clipboard }
    elseif ($dmz) { $dmzpw.pw | Set-Clipboard }
    elseif ($email) { $mail.id | Set-Clipboard }
    elseif ($pfile) { $file.pw | Set-Clipboard }
    elseif ($rt) { $root.pw | Set-Clipboard }
    elseif ($red) { $redhat.pw | Set-Clipboard }
}
#--------------------------------------------------------------------------------------------
function Accesslist {
    param([Parameter(mandatory = $true)]
        [string]$path)
    $a = (get-acl $path).path
    "`nPath: $($a -replace '.+::')"
(get-acl $path).Access | Format-Table -AutoSize IdentityReference, IsInherited, FileSystemRights
}
#--------------------------------------------------------------------------------------------
#Traverse Permissions


function traverse {
    param([parameter(mandatory, Position = 0)]
        [string]$user,
        [parameter(mandatory, Position = 1)]
        [string]$path)
    $acl = get-acl $path
    $identity = "SHACADD\$user"
    [System.Security.AccessControl.FileSystemRights]$rights = @("ReadAndExecute")
    [System.Security.AccessControl.InheritanceFlags]$inher = @("None")
    [System.Security.AccessControl.PropagationFlags]$prop = "None"
    [System.Security.AccessControl.AccessControlType]$type = "Allow"
    $object = $identity, $rights, $inher, $prop, $type
    $newacl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
    $acl.AddAccessRule($newacl)
    Set-Acl $path -AclObject $acl
}
#--------------------------------------------------------------------------------------------
function removepermission {
    param([parameter(mandatory, Position = 0)]
        [string]$person,
        [parameter(mandatory, Position = 1)]
        [string]$path)
    $folder = get-acl $path
    foreach ($acl in $folder.Access) {
        $user = $acl.IdentityReference.Value
        if ($user -match "SHACADD\\$person") {
            $folder.RemoveAccessRule($acl)
        }
    } 
    Set-Acl $path -AclObject $folder
}
#--------------------------------------------------------------------------------------------
function addpermission1 {
    param([parameter(mandatory, Position = 0)]
        [string]$user,
        [parameter(mandatory, Position = 1)]
        [string]$path,
        [parameter(mandatory, Position = 2)]
        [ValidateSet("ReadAndExecute", "Modify")]
        [string[]]$permission)
    $acl = get-acl $path
    $identity = "SHACADD\$user"
    [System.Security.AccessControl.FileSystemRights]$rights = @($permission)
    [System.Security.AccessControl.InheritanceFlags]$inher = @("ContainerInherit", "ObjectInherit")
    [System.Security.AccessControl.PropagationFlags]$prop = "None"
    [System.Security.AccessControl.AccessControlType]$type = "Allow"
    $object = $identity, $rights, $inher, $prop, $type
    $newacl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
    $acl.AddAccessRule($newacl)
    Set-Acl $path -AclObject $acl
}
#--------------------------------------------------------------------------------------------
#Check User permissions to File Path


function access {
    param([parameter(mandatory = $true)]
        [string]$user,
        [parameter(mandatory = $true)]
        [string]$path)
    [string[]]$acl = get-acl $path | Select-Object -Expand access | Select-Object -expand identityreference
    $acl = $acl -replace '.+\\'
    $a = get-acl $path | Select-Object -expand access | Format-Table IdentityReference, FileSystemRights
    $acl | ForEach-Object { if ($_ -match $user) { "$_ has explicit rights." }
        elseif ((Get-ADGroup $_) -and (Get-ADGroupMember $_ | Where-Object name -match $user)) {
            "$user is a member of $_"; $a | Where-Object IdentityReference -Match $_
        }
        else { end } }2>$null
}

#--------------------------------------------------------------------------------------------

function addPermission {
    param([parameter(mandatory, Position = 0)]
        [string]$user,
        [parameter(mandatory, Position = 1)]
        [string]$path,
        [parameter(mandatory, Position = 2)]
        [ValidateSet("ReadAndExecute", "Modify", "Fullcontrol")]
        [string[]]$permission)
    $acl = get-acl $path
    $identity = "SHACADD\$user"
    [System.Security.AccessControl.FileSystemRights]$rights = @($permission)
    [System.Security.AccessControl.InheritanceFlags]$inher = @("ContainerInherit", "ObjectInherit")
    [System.Security.AccessControl.PropagationFlags]$prop = "None"
    [System.Security.AccessControl.AccessControlType]$type = "Allow"
    $object = $identity, $rights, $inher, $prop, $type
    $newacl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
    $acl.AddAccessRule($newacl)
    Set-Acl $path -AclObject $acl
}
#--------------------------------------------------------------------------------------------
#First Version For the transfer Script Josh did

function Update-ADuserAttributes {
    param([parameter(Mandatory = $true)][string]$ParameterName)
    [string]$template,
    [parameter(mandatory = $true)]
    [string]$targetuser
(get-aduser $a -Properties *).description | ForEach-Object { Set-ADUser $b -Description $_ }
(get-aduser $a -Properties *).StreetAddress | ForEach-Object { Set-ADUser $b -StreetAddress $_ }
(get-aduser $a -Properties *).office | ForEach-Object { Set-ADUser $b -Office $_ }
(get-aduser $a -Properties *).pobox | ForEach-Object { Set-ADUser $b -pobox $_ }
(get-aduser $a -Properties *).city | ForEach-Object { Set-ADUser $b -city $_ }
(get-aduser $a -Properties *).postalcode | ForEach-Object { Set-ADUser $b -postalcode $_ }
}
#--------------------------------------------------------------------------------------------

function acl1 {
    param([string]$a)
    get-acl $a | Select-Object @{l = "path"; e = { $([string]$b = $_.path; $b = $b -replace '.+::', "";
                $b) }
    } -ExpandProperty access | Format-Table filesystemrights, isinherited, identityreference -GroupBy path
}
#--------------------------------------------------------------------------------------------
function acl2 {
    param([string]$a)
    get-acl $a | Select-Object @{l = "path"; e = { $([string]$b = $_.path; $b = $b -replace '.+::', "";
                $b) }
    }, owner -ExpandProperty access | Format-Table owner, filesystemrights, isinherited, identityreference -GroupBy path
}
#--------------------------------------------------------------------------------------------
function finduser {
    param([string]$a)
    Get-ADUser -LDAPFilter "(name=$a*)" -Properties * | Format-List displayname, name, employeeid
}
#--------------------------------------------------------------------------------------------
function newuser {
    param([string]$a)
    @"
Name:`t`t`t`t$((Get-ADUser $a -Properties *).displayname)
Username:`t`t`t$((Get-ADUser $a -Properties *).name)
PW:`t`t`t`tMdot@Jun212022
Email:`t`t`t`t$((Get-ADUser $a -Properties *).emailaddress)
Microsoft Sign-in:`t`t$((Get-ADUser $a -Properties *).userprincipalname)
"@
}
#--------------------------------------------------------------------------------------------
#Hide User In GAL

function HideUser {
    param([string]$user)
    Set-ADUser $user -Add @{msExchHideFromAddressLists = $true }
}
#--------------------------------------------------------------------------------------------
function getuser {
    param($a)
    Get-ADUser $a -Properties * | Format-List Name, displayname, Enabled, Created, Lockedout, Homedirectory, Office, OfficePhone, Employeeid, emailaddress, AccountExpirationDate, Description, ExtensionAttribute1, ExtensionAttribute5, DistinguishedName, PrimaryGroup
    $b = "$((Get-ADUser $a -Properties *|Sort-Object proxyaddresses).proxyaddresses|select-string '@')"
    $b = $b.Replace("smtp:", "")
    $b = $b.Replace("SMTP:", "")
    $b = $b.split()
    $b = $b | Sort-Object
    $b
}
#--------------------------------------------------------------------------------------------
function delsheet {
    param($a)
    $add = [PSCustomObject]@{
        email           = $([string]$e = (Get-ADUser $a -properties *).EmailAddress; $e = $e -replace '\.consultant'; $e);
        first_name      = (Get-ADUser $a -properties *).GivenName;
        last_name       = (Get-ADUser $a -properties *).Surname;
        'OU'            = (Read-Host "OU");
        'Deletion Date' = (get-date).ToShortDateString();
        'EIN#'          = (Get-ADUser $a -properties *).EmployeeID;
        'SR#'           = (Read-Host "SR#");
        'Worked By'     = (Read-Host "Worked By (userid)")
    }
    $add | Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Deletes_2025.csv" -Append -NoTypeInformation
}

#--------------------------------------------------------------------------------------------
function addsheet {
    param($a)
    $add = [PSCustomObject]@{
        email           = $([string]$e = (Get-ADUser $a -properties *).EmailAddress; $e = $e -replace '\.consultant'; $e);
        first_name      = (Get-ADUser $a -properties *).GivenName;
        last_name       = (Get-ADUser $a -properties *).Surname;
        group_name      = "SHA";
        OU              = $(read-host "which OU?")
        'Creation Date' = (get-date).ToShortDateString();
        'Notes'         = "";
        'EIN?'          = (Get-ADUser $a -properties *).EmployeeID
        'SR#'           = (read-host "SR#")
        "Worked By"     = (read-host "Worked by (your userid)")
    }
    $add | Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Adds_2025.csv" -Append
}
#--------------------------------------------------------------------------------------------
function AddFMT {
    param($a)
    $add = [PSCustomObject]@{
        email           = $([string]$e = (Get-ADUser $a -properties *).EmailAddress; $e = $e -replace '\.consultant'; $e);
        first_name      = (Get-ADUser $a -properties *).GivenName;
        last_name       = (Get-ADUser $a -properties *).Surname;
        group_name      = "SHA";
        OU              = $(read-host "which OU?");
        'Creation Date' = (get-date).ToShortDateString();
        'Notes'         = "";
        'EIN?'          = (Get-ADUser $a -properties *).EmployeeID
    }
    $add | Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_FMT_Adds_2025.csv" -Append
}
#--------------------------------------------------------------------------------------------
function updatesheet {
    param([string]$old, [string]$new)
    $add = [PSCustomObject]@{
        current_email      = (Get-ADUser $old -properties *).EmailAddress;
        current_first_name = (Get-ADUser $old).GivenName;
        current_last_name  = (Get-ADUser $old).SurName;
        current_group_name = "SHA";
        new_email          = (Get-ADUser $new -properties *).emailaddress;
        new_first_name     = (Get-ADUser $new -properties *).GivenName;
        new_last_name      = (Get-ADUser $new -properties *).SurName;
        new_group_name     = "SHA";
        notes              = (read-host "Notes")
    }
    $add | Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Updates_2025.csv" -Append
}
#--------------------------------------------------------------------------------------------
#Maximo Template 

function NewUserReply {
    param([string]$user, [string]$pw = (read-host "Password"))
    Get-ADUser $user -Properties * | Format-List @{l = 'UserID'; e = { $_.Name } },
    @{l = "Password"; e = { $pw } },
    @{l = 'Email'; e = { $_.emailaddress } },
    @{l = 'Microsoft UserName'; e = { $($a = $_.proxyaddresses[1]; $a = $a -replace 'smtp:'; $a) } }
}
#--------------------------------------------------------------------------------------------
function LitSheet {
    param(
        [parameter(Mandatory = $true)]
        [string]$a
    )
    $add = [PSCustomObject]@{
        email                              = $([string]$e = (Get-ADUser $a -properties *).EmailAddress; $e = $e -replace '\.consultant'; $e);
        first_name                         = (Get-ADUser $a -properties *).GivenName;
        last_name                          = (Get-ADUser $a -properties *).Surname;
        'Litigation Hold or Proxy Needed?' = $(read-host "Describe litigation");
        'User Disabled Date'               = (get-date).ToShortDateString()
        'Worked by'                        = $(read-host "Worked by")
    }
    $add | Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Litigation_Hold.csv" -Append
}
#--------------------------------------------------------------------------------------------
#Remove M:Drive from Server and Clear Homedirectory
function remove-homedirectory {
    param(
        [parameter(Mandatory = $true)]
        [string]$user,

        [parameter(Mandatory = $true)]
        [string]$path
    )
    Remove-Item $path -Force -Recurse; Set-ADUser $user -Clear Homedirectory, HomeDrive
}
#--------------------------------------------------------------------------------------------
function exitdesc {
    param([string]$user)
    $desc = (Get-ADUser $user -Properties *).description
    Set-ADUser $user -Description $("$desc" + " " + "- Disabled $(
(get-date).ToShortDateString()) SR#$(read-host 'SR#') JG")
}
#--------------------------------------------------------------------------------------------
function dismove {
    param([string]$a)
    Disable-ADAccount $a
    [string]$b = (get-aduser $a).DistinguishedName
    Move-ADObject -Identity $b -TargetPath 'OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate'
}
#--------------------------------------------------------------------------------------------

function newmail {
    param([string]$a)
    @"
`$UserCredential = Get-Credential
`$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch1/PowerShell/ -Authentication Kerberos
Import-PSSession `$Session -disablenamechecking
set-ADServerSettings -viewentireforest `$True
Enable-RemoteMailbox $a -RemoteRoutingAddress "$a@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
"@| Set-Clipboard
}
#--------------------------------------------------------------------------------------------

function MDWare {
    start-job { Robocopy /TEE /R:0 /W:0 "\\SHAHANPCE11063\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\RShirk1 qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\RShirk1.txt
        Robocopy /TEE /R:0 /W:0 "\\SHAOMTPCE16232\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\sclark qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\sclark.txt
        Robocopy /TEE /R:0 /W:0 "\\SHAHANPCE10271\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\VVadakoot qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\VVaddakot.txt }
}
#--------------------------------------------------------------------------------------------
function add-alias {
    param([string]$a) Set-ADUser $a -Clear proxyAddresses
    Start-Sleep -Seconds 5
    Set-ADUser $a -EmailAddress "$a@mdot.maryland.gov"
    Set-ADUser $a -add @{proxyAddresses = $('SMTP:' + $a + "@mdot.maryland.gov"),
        $('smtp:' + $a + "@mdot.state.md.us"),
        $('smtp:' + $a + "@mdotgov.mail.onmicrosoft.com"),
        $('smtp:' + $a + "@sha.maryland.gov"),
        $('smtp:' + $a + "@sha.state.md.us")
    }
}
#--------------------------------------------------------------------------------------------
function vminfo {
    param([string]$a)
    Get-ADComputer $a | Select-Object -ExpandProperty DNSHostName
    GET-VM $a | Format-List Name, Folder, NumCpu, CoresPerSocket, MemoryGB, VMHost
    "`nOperating System:"
    Get-VMGuest $a | Select-Object VmName, IPAddress, OSFullName
    "`nUUID:"
    Get-WmiObject win32_computersystemproduct -ComputerName SHAHQ22OHDAPP1 | Format-Table UUID -HideTableHeaders
    "`nDisks:"
    Get-VMGuest SHAHQ22OHDAPP1 | Select-Object -ExpandProperty disks
    "`nDatastore:"
    Get-Datastore -RelatedObject $a | Select-Object Datacenter, Name, FreeSpaceGB, CapacityGB
    "`nVirtual Network:"
    Get-NetworkAdapter -VM $a | Select-Object NetworkName
}
#--------------------------------------------------------------------------------------------
function remove-alias {
    param([string]$a) Set-ADUser $a -Clear proxyAddresses
    Start-Sleep -Seconds 3
    Set-ADUser $a -EmailAddress "$a@mdot.state.md.us"
    Set-ADUser $a -add @{proxyAddresses = $('SMTP:' + $a + '@mdot.state.md.us'), $('smtp:' + $a + '@mdotgov.mail.onmicrosoft.com') }
}
#--------------------------------------------------------------------------------------------

function Move-ADUserToTemplateOU {
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
    }
    else {
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
            }
            elseif ($_.SideIndicator -eq "<=") {
                Write-Host "User '$Target' has extra group: $($_.InputObject) - Removing..."
                Remove-ADGroupMember -Identity $_.InputObject -Members $Target -Confirm:$false
            }
        }

    Write-Host "`nUser '$Target' successfully transferred."
}

#--------------------------------------------------------------------------------------------

function transferinOU {
    param([Parameter(mandatory = $true)]
        [string]$target,
        [Parameter(mandatory = $true)]
        [String]$template)
    Set-ADUser $target -Description $((Get-ADUser $template -Properties *).description) `
        -StreetAddress $((Get-ADUser $template -Properties *).streetaddress) `
        -POBox $((Get-ADUser $template -Properties *).pobox) `
        -City $((Get-ADUser $template -Properties *).city) `
        -Officephone $(Read-Host "Enter New Phone Number") `
        -PostalCode $((Get-ADUser $template -Properties *).postalcode) -Verbose
    $destination = $([string]$a = (Get-ADUser $template).distinguishedname; $a = $a -replace '.+TEMPLATE,(.+)', '$1'; $a)
    Move-ADObject -Identity (Get-ADUser $target).distinguishedname -TargetPath $destination
}


#--------------------------------------------------------------------------------------------


function portsec {
    param([string]$mac, [string]$int)
    "sh port-security address | i ($mac)
sh mac address-table | i ($mac)
sh port-security address | i ($int )
sh mac address-table | i ($int )
sh int $int status
"| set-clipboard
}
#--------------------------------------------------------------------------------------------
function clear-port {
    param([string]$int)
    "clear port-security sticky int $int" | set-clipboard
}
#--------------------------------------------------------------------------------------------
function salesforce {
    param([string]$a)
    Add-ADPrincipalGroupMembership $a -MemberOf SHASalesforceAzure_SSO
    start-sleep -seconds 3
    groups $a | select-string SHASalesforceAzure_SSO
}
#--------------------------------------------------------------------------------------------
function add-alias2 {
    param([string]$a) Set-ADUser $a -Clear proxyAddresses
    Start-Sleep -Seconds 5
    Set-ADUser $a -EmailAddress "$a.consultant@mdot.maryland.gov"
    Set-ADUser $a -add @{proxyAddresses = $('SMTP:' + $a + ".consultant@mdot.maryland.gov"),
        $('Smtp:' + $a + "@mdot.maryland.gov"),
        $('smtp:' + $a + "@mdot.state.md.us"),
        $('smtp:' + $a + "@mdotgov.mail.onmicrosoft.com"),
        $('smtp:' + $a + "@sha.maryland.gov"),
        $('smtp:' + $a + "@sha.state.md.us")
    }
}
#--------------------------------------------------------------------------------------------
function Server {
    param([string]$pc)
    Get-ADComputer $pc -Properties * | Select-Object Enabled, Name, SAMAccountName, Created, Modified, DNSHostName, DistinguishedName
    Resolve-DnsName $pc 2>$null | Format-Table Name, IP4Address -AutoSize
}
#--------------------------------------------------------------------------------------------

#This Script for Consultant converting to EIN Users @mdot.maryland.gov


function add-alias3 {
    param([string]$a) Set-ADUser $a -Clear proxyAddresses
    Start-Sleep -Seconds 5
    Set-ADUser $a -EmailAddress "$a@mdot.maryland.gov"
    Set-ADUser $a -add @{proxyAddresses = $('SMTP:' + $a + "@mdot.maryland.gov"),
        $('smtp:' + $a + ".consultant@mdot.maryland.gov"),
        $('smtp:' + $a + "@mdot.state.md.us"),
        $('smtp:' + $a + "@mdotgov.mail.onmicrosoft.com"),
        $('smtp:' + $a + "@sha.maryland.gov"),
        $('smtp:' + $a + "@sha.state.md.us")
    }
}
#--------------------------------------------------------------------------------------------
#move to OU container based off of the Template

function moveuser {
    param([parameter(mandatory = $true)]
        [string]$targetuser,
        [parameter(mandatory = $true)]
        [string]$template)
    $target = (Get-ADUser $targetuser).distinguishedname
    $destination = $([string]$a = (Get-ADUser $template).distinguishedname; $a = $a -replace 'CN=\w+,(.+)', '$1'; $a)
    Move-ADObject -Identity $target -TargetPath $destination
}

#--------------------------------------------------------------------------------------------

function defender {
    param([parameter(mandatory = $true)]
        [string]$pc)
    Get-WinEvent `
        -FilterHashtable @{providername = "*firewall*"; id = 2011; starttime = $((get-date).AddDays(-30)) } `
        -ComputerName $pc 2>$null | Format-List TimeCreated, MachineName, Providername, ID, Message
}
#--------------------------------------------------------------------------------------------
function patchfilter {
    param([parameter(mandatory = $true)]
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
            -LocalPort 5120 -Verbose }
}
#--------------------------------------------------------------------------------------------
function getdisk {
    param([string]$pc)
    Get-WmiObject Win32_DiskPartition -ComputerName $pc |
        Sort-Object Name | Format-Table SystemName, BootPartition, Name, Type, PrimaryPartition,
        @{label = "Size"; exp = { $($b = $_.size / 1073741824; $b = [System.Convert]::ToInt16($b); "$b GB") } }
}
#--------------------------------------------------------------------------------------------
function Allconnections {
    param([string]$pc)
    invoke-command -ComputerName $pc { function connectinfo {
            $a = Get-NetTCPConnection | Where-Object {
                $_.RemoteAddress -ne '0.0.0.0' -and 
                $_.RemoteAddress -ne '127.0.0.1' -and 
                $_.RemoteAddress -ne '::' -and 
                $_.State -eq "Established" -or 
                $_.State -eq "CloseWait" } | Sort-Object State, RemoteAddress
            $a | Format-Table CreationTime, OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State -AutoSize
            [Int32[]]$b = $a.OwningProcess
            $z = [psobject[]]$b | ForEach-Object { Get-WmiObject win32_process -Filter "processid=$_" | Select-Object ProcessId, Name, Commandline }
            $z | Format-List 2>$null
        }connectinfo }
}
#--------------------------------------------------------------------------------------------
function CheckTCP {
    param([parameter(mandatory = $true)]
        [string]$pc)
    invoke-command -ComputerName $pc { function connectinfo {
            $a = Get-NetTCPConnection | Where-Object {
                $_.State -eq "established" -and `
                    $_.LocalAddress -ne '0.0.0.0' -and `
                    $_.LocalAddress -ne '127.0.0.1' -and `
                    $_.LocalAddress -notmatch '::' } | Sort-Object State, RemoteAddress
            $a | Select-Object State, LocalAddress, LocalPort, RemoteAddress -Unique | Format-Table -AutoSize
            [Int32[]]$b = $a.OwningProcess
            $z = [psobject[]]$b | ForEach-Object { Get-WmiObject win32_process -Filter "processid=$_" | Select-Object ProcessId, Name, Commandline }
            $z | Format-List 2>$null
        }connectinfo 2>$null }
}
#--------------------------------------------------------------------------------------------
function lockout {
    param([string]$a)
    get-winevent -FilterHashtable @{
        logname = "security";
        id      = 4740
    } `
        -ComputerName shahqdc3 | Where-Object message -match $a |
        Select-Object -first 1 | Format-List TimeCreated, MachineName, ProviderName, Id, Message
    get-winevent -FilterHashtable @{
        logname = "security";
        id      = 4740
    } `
        -ComputerName shagbdc1 | Where-Object message -match $a |
        Select-Object -first 1 | Format-List TimeCreated, MachineName, ProviderName, Id, Message
}
#--------------------------------------------------------------------------------------------
function checktimeout {
    $a = Get-NetTCPConnection | Where-Object {
        $_.RemoteAddress -ne '0.0.0.0' -and
        $_.RemoteAddress -ne '127.0.0.1' -and
        $_.RemoteAddress -ne '::' -or
        $_.State -eq "CloseWait" -or $_.State -eq "TimeWait" } | Sort-Object State, RemoteAddress
    $a | Format-Table CreationTime, State, OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort -AutoSize
    $a = $a | Sort-Object OwningProcess | Select-Object -ExpandProperty owningprocess -Unique
    $b = $a | ForEach-Object { Get-WmiObject win32_process -Filter "processid=$_" | Select-Object PSComputername, ProcessID, Name, Commandline }
    $b
}
#--------------------------------------------------------------------------------------------
function TCPConnection {
    param([string]$pc)
    Invoke-Command -ComputerName $pc {
        Get-NetTCPConnection -State Established -AppliedSetting Datacenter, Internet |
            Sort-Object OwningProcess, RemoteAddress | Where-Object LocalAddress -ne ::1 |
            Format-Table -AutoSize LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        $a = (Get-NetTCPConnection -State Established -AppliedSetting Datacenter, Internet |
                Sort-Object OwningProcess, RemoteAddress | Where-Object LocalAddress -ne ::1).OwningProcess
        $a = $a | Select-Object -Unique
        $a = $a | ForEach-Object { Get-WmiObject win32_process -Filter "processid=$_" | Select-Object Name, ProcessID, CommandLine }
        $a | Format-List }
}
#--------------------------------------------------------------------------------------------
Function CheckCentracs {
    "`nConnections from:`r"
    Write-Host 'SHAHQATMSCS1 [10.92.178.213]' -ForegroundColor Red
    "`rto`r"
    Write-Host 'SHAHQATMSFS1 [10.92.178.215]' -ForegroundColor Blue
    $a = (Get-WmiObject win32_process -Filter 'name="devicemanager.exe"' -ComputerName SHAHQATMSCS1).ProcessID
    $b = (Get-WmiObject win32_process -Filter 'name="devicemanager.exe"' -ComputerName SHAHQATMSCS1).Path
    "`nThe program '$b' is using process id $a on SHAHQATMSCS1`n"
    Get-Service CentracsDeviceManager -ComputerName SHAHQATMSCS1 | Select-Object MachineName, StartType, Status, Name, DisplayName | Format-Table -AutoSize
    Invoke-Command -ComputerName SHAHQATMSCS1 {
        Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq '10.92.178.215' } | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess }
    "`nConnections from:`r"
    Write-Host 'SHAHQATMSFS1 [10.92.178.215]' -ForegroundColor Blue
    "`rto`r"
    Write-Host "SHAHQATMSCS1 [10.92.178.213]" -ForegroundColor Red
    $d = (Get-WmiObject win32_process -Filter 'name="Core.exe"' -ComputerName SHAHQATMSFS1).ProcessID
    $e = (Get-WmiObject win32_process -Filter 'name="Core.exe"' -ComputerName SHAHQATMSFS1).Path
    "`nThe program '$e' is using process id $d on SHAHQATMSFS1`n"
    Get-Service CentracsCore -ComputerName SHAHQATMSFS1 | Select-Object MachineName, StartType, Status, Name, DisplayName | Format-Table -AutoSize
    Invoke-Command -ComputerName SHAHQATMSFS1 {
        Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq '10.92.178.213' } | Format-Table -Autosize LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess }
    Write-Host "Note:`rIf no connections are displayed between the servers, please reboot SHAHQATMSFS1" -ForegroundColor Green
}

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
    }
    catch {
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
        }
        catch {
            Write-Warning "Failed to add '$TargetUser' to group '$group'. Error: $_"
        }
    }

    Write-Host "Memberships from '$SourceUser' have been successfully added to '$TargetUser'." -ForegroundColor Cyan
}

#--------------------------------------------------------------------------------------------
function add-alias2 {
    param([string]$a) Set-ADUser $a -Clear proxyAddresses
    Start-Sleep -Seconds 5
    Set-ADUser $a -EmailAddress "$a.consultant@mdot.maryland.gov"
    Set-ADUser $a -add @{proxyAddresses = $('SMTP:' + $a + ".consultant@mdot.maryland.gov"),
        $('Smtp:' + $a + "@mdot.maryland.gov"),
        $('smtp:' + $a + "@mdot.state.md.us"),
        $('smtp:' + $a + "@mdotgov.mail.onmicrosoft.com"),
        $('smtp:' + $a + "@sha.maryland.gov"),
        $('smtp:' + $a + "@sha.state.md.us")
    }
}


#----------------------------------------------------------------------------------------

# Set the value of msExchHideFromAddressLists to Replace @{msExchHideFromAddressLists=$false}
function hideuser {
    param([string]$user)
    Set-ADUser $user -Add @{msExchHideFromAddressLists = $true }
}


#--------------------------------------------------------------------------------------------
function findaccount2 {
    param(
        [parameter(Mandatory = $true)]
        [string]$user
    )
    $DC = "mdotgbfrdc1.ad.mdot.mdstate",
    "MAABWIDC1.maa.ad.mdot.mdstate",
    "TSOGBDC1.mdothq.ad.mdot.mdstate",
    "MDTAICCDC01.mdta.ad.mdot.mdstate",
    "MPADMTENTDC01.mpa.ad.mdot.mdstate",
    "MTACWDRDC1.mtant1.ad.mdot.mdstate",
    "MVAWSDC1.mvant1.ad.mdot.mdstate",
    "SHAGBDC1.shacadd.ad.mdot.mdstate"
    $result = $DC | ForEach-Object { Get-ADUser -LDAPFilter "(samaccountname=$user*)" -Server $_ -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description }
    $result | Format-Table -AutoSize
}
#--------------------------------------------------------------------------------------------

# Function to Search First and Last Name

function findaccount1 {
    param(
        [parameter(Mandatory = $true)]
        [string]$firstname,

        [parameter(Mandatory = $true)]
        [string]$lastname
    )
    # Search for users based on first and last name across multiple domain controllers.
    # Define the domain controllers to search.                      
    # You can add or remove domain controllers as needed.
    # Ensure the domain controllers are reachable and have the necessary permissions.   
    $DC = "mdotgbfrdc1.ad.mdot.mdstate",
    "MAABWIDC1.maa.ad.mdot.mdstate",
    "TSOGBDC1.mdothq.ad.mdot.mdstate",
    "MDTAICCDC01.mdta.ad.mdot.mdstate",
    "MPADMTENTDC01.mpa.ad.mdot.mdstate",
    "MTACWDRDC1.mtant1.ad.mdot.mdstate",
    "MVAWSDC1.mvant1.ad.mdot.mdstate",
    "SHAGBDC1.shacadd.ad.mdot.mdstate"
    $result = $DC | ForEach-Object { Get-ADUser -LDAPFilter "(&(givenname=$firstname*)(sn=$lastname*))" -Server $_ -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description }
    $result | Format-Table -AutoSize
}
#--------------------------------------------------------------------------------------------


# Define the AddPermission function.
function AddPermission {
    # Function to add specific permissions to a file or folder for a user.

    # Prompt the user interactively for each required input parameter.
    param(
        [parameter(Mandatory)]
        [string]$user,

        [parameter(Mandatory)]
        [string]$path,

        [parameter(Mandatory)]
        [ValidateSet("ReadAndExecute", "Modify", "Fullcontrol")]
        [string[]]$permission
    )

    # Prompt for permission level if not provided
    if (-not $permission) {
        $permission = Read-Host "Enter the permission level (ReadAndExecute, Modify, Fullcontrol)"
    }

    # Prompt for the path if not provided
    if (-not $path) {
        $path = Read-Host "Enter the full file or folder path (e.g., C:\example)"
    }

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
    }
    catch {
        Write-Error "Failed to retrieve ACL details for the path '$Path'. Error: $_"
        return
    }

    $ProcessedACL = $ACL.Access | ForEach-Object {
        [PSCustomObject]@{
            Path              = $Path
            FileSystemRights  = ($_.FileSystemRights -join ", ")
            IsInherited       = $_.IsInherited
            IdentityReference = $_.IdentityReference
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
        }
        catch {
            Write-Warning "The file '$OutputPath' is currently in use by another process. Please close the file and try again."
            return
        }
    }

    try {
        $ProcessedACL | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        Write-Host "ACL details successfully exported to '$OutputPath'" -ForegroundColor Green
    }
    catch {
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
    }
    catch {
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
    }
    catch {
        Write-Host "User not found. Please check the username and try again." -ForegroundColor Red
        return
    }

    # Clean up the targetAddress by removing any smtp: or SMTP: prefix
    $targetAddressCleaned = $user.targetAddress -replace '(?i)smtp:', ''

    # Display user properties - Only AD value for msExchHideFromAddressLists
    $user | Format-List Name, EmployeeID, Description, OfficePhone, Office, StreetAddress, DisplayName, Enabled, LockedOut, HomeDirectory, EmailAddress, userPrincipalName, @{label = 'targetAddress'; expression = { $targetAddressCleaned } }, ExtensionAttribute1, AccountExpirationDate, DistinguishedName, PrimaryGroup, msExchArchiveName, msExchHideFromAddressLists 

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

function Invoke-MultipleADUserExits {
    param (
        [Parameter(Mandatory = $false)]
        [string]$CSVPath, # Path to your CSV file

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
    }
    catch {
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
        }
        catch {
            Write-Log "Failed to save user details for ${Username}: $_" "ERROR"
            Write-Host "Failed to save user details for ${Username}: $_" -ForegroundColor Red
        }

        # Step 2: Remove the HomeDirectory
        try {
            Set-ADUser -Identity $Username -HomeDirectory $null
            Write-Log "HomeDirectory removed for user ${Username}."
            Write-Host "HomeDirectory removed for user ${Username}." -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to remove HomeDirectory for ${Username}: $_" "ERROR"
            Write-Host "Failed to remove HomeDirectory for ${Username}: $_" -ForegroundColor Red
        }

        # Step 3: Disable the user account
        try {
            Disable-ADAccount -Identity $Username
            Write-Log "User account for ${Username} has been disabled."
            Write-Host "User account for ${Username} has been disabled." -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to disable user account for ${Username}: $_" "ERROR"
            Write-Host "Failed to disable user account for ${Username}: $_" -ForegroundColor Red
        }

        # Step 4: Move the user to the target OU
        try {
            Move-ADObject -Identity $distinguishedName -TargetPath $TargetOU
            Write-Log "User ${Username} moved to OU: $TargetOU."
            Write-Host "User ${Username} moved to OU: $TargetOU." -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to move user ${Username} to OU: $_" "ERROR"
            Write-Host "Failed to move user ${Username} to the specified OU: $_" -ForegroundColor Red
        }

        # Step 5: Update the user description
        if ([string]::IsNullOrWhiteSpace($currentDescription)) {
            $newDescription = "$AdditionalDescription"
        }
        else {
            $newDescription = "$currentDescription - $AdditionalDescription"
        }

        try {
            Set-ADUser -Identity $Username -Description $newDescription
            Write-Log "Description updated for user ${Username}: $newDescription."
            Write-Host "Description updated for user ${Username}: $newDescription" -ForegroundColor Green
        }
        catch {
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
            }
            catch {
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
    }
    catch {
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
    }
    catch {
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
        $User = Get-ADUser -Filter { SamAccountName -eq $Username } -Properties EmailAddress

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

    }
    catch {
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
        Set-ADUser -Identity $UserAccount -Replace @{msExchHideFromAddressLists = $true } -ErrorAction Stop
        Write-Host "The user account '$UserAccount' has been hidden from the Global Address List (GAL)." -ForegroundColor Yellow

        # Verify the changes
        $user = Get-ADUser -Identity $UserAccount -Properties Enabled, msExchHideFromAddressLists
        Write-Host "Verification:" -ForegroundColor Cyan
        Write-Host "Account Enabled: $($user.Enabled)" -ForegroundColor White
        Write-Host "Hidden from GAL: $($user.msExchHideFromAddressLists)" -ForegroundColor White
    }
    Catch {
        # Handle errors
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}
#--------------------------------------------------------------------------------------------

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

#--------------------------------------------------------------------------------------------
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
                Set-ADUser -Identity $username -DisplayName $newDisplayName -Replace @{ExtensionAttribute1 = 'SHA Consultant' }
            }
        }
        catch {
            # Silently handle errors
            return
        }
    }
}
#--------------------------------------------------------------------------------------------
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

