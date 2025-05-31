function New-MDOTADUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$UserID,

        [Parameter(Mandatory)]
        [string]$FirstName,

        [Parameter(Mandatory)]
        [string]$LastName,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [string]$Phone,

        [Parameter(Mandatory)]
        [string]$TemplateUser,

        [Parameter(Mandatory)]
        [string]$EmployeeID,

        [Parameter(Mandatory)]
        [string]$MailStop
    )

    # Email Format
    $email = "$UserID@mdot.state.md.us"

    # Get Template User Info
    $templateUserInfo = Get-ADUser $TemplateUser -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State, HomeDirectory, MemberOf

    # Derive OU Path from Template
    $path = ($templateUserInfo.DistinguishedName -replace '^.+?Template,(.+)$', '$1')

    # Construct the AD User
    New-ADUser `
        -Name $UserID `
        -SamAccountName $UserID `
        -UserPrincipalName $email `
        -GivenName $FirstName `
        -Surname $LastName `
        -DisplayName "$FirstName $LastName" `
        -OfficePhone $Phone `
        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
        -ChangePasswordAtLogon $true `
        -Enabled $true `
        -EmployeeID $EmployeeID `
        -Instance $templateUserInfo `
        -Path $path `
        -PassThru | Out-Null

    # Set Extension Attribute
    Set-ADUser $UserID -Add @{ExtensionAttribute5 = $MailStop }

    # Copy Group Memberships
    $groups = $templateUserInfo.MemberOf
    if ($groups) {
        Add-ADPrincipalGroupMembership -Identity $UserID -MemberOf $groups -Verbose
    }
    else {
        Write-Host "No groups found for template user $TemplateUser." -ForegroundColor Yellow
    }

    # Set Home Directory
    if ($templateUserInfo.HomeDirectory) {
        $homeRoot = ($templateUserInfo.HomeDirectory -replace '\\[^\\]+$', '')
        $newHomeDir = "$homeRoot\$UserID"
        
        if (-not (Test-Path $newHomeDir)) {
            New-Item -Path $newHomeDir -ItemType Directory | Out-Null
            Write-Host "Created home directory: $newHomeDir" -ForegroundColor Green
        }

        Set-ADUser $UserID -HomeDirectory $newHomeDir -HomeDrive 'M:' -Verbose
    }

    # Exchange Online Enablement
    try {
        $UserCredential = Get-Credential
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange `
            -ConnectionUri http://mdotgbexch2/powershell `
            -Authentication Kerberos
        Import-PSSession $Session -DisableNameChecking -ErrorAction Stop

        Set-ADServerSettings -ViewEntireForest $true
        Enable-RemoteMailbox $UserID -RemoteRoutingAddress "$UserID@mdotgov.mail.onmicrosoft.com" `
            -DomainController shahqdc3.shacadd.ad.mdot.mdstate
        Start-Sleep -Seconds 10

        Get-RemoteMailbox $UserID | Enable-RemoteMailbox -Archive

        Write-Host "Exchange Online mailbox and archive enabled for $UserID." -ForegroundColor Cyan
    }
    catch {
        Write-Error "Exchange Online provisioning failed: $_"
    }

    # Final Confirmation
    Write-Host "User $UserID has been created and configured successfully." -ForegroundColor Green
}
#--------------------------------------------------------------------------------------------





My Portion of the script

# This script creates a new Active Directory user with the specified properties.   
 

$userid = "NSingh2"
$firstName = "Neha"
$lastName = "Singh"
$email = "NSingh2@mdot.state.md.us"
$phone = "410-545-8702"
$template = "template"
$tempinfo = Get-ADUser $template -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State

#--------------------------------------------------------------------------------------------
New-ADUser -Name $userid
-SamAccountName $userid
-AccountPassword (ConvertTo-SecureString $AccountPassword -AsPlainText -Force)
-ChangePasswordAtLogon:$true `
    -GivenName $firstName
-Surname $lastName
-DisplayName "$firstName $lastName"
-UserPrincipalName $email
-AccountExpirationDate $(([datetime]$csv.'End Date').AddDays(1)) `

-OfficePhone $phone
-Path $($path = (Get-ADUser $template).distinguishedname; $path = $path -replace '.+Template,(.+)', '$1'; $path) `
    -AccountPassword (ConvertTo-SecureString (Read-Host -Prompt "Enter the password") -AsPlainText -Force)
-Enabled $true
-EmployeeID (Read-Host -Prompt "Enter the Employee ID")
-Instance $tempinfo
Set-ADUser $userid -add @{ExtensionAttribute5 = $($csv.'Mail Stop') }

  
#Group Membership
#Get the groups from the template user and add them to the new user
$groups = Get-ADUser $template -Properties MemberOf | Select-Object -ExpandProperty MemberOf 
if ($groups) {    
    Add-ADPrincipalGroupMembership -Identity $userid -MemberOf $groups -Verbose
}
else {
    Write-Host "No groups found for template user $template." 
}
#Set the properties for the new user
Set-ADUser $userid -add @{ExtensionAttribute5 = $($csv.'Mail Stop') }


# Set the home directory for the new user
# Get the home directory from the template user and set it for the new user

$folder = (Get-ADUser $template -Properties *).homedirectory
$folder = $folder -replace '(.+\\).+', "`$1$userid"
if (-not (Get-ChildItem $folder 2>$null)) { "`ndoesn't exist...Creating Folder" }
New-Item -Path $folder -ItemType Directory
Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Verbose

# Exchange Online           
# This section connects to Exchange Online and enables the remote mailbox for the new user
# It also sets the remote routing address and enables the archive mailbox for the new user

$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/powershell Kerberos
Import-PSSession $Session -disablenamechecking
set-ADServerSettings -viewentireforest $True
Enable-RemoteMailbox $userid -RemoteRoutingAddress "$userid@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
Start-Sleep -Seconds 10
Get-RemoteMailbox $userid | Enable-RemoteMailbox -Archive }
end { getuser_info2 $userid }