# This script creates a new Active Directory user with the specified properties.

$userid = Read-Host -Prompt "Enter the user ID"
$firstName = Read-Host -Prompt "Enter the first name"
$lastName = Read-Host -Prompt "Enter the last name"
$AccountPassword = Read-Host -Prompt "Enter the account password"
$email = "$userid@mdot.state.md.us"
$phone = Read-Host -Prompt "Enter the phone number"
$template = Read-Host -Prompt 'Enter the OU template to Use'
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
