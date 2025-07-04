







$csv=import-csv '.\Lavar_Richardson_SampleNUAR.csv'
$csv|Add-Member -MemberType NoteProperty -Name UserID -Value 'LRichardson2'
$csv|Add-Member -MemberType NoteProperty -Name Password -Value 'MdotSH@Jun2025'
$csv.'AD Template to Use'= 'SOC_Template'


  


$a=gci *.csv|? name -ne 'Bulk User Sheet.csv'|select -exp Fullname
$a|%{
$csv=import-csv -path $_
$add=[PSCustomObject]@{
'Legal First Name'=$csv.'Legal First Name';
'Legal Last Name'=$csv.'Legal Last Name';
'Display Name'=$csv.'Display Name';
'Office Phone'=$csv.'Office Phone';



'Select TBU of previous account, if exists'=$csv.'Select TBU of previous account, if exists';
'Previous Account, if exists'=$csv.'Previous Account, if exists';
'EIN'=$csv.EIN;
'C-Number'=$csv.'C-Number';
'Start Date'=$csv.'Start Date';
'End Date'=$csv.'End Date';
'Microsoft Office 365 License Required'=$csv.'Microsoft Office 365 License Required';
'AD Template to Use'=$csv.'AD Template to Use';
'Additional Group Memberships (if none, please specify "N/A")'=$csv.'Additional Group Memberships (if none, please specify "N/A")';
'Additional Notes'=$csv.'Additional Notes'}
$add|Export-Csv -Path 'Bulk User Sheet.csv' -Append -NoTypeInformation}


#--------------------------------------------------------------------------------------------

foreach ($user in $csv) {
    >> findaccount $($($user.'Legal First Name' -replace '(\w)\w+', '$1') + $user.'Legal Last Name')
}


#--------------------------------------------------------------------------------------------



$csv=Import-Csv 'Bulk User Sheet.csv'
foreach ($user in $csv) {
if ($user.'C-Number' -match 'C-.+') {
$template=$user.'AD Template to Use'
$tempinfo=Get-ADUser $template -Properties City,Company,Department,Description,Office,PostalCode,StreetAddress,State
$userid=$user.UserID
New-ADUser -Name $userid `
-SamuserName $userid `
-userPassword (ConvertTo-SecureString -AsPlainText $user.Password -Force) `
-ChangePasswordAtLogon:$true `
-DisplayName $($user.'Legal First Name'+" "+$($user.'Legal Last Name')+" (Consultant)") `
-EmployeeID $user.'C-Number' `
-Instance $tempinfo `
-Enabled:$true `
-GivenName $user.'Legal First Name' `
-Surname $user.'Legal Last Name' `
-OfficePhone $($user.'Office Phone' -replace '(\d\d\d)(\d\d\d)(\d\d\d)','$1-$2-$3') `
-Title $user.'Job Title' `
-userExpirationDate $(([datetime]$user.'End Date').AddDays(1)) `
-UserPrincipalName "$userid@mdot.state.md.us" -Verbose

-Path $($path=(Get-ADUser $template).distinguishedname;$path=$path -replace 'CN=.+Template,(.+)','$1';$path) `

set-ADUser $userid -add @{ExtensionAttribute1= "SHA Consultant"} -Verbose  





Start-Sleep -Seconds 5
$folder=(Get-ADUser $template -Properties *).homedirectory
$folder=$folder -replace '(.+\\).+',"`$1$userid"







if (-not (gci $folder 2>$null)) {"`ndoesn't exist...Creating Folder"}
New-Item -Path $folder -ItemType Directory
Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Add @{ExtensionAttribute1="SHA Consultant"} -Verbose

# Set permissions on the folder
# Ensure the user has full control over their home directory
icacls $folder /grant "$userid:(OI)(CI)F" /T



# Add user to additional groups if specified
# Add user to groups from template
groups $template | ForEach-Object {
    Add-ADPrincipalGroupMembership $userid -MemberOf $_ -Verbose 2>$null
}




$UserCredential = Get-Credential
# Create a new PowerShell session for Exchange Online
# Ensure you have the Exchange Online Management module installed   
# Install-Module -Name ExchangeOnlineManagement -Force
# Connect to Exchange Online
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/PowerShell/ -Authentication Kerberos
Import-PSSession $Session -disablenamechecking
set-ADServerSettings -viewentireforest $True
Enable-RemoteMailbox $userid -RemoteRoutingAddress "$userid@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
Start-Sleep -Seconds 10
getuser $userid}
else {
$template=$user.'AD Template to Use'
$tempinfo=Get-ADUser $template -Properties City,Company,Department,Description,Office,PostalCode,StreetAddress,State
$userid=$user.UserID

New-ADUser -Name $userid `
-SamuserName $userid `
-userPassword (ConvertTo-SecureString -AsPlainText $user.Password -Force) `
-ChangePasswordAtLogon:$true `
-DisplayName $($user.'Legal First Name'+" "+$($user.'Legal Last Name')) `
-Path $($path=(Get-ADUser $template).distinguishedname;$path=$path -replace '.+Template,(.+)','$1';$path) `
-EmployeeID $user.'EIN' `
-Instance $tempinfo `
-Enabled:$true `
-GivenName $user.'Legal First Name' `
-Surname $user.'Legal Last Name' `
-OfficePhone $($user.'Office Phone' -replace '(\d\d\d)(\d\d\d)(\d\d\d)','$1-$2-$3') `
-Title $user.'Job Title' `
-userExpirationDate $(([datetime]$user.'End Date').AddDays(1)) `
-UserPrincipalName "$userid@mdot.state.md.us" -Verbose


$folder=(Get-ADUser $template -Properties *).homedirectory
$folder=$folder -replace '(.+\\).+',"`$1$userid"
if (-not (gci $folder 2>$null)) {"`ndoesn't exist...Creating Folder"}
New-Item -Path $folder -ItemType Directory
Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Verbose


groups $template|%{Add-ADPrincipalGroupMembership $userid -MemberOf $_ -Verbose 2>$null}

$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/PowerShell/ -Authentication Kerberos
Import-PSSession $Session -disablenamechecking
set-ADServerSettings -viewentireforest $True
Enable-RemoteMailbox $userid -RemoteRoutingAddress "$userid@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
Start-Sleep -Seconds 10

getuser $userid}}
#--------------------------------------------------------------------------------------------