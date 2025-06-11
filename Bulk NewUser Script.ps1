#.SYNOPSIS
#    Combines multiple CSV files into a single CSV file.
#.DESCRIPTION
#    This script reads all CSV files in the specified directory, excluding any existing 'Bulk User Sheet.csv' file.
#    It extracts specific columns from each CSV file and appends the data to a new CSV file named 'Bulk User Sheet.csv' in the same directory.
#.NOTES
#    File Name  : Combine-CSVs into Bulk.ps1
#    Author     : Josh Green (LRichardson2)
#    Prerequisite: PowerShell 5.0 or higher 
#    Created    : 10/10/2023
#    Updated    : 10/10/2023    
#.LINK
#    https://example.com
#.EXAMPLE
#    PS C:\> .\Combine-CSVs into Bulk.ps1

<#foreach ($item in $csv) {
>> findaccount $($($item.'Legal First Name' -replace '(\w)\w+','$1')+$item.'Legal Last Name')} 

<# Convert all csv files to a Bulk User Sheet
Convert all csv files in C:\Users\LRichardson2\Documents\csv_files to a single csv file with the name 'Bulk User Sheet.csv' in the same directory
Set-Location -Path C:\Users\LRichardson2\Documents\csv_files  
#>
  


$a=gci *.csv|? name -ne 'Bulk User Sheet.csv'|select -exp Fullname
$a|%{
$csv=import-csv -path $_
$add=[PSCustomObject]@{
'Legal First Name'=$csv.'Legal First Name';
'Legal Middle Initial'='';
'Legal Last Name'=$csv.'Legal Last Name';
'Display Name'=$csv.'Display Name';
'AD Account Type'=$csv.'AD Account Type';
'Office Phone'=$csv.'Office Phone';
'Office R/C'=$csv.'Office R/C';
'Division/Location'=$csv.'Division/Location';
'Job Title'=$csv.'Job Title';
'Supervisor'=$csv.Supervisor;
'Mail Stops'=$csv.'Mail Stops';
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

foreach ($item in $csv) {
    >> findaccount $($($item.'Legal First Name' -replace '(\w)\w+', '$1') + $item.'Legal Last Name')
}


#--------------------------------------------------------------------------------------------



$csv=Import-Csv 'Bulk User Sheet.csv'
foreach ($account in $csv) {
if ($account.'C-Number' -match 'C-.+') {
$template=$account.'AD Template to Use'
$tempinfo=Get-ADUser $template -Properties City,Company,Department,Description,Office,PostalCode,StreetAddress,State
$userid=$account.UserID
New-ADUser -Name $userid `
-SamAccountName $userid `
-AccountPassword (ConvertTo-SecureString -AsPlainText $account.Password -Force) `
-ChangePasswordAtLogon:$true `
-DisplayName $($account.'Legal First Name'+" "+$($account.'Legal Last Name')+" (Consultant)") `
-Path $($path=(Get-ADUser $template).distinguishedname;$path=$path -replace 'CN=.+Template,(.+)','$1';$path) `
-EmployeeID $account.'C-Number' `
-Instance $tempinfo `
-Enabled:$true `
-GivenName $account.'Legal First Name' `
-Surname $account.'Legal Last Name' `
-OfficePhone $($account.'Office Phone' -replace '(\d\d\d)(\d\d\d)(\d\d\d)','$1-$2-$3') `
-Title $account.'Job Title' `
-AccountExpirationDate $(([datetime]$account.'End Date').AddDays(1)) `
-UserPrincipalName "$userid@mdot.state.md.us" -Verbose
Set-ADUser $userid -add @{ExtensionAttribute5=$($account.'Mail Stop')}
Start-Sleep -Seconds 5
$folder=(Get-ADUser $template -Properties *).homedirectory
$folder=$folder -replace '(.+\\).+',"`$1$userid"
if (-not (gci $folder 2>$null)) {"`ndoesn't exist...Creating Folder"}
New-Item -Path $folder -ItemType Directory
Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Add @{ExtensionAttribute1="SHA Consultant"} -Verbose
$acl=get-acl $folder
$identity="SHACADD\$userid"
[System.Security.AccessControl.FileSystemRights]$rights=@("FullControl")
[System.Security.AccessControl.InheritanceFlags]$inher=@("ContainerInherit","ObjectInherit")
[System.Security.AccessControl.PropagationFlags]$prop="None"
[System.Security.AccessControl.AccessControlType]$type="Allow"
$object=$identity,$rights,$inher,$prop,$type
$newacl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
$acl.AddAccessRule($newacl)
Set-Acl $folder -AclObject $acl
groups $template|%{Add-ADPrincipalGroupMembership $userid -MemberOf $_ -Verbose 2>$null}
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/PowerShell/ -Authentication Kerberos
Import-PSSession $Session -disablenamechecking
set-ADServerSettings -viewentireforest $True
Enable-RemoteMailbox $userid -RemoteRoutingAddress "$userid@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
Start-Sleep -Seconds 10
getuser $userid}
else {
$template=$account.'AD Template to Use'
$tempinfo=Get-ADUser $template -Properties City,Company,Department,Description,Office,PostalCode,StreetAddress,State
$userid=$account.UserID
New-ADUser -Name $userid `
-SamAccountName $userid `
-AccountPassword (ConvertTo-SecureString -AsPlainText $account.Password -Force) `
-ChangePasswordAtLogon:$true `
-DisplayName $($account.'Legal First Name'+" "+$($account.'Legal Last Name')) `
-Path $($path=(Get-ADUser $template).distinguishedname;$path=$path -replace '.+Template,(.+)','$1';$path) `
-EmployeeID $account.'EIN' `
-Instance $tempinfo `
-Enabled:$true `
-GivenName $account.'Legal First Name' `
-Surname $account.'Legal Last Name' `
-OfficePhone $($account.'Office Phone' -replace '(\d\d\d)(\d\d\d)(\d\d\d)','$1-$2-$3') `
-Title $account.'Job Title' `
-AccountExpirationDate $(([datetime]$account.'End Date').AddDays(1)) `
-UserPrincipalName "$userid@mdot.state.md.us" -Verbose
Set-ADUser $userid -add @{ExtensionAttribute5=$($account.'Mail Stop')}
Start-Sleep -Seconds 5
$folder=(Get-ADUser $template -Properties *).homedirectory
$folder=$folder -replace '(.+\\).+',"`$1$userid"
if (-not (gci $folder 2>$null)) {"`ndoesn't exist...Creating Folder"}
New-Item -Path $folder -ItemType Directory
Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Verbose
$acl=get-acl $folder
$identity="SHACADD\$userid"
[System.Security.AccessControl.FileSystemRights]$rights=@("FullControl")
[System.Security.AccessControl.InheritanceFlags]$inher=@("ContainerInherit","ObjectInherit")
[System.Security.AccessControl.PropagationFlags]$prop="None"
[System.Security.AccessControl.AccessControlType]$type="Allow"
$object=$identity,$rights,$inher,$prop,$type
$newacl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $object
$acl.AddAccessRule($newacl)
Set-Acl $folder -AclObject $acl
groups $template|%{Add-ADPrincipalGroupMembership $userid -MemberOf $_ -Verbose 2>$null}
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/PowerShell/ -Authentication Kerberos
Import-PSSession $Session -disablenamechecking
set-ADServerSettings -viewentireforest $True
Enable-RemoteMailbox $userid -RemoteRoutingAddress "$userid@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
Start-Sleep -Seconds 10
getuser $userid}}
#--------------------------------------------------------------------------------------------