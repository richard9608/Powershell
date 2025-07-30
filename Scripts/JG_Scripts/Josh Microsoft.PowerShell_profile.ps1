$end="machinename","timecreated","providername","id","message"

$User = "SHACADD\LRichardson2_Adm"
$PWord = (ConvertTo-SecureString -AsPlainText 'PeterPan44S*' -Force)
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

function remmobile {
param([string]$user)
"`nRemoving Active sync devices....`n"
Get-MobileDeviceStatistics -Mailbox $user|select -exp Identity|Remove-MobileDevice -Confirm:$false
"`nDisabling OWA and Active Sync in Exchange....`n"
Set-CASMailbox $user -ActiveSyncEnabled:$false -OWAEnabled:$false
Get-CASMailbox $user|Ft -AutoSize}

$exit1="Account Disabled and moved to inactive users OU
Account Hidden from the Global Address Book
Security groups documented and removed
Active sync and OWA were disabled in Exchange
Active sync devices were removed
out of office until $((get-date).AddDays(14).ToShortDateString())."

$sni="J'dan Vaughn (Consultant) <JVaughn.consultant@mdot.maryland.gov>; Theophilus Osei-Adu <TOseiAdu@mdot.maryland.gov>; Paulin Ama (Consultant) <PAma.consultant@mdot.maryland.gov>; Lavar Richardson <LRichardson2@mdot.maryland.gov>; Marcus Williams <MWilliams28@mdot.maryland.gov>; Marcus Buckley <MBuckley@mdot.maryland.gov>"

function autoreply {
param([string]$user)
"I am no longer employed by MDOT. All inquiries should be e-mailed to $((Get-ADUser $user).GivenName+" "+$((Get-ADUser $user).SurName)) at $((Get-ADUser $user -Properties *).emailaddress). Thank you."|Set-Clipboard}

function userid {
$a=(read-host "FirstName?");$b=(read-host "LastName?")
($a+" "+$b) -replace '(\w)\w+\s(\w+)','$1$2'}

function ooo {
param([string]$user,[string]$message)
Set-MailboxAutoReplyConfiguration $user `
-AutoReplyState Scheduled `
-StartTime $(get-date) `
-EndTime $([datetime]$end=(read-host "end date");$end) `
-InternalMessage "$message" `
-ExternalMessage "$message" `
-ExternalAudience All
Get-MailboxAutoReplyConfiguration $user|fl AutoReplyState,StartTime,EndTime,InternalMessage,ExternalMessage}

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
$mail=@{id='jgreen3@mdot.state.md.us'}
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

function Accesslist {
param([Parameter(mandatory=$true)]
[string]$path)
$a=(get-acl $path).path
"`nPath: $($a -replace '.+::')"
(get-acl $path).Access|ft -AutoSize IdentityReference,IsInherited,FileSystemRights}

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

function addpermission {
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

New-PSDrive -Name M -PSProvider FileSystem -Root \\shahqfs1\ADMUsers\OIT\JGreen3
import-module m:\pcinfo.psm1

$end="machinename","timecreated","providername","id","message"

function AddPermission {
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

function groups {
param([Parameter(mandatory=$true)]
[string]$user)
Get-ADPrincipalGroupMembership -Identity $user -AuthType Basic `
-Credential $cred|sort name|select -exp name}
function acl1 {
param([string]$a)
get-acl $a|select @{l="path";e={$([string]$b=$_.path;$b=$b -replace '.+::',"";
$b)}} -ExpandProperty access|ft filesystemrights,isinherited,identityreference -GroupBy path}

function acl2 {
param([string]$a)
get-acl $a|select @{l="path";e={$([string]$b=$_.path;$b=$b -replace '.+::',"";
$b)}},owner -ExpandProperty access|ft owner,filesystemrights,isinherited,identityreference -GroupBy path}

function finduser {
param([string]$a)
Get-ADUser -LDAPFilter "(name=$a*)" -Properties *|fl displayname,name,employeeid}

function newuser {
param([string]$a)
@"
Name:`t`t`t`t$((Get-ADUser $a -Properties *).displayname)
Username:`t`t`t$((Get-ADUser $a -Properties *).name)
PW:`t`t`t`tMdot@Jun212022
Email:`t`t`t`t$((Get-ADUser $a -Properties *).emailaddress)
Microsoft Sign-in:`t`t$((Get-ADUser $a -Properties *).userprincipalname)
"@}

function HideUser {
param([string]$user)
Set-ADUser $user -Add @{msExchHideFromAddressLists=$true}}

function getuser {
param($a)
Get-ADUser $a -Properties *|fl Name,displayname,Enabled,Created,Lockedout,Homedirectory,Office,OfficePhone,Employeeid,emailaddress,AccountExpirationDate,Description,ExtensionAttribute1,ExtensionAttribute5,DistinguishedName,PrimaryGroup
$b="$((Get-ADUser $a -Properties *|sort proxyaddresses).proxyaddresses|select-string '@')"
$b=$b.Replace("smtp:","")
$b=$b.Replace("SMTP:","")
$b=$b.split()
$b=$b|sort
$b}

function delsheet {
param($a)
$add=[PSCustomObject]@{
email=$([string]$e=(Get-ADUser $a -properties *).EmailAddress;$e=$e -replace '\.consultant';$e);
first_name=(Get-ADUser $a -properties *).GivenName;
last_name=(Get-ADUser $a -properties *).Surname;
Notes="";
'Deletion Date'=(get-date).ToShortDateString();
'EIN#'=(Get-ADUser $a -properties *).EmployeeID;
'SR#'=(Read-Host "SR#");
'Worked By'=(Read-Host "Worked By (userid)")}
$add|Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Deletes_2024.csv" -Append -NoTypeInformation}

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
$add|Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Adds_2024.csv" -Append}

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
$add|Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_FMT_Adds_2024.csv" -Append}

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
$add|Export-Csv -Path "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Updates_2024.csv" -Append}

function NewUserReply {
param([string]$user,[string]$pw=(read-host "Password"))
Get-ADUser $user -Properties *|fl @{l='UserID';e={$_.Name}},
@{l="Password";e={$pw}},
@{l='Email';e={$_.emailaddress}},
@{l='Microsoft UserName';e={$($a=$_.proxyaddresses[1];$a=$a -replace 'smtp:';$a)}}}

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

function remdir {
param([string]$user,[string]$path)
rm $path -Force -Recurse;Set-ADUser $user -Clear Homedirectory,HomeDrive}

function exitdesc {
param([string]$user)
$desc=(Get-ADUser $user -Properties *).description
Set-ADUser $user -Description $("$desc"+" "+"- Disabled $(
(get-date).ToShortDateString()) SR#$(read-host 'SR#') JG")}

function dismove {
param([string]$a)
Disable-ADAccount $a
[string]$b=(get-aduser $a).DistinguishedName
Move-ADObject -Identity $b -TargetPath 'OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate'}

function remove-groups {
param([string]$a)
Get-ADPrincipalGroupMembership $a -AuthType Basic -credential $cred|select -ExpandProperty samaccountname|%{
Remove-ADPrincipalGroupMembership $a -MemberOf $_ -Confirm:$false}}

function newmail {
param([string]$a)
@"
`$UserCredential = Get-Credential
`$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch1/PowerShell/ -Authentication Kerberos
Import-PSSession `$Session -disablenamechecking
set-ADServerSettings -viewentireforest `$True
Enable-RemoteMailbox $a -RemoteRoutingAddress "$a@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
"@|Set-Clipboard}


function MDWare {
start-job {Robocopy /TEE /R:0 /W:0 "\\SHAHANPCE11063\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\RShirk1 qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\RShirk1.txt
Robocopy /TEE /R:0 /W:0 "\\SHAOMTPCE16232\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\sclark qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\sclark.txt
Robocopy /TEE /R:0 /W:0 "\\SHAHANPCE10271\c$\program files (x86)\MDWARE\database" \\shahanfs1\omtoocshared\omt\Asphalt\backups\VVadakoot qa.mdb qc.mdb >> \\SHAHANPCE10269\c$\mdware\VVaddakot.txt}}

function add-alias {
param([string]$a) Set-ADUser $a -Clear proxyAddresses
sleep -Seconds 5
Set-ADUser $a -EmailAddress "$a@mdot.maryland.gov"
Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+"@mdot.maryland.gov"),
$('smtp:'+$a+"@mdot.state.md.us"),
$('smtp:'+$a+"@mdotgov.mail.onmicrosoft.com"),
$('smtp:'+$a+"@sha.maryland.gov"),
$('smtp:'+$a+"@sha.state.md.us")}}

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

function remove-alias {
param([string]$a) Set-ADUser $a -Clear proxyAddresses
sleep -Seconds 3
Set-ADUser $a -EmailAddress "$a@mdot.state.md.us"
Set-ADUser $a -add @{proxyAddresses=$('SMTP:'+$a+'@mdot.state.md.us'),$('smtp:'+$a+'@mdotgov.mail.onmicrosoft.com')}}

function transfer {
param([Parameter(mandatory=$true)]
[string]$target,
[Parameter(mandatory=$true)]
[String]$template)
Set-ADUser $target -Description $((Get-ADUser $template -Properties *).description) `
-Office $((Get-ADUser $template -Properties *).office) `
-StreetAddress $((Get-ADUser $template -Properties *).streetaddress) `
-POBox $((Get-ADUser $template -Properties *).pobox) `
-City $((Get-ADUser $template -Properties *).city) `
-PostalCode $((Get-ADUser $template -Properties *).postalcode) -Verbose
$folder=(Get-ADUser $template -Properties *).homedirectory
$folder=$folder -replace '(.+\\).+',"`$1$target"
if (-not (gci $folder 2>$null)) {"`ndoesn't exist...Creating Folder"}
New-Item -Path $folder -ItemType Directory
Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Verbose
Start-Sleep -Seconds 4
getuser $target
Compare-Object -ReferenceObject $(groups $target) -DifferenceObject $(groups $template) -IncludeEqual}

function portsec {
param([string]$mac,[string]$int)
"sh port-security address | i ($mac)
sh mac address-table | i ($mac)
sh port-security address | i ($int )
sh mac address-table | i ($int )
sh int $int status
"|set-clipboard}

function clear-port {
param([string]$int)
"clear port-security sticky int $int"|set-clipboard}

function salesforce {
param([string]$a)
Add-ADPrincipalGroupMembership $a -MemberOf SHASalesforceAzure_SSO
start-sleep -seconds 3
groups $a|select-string SHASalesforceAzure_SSO}

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

function Server {
param([string]$pc)
Get-ADComputer $pc -Properties *|select Enabled,Name,SAMAccountName,Created,Modified,DNSHostName,DistinguishedName
Resolve-DnsName $pc 2>$null|ft Name,IP4Address -AutoSize}

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

function moveuser {
param([parameter(mandatory=$true)]
[string]$targetuser,
[parameter(mandatory=$true)]
[string]$template)
$target=(Get-ADUser $targetuser).distinguishedname
$destination=$([string]$a=(Get-ADUser $template).distinguishedname;$a=$a -replace 'CN=\w+,(.+)','$1';$a)
Move-ADObject -Identity $target -TargetPath $destination}

function defender {
param([parameter(mandatory=$true)]
[string]$pc)
Get-WinEvent `
-FilterHashtable @{providername="*firewall*";id=2011;starttime=$((get-date).AddDays(-30))} `
-ComputerName $pc 2>$null|fl TimeCreated,MachineName,Providername,ID,Message}

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

function getdisk {
param([string]$pc)
Get-WmiObject Win32_DiskPartition -ComputerName $pc|
SORT Name|ft SystemName,BootPartition,Name,Type,PrimaryPartition,
@{label="Size";exp={$($b=$_.size/1073741824;$b=[System.Convert]::ToInt16($b);"$b GB")}}}

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