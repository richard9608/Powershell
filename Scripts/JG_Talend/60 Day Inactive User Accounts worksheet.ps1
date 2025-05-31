60 Day Inactive User Accounts
# This script disables and moves users who have been inactive for 60 days or more to a specific OU.



$d = "JGreer@mdot.state.md.us
JShipe@mdot.state.md.us
NBeall@mdot.state.md.us
WWalters2@mdot.state.md.us
EGerhardt@mdot.state.md.us
ABryant4@mdot.state.md.us
NWorgan@mdot.state.md.us
PJoaquin@mdot.state.md.us
TBlount1@mdot.state.md.us
CStephens@mdot.state.md.us
GWhitten@mdot.state.md.us
JFenwick3@mdot.state.md.us
HDurst@mdot.state.md.us
EMartz1@mdot.state.md.us
GCunningham@mdot.state.md.us
DMills4@mdot.state.md.us
RDorsey5@mdot.state.md.us
BQuartey@mdot.state.md.us
CSheffield@mdot.state.md.us
ANorris2@mdot.state.md.us
TKearse@mdot.state.md.us
KVallandingham@mdot.state.md.us
DBoszko@mdot.state.md.us
MStonestreet@mdot.state.md.us
DTyson1@mdot.state.md.us
DZanoni@mdot.state.md.us
GHerman@mdot.state.md.us
CSmith36@mdot.state.md.us
CEscobar2@mdot.state.md.us
JChildrey@mdot.state.md.us
SBennett4@mdot.state.md.us
DFrykman@mdot.state.md.us
NAmayaCruz@mdot.state.md.us
KWilliams18@mdot.state.md.us
BSilvaRodriguez@mdot.state.md.us
LTodd1@mdot.state.md.us
CBurley2@mdot.state.md.us
PPatel6@mdot.state.md.us
BButler2@mdot.state.md.us
RSmith7@mdot.state.md.us
CGore1@mdot.state.md.us
DRumaker@mdot.state.md.us
CRafter@mdot.state.md.us
JZimmerman3@mdot.state.md.us
DGonzales@mdot.state.md.us
MMercer_Adm@mdot.state.md.us
MVanWert_Adm@mdot.state.md.us".split("`r`n")
$d.Count
$users = $d -replace "@mdot.state.md.us", "" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
Write-Output $users  # Use the $users variable to avoid the "assigned but never used" warning










$users = "ARobertson1
RDaye
TGross1
DShryock
JMull1
JWinebrenner
TWigfield
JVenson
TGant1
DRyan".Split("`r`n")
$users.Count


$c | ForEach-Object {
    Disable-ADAccount $_ -Verbose
    Move-ADObject $((Get-ADUser $_).DistinguishedName) -TargetPath 'OU=60 Day Inactive,OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate' -Verbose
    Set-ADUser $_ -Description $(((Get-ADUser $_ -Properties *).Description) + " - Disabled 04/11/25 SR#1917003(Inactive) LR") -Verbose }






# What do I need removed from the description?
# $remove = " - Disabled 04/11/25 SR#1917003(Inactive) LR" 



$users | ForEach-Object {
    $user = Get-ADUser $_ -Properties Description
    $newDescription = $user.Description -replace " - Disabled 04/11/25 SR#1917003\(Inactive\) LR"
    Set-ADUser $_ -Description $newDescription -Verbose
}




$users | ForEach-Object {
    Enable-ADAccount $_ -Verbose
    Get-aduser $_ -Properties * | Select-Object -Property Name, displayname, Description, enabled  | Format-List
}


$shop = "DShryock
JMull1
JWinebrenner
TWigfield".Split("`r`n")
$shop.Count
$shop | ForEach-Object {
    enable-ADAccount $_ -Verbose
    Move-ADObject $((Get-ADUser $_).DistinguishedName) -TargetPath 'OU=SHOP71,OU=D7,OU=DIST,OU=SHA,DC=shacadd,DC=ad,DC=mdot,DC=mdstate' -Verbose

}




$sers = "TGross1
JVenson".Split("`r`n")
$sers.Count
$sers | ForEach-Object {
    Get-aduser $_ -Properties * | Select-Object -Property Name, displayname, Description, enabled, distinguishedName  | Format-List
}


Move-ADObject -Identity ARobertson1 -TargetPath "OU=SHOP71,OU=D7,OU=DIST,OU=SHA,DC=shacadd,DC=ad,DC=mdot,DC=mdstate" -Verbose
   

Move-ADObject -Identity (get-aduser ARobertson1).DistinguishedName -TargetPath "OU=SHOP71,OU=D7,OU=Districts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate" -Verbose


Move-ADObject -Identity (Get-ADUser DRyan).DistinguishedName -TargetPath "OU=SOC,OU=Hanover,OU=SHA,DC=shacadd,DC=ad,DC=mdot,DC=mdstate" -Verbose
Get-aduser DRyan -Properties * | Select-Object -Property Name, displayname, Description, enabled, distinguishedName  | Format-List
