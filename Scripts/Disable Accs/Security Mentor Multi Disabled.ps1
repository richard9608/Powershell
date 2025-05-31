
$sec = "MAlston3
DHarlee
TBlake2
JBlocker
BButler2
MDowns
HGlacken
KHebron
TJordan2
PPatel6
CSmith36
SVaughan
LHamilton1".split("`n")


$sec.Count


Disable-ADAccount -Identity $sec -Confirm:$false -ErrorAction SilentlyContinue

$sec | ForEach-Object { Get-ADUser $_ | Select-Object Name, Enabled } | Format-Table -AutoSize
$sec | ForEach-Object {
    $user = Get-ADUser $_ -Properties Description
    if ($user) {
        $newDescription = $user.Description + " - Core Course Disabled 4/2/2025 SR#1919940 LR2."
        Set-ADUser -Identity $user.SamAccountName -Description $newDescription
    }
}



$sec | ForEach-Object { Get-ADUser $_ -Properties Description | Select-Object Name, Description } | Format-Table -AutoSize


$sec | ForEach-Object {
    $user = Get-ADUser $_ -Properties Description
    if ($user -and $user.Description -match " - PD-Courses Disabled 4/2/2025 SR#1919940 LR2.") {
        $updatedDescription = $user.Description -replace " - PD-Courses Disabled 4/2/2025 SR#1919940 LR2.", ""
        Set-ADUser -Identity $user.SamAccountName -Description $updatedDescription
    }
}

