function Get-ADUserDetails {
    param (
        [string]$Username
    )

    return Get-ADUser -Identity $Username -Properties *
}

function Disable-AndHideUser {
    param (
        [string]$Username
    )

    Disable-ADAccount -Identity $Username -ErrorAction Stop
    Set-ADUser -Identity $Username -Replace @{ msExchHideFromAddressLists = $true } -ErrorAction Stop
    Write-Host "User '$Username' disabled and hidden from GAL." -ForegroundColor Green
}

function Confirm-YesNo {
    param (
        [string]$Message
    )

    $response = Read-Host "$Message (Y/N)"
    return $response -match '^[Yy]$'
}

function Log-UserExitDetails {
    param (
        [string]$Username, [string[]]$Groups, [string]$HomeDirectory
    )

    $logPath = "$env:USERPROFILE\Desktop\UserDetails_$Username.txt"
    Add-Content -Path $logPath -Value "User: $Username"
    Add-Content -Path $logPath -Value "HomeDirectory: $HomeDirectory"
    Add-Content -Path $logPath -Value "`nGroups:`n"
    $Groups | ForEach-Object { Add-Content -Path $logPath -Value $_ }
    notepad $logPath
}

function Perform-ExitProcedure {
    param (
        [string]$Username
    )

    $user = Get-ADUserDetails -Username $Username
    if (-not $user) {
        Write-Host "User $Username not found." -ForegroundColor Red
        return
    }

    $SRNumber = Read-Host "Enter SR number"
    $date = (Get-Date).ToShortDateString()
    $descriptionUpdate = "Disabled $date SR#$SRNumber LR2."
    $descriptionUpdate | Set-Clipboard
    Write-Host "Description copied to clipboard." -ForegroundColor Yellow

    $groups = $user.MemberOf
    $homeDirectory = $user.HomeDirectory
    $dn = $user.DistinguishedName

    Log-UserExitDetails -Username $Username -Groups $groups -HomeDirectory $homeDirectory

    if (Confirm-YesNo "Remove HomeDirectory?") {
        Set-ADUser -Identity $Username -HomeDirectory $null
    }

    Disable-ADAccount -Identity $Username
    Move-ADObject -Identity $dn -TargetPath "OU=Inactive User Accounts,DC=shacadd,DC=ad,DC=mdot,DC=mdstate"
    $newDesc = "$($user.Description) - $descriptionUpdate"
    Set-ADUser -Identity $Username -Description $newDesc

    foreach ($group in $groups) {
        if ($group -notlike '*Domain Users*') {
            Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
        }
    }

    Write-Host "Exit procedure completed for $Username." -ForegroundColor Green
}

function Set-ExitUserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]$Username,
        [switch]$DisableAndHide,
        [switch]$ExitProcedure
    )

    if ($DisableAndHide) {
        Disable-AndHideUser -Username $Username
    }
    elseif ($ExitProcedure) {
        Perform-ExitProcedure -Username $Username
    }
    else {
        $user = Get-ADUserDetails -Username $Username
        $user | Format-List Name, DisplayName, Enabled, EmailAddress, Description, MemberOf
    }
}

function Show-ExitUserMenu {
    $username = Read-Host "Enter the username"

    Write-Host "Select an option:" -ForegroundColor Cyan
    Write-Host "1. View user details"
    Write-Host "2. Disable and hide from GAL"
    Write-Host "3. Perform full exit procedure"
    Write-Host "4. Exit"

    $choice = Read-Host "Enter choice number"
    switch ($choice) {
        '1' { Set-ExitUserAccount -Username $username }
        '2' { Set-ExitUserAccount -Username $username -DisableAndHide }
        '3' { Set-ExitUserAccount -Username $username -ExitProcedure }
        default { Write-Host "Exiting..." }
    }
} 

# Optional: Run menu automatically
# Show-ExitUserMenu
