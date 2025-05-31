
begin {
    $template = $csv.'AD Template to Use'
    $tempinfo = Get-ADUser $template -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State
    $userid = $csv.UserID
}

process {
    New-ADUser -Name $userid `
        -SamAccountName $userid `
        -AccountPassword (ConvertTo-SecureString -AsPlainText $csv.Password -Force) `
        -ChangePasswordAtLogon:$true `
        -DisplayName $($csv.'Legal First Name' + " " + $csv.'Legal Last Name') `
        -Path $($path = (Get-ADUser $template).distinguishedname; $path = $path -replace '.+Template,(.+)', '$1'; $path) `
        -EmployeeID $csv.'EIN' `
        -Instance $tempinfo `
        -Manager $($csv.Supervisor -replace '@.+') `
        -Enabled:$true `
        -GivenName $csv.'Legal First Name' `
        -Surname $csv.'Legal Last Name' `
        -OfficePhone $($csv.'Office Phone' -replace '(\d\d\d)(\d\d\d)(\d\d\d)', '$1-$2-$3') `
        -Title $csv.'Job Title' `
        --AccountExpirationDate $(([datetime]$csv.'End Date').AddDays(1)) `
        -UserPrincipalName "$userid@mdot.state.md.us" -Verbose
    # Copy group memberships from the template user
    $groups = Get-ADUser $template -Properties MemberOf | Select-Object -ExpandProperty MemberOf 
    if ($groups) {    
        Add-ADPrincipalGroupMembership -Identity $userid -MemberOf $groups -Verbose
    }
    else {
        Write-Host "No groups found for template user $template." 
    }
    Set-ADUser $userid -add @{ExtensionAttribute5 = $($csv.'Mail Stop') }
    Start-Sleep -Seconds 5
    $folder = (Get-ADUser $template -Properties *).homedirectory
    $folder = $folder -replace '(.+\\).+', "`$1$userid"
    if (-not (Get-ChildItem $folder 2>$null)) { "`ndoesn't exist...Creating Folder" }
    New-Item -Path $folder -ItemType Directory
    Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Verbose
    $UserCredential = Get-Credential
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/powershell Kerberos
    Import-PSSession $Session -disablenamechecking
    set-ADServerSettings -viewentireforest $True
    Enable-RemoteMailbox $userid -RemoteRoutingAddress "$userid@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
    Start-Sleep -Seconds 10
    Get-RemoteMailbox $userid | Enable-RemoteMailbox -Archive
}
end { getuser_info2 $userid }

