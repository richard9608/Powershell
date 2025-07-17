Version 1

function New-MDOTADUser {
    [CmdletBinding()]
    param (
        [PSCustomObject]$csv,
        [string]$UserID,
        [string]$Password,
        [string]$TemplateUser
    )

    $email = "$UserID@mdot.state.md.us"
    $templateUserInfo = Get-ADUser $TemplateUser -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State, HomeDirectory, MemberOf
    $path = ($templateUserInfo.DistinguishedName -replace '^.+?Template,(.+)$', '$1')

    $userParams = @{
        Name = $UserID
        SamAccountName = $UserID
        UserPrincipalName = $email
        GivenName = $csv.'Legal First Name'
        Surname = $csv.'Legal Last Name'
        DisplayName = "$($csv.'Legal First Name') $($csv.'Legal Last Name') (Consultant)"
        AccountPassword = (ConvertTo-SecureString $Password -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled = $true
        Instance = $templateUserInfo
        Path = $path
    }

    if ($csv.'Office Phone') { $userParams['OfficePhone'] = $csv.'Office Phone' }
    if ($csv.'C-Number') { $userParams['EmployeeID'] = $csv.'C-Number' }

    # 

    New-ADUser @userParams -PassThru | Out-Null


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
        Start-Sleep -Seconds 30

        Get-RemoteMailbox $UserID | Enable-RemoteMailbox -Archive

        Write-Host "Exchange Online mailbox and archive enabled for $UserID." -ForegroundColor Cyan
    }
    catch {
        Write-Error "Exchange Online provisioning failed: $_"
    }

    Write-Host "User $UserID has been created and configured successfully." -ForegroundColor Green

    # ➕ FINAL STEP: Call getuser_Info2
    try {
        getuser_Info2 $UserID
    }
    catch {
        Write-Warning "Could not run getuser_Info2 for ${UserID}: $_"
    }
}










