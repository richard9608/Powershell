Sample New User 


$userid = $csv.UserID

$email = "$UserID@mdot.state.md.us"

# Get Template User Info
$templateUserInfo = Get-ADUser $TemplateUser -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State, HomeDirectory, MemberOf

# Derive OU Path from Template
$path = ($templateUserInfo.DistinguishedName -replace '^.+?Template,(.+)$', '$1')

# Build parameters for New-ADUser
$userParams = @{
    Name              = $UserID
    SamAccountName    = $UserID
    UserPrincipalName = $email
    GivenName         = $csv.'Legal First Name'
    Surname           = $csv.'Legal Last Name
        DisplayName           = $($csv.'Legal First Name'+" "+$csv.'Legal Last Name')
        EmployeeID            = $csv.'EIN'
        AccountExpirationDate = $(([datetime]$csv.'End Date').AddDays(1)) `
        OfficePhone           = $($csv.'Office Phone' -replace '(\d\d\d)(\d\d\d)(\d\d\d)','$1-$2-$3')
        AccountPassword       = (ConvertTo-SecureString $csv.Password -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled               = $true
        Instance              = $templateUserInfo
        Path                  = $path
    }

   

    # Create the AD user
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
        Write-Warning "Could not run getuser_Info2 for $UserID: $_"
    }
}
