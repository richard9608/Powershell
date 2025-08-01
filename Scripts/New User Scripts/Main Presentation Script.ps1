

function Set-MDOTADUserCsvProperties {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [Parameter(Mandatory = $true)]
        [string]$UserID,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $true)]
        [string]$Template
    )

    # Import the CSV
    $csv = Import-Csv $CsvPath

    foreach ($row in $csv) {
        # Add or update required properties
        Add-Member -InputObject $row -MemberType NoteProperty -Name UserID -Value $UserID -Force
        Add-Member -InputObject $row -MemberType NoteProperty -Name Password -Value $Password -Force

        # Update labeled field that already exists
        $row.'AD Template to Use' = $Template
    }

    # Save updated data back to file
    $csv | Export-Csv -Path $CsvPath -NoTypeInformation -Force

    return $csv
}
#--------------------------------------------------------------------------------------------
function New-MDOTADUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$csv,

        [Parameter(Mandatory = $true)]
        [string]$UserID,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $true)]
        [string]$TemplateUser
    )

    $email = "$UserID@mdot.state.md.us"

    # Get Template Info
    $templateUserInfo = Get-ADUser $TemplateUser -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State, HomeDirectory, MemberOf
    $path = ($templateUserInfo.DistinguishedName -replace '^.+?Template,(.+)$', '$1')

    $userParams = @{
        Name                  = $UserID
        SamAccountName        = $UserID
        UserPrincipalName     = $email
        GivenName             = $csv.'Legal First Name'
        Surname               = $csv.'Legal Last Name'
        DisplayName           = "$($csv.'Legal First Name') $($csv.'Legal Last Name')"
        AccountPassword       = (ConvertTo-SecureString $Password -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled               = $true
        City                  = $templateUserInfo.City
        Company               = $templateUserInfo.Company
        Department            = $templateUserInfo.Department
        Description           = $templateUserInfo.Description
        Office                = $templateUserInfo.Office
        PostalCode            = $templateUserInfo.PostalCode
        StreetAddress         = $templateUserInfo.StreetAddress
        State                 = $templateUserInfo.State
        Path                  = $path
    }

    if ($csv.'Office Phone') { $userParams['OfficePhone'] = $csv.'Office Phone' }
    if ($csv.'EIN')     { $userParams['EmployeeID']  = $csv.'EIN' }

    # Create AD User
    New-ADUser @userParams -PassThru | Out-Null










#--------------------------------------------------------------------------------------------











    # Copy Group Memberships
    $groups = $templateUserInfo.MemberOf
    if ($groups) {
        Add-ADPrincipalGroupMembership -Identity $UserID -MemberOf $groups -Verbose
    } else {
        Write-Host "No groups found for template user $TemplateUser." -ForegroundColor Yellow
    }

    # Set Home Directory
    if ($templateUserInfo.HomeDirectory) {
        $homeRoot   = $templateUserInfo.HomeDirectory -replace '\\[^\\]+$', ''
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

        Enable-RemoteMailbox $UserID `
            -RemoteRoutingAddress "$UserID@mdotgov.mail.onmicrosoft.com" `
            -DomainController shahqdc3.shacadd.ad.mdot.mdstate

        Start-Sleep -Seconds 30
        Get-RemoteMailbox $UserID | Enable-RemoteMailbox -Archive

        Write-Host "Exchange Online mailbox and archive enabled for $UserID." -ForegroundColor Cyan
    } catch {
        Write-Error "Exchange Online provisioning failed: $_"
    }

    Write-Host "User $UserID has been created and configured successfully." -ForegroundColor Green

    try {
        getuser_Info2 $UserID
    } catch {
        Write-Warning "Could not run getuser_Info2 for ${UserID}: $_"
    }
}
