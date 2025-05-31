
function Invoke-CreateUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $userInfo,

        [Parameter(Mandatory)]
        $templateUser
    )
    $UserID = $userInfo.UserID
    $DisplayName = $userInfo.'Display Name'
    $FirstName = $userInfo.'Legal First Name'
    $LastName = $userInfo.'Legal Last Name'
    $email = "$UserID@mdot.state.md.us"
    $userParams = @{
        Name                  = $DisplayName
        SamAccountName        = $UserID
        UserPrincipalName     = $email
        GivenName             = $FirstName
        Surname               = $LastName
        DisplayName           = $DisplayName
        Title                 = $userInfo.'Job Title'
        OfficePhone           = $userInfo.'Office Phone'
        AccountPassword       = (ConvertTo-SecureString $userInfo.Password -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled               = $true
        Instance              = $templateUser
        Path                  = ($templateUser.DistinguishedName -replace '^.+?Template,(.+)$', '$1')
    }
    if ($userInfo.EIN) { $userParams.EmployeeID = $userInfo.EIN }
    New-ADUser @userParams -PassThru | Out-Null
    Write-Host "✅ Created user $UserID" -ForegroundColor Green
}

function Invoke-AddGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $UserID,
        [Parameter(Mandatory)]
        $templateUser,
        [Parameter()]
        $GroupMemberships
    )
    if ($templateUser.MemberOf) {
        Add-ADPrincipalGroupMembership -Identity $UserID -MemberOf $templateUser.MemberOf
    }
    if ($GroupMemberships -and $GroupMemberships -ne "N/A") {
        $GroupList = $GroupMemberships -split ';|,'
        foreach ($grp in $GroupList) {
            $grp = $grp.Trim()
            if ($grp -ne "") {
                Add-ADGroupMember -Identity $grp -Members $UserID
            }
        }
    }
    Write-Host "✅ Group memberships applied" -ForegroundColor Green
}

function Invoke-CreateHomeDrive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $UserID,
        [Parameter(Mandatory)]
        $templateUser
    )
    if ($templateUser.HomeDirectory) {
        $homeRoot = ($templateUser.HomeDirectory -replace '\[^\]+$', '')
        $newHomeDir = "$homeRoot\$UserID"
        if (-not (Test-Path $newHomeDir)) {
            New-Item -Path $newHomeDir -ItemType Directory | Out-Null
        }
        Set-ADUser $UserID -HomeDirectory $newHomeDir -HomeDrive 'M:'
        Write-Host "🏠 Home directory set to $newHomeDir"
    }
}

function Invoke-EnableExchange {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $UserID
    )
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
        Write-Host "📬 Exchange Online mailbox and archive enabled for $UserID." -ForegroundColor Cyan
    } catch {
        Write-Warning ("Exchange provisioning failed for ${UserID}: {0}" -f $_)
    }
}

function Invoke-RunAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $UserID
    )
    try {
        getuser_Info2 $UserID
    } catch {
        Write-Warning ("Audit script failed for ${UserID}: {0}" -f $_)
    }
}
