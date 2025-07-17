# This PowerShell script defines a function to add properties to each row of a CSV file.
# Add-CsvProperties with New-MDOTADUser


function Add-CsvProperties {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,
        [Parameter(Mandatory=$true)]
        [string]$UserID,
        [Parameter(Mandatory=$true)]
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$Template
    )

    $csv = Import-Csv $CsvPath
    foreach ($row in $csv) {
        Add-Member -InputObject $row -MemberType NoteProperty -Name UserID -Value $UserID -Force
        Add-Member -InputObject $row -MemberType NoteProperty -Name Password -Value $Password -Force
        $row.'AD Template to Use' = $Template
    }

    return $csv
}

# Usage Example
$CsvPath = Read-Host "Enter path to CSV file"
$UserID = Read-Host "Enter UserID"
$Password = Read-Host "Enter Password"
$Template = Read-Host "Enter AD Template to Use"

$csv = Add-CsvProperties -CsvPath $CsvPath -UserID $UserID -Password $Password -Template $Template

#--------------------------------------------------------------------------------------------
# Function to create a new AD user based on a template user

function New-MDOTADUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$UserID,

        [Parameter(Mandatory)]
        [string]$FirstName,

        [Parameter(Mandatory)]
        [string]$LastName,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [string]$TemplateUser,

        [string]$Phone,

        [string]$EmployeeID
    )
    
    # Microsoft UPN @mdot.state.md.us          
    $email = "$UserID@mdot.state.md.us"
    
    # Get Template User Info
    $templateUserInfo = Get-ADUser $TemplateUser -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State, HomeDirectory, MemberOf

    # Derive OU Path from Template
    $path = ($templateUserInfo.DistinguishedName -replace '^.+?Template,(.+)$', '$1')

    # Build parameters for New-ADUser
    $userParams = @{
        Name                  = $UserID
        SamAccountName        = $UserID
        AccountPassword       = (ConvertTo-SecureString $Password -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        UserPrincipalName     = $email
        GivenName             = $csv.'Legal First Name' 
        Surname               = $csv.'Legal Last Name'
        DisplayName           = "$FirstName $LastName"
        ChangePasswordAtLogon = $true
        Enabled               = $true
        Instance              = $templateUserInfo
        Path                  = $path
    }

    if ($Phone) { $userParams['OfficePhone'] = $Phone }
    if ($EmployeeID) { $userParams['EmployeeID'] = $EmployeeID }

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
        Write-Warning "Could not run getuser_Info2 for ${UserID}: $_"
    }
}
#--------------------------------------------------------------------------------------------
#
 
    New-MDOTADUser -UserID EAllocca `
        -FirstName Edward `
        -LastName  Allocca `
        -Password "MDOTSHAJune92025@" `
        -TemplateUser "OED_TEMPLATE" `
        -Phone "410-221-1635" `
        -EmployeeID "500590"
       


     


