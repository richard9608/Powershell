NewUserCreation
# Connect to Exchange session once before processing 
param(
    [string]$CsvPath = "C:\Users\LRichardson2\Documents\csv_files\Irtiza_Khan_2025-05-14T18_48_17.4386493Z.csv"
)

$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/powershell -Authentication Kerberos -Credential $UserCredential
Import-PSSession $Session -DisableNameChecking
Set-ADServerSettings -ViewEntireForest $true

# Import CSV file
$csvData = Import-Csv -Path $CsvPath

# Loop through each user
foreach ($csv in $csvData) {

    $template = $csv.'AD Template to Use'
    $tempinfo = Get-ADUser $template -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State
    $userid = $csv.UserID

    New-ADUser -Name $userid `
        -SamAccountName $userid `
        -AccountPassword (ConvertTo-SecureString -AsPlainText $csv.Password -Force) `
        -ChangePasswordAtLogon:$true `
        -DisplayName "$($csv.'Legal First Name') $($csv.'Legal Last Name')" `
        -Path $(
        $path = (Get-ADUser $template).DistinguishedName
        $path = $path -replace '.+Template,(.+)', '$1'
        $path
    ) `
        -EmployeeID $csv.'EIN' `
        -Instance $tempinfo `
        -Manager ($csv.Supervisor -replace '@.+') `
        -Enabled:$true `
        -GivenName $csv.'Legal First Name' `
        -Surname $csv.'Legal Last Name' `
        -OfficePhone ($csv.'Office Phone' -replace '(\d\d\d)(\d\d\d)(\d\d\d)', '$1-$2-$3') `
        -Title $csv.'Job Title' `
        -AccountExpirationDate ([datetime]$csv.'End Date').AddDays(1) `
        -UserPrincipalName "$userid@mdot.state.md.us" -Verbose

    # Copy AD group memberships from template user
    $groups = Get-ADUser $template -Properties MemberOf | Select-Object -ExpandProperty MemberOf
    if ($groups) {
        Add-ADPrincipalGroupMembership -Identity $userid -MemberOf $groups -Verbose
    }
    else {
        Write-Host "No groups found for template user $template."
    }

    Set-ADUser $userid -Add @{ExtensionAttribute5 = $csv.'Mail Stop' }

    Start-Sleep -Seconds 5

    # Create Home Directory
    $folder = (Get-ADUser $template -Properties *).HomeDirectory
    $folder = $folder -replace '(.+\\).+', "`$1$userid"
    if (-not (Test-Path $folder)) {
        Write-Host "Folder doesn't exist...Creating Folder"
        New-Item -Path $folder -ItemType Directory
    }

    Set-ADUser $userid -HomeDirectory $folder -HomeDrive M -Verbose

    # Enable Remote Mailbox
    Enable-RemoteMailbox $userid -RemoteRoutingAddress "$userid@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate

    Start-Sleep -Seconds 10

    Get-RemoteMailbox $userid | Enable-RemoteMailbox -Archive

    # Final info retrieval (assuming getuser_info2 is a custom function)
    getuser_info2 $userid
}

# Cleanup Exchange session
Remove-PSSession $Session
