# How to Run the New-UserFromCsv Script Step-by-Step

# ✅ STEP 1: Launch PowerShell as Administrator
# Right-click your PowerShell icon and select "Run as Administrator"

# ✅ STEP 2: Set the path to your CSV file
$csvPath = Read-Host "Please enter the full path to your CSV file"

# ✅ STEP 3: Run the full provisioning process (AutoFix included)
New-UserFromCsv `
-CsvPath $csvPath `
-AutoFixAndRun `           # Automatically fix, prompt, export, and validate
-CreateUser `              # Create AD account
-ApplyConsultantLogic `    # Apply logic for contractors/consultants (optional)
-AddGroups `               # Assign groups
-CreateHomeDrive `         # Setup home directory
-EnableExchange `          # Enable mailbox
-RunAudit                  # Audit and verify user was created properly

# ✅ ALTERNATIVE: Just validate and preview without making changes
New-UserFromCsv `
    -CsvPath $csvPath `
    -AddMissingFields `
    -PromptMissingValues `
    -ExportUpdatedCsv `
    -ValidateOnly

# This lets you confirm everything is in place BEFORE running real user creation.

# ✅ FILE EXPORT CHECK & NOTIFICATION
# If using -ExportUpdatedCsv switch, the script now confirms file save status:
# Example code embedded in the script:
# 
#     if ($ExportUpdatedCsv) {
#         $outputPath = [System.IO.Path]::ChangeExtension($CsvPath, ".updated.csv")
#         $user | Export-Csv -Path $outputPath -NoTypeInformation
#
#         if (Test-Path $outputPath) {
#             Write-Host "✅ Updated CSV saved successfully:" -ForegroundColor Green
#             Write-Host "   $outputPath" -ForegroundColor Yellow
#             # Optional: Auto-open file in Excel
#             Start-Process "excel.exe" $outputPath
#         } else {
#             Write-Warning "⚠️ Failed to save updated CSV file to: $outputPath"
#         }
#     }
# This ensures you know exactly where your updated CSV is saved and can easily access it.
# ✅ NOTE: Ensure you have the necessary permissions and modules installed to run this script.  





function New-UserFromCsv {
    [CmdletBinding(DefaultParameterSetName = 'Full')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [switch]$AddMissingFields,
        [switch]$PromptMissingValues,
        [switch]$ExportUpdatedCsv,
        [switch]$ValidateOnly,
        [switch]$AutoFixAndRun,

        [switch]$CreateUser,
        [switch]$ApplyConsultantLogic,
        [switch]$AddGroups,
        [switch]$CreateHomeDrive,
        [switch]$EnableExchange,
        [switch]$RunAudit
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "❌ The ActiveDirectory module is not installed. Please install it before running this script."
    }
    Import-Module ActiveDirectory

    if (-not (Test-Path $CsvPath)) {
    $user = Import-Csv -Path $CsvPath | Select-Object -First 1

    $requiredFields = @('Legal First Name', 'Legal Last Name', 'Display Name', 'Password', 'AD Template to Use')
    foreach ($field in $requiredFields) {
        if (-not $user.PSObject.Properties[$field]) {
            throw "❌ Missing required field in CSV: $field"
        }
    }
    }

    $user = Import-Csv -Path $CsvPath | Select-Object -First 1

    if (-not $user) {
        throw "❌ CSV file is empty or invalid."
    }

    if ($AddMissingFields) {
        $missingFields = @{
            'UserID'             = ''
            'Password'           = ''
            'AD Template to Use' = 'N/A'
        }

        foreach ($field in $missingFields.Keys) {
            Add-MissingField -User $user -FieldName $field -DefaultValue $missingFields[$field]
        }

        Write-Host "🛠 Added missing fields: UserID, Password, AD Template to Use (if they were not present)." -ForegroundColor Cyan
    }

    if ($PromptMissingValues) {
        if (-not $user.UserID) {
            $user.UserID = Read-Host "Enter UserID (e.g., jdoe)"
        }
        if (-not $user.Password) {
            $user.Password = New-LRPassword
            Write-Host "🔐 Generated password using New-LRPassword" -ForegroundColor Green
        }
        if (-not $user.'AD Template to Use' -or $user.'AD Template to Use' -eq 'N/A') {
            $user.'AD Template to Use' = Read-Host "Enter AD Template to Use (e.g., D30FF_Template)"
        }
    }

    Test-HRUserCsv -user $user

    if ($ValidateOnly) {
        return $user
    }

    if ($ExportUpdatedCsv) {
        $outputPath = [System.IO.Path]::ChangeExtension($CsvPath, ".updated.csv")
        $user | Export-Csv -Path $outputPath -NoTypeInformation
        Write-Host "📁 Exported updated user to: $outputPath" -ForegroundColor Green
    }

    if ($AutoFixAndRun) {
        $fixedCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, ".updated.csv")
        New-UserFromCsv -CsvPath $CsvPath -AddMissingFields -PromptMissingValues -ExportUpdatedCsv -ValidateOnly | Out-Null

        if ($fixedCsvPath -ne $CsvPath) {
            New-UserFromCsv -CsvPath $fixedCsvPath -CreateUser:$CreateUser -ApplyConsultantLogic:$ApplyConsultantLogic -AddGroups:$AddGroups -CreateHomeDrive:$CreateHomeDrive -EnableExchange:$EnableExchange -RunAudit:$RunAudit
        } else {
            Write-Warning "⚠️ Recursive call prevented: Updated CSV file is identical to the original."
        }
        return
    }

    # Extract user fields
    $FirstName = $user.'Legal First Name'
    $LastName = $user.'Legal Last Name'
    $CNumber = $user.'C-Number'
    $TemplateUser = $user.'AD Template to Use'
    $GroupMemberships = $user.'Additional Group Memberships'
    $RequestedUserID = $user.UserID

    if (-not $RequestedUserID) {
        $baseID = ($FirstName.Substring(0, 1) + $LastName).ToLower()
        $i = 0
        do {
            $candidate = if ($i -eq 0) { $baseID } else { "$baseID$i" }
            $exists = Get-ADUser -Filter { SamAccountName -eq $candidate } -ErrorAction SilentlyContinue
            $i++
        } while ($exists -and $i -lt 100)

        if ($i -ge 100) {
            throw "Unable to find unique UserID after 100 attempts"
        }

        $UserID = $candidate
    }
    else {
        $UserID = $RequestedUserID
    }

    $email = "$UserID@mdot.state.md.us"

    try {
        $templateUserInfo = Get-ADUser $TemplateUser -Properties *
        if (-not $templateUserInfo) {
            throw "❌ Template user '$TemplateUser' not found in Active Directory."
        }
        $ouPath = ($templateUserInfo.DistinguishedName -replace '^.+?Template,(.+)$', '$1')
    } catch {
        throw "❌ Error retrieving template user '$TemplateUser': $_"
    }

    if ($CreateUser) { Invoke-CreateUser -userInfo $user -templateUser $templateUserInfo -UserID $UserID -OUPath $ouPath -Email $email }
    if ($ApplyConsultantLogic) { Invoke-ConsultantLogic -UserID $UserID -CNumber $CNumber }
    if ($AddGroups) { Invoke-AddGroups -UserID $UserID -templateUser $templateUserInfo -GroupMemberships $GroupMemberships }
    if ($CreateHomeDrive) { Invoke-CreateHomeDrive -UserID $UserID -templateUser $templateUserInfo }
    if ($EnableExchange) { Invoke-EnableExchange -UserID $UserID }
    if ($RunAudit) { Invoke-RunAudit -UserID $UserID }

    return $user
}

function Validate-HRUserCsv {
    param($user)

function Test-HRUserCsv {
    param($user)

    $requiredFields = @(
        'Legal First Name',
        'Legal Last Name',
        'Display Name',
        'Password',
        'AD Template to Use'
    )

    $errors = @()

    foreach ($field in $requiredFields) {
        if (-not $user.$field -or $user.$field -eq 'N/A') {
            $errors += "Missing or invalid: $field"
        }
    }

    if ($errors.Count -gt 0) {
        Write-Warning "🚫 Validation failed:"
        $errors | ForEach-Object { Write-Warning " - $_" }
    }
}
}

function Invoke-CreateUser {
    param([Parameter(Mandatory)] $userInfo, [Parameter(Mandatory)] $templateUser, [Parameter(Mandatory)] $UserID, [Parameter(Mandatory)] $OUPath, [Parameter(Mandatory)] $Email)

    $params = @{
        Name                  = $userInfo.'Display Name'
        SamAccountName        = $UserID
        UserPrincipalName     = $Email
        GivenName             = $userInfo.'Legal First Name'
        Surname               = $userInfo.'Legal Last Name'
        DisplayName           = $userInfo.'Display Name'
        Title                 = $userInfo.'Job Title'
        OfficePhone           = $userInfo.'Office Phone'
        AccountPassword       = (ConvertTo-SecureString $userInfo.Password -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled               = $true
        Instance              = $templateUser
        Path                  = $OUPath
    }

    if ($userInfo.EIN) {
        $params.EmployeeID = $userInfo.EIN
    }

    New-ADUser @params -PassThru | Out-Null
    Write-Host "✅ Created user $UserID" -ForegroundColor Green
}

function Invoke-ConsultantLogic {
    param([string]$UserID, [string]$CNumber)

    if ($CNumber -match '^C-\\d+') {
        try {
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$UserID'" -Properties DisplayName
            if ($adUser) {
                $baseDisplayName = $adUser.DisplayName
                $newDisplayName = "$baseDisplayName (Consultant)"
                Set-ADUser -Identity $UserID -DisplayName $newDisplayName -Replace @{ExtensionAttribute1 = 'SHA Consultant'; EmployeeID = $CNumber }
                Write-Host "🔄 Consultant logic applied to $UserID" -ForegroundColor Cyan
            }
        }
        catch {
            Write-Warning "Consultant logic failed for $UserID: $_"
        }
    }
}

function Invoke-AddGroups {
    param([string]$UserID, $templateUser, $GroupMemberships)

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
    Write-Host "✅ Group memberships applied for $UserID" -ForegroundColor Green
}
            Write-Warning "Consultant logic failed for $UserID: ${_}"
function Invoke-CreateHomeDrive {
    param([string]$UserID, $templateUser)

    if ($templateUser.HomeDirectory) {
        $homeRoot = ($templateUser.HomeDirectory -replace '\\[^\\]+$', '')
        $newHomeDir = "$homeRoot\\$UserID"
        if (-not (Test-Path $newHomeDir)) {
            New-Item -Path $newHomeDir -ItemType Directory | Out-Null
        }
        Set-ADUser $UserID -HomeDirectory $newHomeDir -HomeDrive 'M:'
        Write-Host "🏠 Home directory set for $UserID: $newHomeDir"
    }
}

function Invoke-EnableExchange {
    param([string]$UserID)

    try {
        $UserCredential = Get-Credential
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/powershell -Authentication Kerberos
        Import-PSSession $Session -DisableNameChecking -ErrorAction Stop

        Set-ADServerSettings -ViewEntireForest $true
        Enable-RemoteMailbox $UserID -RemoteRoutingAddress "$UserID@mdotgov.mail.onmicrosoft.com" -DomainController shahqdc3.shacadd.ad.mdot.mdstate
        Start-Sleep -Seconds 30
        Get-RemoteMailbox $UserID | Enable-RemoteMailbox -Archive
        Write-Host "📬 Exchange Online mailbox and archive enabled for $UserID." -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Exchange provisioning failed for $UserID: $_"
    }
}

        Write-Host "🏠 Home directory set for $UserID: ${newHomeDir}"
    param([string]$UserID)

    try {
        getuser_Info2 $UserID
    }
    catch {
        Write-Warning "Audit script failed for $UserID: $_"
    }
}
        Write-Warning "Exchange provisioning failed for $UserID: ${_}"
        Write-Warning "Audit script failed for $UserID: ${_}"
