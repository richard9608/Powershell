#.synopsis
# Updates user exit records for deletion, license changes, and litigation holds.
# .description
# This script allows the user to select actions to update records related to user exits, including deletion records, license changes, and litigation holds. It prompts for necessary information and saves the records to specified CSV files and an Excel file.
# .example
# Update-UserExitRecordsLR
# This command will prompt the user to select actions and enter required information to update user exit records.
# .notes
# This script is intended for use by IT administrators to manage user exit processes.
# Ensure that you have the necessary permissions to update user records.    
# .requires -Module ImportExcel
# Ensure that the ImportExcel module is installed and available.
# .requires -Module ActiveDirectory
# Ensure that the ActiveDirectory module is available to access AD user information.                    
# .link



function Update-UserExitRecordsLR {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        try { Import-Module ImportExcel -ErrorAction Stop }
        catch {
            Write-Host "❌ ImportExcel is not installed. Use: Install-Module ImportExcel"
            return
        }
    }

    Write-Host "Select the action(s) you want to perform (comma-separated if multiple):"
    Write-Host "1. Update Delete Sheet"
    Write-Host "2. Update License Sheet"
    Write-Host "3. Update Litigation Sheet"
    $selection = Read-Host "Enter your selection (e.g., 1,2 or 2,3)"

    $choices = $selection -split "," | ForEach-Object { $_.Trim() }

    if ($choices.Count -eq 0) {
        Write-Host "❌ No valid selection made."
        return
    }

    $userId = Read-Host "Enter AD Username"
    $adUser = Get-ADUser -Identity $userId -Properties EmailAddress, GivenName, Surname, EmployeeID

    if (-not $adUser) {
        Write-Host "❌ AD User not found." -ForegroundColor Red
        return
    }

    $email = $adUser.EmailAddress -replace '\.consultant'
    $first = $adUser.GivenName
    $last = $adUser.Surname
    $eid = $adUser.EmployeeID
    $date = (Get-Date).ToShortDateString()

    $sr = if ($choices -contains "1" -or $choices -contains "2") { Read-Host "Enter SR#" } else { $null }
    $workedBy = if ($choices -contains "1" -or $choices -contains "2" -or $choices -contains "3") { Read-Host "Worked By (UserID)" } else { $null }
    $ou = if ($choices -contains "1") { Read-Host "Enter OU" } else { $null }

    # License-specific prompts
    if ($choices -contains "2") {
        Write-Host "Select License Type:"
        Write-Host "1. G5"
        Write-Host "2. G3"
        Write-Host "3. F3"
        $ltChoice = Read-Host "Enter your selection (1-3)"
        $licenseType = switch ($ltChoice) {
            "1" { "G5" }
            "2" { "G3" }
            "3" { "F3" }
            default { "Unknown" }
        }

        Write-Host "Was the License:"
        Write-Host "1. Added"
        Write-Host "2. Removed"
        $licenseStatusChoice = Read-Host "Enter your selection (1 or 2)"
        $licenseStatus = if ($licenseStatusChoice -eq "1") { "Added" } elseif ($licenseStatusChoice -eq "2") { "Removed" } else { "Unknown" }

        $creationDate = if ($licenseStatus -eq "Added") { $date } else { "" }
        $deletionDate = if ($licenseStatus -eq "Removed") { $date } else { "" }
    }

    # Litigation-specific prompt
    if ($choices -contains "3") {
        Write-Host "Select Litigation Option:"
        Write-Host "1. Out of Office - Y - Hidden in GAL"
        Write-Host "2. Out of Office - Proxy Rights until [date] - Y - Hidden in GAL"
        Write-Host "3. Hidden in GAL"
        Write-Host "4. Proxy Rights until [date]"
        $litOption = Read-Host "Enter your selection (1-4)"

        $litDesc = switch ($litOption) {
            "1" { "Out of Office - Y - Hidden in GAL" }
            "2" {
                $proxyDate = Read-Host "Enter the date the proxy rights will expire (e.g. 08/30/2025)"
                "Out of Office - Proxy Rights until $proxyDate - Y - Hidden in GAL"
            }
            "3" { "Hidden in GAL" }
            "4" {
                $proxyDate = Read-Host "Enter the date the proxy rights will expire (e.g. 08/30/2025)"
                "Proxy Rights until $proxyDate"
            }
            default { "Unspecified" }
        }
    }

    if ($choices -contains "1") {
        $UserDeleteRecord = [PSCustomObject]@{
            email           = $email
            first_name      = $first
            last_name       = $last
            OU              = $ou
            'Deletion Date' = $date
            'EIN#'          = $eid
            'SR#'           = $sr
            'Worked By'     = $workedBy
        }

        $UserDeleteRecord | Export-Csv -Path "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Deletes_2025.csv" -Append -NoTypeInformation
        Write-Host "✅ Delete record saved."
    }

    if ($choices -contains "2") {
        $UserLicenseRecord = [PSCustomObject]@{
            email                   = $email
            first_name              = $first
            last_name               = $last
            License_Type            = $licenseType
            'SR#'                   = $sr
            Worked_By               = $workedBy
            'License_Added/Removed' = $licenseStatus
            Notes                   = ""
            Creation_Date           = $creationDate
            Deletion_Date           = $deletionDate
        }

        $csvPath = "$env:USERPROFILE\Documents\LicenseInfo.csv"
        $excelPath = '\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\SHA_Licenses.xlsx'

        

$success = $false
$attempt = 0
while (-not $success -and $attempt -lt 5) {
    try {
        $UserLicenseRecord | Export-Csv -Path $csvPath -Append -NoTypeInformation
        $check = Import-Csv -Path $csvPath | Where-Object { $_.email -eq $UserLicenseRecord.email }
        if ($check) {
            Write-Host "✅ Record for $($UserLicenseRecord.email) successfully written to License CSV." -ForegroundColor Green
        } else {
            Write-Host "⚠️ Unable to confirm write to License CSV. Please verify manually." -ForegroundColor Yellow
        }
        $success = $true
    } catch {
        $attempt++
        Write-Host "❌ Could not write to the License CSV (Attempt $attempt). File may be open. Retrying in 3 seconds..." -ForegroundColor Red
        Start-Sleep -Seconds 3
    }
}


        $UserLicenseRecord | Export-Excel -Path $excelPath -WorksheetName 'SHA_Licenses' -Append
        Write-Host "✅ License record saved."
    }

    if ($choices -contains "3") {
        $UserLitigationRecord = [PSCustomObject]@{
            email                              = $email
            first_name                         = $first
            last_name                          = $last
            'Litigation Hold or Proxy Needed?' = $litDesc
            'User Disabled Date'               = $date
            'Worked by'                        = $workedBy
        }

        $litPath = "\\SHAHQFS1\ADMShared\OIT\TSD\Network\Document\Security Mentor\Current\Litigation_Hold.csv"
        

$success = $false
$attempt = 0
while (-not $success -and $attempt -lt 5) {
    try {
        $UserLitigationRecord | Export-Csv -Path $litPath -Append -NoTypeInformation
        $check = Import-Csv -Path $litPath | Where-Object { $_.email -eq $UserLitigationRecord.email }
        if ($check) {
            Write-Host "✅ Record for $($UserLitigationRecord.email) successfully written to Litigation CSV." -ForegroundColor Green
        } else {
            Write-Host "⚠️ Unable to confirm write to Litigation CSV. Please verify manually." -ForegroundColor Yellow
        }
        $success = $true
    } catch {
        $attempt++
        Write-Host "❌ Could not write to the Litigation CSV (Attempt $attempt). File may be open. Retrying in 3 seconds..." -ForegroundColor Red
        Start-Sleep -Seconds 3
    }
}


        Write-Host "✅ Litigation record saved."
    }

    Write-Host "`n🎯 Selected task(s) completed successfully." -ForegroundColor Green
}
