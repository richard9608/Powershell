Add-SHARecord
function Add-SHARecord {
    [CmdletBinding()]
    param ()

    # --- Fetch AD User Info ---
    $userId = Read-Host "Enter UserID (sAMAccountName)"
    $adUser = Get-ADUser -Identity $userId -Properties EmailAddress, GivenName, Surname, EmployeeID
    if (-not $adUser) {
        Write-Host "❌ User not found in AD." -ForegroundColor Red
        return
    }

    # --- Ask which records to add ---
    Write-Host "`nWhich record(s) do you want to add? (Enter numbers separated by comma, e.g. 1,2)"
    Write-Host "1. Adds"
    Write-Host "2. FMT"
    Write-Host "3. License"
    $recordTypes = Read-Host "Selection"
    $selected = $recordTypes -split "," | ForEach-Object { $_.Trim() }

    # --- Always collected fields (if needed for any selected sheet) ---
    if ($selected -contains "1" -or $selected -contains "2") {
        $ou = Read-Host "Which OU?"
    }
    if ($selected -contains "1" -or $selected -contains "3") {
        $srNumber = Read-Host "SR#"
    }
    if ($selected -contains "3") {
        $licenseType = Read-Host "Enter License Type (F3 or G3)"
        $addedOrRemoved = Read-Host "Was the License Added or Removed?"
        $creation = Read-Host "Is there a creation date? (yes/no)"
        $creationDate = if ($creation -eq "yes") { (Get-Date).ToShortDateString() } else { "" }
        $deletion = Read-Host "Is there a deletion date? (yes/no)"
        $deletionDate = if ($deletion -eq "yes") { (Get-Date).ToShortDateString() } else { "" }
    }

    # --- Always reused fields ---
    $email = $adUser.EmailAddress -replace '\.consultant'
    $first = $adUser.GivenName
    $last = $adUser.Surname
    $ein = $adUser.EmployeeID
    $workedBy = "LRichardson2"  # Always this value

    # --- Now generate and save each record as needed ---
    if ($selected -contains "1") {
        $add = [PSCustomObject]@{
            email           = $email
            first_name      = $first
            last_name       = $last
            group_name      = "SHA"
            OU              = $ou
            'Creation Date' = (Get-Date).ToShortDateString()
            'Notes'         = ""
            'EIN?'          = $ein
            'SR#'           = $srNumber
            "Worked By"     = $workedBy
        }
        $addsPath = "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_Trainee_Adds_2025.csv"
        $add | Export-Csv -Path $addsPath -NoTypeInformation -Append
        Write-Host "✅ 'Adds' record written."
    }

    if ($selected -contains "2") {
        $fmt = [PSCustomObject]@{
            email           = $email
            first_name      = $first
            last_name       = $last
            group_name      = "SHA"
            OU              = $ou
            'Creation Date' = (Get-Date).ToShortDateString()
            'Notes'         = ""
            'EIN?'          = $ein
        }
        $fmtPath = "\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\Maryland_State_FMT_Adds_2025.csv"
        $fmt | Export-Csv -Path $fmtPath -NoTypeInformation -Append
        Write-Host "✅ 'FMT' record written."
    }

    if ($selected -contains "3") {
        $lic = [PSCustomObject]@{
            email                   = $email
            first_name              = $first
            last_name               = $last
            License_Type            = $licenseType
            'SR#'                   = $srNumber
            Worked_By               = $workedBy
            'License_Added/Removed' = $addedOrRemoved
            Notes                   = ""
            Creation_Date           = $creationDate
            Deletion_Date           = $deletionDate
        }
        # Write to CSV as before
        $licCsvPath = "$HOME\Documents\LicenseInfo.csv"
        $lic | Export-Csv -Path $licCsvPath -NoTypeInformation -Append
        Write-Host "✅ 'License' record written to CSV."

        # Write to Excel (worksheet SHA_Licenses, hardcoded path)
        $pathToExcel = '\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\SHA_Licenses.xlsx'
        $worksheetName = 'SHA_Licenses'
        $lic | Export-Excel -Path $pathToExcel -WorksheetName $worksheetName -Append
        Write-Host "✅ 'License' record appended to Excel worksheet ($worksheetName)."
    }

    Write-Host "`nAll selected records have been processed."
}
