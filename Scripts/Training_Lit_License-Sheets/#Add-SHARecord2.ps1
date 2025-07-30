#Add-SHARecord2
# PowerShell script to add SHA records for a user in Active Directory
# This script collects user information and allows the user to select which records to add (Adds,   FMT, License).
# It then saves the records to specified CSV files and an Excel file.
function Add-SHARecord2 {
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

    # --- License specific input ---
    if ($selected -contains "3") {
        # License Type: Enforce input 1 or 2 for F3 or G5
        do {
            $licenseChoice = Read-Host "Enter License Type (1 for F3, 2 for G5)"
        } while ($licenseChoice -notin "1","2")
        $licenseType = if ($licenseChoice -eq "1") { "F3" } else { "G5" }

        # License Added or Removed: Enforce input 1 or 2
        do {
            $addedOrRemovedChoice = Read-Host "Was the License Added or Removed? (1 for Added, 2 for Removed)"
        } while ($addedOrRemovedChoice -notin "1","2")
        $addedOrRemoved = if ($addedOrRemovedChoice -eq "1") { "Added" } else { "Removed" }

        # Set dates based on added or removed
        if ($addedOrRemoved -eq "Added") {
            $creationDate = (Get-Date).ToShortDateString()
            $deletionDate = ""
        }
        else {
            $creationDate = ""
            $deletionDate = (Get-Date).ToShortDateString()
        }
    }

    # --- Always reused fields ---
    $email = $adUser.EmailAddress -replace '\.consultant'
    $first = $adUser.GivenName
    $last = $adUser.Surname
    $ein = $adUser.EmployeeID
    $workedBy = "LRichardson2"  # Always this value

    # --- Generate and save each record as needed ---
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
        # Write to CSV
        $licCsvPath = "$HOME\Documents\LicenseInfo.csv"
        $lic | Export-Csv -Path $licCsvPath -NoTypeInformation -Append
        Write-Host "✅ 'License' record written to CSV."

        # Write to Excel (using ImportExcel module)
        $pathToExcel = '\\shahqfs1\admshared\oit\TSD\Network\Document\Security Mentor\Current\SHA_Licenses.xlsx'
        $worksheetName = 'SHA_Licenses'
        $lic | Export-Excel -Path $pathToExcel -WorksheetName $worksheetName -Append
        Write-Host "✅ 'License' record appended to Excel worksheet ($worksheetName)."
    }

    Write-Host "`nAll selected records have been processed."
}
