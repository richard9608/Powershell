Find-MultiAccsByFirst_Last_Name

$n = @"
Aaron Deepree
Al Shaw
Anakin Sandoval Caceres
Christopher Barnett
Jeneba Kamara
Kendon Guy
Mason Orndorff
Samuel Akosite
William Jones
"@ -split "`n"


function Find-AccountByName {
    param (
        [Parameter(Mandatory)]
        [string]$FullName
    )

    $first, $last, $rest = $FullName -split ' ', 3  # Handles middle names
    if (-not $last) {
        Write-Warning "Skipping '$FullName' — could not determine last name."
        return
    }

    # Build filter using both first and last name
    $filter = "GivenName -like '$first*' -and Surname -like '$last*'"

    try {
        Get-ADUser -Filter $filter -Properties DisplayName, SamAccountName |
            Select-Object DisplayName, SamAccountName, GivenName, Surname
    }
    catch {
        Write-Warning "Error processing '$FullName': $_"
    }
}


$n | ForEach-Object { Find-AccountByName $_ }
