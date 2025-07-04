# This PowerShell script defines a function to add properties to each row of a CSV file.
#Usage Example
$CsvPath = Read-Host "Enter path to CSV file"
$UserID = Read-Host "Enter UserID"
$Password = Read-Host "Enter Password"
$Template = Read-Host "Enter AD Template to Use"

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

$csv = Add-CsvProperties -CsvPath $CsvPath -UserID $UserID -Password $Password -Template $Template












