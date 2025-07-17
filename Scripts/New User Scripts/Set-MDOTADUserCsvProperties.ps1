<#
.SCRIPT NAME
Set-MDOTADUserCsvProperties.ps1
# AUTHOR
Your Name  LRichardson2
# This script updates a CSV file with user properties for MDOT AD users.
# Usage:
# Set-MDOTADUserCsvProperties -CsvPath "path\to\your.csv"   
#                        -UserID "your_user_id"
#                        -Password "your_password"  
#                        -Template "your_template_name"
<#
.SYNOPSIS
Updates a CSV file with user properties for MDOT AD users.      
.DESCRIPTION
This script takes a CSV file and updates it with user properties such as UserID, Password, and a specified AD Template. It adds these properties to each row in the CSV file.
.PARAMETER CsvPath
The path to the CSV file that needs to be updated.
.PARAMETER UserID
The UserID to be added or updated in the CSV file.
.PARAMETER Password
The Password to be added or updated in the CSV file.
.PARAMETER Template
The AD Template to be used for the users in the CSV file.
.EXAMPLE
Set-MDOTADUserCsvProperties -CsvPath "C:\Users\example.csv" -
UserID "jdoe" -Password "P@ssw0rd" -Template "DefaultTemplate"
This command updates the specified CSV file with the UserID, Password, and Template for each user in the file.
#>

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

    # Optionally: Save updated data back to file (uncomment if needed)
    # $csv | Export-Csv -Path $CsvPath -NoTypeInformation

    return $csv
}





#--------------------------------------------------------------------------------------------# 


