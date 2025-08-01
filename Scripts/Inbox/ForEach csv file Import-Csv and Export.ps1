ForEach csv file Import-Csv and Export
$a = Get-ChildItem | Select-Object -ExpandProperty Fullname
$exportPath = "$env:USERPROFILE\Documents\csvadm_files\Results.csv"

foreach ($file in $a) {
    $csv = Import-Csv -Path $file
    $add = [PSCustomObject]@{
        'Legal First Name'                                             = $csv.'Legal First Name';
        'Legal Middle Initial'                                         = '';
        'Legal Last Name'                                              = $csv.'Legal Last Name';
        'Display Name'                                                 = $csv.'Display Name';
        'AD Account Type'                                              = $csv.'AD Account Type';
        'Office Phone'                                                 = $csv.'Office Phone';
        'Office R/C'                                                   = $csv.'Office R/C';
        'Division/Location'                                            = $csv.'Division/Location';
        'Job Title'                                                    = $csv.'Job Title';
        'Supervisor'                                                   = $csv.Supervisor;
        'Mail Stops'                                                   = $csv.'Mail Stops';
        'Select TBU of previous account, if exists'                    = $csv.'Select TBU of previous account, if exists';
        'Previous Account, if exists'                                  = $csv.'Previous Account, if exists';
        'EIN'                                                          = $csv.EIN;
        'C-Number'                                                     = $csv.'C-Number';
        'Start Date'                                                   = $csv.'Start Date';
        'End Date'                                                     = $csv.'End Date';
        'Microsoft Office 365 License Required'                        = $csv.'Microsoft Office 365 License Required';
        'AD Template to Use'                                           = $csv.'AD Template to Use';
        'Additional Group Memberships (if none, please specify "N/A")' = $csv.'Additional Group Memberships (if none, please specify "N/A")';
        'Additional Notes'                                             = $csv.'Additional Notes'
    }
    $add | Export-Csv -Path $exportPath -Append -NoTypeInformation
}
    