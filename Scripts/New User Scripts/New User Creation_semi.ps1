
foreach ($csv in $csvList) {
    $userid = $csv.SamAccountName
    $template = "D5OFF_TEMPLATE"  # You must define this
    $tempinfo = Get-ADUser $template -Properties *

    # Derive OU path from template user
    $path = ($tempinfo.DistinguishedName -replace '^CN=.+?,', '')

    # Get Manager DN if manager exists
    $managerSam = ($csv.Supervisor -replace '@.+')  # if Supervisor is email
    $manager = Get-ADUser -Filter { SamAccountName -eq $managerSam } | Select-Object -ExpandProperty DistinguishedName

    # Format phone number (assumes 10-digit)
    $formattedPhone = ($csv.'Office Phone' -replace '[^\d]', '') -replace '(\d{3})(\d{3})(\d{4})', '$1-$2-$3'

    # Create the new user
    New-ADUser -Name $userid `
        -SamAccountName $userid `
        -AccountPassword (ConvertTo-SecureString -AsPlainText $csv.Password -Force) `
        -ChangePasswordAtLogon $true `
        -DisplayName "$($csv.'Legal First Name') $($csv.'Legal Last Name')" `
        -Path $path `
        -EmployeeID $csv.EIN `
        -Instance $tempinfo `
        -Manager $manager `
        -Enabled $true `
        -GivenName $csv.'Legal First Name' `
        -Surname $csv.'Legal Last Name' `
        -OfficePhone $formattedPhone `
        -Title $csv.'Job Title' `
        -AccountExpirationDate ([datetime]$csv.'End Date').AddDays(1) `
        -UserPrincipalName "$userid@mdot.state.md.us" `
        -Verbose
}
