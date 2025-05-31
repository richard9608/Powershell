function Copy-ADUserTemplate {
    param (
        [Parameter(Mandatory)]
        [string]$TemplateUser,

        [Parameter(Mandatory)]
        [string]$NewUsername,

        [Parameter(Mandatory)]
        [string]$NewDisplayName,

        # If provided, sets the account's expiration date.
        # Use the format "MM/dd/yyyy".
        [Parameter()]
        [string]$AccountExpirationDate,

        # If specified, sets the user's password to never expire.0

        [Parameter()]
        [switch]$PasswordNeverExpires
    )

    # Get the template user and handle errors if not found
    try {
        $template = Get-ADUser -Identity $TemplateUser -Properties *
    }
    catch {
        Write-Error "Template user '$TemplateUser' not found."
        return
    }

    # Generate a random 13-character password using a mix of letters, digits, and symbols
    $allowedChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
    $randomPassword = -join ((1..13) | ForEach-Object { $allowedChars[(Get-Random -Minimum 0 -Maximum $allowedChars.Length)] })

    # Ensure the log directory exists and define the log file path
    $logDirectory = "C:\Users\LRichardson2\Documents\ADTempass_Logs"
    if (-not (Test-Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }
    $logFile = Join-Path -Path $logDirectory -ChildPath "ADUserCreation.log"

    # Generate the target home directory based on the template user's home directory
    $parentDirectory = Split-Path -Path $template.HomeDirectory
    $targetHomeDirectory = Join-Path -Path $parentDirectory -ChildPath $NewUsername

    # Determine the OU from the template user's DistinguishedName
    $templateDN = $template.DistinguishedName
    # Remove the "CN=" part to extract the OU path (e.g., "OU=Users,DC=domain,DC=com")
    $templateOU = $templateDN -replace '^CN=[^,]+,', ''

    # Prepare parameters for New-ADUser
    $newADUserParams = @{
        Name              = $NewDisplayName
        SamAccountName    = $NewUsername
        UserPrincipalName = "$NewUsername@domain.com"
        GivenName         = $template.GivenName
        Surname           = $template.Surname
        DisplayName       = $NewDisplayName
        Title             = $template.Title
        Department        = $template.Department
        Company           = $template.Company
        Office            = $template.Office
        StreetAddress     = $template.StreetAddress
        City              = $template.City
        State             = $template.State
        PostalCode        = $template.PostalCode
        ProfilePath       = $template.ProfilePath
        HomeDirectory     = $targetHomeDirectory
        HomeDrive         = $template.HomeDrive
        ScriptPath        = $template.ScriptPath
        Path              = $templateOU
        AccountPassword   = (ConvertTo-SecureString $randomPassword -AsPlainText -Force)
        Enabled           = $true
    }

    # If an account expiration date is provided, parse and add it to the parameters
    if ($AccountExpirationDate) {
        try {
            $expirationDate = [datetime]::ParseExact($AccountExpirationDate, 'MM/dd/yyyy', $null)
            $newADUserParams['AccountExpirationDate'] = $expirationDate
        }
        catch {
            Write-Warning "Invalid date format for AccountExpirationDate. Expected format: MM/dd/yyyy. Skipping account expiration setting."
        }
    }

    # Create the new user
    try {
        New-ADUser @newADUserParams
    }
    catch {
        Write-Error "Failed to create user '$NewUsername'. Error: $_"
        return
    }

    # Set PasswordNeverExpires if the switch is specified
    if ($PasswordNeverExpires) {
        Set-ADUser -Identity $NewUsername -PasswordNeverExpires $true
    }

    # Force password change on first logon
    Set-ADUser -Identity $NewUsername -ChangePasswordAtLogon $true

    # Copy group memberships from the template user to the new user
    $groups = Get-ADUser $TemplateUser -Properties MemberOf | Select-Object -ExpandProperty MemberOf
    foreach ($group in $groups) {
        try {
            Add-ADGroupMember -Identity $group -Members $NewUsername
        }
        catch {
            Write-Warning "Failed to add user '$NewUsername' to group '$group'."
        }
    }

    # Build a log entry detailing the actions performed
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Created user '$NewUsername' from template '$TemplateUser' in OU '$templateOU' with home directory '$targetHomeDirectory'. Random password: '$randomPassword'."
    if ($PasswordNeverExpires) {
        $logEntry += " Password set to never expire."
    }
    if ($AccountExpirationDate) {
        $logEntry += " Account expiration date set to '$AccountExpirationDate'."
    }
    Add-Content -Path $logFile -Value $logEntry

    Write-Verbose "User '$NewUsername' created successfully in OU '$templateOU'."
}
