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

    # Save updated data back to file
    $csv | Export-Csv -Path $CsvPath -NoTypeInformation -Force

    return $csv
}
#--------------------------------------------------------------------------------------------
# Function to create a new AD user based on a template user

function New-MDOTADUserLR2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][PSCustomObject]$Csv,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TemplateUser,
        [Parameter()][System.Management.Automation.Runspaces.PSSession]$ExchangeSession,
        [Parameter()][string]$DomainController = "shahqdc3.shacadd.ad.mdot.mdstate"
    )
    begin {
        # Define your fixed domain here
        $Domain = 'mdot.state.md.us'
        # Get NetBIOS domain name for file system permissions
        $NetBIOSDomain = (Get-ADDomain).NetBIOSName
    }
    process {
        # Extract values from the CSV row
        $UserID      = $Csv.UserID
        $Password    = $Csv.Password
        $FirstName   = $Csv.'Legal First Name'
        $LastName    = $Csv.'Legal Last Name'
        $Phone       = $Csv.Phone
        $EmployeeID  = $Csv.EmployeeID

        # Build UPN and DisplayName
        $UserPrincipalName = "$UserID@$Domain"
        $DisplayName       = "$FirstName $LastName"

        # Get template user properties
        $templateUserInfo = Get-ADUser $TemplateUser `
            -Properties City,Company,Department,Description,Office,PostalCode,
                        StreetAddress,State,HomeDirectory,MemberOf

        # Derive the OU path from the template’s DN
        if ($templateUserInfo.DistinguishedName -match '^.+?Template,(.+)$') {
            $Path = $Matches[1]
        } else {
            # Fallback: use the OU part of the DN
            $Path = ($templateUserInfo.DistinguishedName -replace '^CN=[^,]+,', '')
        }

        # Splat the New-ADUser parameters
        $splat = @{
            Name                  = $UserID
            SamAccountName        = $UserID
            AccountPassword       = (ConvertTo-SecureString $Password -AsPlainText -Force)
            ChangePasswordAtLogon = $true
            UserPrincipalName     = $UserPrincipalName
            DisplayName           = $DisplayName
            GivenName             = $FirstName
            Surname               = $LastName
            Instance              = $templateUserInfo
            Path                  = $Path
        }
        if ($Phone)      { $splat['OfficePhone'] = $Phone }
        if ($EmployeeID) { $splat['EmployeeID']  = $EmployeeID }

        # Create the AD user
        New-ADUser @splat -PassThru


        # Add user to groups from the template
        if ($templateUserInfo.MemberOf) {
            foreach ($group in $templateUserInfo.MemberOf) {
                Add-ADGroupMember -Identity $group -Members $UserID
            }
        }
        # Set up the user's home directory if specified in the template
        $homeDir = $templateUserInfo.HomeDirectory
        if ($homeDir) {
            Set-ADUser -Identity $UserID -HomeDirectory $homeDir
            if (-not (Test-Path $homeDir)) {
                New-Item -Path $homeDir -ItemType Directory 
            }
            # Set permissions to allow user full control over their home directory
            $acl = Get-Acl $homeDir
            $ar = New-Object System.Security.AccessControl.FileSystemAccessRule("$NetBIOSDomain\$UserID", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($ar)
            Set-Acl $homeDir $acl
        }

        # Set Exchange Mailbox and Archive
        if (-not $ExchangeSession) {
            throw "ExchangeSession parameter is required. Please create and import the session before calling this function."
        }
        Import-PSSession $ExchangeSession -DisableNameChecking
        Set-ADServerSettings -ViewEntireForest $true
        # Set Exchange Mailbox and Archive
        if (-not $ExchangeSession) {
            throw "ExchangeSession parameter is required. Please create and import the session before calling this function."
        }
        Import-PSSession $ExchangeSession -DisableNameChecking
        Set-ADServerSettings -ViewEntireForest $true
        Enable-RemoteMailbox $UserID -RemoteRoutingAddress "$UserID@mdotgov.mail.onmicrosoft.com" -DomainController $DomainController
        Get-RemoteMailbox $UserID | Enable-Mailbox -Archive

        # Clean up Exchange session to avoid session leaks
        Remove-PSSession $ExchangeSession
        # Call a custom function to display or log user information after setup is complete.
        # GetUser_Info2 is assumed to retrieve and display user details for verification or logging.
        GetUser_Info2 -UserID $UserID
    }
}
