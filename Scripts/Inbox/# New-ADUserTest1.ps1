#   New-ADUserTest1.ps1
#   This script creates a new Active Directory user based on a template or CSV input.   


function New-ADUserTest1 {
    param (
         [Parameter(Mandatory)]
        [string]$UserID,

        [Parameter(Mandatory)]
        [string]$FirstName,

        [Parameter(Mandatory)]
        [string]$LastName,

        [Parameter(Mandatory)]
        [string]$Password,
        
        [Parameter(Mandatory)]
        [string]$TemplateUser,

        [string]$Phone,

        [string]$EmployeeID
    )
 
        # Microsoft UPN @mdot.state.md.us          
    $email = "$UserID@mdot.state.md.us"


     # TEMPLATE-BASED USER CREATION
    #--------------------------------------------------------------------------------------------
    if ($UseTemplate) {
        if (-not $TemplateUser) {
            Write-Error "TemplateUser parameter is required when using -UseTemplate switch"
            return
        }

        Write-Host "Creating user from template: $TemplateUser" -ForegroundColor Yellow
        
        # Get Template User Info
        $templateUserInfo = Get-ADUser $TemplateUser -Properties City, Company, Department, Description, Office, PostalCode, StreetAddress, State, HomeDirectory, MemberOf

        # Derive OU Path from Template
        $path = ($templateUserInfo.DistinguishedName -replace '^.+?Template,(.+)$', '$1')

        # Build parameters for New-ADUser with template
        $userParams = @{
            Name                  = $UserID
            SamAccountName        = $UserID
            UserPrincipalName     = $email
            GivenName             = $FirstName
            Surname               = $LastName
            DisplayName           = "$FirstName $LastName"
            AccountPassword       = (ConvertTo-SecureString $Password -AsPlainText -Force)
            ChangePasswordAtLogon = $true
            Enabled               = $true
            Instance              = $templateUserInfo
            Path                  = $path
        }

        # Add optional parameters
        if ($Phone) { $userParams['OfficePhone'] = $Phone }
        if ($EmployeeID) { $userParams['EmployeeID'] = $EmployeeID }

        # Create the AD user with template
        New-ADUser @userParams -PassThru | Out-Null
        Write-Host "Template-based user $UserID created successfully." -ForegroundColor Green

        # Copy Group Memberships if requested
        if ($CopyGroups) {
            Write-Host "Copying group memberships from template..." -ForegroundColor Yellow
            $groups = $templateUserInfo.MemberOf
            if ($groups) {
                Add-ADPrincipalGroupMembership -Identity $UserID -MemberOf $groups -Verbose
                Write-Host "Group memberships copied successfully." -ForegroundColor Green
            }
            else {
                Write-Host "No groups found for template user $TemplateUser." -ForegroundColor Yellow
            }
        }

        # Create Home Directory if requested
        if ($CreateHomeDirectory) {
            Write-Host "Setting up home directory..." -ForegroundColor Yellow
            if ($templateUserInfo.HomeDirectory) {
                $homeRoot = ($templateUserInfo.HomeDirectory -replace '\\[^\\]+$', '')
                $newHomeDir = "$homeRoot\$UserID"

                if (-not (Test-Path $newHomeDir)) {
                    New-Item -Path $newHomeDir -ItemType Directory | Out-Null
                    Write-Host "Created home directory: $newHomeDir" -ForegroundColor Green
                }

                Set-ADUser $UserID -HomeDirectory $newHomeDir -HomeDrive 'M:' -Verbose
                Write-Host "Home directory configured successfully." -ForegroundColor Green
            }
            else {
                Write-Host "Template user has no home directory configured." -ForegroundColor Yellow
            }
        }
    }


    #CSV-BASED USER CREATION

    



















}
