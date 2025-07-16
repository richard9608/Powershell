OMG This Work New-ADUserLR_MDOT



function New-ADUserLR_MDOT {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$UserID,

        [Parameter(Mandatory)]
        [string]$FirstName,

        [Parameter(Mandatory)]
        [string]$LastName,

        [Parameter(Mandatory)]
        [string]$Password,

        [string]$TemplateUser,

        [string]$Phone,

        [string]$EmployeeID,

        # Switch parameters to control functionality
        [switch]$CreateBasicUser,
        [switch]$UseTemplate,
        [switch]$SetupExchange,
        [switch]$CreateHomeDirectory,
        [switch]$CopyGroups
    )
    
    # Microsoft UPN @mdot.state.md.us          
    $email = "$UserID@mdot.state.md.us"

    #--------------------------------------------------------------------------------------------
    # BASIC USER CREATION
    #--------------------------------------------------------------------------------------------
    if ($CreateBasicUser) {
        Write-Host "Creating basic AD user..." -ForegroundColor Green
        
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
        }

        # Add optional parameters
        if ($Phone) { $userParams['OfficePhone'] = $Phone }
        if ($EmployeeID) { $userParams['EmployeeID'] = $EmployeeID }

        # Create the basic AD user
        New-ADUser @userParams -PassThru | Out-Null
        Write-Host "Basic user $UserID created successfully." -ForegroundColor Green
    }

    #--------------------------------------------------------------------------------------------
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

    #--------------------------------------------------------------------------------------------
    # EXCHANGE SETUP
    #--------------------------------------------------------------------------------------------
    if ($SetupExchange) {
        Write-Host "Setting up Exchange mailbox..." -ForegroundColor Yellow
        
        try {
            $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mdotgbexch2/powershell -Authentication Kerberos
            Import-PSSession $Session -DisableNameChecking      
            Set-ADServerSettings -ViewEntireForest $true
            
            # Enable the mailbox for the new user
            Enable-RemoteMailbox $UserID -RemoteRoutingAddress "$UserID@mdot.state.md.us"
            
            # Enable the archive mailbox for the new user
            Get-RemoteMailbox $UserID | Enable-Mailbox -Archive 
            
            Write-Host "Exchange mailbox configured successfully." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to configure Exchange mailbox: $($_.Exception.Message)"
        }
        finally {
            # Clean up Exchange session to avoid session leaks
            if ($Session) {
                Remove-PSSession $Session
            }
        }
    }

    # Display final user information
    Write-Host "`nUser creation completed!" -ForegroundColor Green
    Write-Host "UserID: $UserID" -ForegroundColor Cyan
    Write-Host "Email: $email" -ForegroundColor Cyan
    Write-Host "Display Name: $FirstName $LastName" -ForegroundColor Cyan
}

#--------------------------------------------------------------------------------------------
# EXAMPLE USAGE WITH DIFFERENT SWITCHES
#--------------------------------------------------------------------------------------------
<# 
# Basic user creation only
New-ADUserLR_MDOT -UserID "JDoe" -FirstName "John" -LastName "Doe" -Password "TempPass123!" -CreateBasicUser

# Template-based user with all features
New-ADUserLR_MDOT -UserID "EAllocca" `
    -FirstName "Edward" `
    -LastName "Allocca" `
    -Password "MDOTSHAJune92025@" `
    -TemplateUser "OED_TEMPLATE" `
    -Phone "410-221-1635" `
    -EmployeeID "500590" `
    -UseTemplate `
    -CopyGroups `
    -CreateHomeDirectory `
    -SetupExchange

# Template user without Exchange
New-ADUserLR_MDOT -UserID "TestUser" `
    -FirstName "Test" `
    -LastName "User" `
    -Password "TestPass123!" `
    -TemplateUser "OED_TEMPLATE" `
    -UseTemplate `
    -CopyGroups `
    -CreateHomeDirectory

#>

<# Template-based user with all features
New-ADUserLR_MDOT -UserID "OOshineye" `
    -FirstName "Oluwakemi" `
    -LastName "Oshineye" `
    -Password "MdotSH@July1425" `
    -TemplateUser "HHD_TEMPLATE" `
    -EmployeeID "500766" `
    -UseTemplate `
    -CopyGroups `
    -CreateHomeDirectory 
#> #Needs work -SetupExchange


