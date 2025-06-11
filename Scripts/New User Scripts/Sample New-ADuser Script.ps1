Sample New-ADuser Script 





New-ADUser -Name "John Doe" `
    -GivenName "John" `
    -Surname "Doe" `
    -SamAccountName "jdoe" `
    -UserPrincipalName "jdoe@mdot.state.md.us" `
    -Path "OU=Users,DC=mdot,DC=state,DC=md,DC=us" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) `
    -Enabled $true  
Set-ADUser -Identity "jdoe" `
    -Description "New user account for John Doe" `
    -Title "Transportation Engineer" `
    -Department "Engineering" `
    -OfficePhone "410-555-1234" `
    -MobilePhone "410-555-5678" `
    -EmailAddress "jdoe@mdot.state.md.us"                                       
Set-ADUser -Identity "jdoe" `
    -Add @{ "MemberOf" = "CN=Engineering,OU=Groups,DC=mdot,DC=state,DC=md,DC=us" } `
    -Replace @{ "Manager" = "CN=Jane Smith,OU=Users,DC=mdot,DC=state,DC=md,DC=us" } `
    -Clear "thumbnailPhoto"     
Set-ADUser -Identity "jdoe" `
    -HomeDirectory "\\mdot.state.md.us\home\jdoe" `
    -HomeDrive "H:" `
    -ProfilePath "\\mdot.state.md.us\profiles\jdoe" `
    -ScriptPath "logon.ps1" `
    -TerminalServicesProfilePath "\\mdot.state.md.us\profiles\jdoe" `
    -TerminalServicesHomeDirectory "\\mdot.state.md.us\home\jdoe" `
    -TerminalServicesWorkDirectory "\\mdot.state.md.us\work\jdoe"
Set-ADUser -Identity "jdoe" `
    -PasswordNeverExpires $false `
    -CannotChangePassword $false `
    -ChangePasswordAtLogon $true `
    -SmartcardLogonRequired $false `
    -UserWorkstations "workstation1,workstation2" `
    -LogonHours "0000000" # 24/7 access
Set-ADUser -Identity "jdoe" `
    -ProfilePath "\\mdot.state.md.us\profiles\jdoe" `
    -TerminalServicesProfilePath "\\mdot.state.md.us\profiles\jdoe" `
    -TerminalServicesHomeDirectory "\\mdot.state.md.us\home\jdoe" `
    -TerminalServicesWorkDirectory "\\mdot.state.md.us\work\jdoe" `
    -ScriptPath "logon.ps1"
Set-ADUser -Identity "jdoe" `
    -Description "Updated user account for John Doe" `
    -Title "Senior Transportation Engineer" `
    -Department "Engineering" `
    -OfficePhone "410-555-1234" `
    -MobilePhone "410-555-5678" `
    -EmailAddress "