Resetpassword and Friends for SHA Accounts

#--------------------------------------------------------------------------------------------
# 1. Enable the account
Enable-ADAccount -Identity "MVanWert_Adm"
#--------------------------------------------------------------------------------------------
# 2. Reset password for a specific user account
$Username = "MVanWert_Adm"
$NewPassword = ConvertTo-SecureString "MdotSH@Jun3025" -AsPlainText -Force
Set-ADAccountPassword -Identity $Username -NewPassword $NewPassword -Reset
Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
#--------------------------------------------------------------------------------------------
# 3. Update the description for the user account
Set-ADUser -Identity "AAjimo" -Description "OHD User -Disabled 6/30/2025 SR#1954198 LR2"

#--------------------------------------------------------------------------------------------
# 4. Set the expiration date for the account
Set-ADAccountExpiration -Identity "LRichardson2" -DateTime (Get-Date "12/31/2025")
#--------------------------------------------------------------------------------------------
# 5. Disable the account
Disable-ADAccount -Identity "LRichardson2"
#--------------------------------------------------------------------------------------------
# 6. Reset the password for the service account
Import-Module ActiveDirectory
# Reset the password for the service account                                                                                                
Reset-ADServiceAccountPassword -Identity "shainterview3" -NewPassword (ConvertTo-SecureString "MDOTSHAomt0515@" -AsPlainText -Force)
#--------------------------------------------------------------------------------------------
# 7. Grant full permissions to a user's folder  
# Ensure the user has the necessary permissions to access the folder
# Replace "TEteyBenissan" with the actual username
# Ensure the path is correct and accessible             
# Import the Active Directory module



    

# Grant full permissions to user's folder
icacls "\\shahqfs2\dgnusers\oos\TEteyBenissan" /grant "TEteyBenissan:(F)"






