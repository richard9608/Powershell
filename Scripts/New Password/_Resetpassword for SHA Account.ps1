Resetpassword for SHA Account

#--------------------------------------------------------------------------------------------
# Enable the account
Enable-ADAccount -Identity "JGreer"
#--------------------------------------------------------------------------------------------
# Reset password for a specific user account
$Username = "JGreer"
$NewPassword = ConvertTo-SecureString "MdotSH@July1425" -AsPlainText -Force
Set-ADAccountPassword -Identity $Username -NewPassword $NewPassword -Reset
Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
#--------------------------------------------------------------------------------------------
# set the expiration date for the account                  
Set-ADAccountExpiration -Identity "HMohammed" -DateTime (Get-Date "12/18/2025") 



# Reset the password for the service account
Reset-ADServiceAccountPassword -Identity "shainterview3" -NewPassword (ConvertTo-SecureString "MDOTSHAomt0515@" -AsPlainText -Force)











# Grant full permissions to user's folder
icacls "\\shahqfs2\dgnusers\oos\TEteyBenissan" /grant "TEteyBenissan:(F)"






