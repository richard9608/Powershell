Resetpassword for SHA Account

Reset-ADServiceAccountPassword -Identity "shainterview3" -NewPassword (ConvertTo-SecureString "MDOTSHAomt0515@" -AsPlainText -Force) 






$Username = "DRandolph3"
$NewPassword = ConvertTo-SecureString "MDOTApril282025" -AsPlainText -Force
Set-ADAccountPassword -Identity $Username -NewPassword $NewPassword -Reset
Set-ADUser -Identity $Username -ChangePasswordAtLogon $true








