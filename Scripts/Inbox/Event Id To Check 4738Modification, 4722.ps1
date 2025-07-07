Get-Event Id To Check 4738Modification, 4722enabled, 4725disabled 



Get-WinEvent -FilterHashtable @{logname = "security"; id = 4738, 4722, 4725 } -ComputerName shahqdc3 | Select-Object -first 40 | Format-List TimeCreated, MachineName, ProviderName, ID, Message >> C:\Users\jgreen3_adm\Documents\ADModifications.txt