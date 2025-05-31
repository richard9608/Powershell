Get Mailbox Exchange Filter

Get-Mailbox -Filter 'displayname -like "SHA *" -and displayname -like "* D1 *" -and displayname -like "*rm*"' | Sort-Object Name | Select-Object DisplayName, Alias