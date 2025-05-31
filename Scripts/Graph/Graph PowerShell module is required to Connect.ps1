Graph PowerShell module is required to run this script 



Get-MgUserMemberOf -UserId "LRichardson2@mdot.state.md.us" |
    Select-Object @{Name = "DisplayName"; Expression = { $_.AdditionalProperties.displayName } },
    @{Name = "ObjectType"; Expression = { $_.'@odata.type' } }




Get-MgUser -UserId $(Get-MgContext).Account |
    Get-MgUserMemberOf |
    Select-Object @{Name = "Role"; Expression = { $_.AdditionalProperties.displayName } }



# Get the current signed-in user UPN
$me = Get-MgContext

# Get your directory roles (human readable)
Get-MgUser -UserId $me.Account |
    Get-MgUserMemberOf |
    Where-Object { $_.AdditionalProperties.displayName } |
    Select-Object @{Name = "Role"; Expression = { $_.AdditionalProperties.displayName } }
