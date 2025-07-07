# CASH Exchanged for returning users 

Set-CASMailbox -Identity "AAjimo@mdot.state.md.us" -ActiveSyncEnabled $true `
    -MAPIEnabled $true `
    -EwsEnabled $true `
    -ImapEnabled $true `
    -PopEnabled $true `
    -OWAEnabled $true

# Disable CASH Exchange for returning users

Set-CASMailbox -Identity "AAjimo@mdot.state.md.us" -ActiveSyncEnabled $false `
       -OWAEnabled $false
