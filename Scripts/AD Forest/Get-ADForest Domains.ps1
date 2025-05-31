Get-ADForest -Identity $env:USERDNSDOMAIN | ForEach-Object {
    foreach ($domain in $_.Domains) {
        Get-ADDomainController -Filter * -Server $domain | Select-Object Name, Domain, Site, IPv4Address
    }
}



Get-Folder -Path $env:USERDNSDOMAIN -Recurse -Directory | ForEach-Object {
    Get-ChildItem -Path $_.FullName -Recurse -File | Select-Object FullName, Length, LastWriteTime
}






