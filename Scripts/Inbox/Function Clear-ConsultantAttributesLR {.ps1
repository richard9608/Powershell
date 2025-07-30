Function Clear-ConsultantAttributesLR {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [switch]$ClearADUserExpiration
    )

    # Clear extensionAttribute1
    Set-ADUser -Identity $UserName -Clear @("extensionAttribute1")

    # Remove "(Consultant)" from DisplayName
    $displayName = (Get-ADUser -Identity $UserName -Properties DisplayName).DisplayName
    $newDisplayName = $displayName -replace '\(Consultant\)', ''
    Set-ADUser -Identity $UserName -DisplayName $newDisplayName.Trim()

    # Clear account expiration if switch is set
    if ($ClearADUserExpiration) {
        Set-ADUser -Identity $UserName -AccountExpirationDate $null
    }
}
