#Clear-ConsultantAttributes



Function Clear-ConsultantAttributesLR {
   param(
      [Parameter(Mandatory=$true)]
      [string]$UserName,
      [switch]$ClearADUserExpiration
   )

    # Clear the extensionAttribute1 attribute for the specified user
   Set-ADUser $UserName -Clear @("extensionAttribute1")

   # Remove "(Consultant)" from the display name
    $user = Get-ADUser $UserName -Properties DisplayName
    if ($user.DisplayName -like "*\(Consultant\)*") {
        $newDisplayName = $user.DisplayName -replace "\(Consultant\)", ""
        Set-ADUser $UserName -DisplayName $newDisplayName
    }   

    #Switch parameter to clear the AD user expiration date
    if ($ClearADUserExpiration) {
        Set-ADUser $UserName -accountExpirationDate $null
    }

}

