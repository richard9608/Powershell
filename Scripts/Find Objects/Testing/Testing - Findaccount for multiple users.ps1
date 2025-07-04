#Findaccount for multiple users
# This script searches for Active Directory users based on their first and last names or usernames.
#--------------------------------------------------------------------------------------------
$names = "RAIMOND BALBUENA
KATHLEEN BARRY
CRAIG BUCHANAN
Bryan Chant
RONNELL CORNISH
ANDRAE FRANCOIS
SHARDE GRINDER
APRIL HALL
Russell Heino
Jay Ingle
Georgios Margaritis
MURITHI MARSHALL
Kari Myers
Anthony Porco".Split("`n")

$names.Count

$names | ForEach-Object { get-aduser -Filter { givenname -like $_.Split(' ')[0] -and sn -like $_.Split(' ')[1] } -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description } | Format-Table -AutoSize
#--------------------------------------------------------------------------------------------   
    $parts = $_ -split ' '
    $first = $parts[0]
    $last = $parts[1]
    findaccount1 $first $last
}

$names | ForEach-Object { get-aduser -Filter { firstname -like $first and  Lastname -like $last } -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description } | Format-Table -AutoSize

#--------------------------------------------------------------------------------------------
$names = "Eallocca
JMiller29
Mmarshall1
RCornish
SSoni
LRichardson2".Split("`n")

$names.Count

$names | ForEach-Object {
    findaccount2 $_
}

findaccount2
findaccount2

getuser_info2 Eallocca
getuser_info2 JMiller29
getuser_info2 Mmarshall1
getuser_info2 RCornish3
getuser_info2 SSoni
getuser_info2 LRichardson5

<#--------------------------------------------------------------------------------------------


$names1 = @"
Edward Allocca
Jason Miller
Murithi Marshall
Ronnell Cornish
"@ -split "`n"

#--------------------------------------------------------------------------------------------

$names = @()
$names += "Edward Allocca"
$names += "Jason Miller"
$names += "Murithi Marshall"
$names += "Ronnell Cornish"
$names.Count



function findaccount2 {
    param(
        [parameter(Mandatory = $true)]
        [string]$user
    )
    $DC = "mdotgbfrdc1.ad.mdot.mdstate",
    "MAABWIDC1.maa.ad.mdot.mdstate",
    "TSOGBDC1.mdothq.ad.mdot.mdstate",
    "MDTAICCDC01.mdta.ad.mdot.mdstate",
    "MPADMTENTDC01.mpa.ad.mdot.mdstate",
    "MTACWDRDC1.mtant1.ad.mdot.mdstate",
    "MVAWSDC1.mvant1.ad.mdot.mdstate",
    "SHAGBDC1.shacadd.ad.mdot.mdstate"
    $result = $DC | ForEach-Object { Get-ADUser -LDAPFilter "(samaccountname=$user*)" -Server $_ -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description }
    $result | Format-Table -AutoSize
}
#--------------------------------------------------------------------------------------------

# Function to Search First and Last Name

function findaccount1 {
    param(
        [parameter(Mandatory = $true)]
        [string]$firstname,

        [parameter(Mandatory = $true)]
        [string]$lastname
    )
    # Search for users based on first and last name across multiple domain controllers.
    # Define the domain controllers to search.                      
    # You can add or remove domain controllers as needed.
    # Ensure the domain controllers are reachable and have the necessary permissions.   
    $DC = "mdotgbfrdc1.ad.mdot.mdstate",
    "MAABWIDC1.maa.ad.mdot.mdstate",
    "TSOGBDC1.mdothq.ad.mdot.mdstate",
    "MDTAICCDC01.mdta.ad.mdot.mdstate",
    "MPADMTENTDC01.mpa.ad.mdot.mdstate",
    "MTACWDRDC1.mtant1.ad.mdot.mdstate",
    "MVAWSDC1.mvant1.ad.mdot.mdstate",
    "SHAGBDC1.shacadd.ad.mdot.mdstate"
    $result = $DC | ForEach-Object { Get-ADUser -LDAPFilter "(&(givenname=$firstname*)(sn=$lastname*))" -Server $_ -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description }
    $result | Format-Table -AutoSize
}
#--------------------------------------------------------------------------------------------


function findaccount2 {
    param(
        [parameter(Mandatory = $true)]
        [string]$user
    )
    $DC = "mdotgbfrdc1.ad.mdot.mdstate",
    "MAABWIDC1.maa.ad.mdot.mdstate",
    "TSOGBDC1.mdothq.ad.mdot.mdstate",
    "MDTAICCDC01.mdta.ad.mdot.mdstate",
    "MPADMTENTDC01.mpa.ad.mdot.mdstate",
    "MTACWDRDC1.mtant1.ad.mdot.mdstate",
    "MVAWSDC1.mvant1.ad.mdot.mdstate",
    "SHAGBDC1.shacadd.ad.mdot.mdstate"
    $result = $DC | ForEach-Object { Get-ADUser -LDAPFilter "(samaccountname=$user*)" -Server $_ -Properties Department, Office, Description | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description }
    $result | Format-Table -AutoSize
}

function Findaccount3 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$firstname,

        [Parameter(Mandatory)]
        [string]$lastname
    )

    # List of Domain Controllers
    $DCs = @(
        "mdotgbfrdc1.ad.mdot.mdstate",
        "MAABWIDC1.maa.ad.mdot.mdstate",
        "TSOGBDC1.mdothq.ad.mdot.mdstate",
        "MDTAICCDC01.mdta.ad.mdot.mdstate",
        "MPADMTENTDC01.mpa.ad.mdot.mdstate",
        "MTACWDRDC1.mtant1.ad.mdot.mdstate",
        "MVAWSDC1.mvant1.ad.mdot.mdstate",
        "SHAGBDC1.shacadd.ad.mdot.mdstate"
    )

    $allResults = @()

    foreach ($dc in $DCs) {
        Write-Verbose "Testing connectivity to $dc on port 389..."
        $test = Test-NetConnection -ComputerName $dc -Port 389 -WarningAction SilentlyContinue

        if ($test.TcpTestSucceeded) {
            Write-Verbose "Connected to $dc. Querying AD..."
            try {
                $results = Get-ADUser -LDAPFilter "(&(givenname=$firstname*)(sn=$lastname*))" `
                    -Server $dc `
                    -Properties Department, Office, Description, Enabled `
                    -ErrorAction Stop

                if ($results) {
                    # Sort and select desired properties
                    $selected = $results | Sort-Object SamAccountName | Select-Object Department, Enabled, SamAccountName, GivenName, SurName, Office, Description
                    $allResults += $selected
                }
            }
            catch {
                Write-Warning ("Error querying {0}: {1}" -f $dc, $_.Exception.Message)
            }
        }
        else {
            Write-Warning "Cannot connect to $dc on port 389. Skipping..."
        }
    }

    if ($allResults.Count -gt 0) {
        $allResults | Format-Table -AutoSize
    }
    else {
        Write-Host "No results found or unable to query any Domain Controller." -ForegroundColor Yellow
    }
}
















finduser KBarry1
finduser RCornish3
finduser SGrinder
finduser AHall5
finduser RHeino
finduser JIngle
finduser Mmarshall1
finduser KMyers4
finduser APorco
