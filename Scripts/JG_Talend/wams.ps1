wams


 $wams = @(
    "FAdoube",
    "KBarry1",
    "RCornish3",
    "SGrinder",
    "AHall5",
    "RHeino",
    "JIngle",
    "APorco"
)

$wams | ForEach-Object {
    get-aduser $_ -Properties *| Select-Object samaccountname, EmployeeID
}