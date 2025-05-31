$excel | % {
    [PSCustomObject][ordered]@{
        First_Name         = $_.First_Name;
        Last_Name          = $_.Last_Name;
        User_ID            = $_.User_ID;
        Description        = $_.Description;
        Department         = $_.Department;
        Office_District    = $_.Office_District;
        Email_Display_Name = $_.Email_Display_Name;
        Office_Name        = $_.Office_Name;
        whenCreated        = $([datetime]$_.whenCreated);
        userprincipalname  = $_.userprincipalname;
        Azure_LastLogon    = $(Get-MailboxStatistics $_.User_ID 2>$null | select -exp LastLogonTime)
    } | Export-Excel `
        -Path C:\Users\LRichardson2\Documents\60days\Neverloggedin.xlsx -Append } 2>$null






$excel | % {
    [PSCustomObject][ordered]@{
        First_Name               = $_.First_Name;
        Last_Name                = $_.Last_Name;
        User_ID                  = $_.User_ID;
        Description              = $_.Description;
        Department               = $_.Department;
        Office_District          = $_.Office_District;
        Email_Display_Name       = $_.Email_Display_Name;
        Office_Name              = $_.Office_Name;
        whenCreated              = $_.whenCreated;
        lastLogonTimestamp       = $_.lastLogonTimestamp;
        NumberofDays             = $_.NumberofDays;
        userprincipalname        = $_.userprincipalname;
        Azure_LastLogonTimestamp = $(Get-MailboxStatistics $_.User_ID 2>$null | select -exp LastLogonTime)
    } | Export-Excel `
        -Path C:\Users\LRichardson2\Documents\60days\75days.xlsx -Append }