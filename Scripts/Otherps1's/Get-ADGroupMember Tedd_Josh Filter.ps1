Get-ADGroupMember TEDD_Data_RW | sort name | select -exp name | % {
    Get-ADUser $_ -Properties * | select Enabled, Title, Name, DisplayName, Office } | ft -AutoSize

