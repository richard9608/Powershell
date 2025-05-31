# .SYNOPSIS             
# This script checks and manages Active Directory group memberships for specified users.                        
# Description: This script checks if specific users are members of specified Active Directory groups.
# It adds them to the groups if they are not already members and logs the results.  
# It also exports the results to an Excel file for review.
# Requirements: Active Directory module, ImportExcel module

Import-Module ActiveDirectory
Import-Module ImportExcel

# Define the list of users and groups
$groupsToCheck = @("SHASalesforceAzure_SSO", "SHA_SFDC_SSO")  # Replace with your groups
# Replace with your users (sAMAccountNames)
$names = "apierce
dwyatt
ddarling
dphillips1
jchambers
jminer1
JJenkins5
jdwyer1
JThompson4
phusselbee
rmartin
shiggs
tmaqui
tcashen
vdjeunga".Split("`n")

#--------------------------------------------------------------------------------------------


$results = @()

foreach ($user in $names) {
    try {
        # Get user's group memberships
        $userGroups = Get-ADUser -Identity $user -Properties MemberOf |
            Select-Object -ExpandProperty MemberOf |
            ForEach-Object {
            ($_ -split ',')[0] -replace '^CN='
            }

        Write-Host "`nChecking memberships for user: $user" -ForegroundColor Cyan

        foreach ($group in $groupsToCheck) {
            $isMember = $userGroups -contains $group

            if ($isMember) {
                Write-Host " - $user IS a member of '$group'" -ForegroundColor Green
                $results += [PSCustomObject]@{
                    User   = $user
                    Group  = $group
                    Action = 'Already a member'
                    Status = 'Success'
                }
            }
            else {
                Write-Host " - $user is NOT a member of '$group'. Adding to group..." -ForegroundColor Yellow
                try {
                    Add-ADGroupMember -Identity $group -Members $user -ErrorAction Stop
                    Write-Host "   > Successfully added $user to $group" -ForegroundColor Green
                    $results += [PSCustomObject]@{
                        User   = $user
                        Group  = $group
                        Action = 'Added to group'
                        Status = 'Success'
                    }
                }
                catch {
                    Write-Host "   > Failed to add $user to $group. Error: $_" -ForegroundColor Red
                    $results += [PSCustomObject]@{
                        User   = $user
                        Group  = $group
                        Action = 'Add failed'
                        Status = "Error: $_"
                    }
                }
            }
        }
    }
    catch {
        Write-Host "`nFailed to process user '$user'. Error: $_" -ForegroundColor Magenta
        $results += [PSCustomObject]@{
            User   = $user
            Group  = 'N/A'
            Action = 'Failed to process user'
            Status = "Error: $_"
        }
    }
}

# Export to Excel
$results | Export-Excel -Path "C:\Users\LRichardson2\Documents\GroupMembershipResults2.xlsx" `
    -AutoSize -Title "Group Membership Audit" -WorksheetName "Results" `
    -BoldTopRow -FreezeTopRow -TableName "AuditResults" -Show


