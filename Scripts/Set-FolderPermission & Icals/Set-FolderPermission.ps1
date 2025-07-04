#.Help
<# 
.SYNOPSIS
    Sets the specified permission for a user on a folder.

.DESCRIPTION
    This function modifies the Access Control List (ACL) of a folder to grant the specified permission to a user.

.PARAMETER FolderPath
    The path to the folder on which to set the permission.

.PARAMETER User
    The username or user account to which the permission will be granted.

.PARAMETER Permission
    The level of permission to grant. Valid values are: FullControl, Modify, ReadAndExecute, Read, Write.

.EXAMPLE
    Set-FolderPermission -FolderPath "C:\SharedFolder" -User "DOMAIN\User" -Permission "Read"

.NOTES
    Author: Your Name
    Date: Today's Date
#>
function Set-FolderPermission {
    param (
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [Parameter(Mandatory)]
        [string]$User,

        [Parameter(Mandatory)]
        [ValidateSet("FullControl", "Modify", "ReadAndExecute", "Read", "Write")]
        [string]$Permission
    )

    if (-Not (Test-Path -Path $FolderPath)) {
        Write-Error "Folder path does not exist: $FolderPath"
        return
    }

    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $User,
        $Permission,
        $inheritanceFlags,
        $propagationFlags,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $acl = Get-Acl -Path $FolderPath
    $acl.SetAccessRule($accessRule)

    try {
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-Host "✅ $Permission permission set for $User on $FolderPath"
    }
    catch {
        Write-Error "Failed to set ACL: $_"
    }
}
