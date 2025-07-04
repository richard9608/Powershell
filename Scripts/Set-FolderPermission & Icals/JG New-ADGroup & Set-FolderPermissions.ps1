New-ADGroup and Set-FolderPermissions for ADGroup


New-ADGroup -Name 'NEVIRound1_RW' `
    -DisplayName 'NEVIRound1_RW' `
    -GroupScope Global `
    -GroupCategory Security `
    -Description "RW Access to \\shahqfs2\DGNShared\OP3\MDOT SHA\NEVI\NEVI Round 1 Contracts\" `
    -Path "OU=Groups,OU=OP3,OU=Design,OU=HQ,OU=SHA,DC=shacadd,DC=ad,DC=mdot,DC=mdstate" -Verbose


#--------------------------------------------------------------------------------------------
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