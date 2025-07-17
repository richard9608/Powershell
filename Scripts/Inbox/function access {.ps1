function access {
    param([Parameter(mandatory, position = 0)]
        [string]$path,
        [string]$user,
        [ValidateSet("ReadAndExecute", "Modify", "FullControl")]
        [string[]]$access,
        [switch]$add,
        [switch]$addfile,
        [switch]$remove,
        [switch]$traverse,
        [switch]$checkaccess,
        [switch]$accesslist,
        [switch]$disableinheritance,
        [switch]$changeowner)
    if ($add) {
        "`nCurrent Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
        $acl = get-acl $path
        [string]$identity = "$user"
        [System.Security.AccessControl.FileSystemRights]$rights = $access
        [System.Security.AccessControl.InheritanceFlags]$inheritance = @("ContainerInherit", "ObjectInherit")
        [System.Security.AccessControl.PropagationFlags]$propagation = "None"
        [System.Security.AccessControl.AccessControlType]$contoltype = "Allow"
        $aclobject = $identity, $rights, $inheritance, $propagation, $contoltype
        $newacl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $aclobject
        $acl.AddAccessRule($newacl)
        Set-Acl -Path $path -AclObject $acl -Verbose
        "`nNew Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
    }
 
    if ($addfile) {
        "`nCurrent Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
        $acl = get-acl $path
        [string]$identity = "$user"
        [System.Security.AccessControl.FileSystemRights]$rights = $access
        [System.Security.AccessControl.AccessControlType]$contoltype = "Allow"
        $aclobject = $identity, $rights, $contoltype
        $newacl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $aclobject
        $acl.AddAccessRule($newacl)
        Set-Acl -Path $path -AclObject $acl -Verbose
        "`nNew Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
    }
    if ($checkaccess) {
        "`nCurrent Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
        [string[]]$acl = get-acl $path | Select-Object -Expand access | Select-Object -expand identityreference
        $acl = $acl -replace '.+\\'
        $a = get-acl $path | Select-Object -expand access | Format-Table IdentityReference, FileSystemRights
        $acl | ForEach-Object { if ($_ -match $user) { "$_ has explicit rights." }
            elseif ((Get-ADGroup $_) -and (Get-ADGroupMember $_ | Where-Object name -match $user)) {
                "$user is a member of $_"; $a | Where-Object IdentityReference -Match $_
            }
            else { end } }2>$null
    }
    if ($traverse) {
        "`nCurrent Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
        $acl = get-acl $path
        [string]$identity = "$user"
        [System.Security.AccessControl.FileSystemRights]$rights = "ReadAndExecute"
        [System.Security.AccessControl.InheritanceFlags]$inheritance = @("None")
        [System.Security.AccessControl.PropagationFlags]$propagation = "None"
        [System.Security.AccessControl.AccessControlType]$contoltype = "Allow"
        $aclobject = $identity, $rights, $inheritance, $propagation, $contoltype
        $newacl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $aclobject
        $acl.AddAccessRule($newacl)
        Set-Acl -Path $path -AclObject $acl -Verbose
        "`nNew Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
    }
    if ($accesslist) {
        get-acl $path | Select-Object @{l = "path"; e = { $([string]$b = $_.path; $b = $b -replace '.+::', "";
                    $b) }
        } -ExpandProperty access | Format-Table filesystemrights, isinherited, identityreference -GroupBy path
    }
 
    if ($remove) {
        "`nCurrent Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
        $acl = get-acl $path
        foreach ($a in $acl.access | Where-Object Identityreference -eq "shacadd\$user") {
            $acl.RemoveAccessRule($a)
            Set-Acl $path -AclObject $acl -Verbose
        }
        "`nNew Access List`n"
        get-acl -Path "$path" |
            Select-Object @{l = "Path"; e = { $_.path -replace '.+::' } } -ExpandProperty Access |
            Format-Table FileSystemRights, IsInherited, IdentityReference -AutoSize -GroupBy Path
    }
 
    if ($disableinheritance) { icacls.exe $path /inheritance:d }
 
    if ($changeowner) { icacls.exe $path /setowner $user /T /C /Q }
}