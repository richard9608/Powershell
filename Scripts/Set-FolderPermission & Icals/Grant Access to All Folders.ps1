✅ PowerShell Script to Grant Access to All Folders


# Define target
$profilePath = "C:\Users\LRichardson2"
$userToGrant = "LRichardson2_adm"

# Get all folders under the profile
$folders = Get-ChildItem -Path $profilePath -Directory -Recurse -Force -ErrorAction SilentlyContinue
$folders += Get-Item -Path $profilePath  # Include root profile folder

foreach ($folder in $folders) {
    try {
        $acl = Get-Acl $folder.FullName

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $userToGrant,
            "Modify",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

        $acl.AddAccessRule($rule)
        Set-Acl -Path $folder.FullName -AclObject $acl

        Write-Host "✅ Access granted to: $($folder.FullName)" -ForegroundColor Green
    } catch {
        Write-Warning "⚠️ Failed to set permissions on: $($folder.FullName) - $_"
    }
}

