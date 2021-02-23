# 
# TASK -> ADD 'Share-Global-All-Full Ctrl' with Full Control Access to all folders that need it in \\unfcsd.unf.edu\files\global\Scans 
# 
# 
#
#

CLEAR
$Error.Clear()

# Set properties ( Reference: https://community.spiceworks.com/topic/727786-set-acl-folder-permissions, https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemaccessrule)
$identity = "Share-Global-All-Full Ctrl"
$fileSystemRights = "FullControl"
$InheritanceFlags = @([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
$type = "Allow"

# Create new rule
$fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $InheritanceFlags, $PropagationFlags, $type
$fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList

# Declare other variables for script
$rootPath = '\\unfcsd.unf.edu\files\global\temp\private'
$subPaths = Get-ChildItem -LiteralPath $RootPath -Directory 
$subFolderList = $subPaths.FullName
$folderAddList = @() # folders where $identity was added
$xml = @() # previous ACL before $identity is added to ACL
$regex = "*" + $identity + "*" # to be used with Where command

#remove .csv files from last run
if( Test-Path .\Needs-FullCtrl.csv ){rm .\Needs-FullCtrl.csv}
if( Test-Path .\Needs-FullCtrl_Errors.csv ){rm .\Needs-FullCtrl_Errors.csv}
if( Test-Path .\Add-FullCtrl_Errors.csv ){rm .\Add-FullCtrl_Errors.csv}

ForEach( $subFolder in $subFolderList ) {
    CLEAR
    
    # See if first level subdirectories have user($identity) with specified access($fileSystemRights)
    $acl = Get-Acl -LiteralPath $subFolder
    $subFolder
    $contains = $acl.Access | Where{$_.IdentityReference -like $regex}
    if( ($contains.count -eq 0) -or ($contains.FileSystemRights -ne $fileSystemRights) ) {
        $xml += Get-Acl -LiteralPath $subFolder # add backup of previous acl to .xml
        $item = New-Object –TypeName PSObject
            $item | Add-Member –MemberType NoteProperty –Name "Folder Path" -Value $subFolder
            $item | Add-Member –MemberType NoteProperty –Name "Add User" -Value $identity
        $folderAddList += $item
    }

    # Append to .csv 
    $folderAddList | Export-CSV -LiteralPath .\Needs-FullCtrl.csv -NoTypeInformation -Append
    $folderAddlist = @()

    $Error | Export-Csv -LiteralPath .\Needs-FullCtrl_Errors.csv -NoTypeInformation -Append
    $Error.Clear()
}



# Add 'Share-Global-All-Full Ctrl'
CLEAR
$Error.Clear()

$importedCsv = Import-Csv .\Needs-FullCtrl.csv
foreach( $line in $importedCsv ) {
        $folderPath = $line.'Folder Path'
        $acl = Get-Acl -LiteralPath $folderPath #-LiteralPath used to avoid regex characters in file pathname
        $workAround = $false

        # this is a workaround for when filenames have special characters that -LiteralPath couldn't interpret
        if( $acl -eq $null ) { 
            $acl = Get-Acl -Path $folderPath 
            $workAround = $true
            $Error.Clear()
        }

        $acl.SetAccessRule($fileSystemAccessRule)
        if( $workAround -eq $false ) { 
            Set-Acl -LiteralPath $folderPath -AclObject $acl
        } else {
            Set-Acl -Path $folderPath -AclObject $acl
        }
        if(!$Error){Write-Host -ForegroundColor Red -BackgroundColor Blue 'Added' $identity 'to' $folderPath}
        $Error | Export-CSV -LiteralPath .\Add-FullCtrl_Errors.csv -NoTypeInformation -Append
        $Error.Clear()
}#>