# IN TEST MODE check $rootPath
# TASK -> ADD 'Share-Global-All-Full Ctrl' to all folders in \\smb01.unfcsd.unf.edu\global
# 
# 
#
#

CLEAR
$Error.Clear()

# Set properties
$identity = "Share-Global-All-Full Ctrl"
$fileSystemRights = "FullControl"
$type = "Allow"

# Create new rule
$fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
$fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList

# Declare other variables for script
$rootPath = 'C:\Users\AndrewsP\Documents\Add-FullControl\Scans'
$subPaths = Get-ChildItem -LiteralPath $RootPath -Directory 
$subFolderList = $subPaths.FullName
$folderAddList = @() # folders where $identity was added
$xml = @() # previous ACL before $identity is added to ACL
$regex = "*" + $identity + "*" # to be used with Where command

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

    # See if all subdirectories in first level folder have user($identity) with specified access($fileSystemRights)
    Get-ChildItem -LiteralPath $subFolder -Recurse -Directory | %{
	    $folder = $_.FullName
        $acl = Get-Acl -LiteralPath $folder
        $folder
        $contains = $acl.Access | Where{$_.IdentityReference -like $regex}

        # if a folder has at least one inherited ACL then inheritance is enabled
        $isInherited = $acl.Access | where{$_.IsInherited -eq $true}
        if( $isInherited.Count -gt 0 ) { 
        
        } elseif( ($contains.count -eq 0) -or ($contains.FileSystemRights -ne $fileSystemRights) ) {
            $xml += Get-Acl -LiteralPath $folder # add backup of previous acl to .xml
            $item = New-Object –TypeName PSObject
                $item | Add-Member –MemberType NoteProperty –Name "Folder Path" -Value $folder
                $item | Add-Member –MemberType NoteProperty –Name "Add User" -Value $identity
            $folderAddList += $item
        }
    }

    # Append to .csv 
    $folderAddList | Export-CSV -LiteralPath .\global-NeedsFullCtrl.csv -NoTypeInformation -Append
    $folderAddlist = @()

    # backup of $acl for each folder before user($identity) with FileSystemRights($fileSystemRights) were added 
    $filePath = $subFolder.Replace('\', '.')
	$xml | Export-Clixml .\$filePath.xml 
    $xml = @()

    $Error | Export-Csv -LiteralPath .\globalErrors-NeedsFullCtrl.csv -NoTypeInformation -Append
    $Error.Clear()
}



<# Add User
CLEAR
$importedCsv = Import-Csv .\global-NeedsFullCtrl.csv
foreach( $line in $importedCsv ) {
        $folderPath = $line.'Folder Path'
        $acl = Get-Acl -LiteralPath $folderPath
        $workAround = $false

        # this is a workaround for when filenames have special characters that the .csv format couldn't interpret
        if( $acl -eq $null ) { 
            $acl = Get-Acl -Path $folderPath 
            $workAround = $true
        }

        $acl.SetAccessRule($fileSystemAccessRule)
        if( $workAround -eq $false ) { 
            Set-Acl -LiteralPath $folderPath -AclObject $acl
        } else {
            Set-Acl -Path $folderPath -AclObject $acl
        }
        Write-Host -ForegroundColor Red -BackgroundColor Blue 'Added' $identity 'to' $folderPath
        $Error | Export-CSV -LiteralPath .\addUserGlobalErrors.csv -NoTypeInformation -Append
        $Error.Clear()
}#>