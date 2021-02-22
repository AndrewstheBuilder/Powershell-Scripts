# Run as admin
# Make sure correct token privileges are enabled check enabled tokens. Check by running command 'whoami /priv'
# To enable all token privilieges run my script Enable-AllPriv.ps1
# Check current directory -> make sure the .csv files that are appended to in this script are not there
#
# \\smb01.unfcsd.unf.edu\global
#
#

CLEAR
$Error.Clear()
$RootPath = '\\smb01.unfcsd.unf.edu\global'
$FolderPurgeList = @()
$GlobalXML = @() # array of XMl objects -> XML objects are backups of ACL before some ACLs are removed

# get first-level subdirectories of $RootPath
$SubPaths = Get-ChildItem -LiteralPath $RootPath -Directory 
$SubFolderList = $SubPaths.FullName

ForEach( $SubFolder in $SubFolderList ) {
    CLEAR

    # Check $ACL on first level $Subfolders on $RootPath
    $SubFolder 
    $ACL = Get-Acl -LiteralPath $SubFolder
    $RemoveUser = $ACL.Access | where {($_.IdentityReference -like "*CREATOR OWNER*" -or $_.IdentityReference -like "S-*-*-*-*")}
    if( $RemoveUser.count -gt 0 ) { $GlobalXML += Get-Acl -LiteralPath $SubFolder }
    ForEach ($UserName in $RemoveUser ) {
        $itemHasPerm = New-Object –TypeName PSObject
            $itemHasPerm | Add-Member –MemberType NoteProperty –Name "Target User" -Value $UserName.IdentityReference
            $itemHasPerm | Add-Member –MemberType NoteProperty –Name "Folder Path" -Value $SubFolder
        $FolderPurgeList += $itemHasPerm
    } 

    # Check $ACL on $AllSubFolders inside a first-level subdirectory of the $RootPath
    Get-ChildItem -LiteralPath $SubFolder -Recurse -Directory | %{
            $Folder = $_.FullName
            $Folder
            $ACL = Get-Acl -LiteralPath $Folder
            $RemoveUser = $ACL.Access | where {($_.IdentityReference -like "*CREATOR OWNER*" -or $_.IdentityReference -like "S-*-*-*-*")}
            if( $RemoveUser.count -gt 0 ) { $GlobalXML += Get-Acl -LiteralPath $Folder }
            ForEach ($UserName in $RemoveUser ) {
                if( $UserName.IsInherited -eq $true ){ continue }
                $itemHasPerm = New-Object –TypeName PSObject
                    $itemHasPerm | Add-Member –MemberType NoteProperty –Name "Target User" -Value $UserName.IdentityReference
                    $itemHasPerm | Add-Member –MemberType NoteProperty –Name "Folder Path" -Value $Folder
                $FolderPurgeList += $itemHasPerm
            }
    }

    # Append Errors and PurgeList to .csv files
    $FolderPurgeList | Export-CSV -LiteralPath .\global2.csv -NoTypeInformation -Append
    $FolderPurgeList = @()
    $filePath = $SubFolder.Replace('\', '.')
    if( $GlobalXML -ne $null ) {
        $GlobalXML | Export-Clixml .\$filePath.xml
        $GlobalXML = @()
    }
    $Error | Export-CSV -LiteralPath .\globalErrors2.csv -NoTypeInformation -Append
    $Error.Clear()
}



#remove users
CLEAR
$importedCsv = Import-Csv .\global2.csv
foreach($line in $importedCsv) { 
     $folderPath = $line.'Folder Path'
     $removeUser = $line.'Target User'
     $acl = Get-Acl -LiteralPath $folderPath
     $workAround = $false

     # this is a workaround for when filenames have special characters because the .csv doesn't interpret that
     if( $acl -eq $null ) { 
        $acl = Get-Acl -Path $folderPath 
        $workAround = $true
     }

     $regex = $removeUser + "*"
     $removeAcl = $acl.Access | where {$_.IdentityReference -like $regex}
     if( $removeAcl -eq $null ) { 
        Write-Host -ForegroundColor Magenta -BackgroundColor Black 'Warning: Acl' $removeUser 'not found in' $folderPath 
        #break # remove this if you don't want the script to break on this condition
     } 
     foreach( $user in $removeAcl ) {
        $acl.RemoveAccessRule( $user )
     }
     if( $workAround -eq $false ) { 
        Set-Acl -LiteralPath $folderPath -AclObject $acl -ErrorAction Stop # applies removed acl to $folderPath
     } else {
        Set-Acl -Path $folderPath -AclObject $acl -ErrorAction Stop # applies removed acl to $folderPath
     }
     Write-Host -ForegroundColor Red -BackgroundColor Blue 'Removed user' $removeUser 'in' $folderPath
     $Error | Export-CSV -LiteralPath .\removeUserGlobalErrors2.csv -NoTypeInformation -Append
     $Error.Clear()
}

