# Powershell-Scripts
## Add/Delete-Acls.ps1
- Access Control List(ACLS) : is a list of permissions associated with a folder or a file.
- Delete-Acl.ps1: Makes a backup of all acls in all folders specified by $rootpath then removes CREATOR OWNER and SIDs from folders.
- Add-Acl.ps1: Makes a backup of all acls in all folders specified by $rootpath then adds ACL specified by $identity to all folders.

## Privilege Access Tokens (Enable-AllPrivilegeAccessTokens.ps1)
- This script will enable all the constants that are in the link below.
- https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
