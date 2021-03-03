# Requires ActiveDirectory module
# Requires Powershell ISE installed

$EAP = $ErrorActionPreference
$ErrorActionPreference = "silentlycontinue"

while (!$userobj) {
    $user = read-host -Prompt "Enter username";
    $userobj = Get-ADUser $user;
    if (!$?) 
        {
            Write-Warning "object not found. please try again."
        }
}

Get-ADUser $userobj.DistinguishedName -Properties memberOf | 
    Select -ExpandProperty memberOf | ForEach-Object { 
        Get-ADReplicationAttributeMetadata $_ -Server $env:LOGONSERVER.Replace("\\","") -ShowAllLinkedValues | 
        Where-Object {$_.AttributeName -eq 'member' -and $_.AttributeValue -eq $userobj.DistinguishedName} |
        Select-Object @{n='DateTime When Account Added To Group';e={$_.FirstOriginatingCreateTime}}, @{n='Group';e={$_.Object}}, @{n='Account';e={$_.AttributeValue}}
        } | 
        Sort FirstOriginatingCreateTime | Out-GridView -Title "Current Groups for $($user.ToUpper()) - When added to Group(s)"

Remove-Variable userobj, user
$ErrorActionPreference = $EAP
