# Requires ActiveDirectory module
# Requires Powershell ISE installed

# Version: 1.0.1 - added lookup for oldest DC (usually oldest holds more replication metadata and evidence longer back in time)
# comments to: yossis@protonmail.com (Part of Hacktive Directory Toolkit)

$EAP = $ErrorActionPreference
$ErrorActionPreference = "silentlycontinue"

while (!$accountobj) {
    $account = read-host -Prompt "Enter account name (e.g. administrator, srv01$)";
    $accountobj = Get-ADUser $account;
    if (!$?) 
        {
            Write-Warning "user/computer not found. please try again."
        }
}

# Get oldest Domain controller in the environment
$searcher = New-Object System.DirectoryServices.DirectorySearcher;

# Only computer objects with server roles indicating a DC
$searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";

# Ask for attributes
$searcher.PropertiesToLoad.Add("name")        | Out-Null;
$searcher.PropertiesToLoad.Add("dnsHostName") | Out-Null;
$searcher.PropertiesToLoad.Add("whenCreated") | Out-Null;

$results = $searcher.FindAll();

$DCs = foreach ($r in $results) {
    $props = $r.Properties;

    [PSCustomObject]@{
        DCName      = $props["dnshostname"][0]
        WhenCreated = [datetime]$props["whencreated"][0]
    }
}

# Sort and return the oldest DC
$DC = $DCs | Sort-Object WhenCreated | Select-Object -First 1 -ExpandProperty DCName;

# get account's metadata for replication group changes
Get-ADUser $accountobj.DistinguishedName -Properties memberOf | 
    Select -ExpandProperty memberOf | ForEach-Object { 
        Get-ADReplicationAttributeMetadata $_ -Server $DC -ShowAllLinkedValues | 
        Where-Object {$_.AttributeName -eq 'member' -and $_.AttributeValue -eq $accountobj.DistinguishedName} |
        Select-Object @{n='DateTime When Account Added To Group';e={$_.FirstOriginatingCreateTime}}, @{n='Group';e={$_.Object}}, @{n='Account';e={$_.AttributeValue}}
        } | 
        Sort FirstOriginatingCreateTime | Out-GridView -Title "Current Groups for $($account.ToUpper()) - When added to Group(s)"

Remove-Variable accountobj, account
$ErrorActionPreference = $EAP