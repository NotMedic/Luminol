#Create our base JSON object
$jsonobject = @{
    "data" = New-Object System.Collections.ArrayList
    "meta" = @{
        methods = 0
        type    = "computers"
        count   = 0
        version = 5
    }
}

#Create Custom PS Object that matches Bloodhound JSON
$newobject = [PSCustomObject]@{
    Properties         = @{
        domain                  = ""
        name                    = ""
        distinguishedname       = "" #Populated from LDAP
        domainsid               = ""
        highvalue               = $false
        samaccountname          = ""
        haslaps                 = $false #Populated from LDAP
        description             = "" #Populated from LDAP
        whencreated             = 0 #NEED
        enabled                 = "" #Populated from LDAP
        unconstraineddelegation = "" #Populated from LDAP
        trustedtoauth           = "" #Populated from LDAP
        lastlogon               = "" #Populated from LDAP
        lastlogontimestamp      = "" #Populated from LDAP        
        pwdlastset              = "" #Populated from LDAP
        serviceprincipalnames   = New-Object System.Collections.ArrayList #Populated from LDAP
        operatingsystem         = ""  
        sidhistory              = New-Object System.Collections.ArrayList #Populated from LDAP
    }
    PrimaryGroupSID    = "" #Populated from LDAP
    AllowedToDelegate  = New-Object System.Collections.ArrayList #Populated from LDAP
    AllowedToAct       = New-Object System.Collections.ArrayList #Populated from LDAP
    HasSIDHistory      = New-Object System.Collections.ArrayList #Populated from LDAP
 
    Sessions           = @{
        Results       = New-Object System.Collections.ArrayList
        Collected     = $false
        FailureReason = $null
    }
    PrivilegedSessions = @{
        Results       = New-Object System.Collections.ArrayList
        Collected     = $false
        FailureReason = $null
    }
    RegistrySessions   = @{
        Results       = New-Object System.Collections.ArrayList
        Collected     = $false
        FailureReason = $null
    }
    LocalAdmins        = @{
        Results       = New-Object System.Collections.ArrayList
        Collected     = $false
        FailureReason = $null
    }
    RemoteDesktopUsers = @{
        Results       = New-Object System.Collections.ArrayList
        Collected     = $false
        FailureReason = $null
    }
    DcomUsers          = @{
        Results       = New-Object System.Collections.ArrayList
        Collected     = $false
        FailureReason = $null
    }
    PSRemoteUsers      = @{
        Results       = New-Object System.Collections.ArrayList
        Collected     = $false
        FailureReason = $null
    }
    Status             = $null
    Aces               = New-Object System.Collections.ArrayList #Populated from LDAP
    ObjectIdentifier   = ""
    IsDeleted          = $false
    IsACLProtected     = $false  
}

#Populate name and domain
$newobject.Properties.samaccountname = "$env:COMPUTERNAME$"
$newobject.Properties.name = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
$newobject.Properties.domain = "$env:USERDNSDOMAIN"

#Populate OperatingSystem
$newobject.Properties.operatingsystem = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption

#Populate Domain SID
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainSid = $domain.GetDirectoryEntry().objectSid
$domainDN = $domain.GetDirectoryEntry().distinguishedName
$newobject.Properties.domainsid = (New-Object System.Security.Principal.SecurityIdentifier($domainSid[0], 0)).Value



#Set up LDAP Queries
$adsisearcher = New-Object System.DirectoryServices.DirectorySearcher
$adsisearcher.Filter = "(&(objectCategory=computer)(name=$env:COMPUTERNAME))"
$adsisearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
$adsisearcher.SearchScope = "Subtree"
$adsisearcher.PropertiesToLoad.Add("distinguishedName")
$adsisearcher.PropertiesToLoad.Add("primaryGroupID")
$result = $adsisearcher.FindOne()

#Populate DistinguishedName
$newobject.Properties.distinguishedname = $result.Properties.distinguishedname[0]

#Populate PrimaryGroupSID
$newobject.PrimaryGroupSID = $newobject.Properties.domainsid + "-" + $result.Properties.primarygroupid[0].ToString()

#Populate Properties.objectid and ObjectIdentifier
$ntAccount = New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME$")
$newobject.ObjectIdentifier = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

#Populate LocalAdmins
(Get-LocalGroupMember -Group "Administrators").foreach{
    $adminobject = @{
        ObjectIdentifier   = $_.SID
        ObjectType = $_.ObjectClass
    }
    $newobject.LocalAdmins.Collected = $true
    $newobject.LocalAdmins.Results.Add($adminobject)
}

#Populate RemoteDesktopUsers
(Get-LocalGroupMember -Group "Remote Desktop Users").foreach{
    $rdpobject = @{
        ObjectIdentifier   = $_.SID
        ObjectType = $_.ObjectClass
    }
    $newobject.RemoteDesktopUsers.Collected = $true
    $newobject.RemoteDesktopUsers.Results.Add($rdpobject)
}

#Populate DcomUsers
(Get-LocalGroupMember -Group "Distributed COM Users").foreach{
    $dcomobject = @{
        ObjectIdentifier   = $_.SID
        ObjectType = $_.ObjectClass
    }
    $newobject.DcomUsers.Collected = $true
    $newobject.DcomUsers.Results.Add($dcomobject)
}

#Populate PSRemoteUsers
(Get-LocalGroupMember -Group "Remote Management Users").foreach{
    $psremoteobject = @{
        ObjectIdentifier   = $_.SID
        ObjectType = $_.ObjectClass
    }
    $newobject.PSRemoteUsers.Collected = $true
    $newobject.PSRemoteUsers.Results.Add($psremoteobject)
}

#Populate Sessions from Processes
(Get-Process -IncludeUserName | Select-Object -Unique UserName).foreach{
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($_.UserName)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

        if ($sid.StartsWith("S-1-5-21")) {
            $processobject = @{
                UserSID     = $sid
                ComputerSID = $newobject.ObjectIdentifier
            }
            $newobject.PrivilegedSessions.Collected = $true
            if ($newobject.PrivilegedSessions.Results -notcontains $processobject) {
                $newobject.PrivilegedSessions.Results.Add($processobject)
            }
        }
    }
    catch {
    }
}

#Populate Sessions from Scheduled Tasks
ForEach ($task in Get-ScheduledTask | Select-Object -ExpandProperty Principal | Where-Object -Property "LogonType" -EQ "Password" | Select-Object -Unique UserId) {
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($task.UserId)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

        if ($sid.StartsWith("S-1-5-21")) {
            $taskobject = @{
                UserSID     = $sid
                ComputerSID = $newobject.ObjectIdentifier
            }
            if ($newobject.PrivilegedSessions.Results -notcontains $taskobject) {
                $newobject.PrivilegedSessions.Results.Add($taskobject)
            }
        }
    }
    catch {
    }
}

#Populate Sessions from Services
ForEach ($service in Get-CimInstance -ClassName Win32_Service -Filter "StartName != 'LocalSystem' AND NOT StartName LIKE 'NT AUTHORITY%' " | Select-Object StartName) {
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($service.StartName)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

        if ($sid.StartsWith("S-1-5-21")) {
            $serviceobject = @{
                UserSID     = $sid
                ComputerSID = $newobject.ObjectIdentifier
            }

            if ($newobject.PrivilegedSessions.Results -notcontains $serviceobject) {
                $newobject.PrivilegedSessions.Results.Add($serviceobject)
            }
        }
    }
    catch {
    }
}

$jsonobject.data.Add($newobject)
$jsonobject.meta.count = $jsonobject.data.Count

$jsonobject | ConvertTo-Json -Depth 5
