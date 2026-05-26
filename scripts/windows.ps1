Write-Host "========================================================"
Write-Host " Windows Vulnerability Manual Inspection Script"
Write-Host "========================================================"

Write-Host "`n[W-01, W-02, W-03] Local User Accounts Status"
Write-Host "-> Check for Administrator rename, Guest disable, and unnecessary accounts."
Get-LocalUser

Write-Host "`n[W-04, W-08, W-09] Password and Lockout Policies"
Write-Host "-> Check max/min age, length, lockout threshold, and duration."
net accounts

Write-Host "`n[W-06] Administrators Group Members"
Write-Host "-> Ensure minimum necessary users are in the Admin group."
Get-LocalGroupMember -Group "Administrators"

Write-Host "`n[W-14] Remote Desktop Users Group Members"
Write-Host "-> Check who has RDP access."
Get-LocalGroupMember -Group "Remote Desktop Users"

Write-Host "`n[W-10, W-52] Logon Registry Settings"
Write-Host "-> Check 'DontDisplayLastUserName' and 'AutoAdminLogon'."
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue

Write-Host "`n[W-13, W-51] Local Security Authority (LSA) Settings"
Write-Host "-> Check 'LimitBlankPasswordUse' and 'RestrictAnonymous'."
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse", "RestrictAnonymous" -ErrorAction SilentlyContinue

Write-Host "`n[W-16, W-17] Shared Folders and Default Shares"
Write-Host "-> Check active SMB shares and AutoShareServer registry."
Get-SmbShare
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "AutoShareServer" -ErrorAction SilentlyContinue

Write-Host "`n[W-18, W-29, W-34, W-44] Critical Services Status"
Write-Host "-> Check state of RemoteRegistry, SNMP, Telnet, etc."
Get-Service -Name "RemoteRegistry", "SNMP", "TlntSvr", "W3SVC", "LanmanServer" -ErrorAction SilentlyContinue

Write-Host "`n[W-40] System Audit Policies"
Write-Host "-> Dump raw audit policy configuration."
auditpol /get /category:*

Write-Host "`n[W-54] DoS Defense Registry Settings"
Write-Host "-> Check TCP/IP parameters (SynAttackProtect, KeepAliveTime, etc.)."
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect", "EnableDeadGWDetect", "KeepAliveTime", "NoNameReleaseOnDemand" -ErrorAction SilentlyContinue

Write-Host "`n[W-64] Windows Firewall Profiles"
Write-Host "-> Check if Domain, Private, and Public profiles are enabled."
Get-NetFirewallProfile

Write-Host "`n========================================================"
Write-Host " Inspection Complete "
Write-Host "========================================================"
