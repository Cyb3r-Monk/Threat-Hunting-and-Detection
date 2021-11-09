# Potential Lateral Movement with Personal Privileged Account
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Medium](https://mergene.medium.com/building-a-custom-ueba-with-kql-to-hunt-for-lateral-movement-7459a899091)

Language: Azure KQL

Products: M365D

Coverage: Lateral Movement with Domain Accounts only  

Required: IdentityLogonEvents


## Description

Below query detects potential Lateral Movement that involves personal privileged accounts.  
Since valid accounts are used for Lateral Movement, it covers Valid Accounts technique as well.
ATTENTION: You need to modify to query according to your environment.

**Query:**

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post: https://mergene.medium.com/building-a-custom-ueba-with-kql-to-hunt-for-lateral-movement-7459a899091
//
//
//              How to use this query:
//              Modify the "Admin account condition" sections according to your environment. Set query time to 15d or 30d.
//              If a personal privileged account gets compromised, it would be used from the same machine as it was usually used from. 
//              If you want to see the results where there is no associated alert, change the value ShowResultsWithNoAlerts to 'YES'. Otherwise, set it to 'NO'.
//              
//              In an attack involving Lateral Movement or Valid Accounts, you might expect to see at least one alert related to either the source device, the target device or the identity(normal or admin account) account. 
//              Admin accounts are expected to be used from the same devices. If the account is seen on a new source/target device (IsSourceUsedBefore=No, IsTargetUsedBefore=No), it may be anomalous.
//              Some Admin accounts have privileges on many devices(helpdesk, Windows admins). SourceCount and TargetCount gives an idea about the account usage.
//              
//              Explanations of the custom fields in the results:
//              IsSourceUsedBefore/IsTargetUsedBefore: if the acount has used Source/Target device before. 
//              AccountSourceCount/AccountTargetCount: Number of distinct Source/Target Devices that the account has used before.
//              Job Title: Job title of the personal account(if exists in the IdentityInfo table). If you don't have the table, remove the enrichment.
//
let ShowResultsWithNoAlerts = "NO";
// Query parameters
let lookback = 30d;
let timeframe = 1d;
// Generate building blocks
// Whitelisted alerts. (Some alerts may keep popping up as false positives, add the title info to the list)
let whitelisted_alerts = dynamic(["EICAR_Test_File"]);
// 1. Generate list of Servers based on OSPlatform info
let server_list = 
    DeviceInfo
    | where Timestamp > ago(lookback)
    | where OSPlatform startswith "WindowsServer"
    | summarize make_set(DeviceName)
    ;
// 2. Generate list of Workstations based on OSPlatform info
let workstation_list = 
    DeviceInfo
    | where Timestamp > ago(lookback)
    | where OSPlatform == "Windows10"
    | summarize make_set(DeviceName)
    ;
// 3. Generate the logon baseline for each account
//    Baseline: devices(source and target) that the account logged on before
let baseline_data = 
    IdentityLogonEvents
    | where Timestamp between (ago(lookback) .. ago(timeframe))
    | where Application == "Active Directory"
    | where ActionType == "LogonSuccess"
    // Condition for admin account
    | where AccountName startswith "admin"
    | where isnotempty(TargetDeviceName) and isnotempty(AccountName)
    | summarize SourceDevices=make_set(DeviceName),TargetDevices=make_set(TargetDeviceName) by AccountName
    ;
// Get admin logons of last 1 day(assume all of them are suspicious) and enrich the results with account baseline info
let SuspiciousLogons = materialize (
    IdentityLogonEvents
    | where Timestamp > ago(timeframe)
    | where Application == "Active Directory"
    | where ActionType == "LogonSuccess"
    // Admin account condition
    | where AccountName startswith "admin"
    | where isnotempty(TargetDeviceName) and isnotempty(AccountName)
    | summarize arg_max(Timestamp, *), LogonCount=count() by DeviceName, TargetDeviceName, AccountName // Get only the last logon for each source-target-account.
    // Enrich unusual logons with the baseline information and the building blocks
    | join kind=leftouter baseline_data on AccountName
    | extend IsSourceUsedBefore = iff(SourceDevices has DeviceName, 'Yes', 'No'), IsTargetUsedBefore = iff(TargetDevices has TargetDeviceName , 'Yes', 'No'),
            SourceDeviceType = case(DeviceName in~ (workstation_list),'Workstation',DeviceName in~ (server_list), 'Server', 'Unknown'), 
            TargetDeviceType = case(TargetDeviceName in~ (workstation_list),'Workstation',TargetDeviceName in~ (server_list), 'Server', 'Unknown'),
            AccountSourceCount=array_length(SourceDevices), 
            AccountTargetCount=array_length(TargetDevices)
    // Generate normalized account name. Normalized account name is the account that has a separate admin account).
    // Both accounts will be treated as the same identity. Modify this section according to your naming conventions.
    | extend NormalizedAccountName = replace(@'admin',@'',AccountName)
    | project-away SourceDevices, TargetDevices
    )
    ;
// Get all alerts of the Source/Target devices and accounts
let SourceDeviceList = SuspiciousLogons | summarize make_set(DeviceName);
let TargetDeviceList = SuspiciousLogons | summarize make_set(TargetDeviceName);
let AdminAccountList = SuspiciousLogons | summarize make_set(AccountName);
let NormalAccountList = SuspiciousLogons | summarize make_set(NormalizedAccountName);
// Account alerts
let AccountAlerts = materialize 
    (
    AlertInfo
    | where Timestamp > ago(2d)
    | where not (Title has_any(whitelisted_alerts))
    | join kind=inner 
        (
        AlertEvidence 
        | where Timestamp > ago(2d)
        | where isnotempty(AccountName)
        ) on AlertId
    | where AccountName in (AdminAccountList) or AccountName in (NormalAccountList)
    | project AccountName, AlertId,Title, Severity
    | extend AlertDetails=pack('AlertId', AlertId, 'Title', Title, 'Severity', Severity)
    | summarize Alerts=make_set(AlertDetails) by AccountName
    | extend All=pack(AccountName,Alerts)
    | summarize make_bag(All)
    )
    ;
// Define function for getting all the alerts of a given account
let GetAccountAlerts = (entity:string) {
    toscalar(AccountAlerts)[entity]
};
// Device Alerts
let DeviceAlerts = materialize 
    (
    AlertInfo
    | where Timestamp > ago(2d)
    | where not (Title has_any(whitelisted_alerts))
    | join kind=inner 
        (
        AlertEvidence 
        | where Timestamp > ago(2d)
        | where isnotempty(DeviceName)
        ) on AlertId
    | where DeviceName in (SourceDeviceList) or DeviceName in (TargetDeviceList)
    | project DeviceName, AlertId,Title, Severity
    | extend AlertDetails=pack('AlertId', AlertId, 'Title', Title, 'Severity', Severity)
    | summarize Alerts=make_set(AlertDetails) by DeviceName
    | extend All=pack(DeviceName,Alerts)
    | summarize make_bag(All)
    )
    ;
// Define function for getting all the alerts of a given device
let GetDeviceAlerts = (entity:string) {
    toscalar(DeviceAlerts)[entity]
};
// Get any alert info related to the Source, Target, personal or personal privileged(admin) account and enrich the results.  
SuspiciousLogons
| extend SourceDeviceAlerts = GetDeviceAlerts(DeviceName), TargetDeviceAlerts = GetDeviceAlerts(TargetDeviceName), AdminAccountAlerts = GetAccountAlerts(AccountName), NormalAccountAlerts = GetAccountAlerts(NormalizedAccountName)
// Display the most important results. 
| where (IsTargetUsedBefore == "No" and (isnotempty(AdminAccountAlerts) or isnotempty(NormalAccountAlerts) or isnotempty(SourceDeviceAlerts) or isnotempty(TargetDeviceAlerts))) or (IsSourceUsedBefore == "No" and ShowResultsWithNoAlerts == "YES" )
// Try to get information of the Person owning the Admin account. Remove the line below if you don't have this table. 
| join kind=leftouter (IdentityInfo| summarize arg_max(AccountObjectId,*) by AccountName, AccountDomain) on $left.NormalizedAccountName==$right.AccountName
| project-reorder Timestamp, DeviceName, SourceDeviceType, AccountName, JobTitle, TargetDeviceName, TargetDeviceType, LogonCount, IsSourceUsedBefore, IsTargetUsedBefore, AccountSourceCount, AccountTargetCount, SourceDeviceAlerts, TargetDeviceAlerts, AdminAccountAlerts, NormalAccountAlerts
```
