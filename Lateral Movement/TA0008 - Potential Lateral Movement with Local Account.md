# Potential Lateral Movement with Local Account
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Medium](https://mergene.medium.com/hunting-for-lateral-movement-local-accounts-bc08742f3d83)

Language: Azure KQL

Products: M365D. For MDE, you need to customize the query and use DeviceAlertEvents table.

Coverage: Lateral Movement with Local Accounts only  

Required: DeviceLogonEvents


## Description

Below query detects potential Lateral Movement that involves local accounts.  
Since valid accounts are used for Lateral Movement, it covers Valid Accounts technique as well.  
ATTENTION: You need to modify to query according to your environment.

**Query:**

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post: https://mergene.medium.com/hunting-for-lateral-movement-local-accounts-bc08742f3d83
//
//    How to use this query:
//    Set query time to 15d or 30d. Populate the DomainList below.
//    It is quite suspicious if a local account is used from a new source (espcially from a workstation)
//    If you want to see the results where there is no associated alert, change the value ShowResultsWithNoAlerts to 'YES'. Otherwise, set it to 'NO'.
//    
//    In an attack involving lateral movement or valid accounts, you might expect to see at least one alert related to either the source device, the destination device or the local account. 
//    Local accounts are expected to be used from specific devices. If the account was used from a new source device (IsSourcedUsedBefore=No), it may be anomalous.
//    
//    Explanations of the custom fields in the results:
//    IsSourceUsedBefore/IsTargetUsedBefore: if the acount has used Source/Target device before. 
//    AccountSourceCount/AccountTargetCount: Number of distinct Source/Target Devices that the account has used befor
//
let ShowResultsWithNoAlerts = "YES";
// Query parameters:
let lookback = 30d;
let timeframe = 1d;
// Generate building blocks
// Whitelisted alerts. (Some alerts may keep popping up as false positives)
let whitelisted_alerts = dynamic(["EICAR_Test_File"]);
// Exclude Domain logons
let DomainList = dynamic(["put your AD domain names here"]);
// 1. Generate list of Servers based on OSPlatform info
let server_list = 
    DeviceInfo
    | where Timestamp > ago(lookback)
    | where OSPlatform startswith "WindowsServer"
    | extend DeviceName=replace(@'([A-z0-9-]+)\..*', @'\1',DeviceName)
    | summarize make_set(DeviceName)
    ;
// 2. Generate list of Workstations based on OSPlatform info
let workstation_list = 
    DeviceInfo
    | where Timestamp > ago(lookback)
    | where OSPlatform == "Windows10"
    | extend DeviceName=replace(@'([A-z0-9-]+)\..*', @'\1',DeviceName)
    | summarize make_set(DeviceName)
    ;
// 3. Generate the logon baseline for each account separately
//    Baseline: devices(source and target) that the account was seen before
let baseline_data = 
    DeviceLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ActionType == "LogonSuccess"
    | where AccountDomain !in (DomainList)
    | where isnotempty(RemoteDeviceName)
    | extend DeviceName=replace(@'([A-z0-9-]+)\..*', @'\1',DeviceName)
    | summarize arg_max(Timestamp,*) by DeviceName, AccountName, AccountDomain, RemoteDeviceName, Protocol
    | summarize SourceDevices=make_set(RemoteDeviceName),TargetDevices=make_set(DeviceName) by AccountName
    ;
// Get Local account logons of last 1 day(assume all of them are suspicious) and enrich the results with account baseline info
let SuspiciousLogons = materialize  (
    DeviceLogonEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "LogonSuccess"
    | where AccountDomain !in (DomainList)
    | where isnotempty(RemoteDeviceName)
    | extend DeviceName=replace(@'([A-z0-9-]+)\..*', @'\1',DeviceName)
    | summarize arg_max(Timestamp,*) by DeviceName, AccountName, AccountDomain, RemoteDeviceName, Protocol // Get only the last logon
    // Enrich unusual logons with the baseline information and the building blocks
    | join kind=leftouter baseline_data on AccountName
    | extend IsSourceUsedBefore = iff(SourceDevices has RemoteDeviceName, 'Yes', 'No'), IsTargetUsedBefore = iff(TargetDevices has DeviceName , 'Yes', 'No'),
            SourceDeviceType = case(RemoteDeviceName in~ (workstation_list),'Workstation',RemoteDeviceName in~ (server_list), 'Server', 'Unknown'), TargetDeviceType = case(DeviceName in~ (workstation_list),'Workstation',DeviceName in~ (server_list), 'Server', 'Unknown'),
            AccountSourceCount=array_length(SourceDevices), AccountTargetCount=array_length(TargetDevices)
    | project-away SourceDevices, TargetDevices
    )
    ;
// Get all alerts of the Source/Target devices and accounts
let SourceDeviceList = SuspiciousLogons | extend RemoteDeviceName=replace(@'([A-z0-9-]+)\..*', @'\1',RemoteDeviceName) | summarize make_set(RemoteDeviceName);
let TargetDeviceList = SuspiciousLogons | extend DeviceName=replace(@'([A-z0-9-]+)\..*', @'\1',DeviceName)  | summarize make_set(DeviceName);
let LocalAccountList = SuspiciousLogons | summarize make_set(AccountName);
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
    | where AccountName in (LocalAccountList)
    | project AccountName, AlertId,Title, Severity
    | extend AlertDetails=pack('AlertId', AlertId, 'Title', Title, 'Severity', Severity)
    | summarize Alerts=make_set(AlertDetails) by AccountName
    | extend All=pack(AccountName,Alerts)
    | summarize make_bag(All)
    )
    ;
// Define function for getting all the alerts of a given entity(account)
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
    | extend DeviceName=replace(@'([A-z0-9-]+)\..*', @'\1',DeviceName)
    | where DeviceName in (SourceDeviceList) or DeviceName in (TargetDeviceList)
    | project DeviceName, AlertId,Title, Severity
    | extend AlertDetails=pack('AlertId', AlertId, 'Title', Title, 'Severity', Severity)
    | summarize Alerts=make_set(AlertDetails) by DeviceName
    | extend All=pack(DeviceName,Alerts)
    | summarize make_bag(All)
    )
    ;
// Define function for getting all the alerts of a given entity(device)
let GetDeviceAlerts = (entity:string) {
    toscalar(DeviceAlerts)[entity]
};
// Enrich the results with the alerts
SuspiciousLogons
// Get any alert info related to the source, Target or the identity(normal or Service account) and enrich the results. 
| extend SourceDeviceAlerts = GetDeviceAlerts(RemoteDeviceName), TargetDeviceAlerts = GetDeviceAlerts(DeviceName), LocalAccountAlerts = GetAccountAlerts(AccountName)
// Display the most important results. 
| where isnotempty(LocalAccountAlerts) or isnotempty(SourceDeviceAlerts) or isnotempty(TargetDeviceAlerts) or (IsSourceUsedBefore == "No" and ShowResultsWithNoAlerts == "YES")
// specific filter out conditions
// If there isn't any related alert and the account is known to be used from many sources, exclude it. no time to investigate. 
| where not (AccountSourceCount > 10 and isempty(LocalAccountAlerts) and isempty(SourceDeviceAlerts) and isempty(TargetDeviceAlerts))
| project-reorder Timestamp, DeviceName, SourceDeviceType, AccountName, RemoteDeviceName, TargetDeviceType, IsSourceUsedBefore, IsTargetUsedBefore, AccountSourceCount, AccountTargetCount, SourceDeviceAlerts, TargetDeviceAlerts, LocalAccountAlerts
```
