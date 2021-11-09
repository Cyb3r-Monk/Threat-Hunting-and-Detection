# Potentially Relayed NTLM Authentication - Microsoft Defender for Endpoint

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )


**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-ntlm-relay-attacks-d92e99e68fb9)

Language: Azure KQL

Products: Microsoft Defender for Endpoint (MDE/M365D)

Required: DeviceLogonEvents, DeviceInfo,  (machine and user logon events)

**!!! Important !!!:** If you have Windows Server 2012 in your environment, you may need to use the new MDE agents. The old agents that use the OMS agent don't log NTLM logons properly.


## Description

The below query detects NTLM logons where Network Address in the logon event doesn't match the Workstation Name's IP. This indicates potentially relayed NTLM authentication. It analyzes only the logons with domain accounts having admin privileges.



## How to use the query
Populate the `domains` and `SNAT_Subnets` lists accordingly and run the query.



**Query:**
---

```C#
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/detecting-ntlm-relay-attacks-d92e99e68fb9
//
// Description: This query detects NTLM logons where RemoteIP in the logon event doesn't match the RemoteDevice's IP. 
//				      This indicates potentially relayed NTLM authentication. The query analyzes only the logons with domain accounts having admin privileges. 
//
// Query parameters:
//
let lookup_window = 24h;
let baseline_window = 7d;
// Specify domains in NETBIOS name and full domain format
let domains = dynamic(["PUT YOUR AD DOMAINS HERE!", "contoso","contoso.local"]);
// Exclude authentications coming from  device performing SNAT.
let SNAT_Subnets = datatable (subnet:string)
[
"1.0.0.0/26", "1.1.1.1/32"
];
// Generate list of all known(enrolled) Devices
let all_devices = toscalar (
    DeviceInfo
    | where Timestamp > ago(baseline_window)
    | summarize make_set(DeviceName)
    );
// Create a baseline for known NTLM authentication events.
// This will be used for removing the potential false positives.
let baseline = materialize (
    DeviceLogonEvents
    | where Timestamp > ago(baseline_window) and Timestamp < ago(lookup_window)
    | where ActionType == "LogonSuccess"
    | where LogonType == "Network"
    | where Protocol=="NTLM"
    | where isnotempty(RemoteDeviceName) and isnotempty(RemoteIP)
    | where RemoteIPType <> "Loopback"
    | where AdditionalFields !has '{"IsLocalLogon":true}' // exclude local(interactive) logon
    | where AccountName !has RemoteDeviceName // exclude computer account logon
    | where AccountDomain in~ (domains) // get only the logons with domain accounts
    | distinct DeviceName, RemoteDeviceName, AccountName, RemoteIP
    );
// Generate list of servers (assuming NTLM relay is performed towards servers)
let servers = materialize (
    DeviceInfo
    | where Timestamp > ago(baseline_window)
    | where DeviceType == "Server"
    | summarize make_set(DeviceName)
    );
// Get logons to servers with LocalAdmin rights
DeviceLogonEvents
| where Timestamp > ago(lookup_window)
| where ActionType == "LogonSuccess"
| where DeviceName in (servers)
| where LogonType == "Network"
| where IsLocalAdmin == 1
| project TimestampX=Timestamp, DeviceIdX=DeviceId, DeviceName,AccountName,IsLocalAdmin
// Join LocalAdmin logons with NTLM logons. LocalAdmin logon events don't have logonID, Protocol, etc.,
// use time window join. 
| join kind=inner 
    (
    DeviceLogonEvents
    | where Timestamp > ago(lookup_window)
    | where ActionType == "LogonSuccess"
    | where LogonType == "Network"
    | where Protocol=="NTLM"
    | where isnotempty(RemoteDeviceName) and isnotempty(RemoteIP)
    | where RemoteIPType <> "Loopback"
    | where AdditionalFields !has '{"IsLocalLogon":true}' // exclude local(interactive) logon
    | where AccountName !has RemoteDeviceName // exclude computer account logon
    | where AccountDomain in~ (domains) // get only the logons with domain accounts
    )
    on $left.DeviceIdX==$right.DeviceId, AccountName 
| where abs(datetime_diff('second', Timestamp, TimestampX)) < 15 // time window condition
| summarize arg_max(Timestamp,*) by DeviceId, LogonId // get last event for each logonID
// Filter logons that are not in the baseline(unknown/new logons)
| join kind=leftanti baseline on DeviceName, RemoteDeviceName, AccountName, RemoteIP
// Filter events where there is no corresponding IP address for the RemoteDeviceName
| join kind=leftanti 
    (
    DeviceNetworkInfo
    | where Timestamp > ago(lookup_window)
    | mv-expand todynamic(IPAddresses)
    | extend DvcIP = tostring(IPAddresses.IPAddress)
    | summarize arg_max(Timestamp,*) by DeviceId, DvcIP // get last report event for each IP
    | project DeviceId, DeviceName=replace(@'([A-z0-9-]+)\.?.*',@'\1',DeviceName), ReportTimestamp = Timestamp, DvcIP, IPAddresses
    )
    on $left.RemoteDeviceName==$right.DeviceName, $left.RemoteIP==$right.DvcIP // filter condition
// Get last logon event (remove duplication)
| summarize arg_max(Timestamp,*), count() by DeviceId, AccountName, RemoteDeviceName, RemoteIP
// Get only the logons originated from a known(enrolled) device.
| where all_devices has RemoteDeviceName
// Exclude SNAT subnets
// ipv4 lookup doesn't have notmatch condition. 
| evaluate ipv4_lookup(SNAT_Subnets, RemoteIP, subnet, return_unmatched = true)
| where isempty(subnet) // remove results that matched a SNAT subnet.
| extend Origin = RemoteDeviceName, RelayingDeviceIP = RemoteIP, Target = DeviceName
| project-away TimestampX, DeviceIdX, AccountName1, DeviceName1
| project-reorder Timestamp, Origin, RelayingDeviceIP, Target, AccountName
```
