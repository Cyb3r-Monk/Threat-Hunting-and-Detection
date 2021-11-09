# Suspicious Network Connections - Supply Chain Attack
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: Will be published later

Language: Azure KQL

Products: Microsoft 365 Defender / Microsoft Defender for Endpoint

Required: DeviceNetworkEvents, DeviceInfo


## Description

Below query detects unusual network conenctions from servers that have 3rd party software installed.  
You can further improve the query by using a list of servers that have privileges across the whole domain.



**Query:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Query parameters:
let lookback = 14d; 
// Generate list of all Servers
let server_list = 
    DeviceInfo
    | where Timestamp > ago(lookback)
    | where isnotempty(OSPlatform)
    | where DeviceType <> "Workstation" and OSPlatform <> "macOS"
    | summarize make_set(DeviceName)
    ;
// Generate list of servers that have 3rd party software installed.
// Criteria: if a software is installed on less than 10 servers, it's probably a 3rd party software.
// There are probably(hopefully) just a few servers or server groups that have privileges across the whole domain.
// You can change the threshold according to your environment.
let ServersWithThirdPartyApps = materialize (
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where DeviceName in (server_list)
    | where ActionType <> "ListeningConnectionCreated"
    | where RemoteIPType !in ("Private","Loopback") and (not (RemoteIPType == "FourToSixMapping" and RemoteIP startswith "::ffff:"))
    | summarize dcount(DeviceName) by InitiatingProcessVersionInfoCompanyName
    | where dcount_DeviceName < 10
    | join kind=inner (
        DeviceNetworkEvents
        | where Timestamp > ago(lookback)
        | where DeviceName in (server_list)
        | where ActionType <> "ListeningConnectionCreated"
        | where RemoteIPType !in ("Private","Loopback") and (not (RemoteIPType == "FourToSixMapping" and RemoteIP startswith "::ffff:"))
        )
        on InitiatingProcessVersionInfoCompanyName
        | summarize make_set(DeviceName)
        )
        ;
// Get network connection statistics
let baseline = materialize (
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where DeviceName in (ServersWithThirdPartyApps)
    | where ActionType <> "ListeningConnectionCreated"
    | where RemoteIPType !in ("Private","Loopback") and (not (RemoteIPType == "FourToSixMapping" and RemoteIP startswith "::ffff:"))
    | summarize hint.strategy=shuffle Count=count(), starttime = min(Timestamp), endtime = max(Timestamp) by DeviceName, RemoteIP, RemotePort
    )
    ;
// Get destination IP 
let Destinations = baseline | summarize make_set(RemoteIP);
// Filter connections that was not seen before last 1d 
// Generate prevalence info, URL info(if available) and enrich results
// Filter based on prevalence and URL information and display everything by hostname
baseline
| where starttime > ago(1d)
| lookup kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(5d)
    | where RemoteIP in (Destinations)
    | summarize hint.strategy=shuffle Prevalence = dcount(DeviceId), URLs=make_set(RemoteUrl) by RemoteIP
    )
    on RemoteIP
| where Prevalence < 6 or isempty( Prevalence)
// If you want to see all the events in distinct rows, remove the below 2 lines
// filter out results based on trusted URLs if you like. 
| extend Details = pack('RemoteIP',RemoteIP, 'RemotePort',RemotePort, 'Count',Count, 'Prevalence',Prevalence, 'URLs',URLs)
| summarize make_set(Details) by DeviceName
```
