# Server Network Connection Anomalies
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

Language: Azure KQL
Products: MDATP/MDE/M365D,  Azure Sentinel (Sysmon)


## Description

Servers have a specific baseline. This makes it easy to create a baseline and detect anomalies.  
Below queries analyze the network connections made by the specified servers and detects the rare/anomalous ones.  
You can add process info to the analysis, but it will probably generate more results(different processes for the same IP). 


**Query for MDE/M365D :**

```C#
// Define servers you want to monitor. 
let Servers = dynamic(["server1","server2","etc."]);
// Get rare connections by RemoteIP and InitiatingProcessFileName
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName in (Servers) and ActionType == "ConnectionSuccess"
| where RemoteIPType !in ( "Private", "Loopback" )
| where RemoteIP !startswith "169.254."
| summarize make_set(RemoteUrl), count() by RemoteIP
| where count_ < 50
// Exclude traffic to known destinations.
| where not ( set_RemoteUrl has_any (".microsoft.com",".windowsupdate.com","login.microsoftonline.com","login.live.com","autodiscover-s.outlook.com","ocsp.digicert.com","ocsp.verisign.com","login.windows.net", "outlook.office365.com","accounts.accesscontrol.windows.net"))
// Get details of the connections that were made in the last 5 days.
// If you are going to check the results everyday, change the threshold to 1d. 
| join kind=inner
    (
    DeviceNetworkEvents
    | where Timestamp > ago(5d)
    | where DeviceName in (Servers) and ActionType == "ConnectionSuccess"
    | where RemoteIPType !in ( "Private", "Loopback" )
    | where RemoteIP !startswith "169.254."
    ) on RemoteIP
```

**Query for Azure Sentinel (Sysmon) :**

```C#
// Define servers you want to monitor. 
let Servers = dynamic(["server1","server2","etc."]);
// Get rare connections by DestinationIp
let _lookback = 30d;
let _timeframe = 5d;
let PrivateIPregex = @'^127\.|^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.';
// Parse Sysmon network connections and get only the ones towards the internet.
let parse_sysmon_id3 = (T:(TimeGenerated:datetime,EventID:int, Source:string,RenderedDescription:string, EventData:string))
{
T 
| where TimeGenerated > ago(_lookback)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key=tostring(['@Name']), Value=tostring(['#text'])
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)
| extend RuleName = column_ifexists("RuleName", ""), TechniqueId = column_ifexists("TechniqueId", ""),  TechniqueName = column_ifexists("TechniqueName", "")
| parse RuleName with * 'technique_id=' TechniqueId ',' * 'technique_name=' TechniqueName
// Filter connections towards the internet
| where not (DestinationIp matches regex PrivateIPregex)
};
// Get rare connections by DestinationIp
Event
| where TimeGenerated > ago(_lookback)
| where Computer in (Servers)
| invoke parse_sysmon_id3()
| summarize count() by DestinationIp
| where count_ < 50
// get details of the rare connections for further analysis.
| join kind=inner
    (
    Event
    | where TimeGenerated > ago(_timeframe)
    | where Computer in (Servers)
    | invoke parse_sysmon_id3()
    ) on DestinationIp
```
