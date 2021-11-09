# Spearphishing Attachment: ISO Images
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Part-1 (Medium)](https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-1-c4f953edd13f?source=friends_link&sk=e685d7d44928edd142972a4041463f10), 
[Part-2 (Medium)](https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-2-f8dd600430e2?source=friends_link&sk=38b7cd310a4929c25d3eefc545683d5f)

Language: Azure KQL

Products: Azure Sentinel

Required: Sysmon logs


## Description
ISO images are often meant to be used offline and they are often used by IT Admins and/or used on Servers.  
Installation from an iso file don't require network connection most of the time.
Activities deviating from these situations can be considered as highly suspicious.

Below queries detects opening a mounted image, process creation under a mounted image, and network connection from a process created under a mounted image.  
All detections can be used seperately or combined together to generate a higher fidelity alert.

WARNING: Check your Sysmon parsing functions and verify you have the logs. Using "Rendered Description" field for parsing causes parsing issues for registry events.


**Detect opening of a mounted image:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post:
// Part-1: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-1-c4f953edd13f?source=friends_link&sk=e685d7d44928edd142972a4041463f10
// Part-2: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-2-f8dd600430e2?source=friends_link&sk=38b7cd310a4929c25d3eefc545683d5f
//
//
let parse_sysmon_events = (T:(TimeGenerated:datetime,EventID:int, Source:string, EventData:string))
{
T 
| where Source == "Microsoft-Windows-Sysmon"
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key=tostring(['@Name']), Value=['#text']
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)
};
// Query Parameters
let lookback = 2h;
Event
| where TimeGenerated > ago(lookback)
| where EventID == 11
| invoke parse_sysmon_events()
| where tostring(TargetFilename) endswith ".iso.lnk" or tostring(TargetFilename) endswith ".img.lnk"
// Exclude servers and workstation used by IT admins if needed.

```

**Detect process creation under a mounted image:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post:
// Part-1: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-1-c4f953edd13f?source=friends_link&sk=e685d7d44928edd142972a4041463f10
// Part-2: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-2-f8dd600430e2?source=friends_link&sk=38b7cd310a4929c25d3eefc545683d5f
//
//
let parse_sysmon_events = (T:(TimeGenerated:datetime,EventID:int, Source:string, EventData:string))
{
T 
| where Source == "Microsoft-Windows-Sysmon"
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key=tostring(['@Name']), Value=['#text']
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)
};
// Query Parameters
let lookback = 2h;
Event
| where TimeGenerated > ago(lookback)
| where EventID == 13
| invoke parse_sysmon_events()
| where TargetObject startswith @"HKLM\SYSTEM\MountedDevices\\DosDevices"
| extend Folder = replace(@'.*\\([A-Z]:)',@'\1\\',tostring(TargetObject))
| join kind = inner 
    (
    Event
    | where TimeGenerated > ago(lookback)
    | where EventID == 1
    | invoke parse_sysmon_events()
    | extend Folder = tostring(CurrentDirectory)
    ) on Computer, Folder
// If needed, exclude servers from the results.
```

**Detect network connection from a process created under a mounted image:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post:
// Part-1: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-1-c4f953edd13f?source=friends_link&sk=e685d7d44928edd142972a4041463f10
// Part-2: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-2-f8dd600430e2?source=friends_link&sk=38b7cd310a4929c25d3eefc545683d5f
//
//
let parse_sysmon_events = (T:(TimeGenerated:datetime,EventID:int, Source:string, EventData:string))
{
T 
| where Source == "Microsoft-Windows-Sysmon"
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key=tostring(['@Name']), Value=['#text']
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)
};
// Query Parameters
let lookback = 30h;
Event
| where TimeGenerated > ago(lookback)
| where EventID == 13
| invoke parse_sysmon_events()
| where TargetObject startswith @"HKLM\SYSTEM\MountedDevices\\DosDevices"
| extend Folder = replace(@'.*\\([A-Z]:)',@'\1\\',tostring(TargetObject))
| join kind = inner 
    (
    Event
    | where TimeGenerated > ago(lookback)
    | where EventID == 3
    | invoke parse_sysmon_events()
    | extend Folder = replace(@'^([A-Z]:\\).*',@'\1',tostring(Image))
    ) on Computer, Folder
// If needed, exclude the legitimate activity and servers
```
