# Rouge RDP: Suspicious File Creation

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk), [Website](https://academy.bluraven.io) )



Language: KQL

Products: MDE/M365D

Tables  : DeviceNetworkEvents, DeviceFileEvents

Technique(s):
- T1556:	Phishing

## References
- https://cert.gov.ua/article/6281076
- https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/

## Description

Below query detects file creations of `mstsc.exe` where it also makes a network connection to a public IP address. This behavior is an indication of Rogue RDP.  
**False Positives:** Copying files to the local machine over RDP may cause false positives.




**Query:**
---

```KQL
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Description: Detect file creations of mstsc.exe where it also makes a network connection to a public IP address. This behavior is an indication of Rogue RDP. 
//
// Query parameters:
// there might be more file types that can be leveraged
// adjust file types to monitor
// consider DLL sideloading opportunities if you want to filter based on folders.
let file_types = dynamic([".dll", ".exe", ".cpl", ".pif", ".com", ".js", ".vbs", ".wsh", ".vbe", ".jse", ".bat", ".cmd", ".lnk", ".url", ".png", ".hta", ".svg"]);
let _query_period = 7d;
DeviceNetworkEvents
| where Timestamp > ago(_query_period)
| where ActionType in ("ConnectionSuccess")
| where InitiatingProcessFileName =~ "mstsc.exe"
| where RemoteIPType == "Public"
| project Timestamp, DeviceId, DeviceName, InitiatingProcessFileName=tolower(InitiatingProcessFileName), InitiatingProcessId, RemoteIP, RemoteUrl, RemotePort, NetworkTimestamp = Timestamp
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(_query_period)
    | where ActionType in ("FileCreated", "FileModified")
    | where InitiatingProcessFileName =~ "mstsc.exe" 
    | where FileName has_any (file_types)
    | extend InitiatingProcessFileName=tolower(InitiatingProcessFileName), FileTimestamp = Timestamp
    ) on InitiatingProcessFileName, DeviceId // InitiatingProcessId or InitiatingProcessUniqueId can be used as well but be mindful of multiple connections and telemetry sampling.
    // adjust time between RDP connection and file creation
    | where datetime_diff('minute', FileTimestamp, NetworkTimestamp) < 60
```
