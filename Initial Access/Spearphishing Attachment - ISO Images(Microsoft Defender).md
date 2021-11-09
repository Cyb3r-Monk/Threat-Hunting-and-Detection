# Spearphishing Attachment: ISO Images
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Part-1 (Medium)](https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-1-c4f953edd13f?source=friends_link&sk=e685d7d44928edd142972a4041463f10), 
[Part-2 (Medium)](https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-2-f8dd600430e2?source=friends_link&sk=38b7cd310a4929c25d3eefc545683d5f)

Language: Azure KQL

Products: Microsoft 365 Defender / Microsoft Defender for Endpoint

Required: DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents 


## Description
ISO images are often meant to be used offline and they are often used by IT Admins and/or used on Servers.  
Installation from an iso file don't require network connection most of the time.
Activities deviating from these situations can be considered as highly suspicious.

Below queries detects opening a mounted image, process creation under a mounted image, and network connection from a process created under a mounted image.  
All detections can be used seperately or combined together to generate a higher fidelity alert.


**Detect opening of a mounted image:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post:
// Part-1: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-1-c4f953edd13f?source=friends_link&sk=e685d7d44928edd142972a4041463f10
// Part-2: https://mergene.medium.com/detecting-initial-access-html-smuggling-and-iso-images-part-2-f8dd600430e2?source=friends_link&sk=38b7cd310a4929c25d3eefc545683d5f
//
//
// Query parameters:
let lookback = 1h;
// Get ISO mount events
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName endswith ".iso.lnk" or FileName endswith ".img.lnk"
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
// Query parameters:
let lookback = 1h;
// Get mounted devices and extract the folder name
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where ActionType == "RegistryValueSet" and RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices" and RegistryValueName startswith @"\DosDevices\"
| extend Folder = toupper(replace(@'\\DosDevices\\(\w:)',@'\1',RegistryValueName)) // Extract the folder name
// Get process creations that have the mounted image as the FolderPath
| join kind=inner 
    (
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | extend Folder = toupper(replace(@'(\w:)\\.*',@'\1',FolderPath))
    ) on DeviceId, Folder
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
// Query parameters:
let lookback = 1h;
// Get mounted devices and extract the folder name
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where ActionType == "RegistryValueSet" and RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices" and RegistryValueName startswith @"\DosDevices\"
| extend Folder = toupper(replace(@'\\DosDevices\\(\w:)',@'\1',RegistryValueName)) // Extract the folder name
// Get network connections of processes that have the mounted image as the InitiatingProcessFolderPath
| join kind=inner 
    (
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | extend Folder = toupper(replace(@'(\w:)\\.*',@'\1',InitiatingProcessFolderPath))
    ) on DeviceId, Folder
// If needed, exclude the legitimate activity and servers
```
