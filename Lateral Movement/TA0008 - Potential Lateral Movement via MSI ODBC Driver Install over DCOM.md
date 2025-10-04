# Potential Lateral Movement via MSI ODBC Driver Install over DCOM

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [X](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Reference**: https://specterops.io/blog/2025/09/29/dcom-again-installing-trouble-lateral-movement-bof/

Language: Azure KQL

Products: Microsfot Defender XDR, Defender for Endpoint

Tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceImageLoadEvents


## Description
Detects Potential Lateral Movement via MSI Custom Actions to install ODBC Driver over DCOM remotely.

**Query:**

```KQL
// Description: Detect Potential Lateral Movement via MSI ODBC Driver Installer over DCOM
// Author: Cyb3rMonk(https://x.com/Cyb3rMonk)
// Website: https://academy.bluraven.io 
// Reference: https://specterops.io/blog/2025/09/29/dcom-again-installing-trouble-lateral-movement-bof/
//
DeviceProcessEvents
| where InitiatingProcessParentFileName == "services.exe"
| where InitiatingProcessFileName == "msiexec.exe"
| where FileName == "msiexec.exe"
| project DeviceId, DeviceName, ProcessUniqueId
| join kind=inner (
    DeviceNetworkEvents
    | where ActionType == "InboundConnectionAccepted"
    | where InitiatingProcessFileName == "msiexec.exe"
    | distinct DeviceId
    ) on DeviceId
    | join kind=inner 
        DeviceImageLoadEvents
        on DeviceId, DeviceName, $left.ProcessUniqueId == $right.InitiatingProcessUniqueId
| project-away DeviceId1, DeviceName1, DeviceId2
| project-reorder TimeGenerated, ActionType, DeviceId, DeviceName, FolderPath, InitiatingProcessFileName
```
