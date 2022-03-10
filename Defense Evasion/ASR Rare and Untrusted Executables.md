# ASR Rare and Untrusted Executables

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )


Language: Azure KQL

Products: MDE/M365D

Tables  : DeviceEvents, DeviceFileCertificateInfo


## Description

Below query shows Untrusted executables that are seen on few devices (LocalPrevalence). It requires the below ASR rule to be configured and Cloud-delivered protection to be enabled.  
[Block executable files from running unless they meet a prevalence, age, or trusted list criterion](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion)  

You may need to exclude software development users/machines/folders. 


**Query:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Query parameters:
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("AsrUntrustedExecutableAudited","AsrUntrustedExecutableBlocked")
| summarize arg_min(Timestamp,*), LocalPrevalence = dcount(DeviceId) by SHA1, FileName
| where Timestamp > ago(1d)
| where LocalPrevalence <= 5
// there might be files without signature info, perform leftouter join
| join kind=leftouter (
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp,*) by SHA1
    )
    on SHA1
// Get GlobalPrevalence info, etc.
| invoke FileProfile(SHA1, 1000)
// GlobalFirstSeen can be used for filtering the results further
// If you want to list only the files that have invalid signatures uncomment the below line
// there might be files without signature info, don't exclude them
// | where IsTrusted <> 1
```