# Microsoft Recommended Driver Block List

**Author:** Cyb3rMonk ( [Website](https://academy.bluraven.io), [Twitter](https://twitter.com/Cyb3rMonk) )


Language: Azure KQL

Products: MDE/M365D

Tables  : DeviceEvents, DeviceFileEvents


## Description

The query below detects loading or creation of a vulnerable driver that is listed in the Microsoft recommended driver block rules. 



**Query:**
---

```KQL
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://academy.bluraven.io)
//
// Query parameters:
let driver_block_list = externaldata (line:string) [@"https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md"]
    with (format=txt)
| parse-where line with * 'FriendlyName="' FriendlyName ' Hash' * 'Hash="' Hash '"' * 
| project FriendlyName, HashType = iff(line has "Sha1", "SHA1", "SHA256"), HashValue=Hash
;
let driver_hashes = toscalar(
    driver_block_list
    | summarize make_set(HashValue)
    )
;
union 
    (
        DeviceEvents
        | where ActionType == "DriverLoad"
        | where SHA1 in~ (driver_hashes) or SHA256 in~ (driver_hashes)
    ),
    (
        DeviceFileEvents
        | where SHA1 in~ (driver_hashes) or SHA256 in~ (driver_hashes)
    )
```