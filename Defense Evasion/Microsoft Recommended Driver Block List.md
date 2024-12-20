# Microsoft Recommended Driver Block List

**Author:** Cyb3rMonk ( [Website](https://academy.bluraven.io), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

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