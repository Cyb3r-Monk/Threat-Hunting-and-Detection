# ShieldBreak: Defender AV Privilege Escalation  

**Author:** Cyb3rMonk ( [Website](https://academy.bluraven.io), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

Language: Kusto Query Language (KQL)

Products: Microsoft Sentinel / Defender XDR

Tables  : DeviceProcessEvents


## Description

The query below detects processes created with System-level integrity by `wermgr.exe`. DLLs loaded during the exploitation is not recorded in MDE for some reason (filtering/sampling). That's why process creation chain is more reliable.

## References 
- [ShieldBreak](https://github.com/MSNightmare/ShieldBreak)




**Query:**
---

```KQL
// Description: detects processes created with System-level integrity by wermgr.exe 
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://academy.bluraven.io)
//
// Query Parameters
DeviceProcessEvents
| where 
    (InitiatingProcessFileName =~ "wermgr.exe" and ProcessIntegrityLevel =~ "System") or 
    (InitiatingProcessParentFileName =~ "wermgr.exe" and ProcessIntegrityLevel =~ "System")
```