# Silent Enabling of Chrome DevTools Protocol

**Author:** Cyb3rMonk ( [Website](https://academy.bluraven.io), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

Language: Kusto Query Language (KQL)

Products: Microsoft Sentinel / Defender XDR

Tables  : DeviceNetworkEvents


## Description

[CDP-Enable-BOF](https://github.com/KingOfTheNOPs/CDP-Enable-BOF) enables Chrome DevTools Protocol by injecting code into the main browser process that hasn't started with the  `--remote-debugging-port`. This enables access to the current user's cookies and credential data without triggering any EDR detections that often monitors the `--remote-debugging-port` command line parameter.  

The query below detects when a Chrome/Edge process that doesn't have the `--remote-debugging-port` parameter in its command line creates a listening port (remote debugging port). This behavior is normal when chromedriver/msedgedriver starts Chrome/Edge (used in automation workflows). 

## References 
- https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/
- https://github.com/KingOfTheNOPs/CDP-Enable-BOF




**Query:**
---

```KQL
// Description: detects when a Chrome/Edge process that doesn't have the `--remote-debugging-port` parameter in its command line creates a listening port (remote debugging port)
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://academy.bluraven.io)
//
// Query Parameters
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe") and InitiatingProcessCommandLine !has "--remote-debugging-port"
| where InitiatingProcessParentFileName !in~ ("chromedriver.exe", "msedgedriver.exe")
```