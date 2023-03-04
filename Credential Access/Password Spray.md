# Password Spray

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk), [Mastodon](https://infosec.exchange/@cyb3rmonk) )


**Link to Original Post**: [Medium](https://posts.bluraven.io/advanced-kql-for-threat-hunting-window-functions-part-2-dce3e321f54b)

Language: Azure KQL

Products: Microsoft Sentinel, Defender for Endpoint

Required: SecurityEvent (Sentinel), DeviceLogon (MDE)


## Description

Below queries detect password spray attacks using sliding window count plugin. Because of implementation of the sliding window, queries work better than the bin() usage, but may create duplicate alerts. Grouping can be used in such cases.



**Sentinel Query:**
---

```Kusto
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/advanced-kql-for-threat-hunting-window-functions-part-2-dce3e321f54b
//
// Description  : Detect if there are more than 2 distinct users seen from the same IP in a 3h window.
//
// Query parameters:
//
let start = ago(12h);
let end = now();
let lookbackWindow = 3h;
let bin = 1h;
let threshold = 2;
SecurityEvent
| where EventID in (4624, 4625)
| where IpAddress !in ("127.0.0.1", "::1", "-")
| evaluate sliding_window_counts(TargetUserName, TimeGenerated, start, end, lookbackWindow, bin, IpAddress)
| sort by IpAddress, TimeGenerated asc
| where Dcount >= 2
```

**MDE Query:**
---

```Kusto
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/advanced-kql-for-threat-hunting-window-functions-part-2-dce3e321f54b
//
// Description  : Detect if there are more than 2 distinct users seen from the same IP in a 3h window.
//
// Query parameters:
//
let start = ago(12h);
let end = now();
let lookbackWindow = 3h;
let bin = 1h;
let threshold = 2;
DeviceLogonEvents
| where Timestamp > ago(lookbackWindow)
| where RemoteIP !in ("127.0.0.1","::1","-") and isnotempty(RemoteIP)
| evaluate sliding_window_counts(AccountName, Timestamp, start, end, lookbackWindow, bin, RemoteIP)
| where Dcount > threshold
```
