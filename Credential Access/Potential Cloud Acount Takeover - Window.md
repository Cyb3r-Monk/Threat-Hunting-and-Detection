# Potential Cloud Account Takeover - Window Function

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk), [Mastodon](https://infosec.exchange/@cyb3rmonk) )


**Link to Original Post**: [Medium](https://posts.bluraven.io/advanced-kql-for-threat-hunting-window-functions-part-1-14ac09353ad3)

Language: Azure KQL

Products: Microsoft Sentinel

Required: SigninLogs, AADNonInteractiveUserSignInLogs


## Description

Below query detects if a user signs in from an IP address that has not been observed in the last X days AND the sign-in happens in close proximity of the user's latest sign-in time. The query uses window functions.



**Query:**
---

```C#
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/advanced-kql-for-threat-hunting-window-functions-part-1-14ac09353ad3
//
// Description  : Detect if a user signs in from an IP address that has not been observed in the last X days AND the sign-in happens in close proximity of the user's latest sign-in time. It's an indication of account takeover
//
// Query parameters:
//
let query_period = 1d;
let look_back = 14d;
let knownIPs =
    union SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (ago(look_back) .. ago(query_period))
    | summarize ObservedIPsOfUPN = make_set(IPAddress) by UserPrincipalName
    ;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(query_period)
| sort by  UserPrincipalName asc, TimeGenerated asc
| extend PrevUserPrincipleName = iff(prev(UserPrincipalName) != UserPrincipalName, 'FirstTimeSeen', prev(UserPrincipalName))
| extend TimeDiffInSeconds = iff(prev(UserPrincipalName) == UserPrincipalName, datetime_diff('second', TimeGenerated, prev(TimeGenerated)), -1)
| sort by UserPrincipalName asc, AppId asc, TimeGenerated asc
| extend PrevAppId = case(PrevUserPrincipleName == 'FirstTimeSeen', 'FirstTimeSeen', PrevUserPrincipleName == UserPrincipalName and prev(AppId) != AppId, 'FirstTimeSeen', prev(AppId))
| extend PrevIPAddress = case(PrevUserPrincipleName == 'FirstTimeSeen', 'FirstTimeSeen',
                              PrevUserPrincipleName == UserPrincipalName and PrevAppId == 'FirstTimeSeen', 'FirstTimeSeen',
                              prev(IPAddress))
| lookup kind=leftouter knownIPs on UserPrincipalName
| extend Risk_Score = case(IPAddress == PrevIPAddress, 0,
                           PrevIPAddress == 'FirstTimeSeen' and ObservedIPsOfUPN has IPAddress, 1,
                           PrevIPAddress != 'FirstTimeSeen' and ObservedIPsOfUPN has IPAddress, 2,
                           PrevIPAddress == 'FirstTimeSeen' and ObservedIPsOfUPN !has IPAddress, 3,
                           PrevIPAddress != 'FirstTimeSeen' and ObservedIPsOfUPN !has IPAddress, 4,
                           99)
| where Risk_Score > 2
| project-reorder TimeGenerated, TimeDiffInSeconds, UserPrincipalName, PrevUserPrincipleName, AppDisplayName, AppId, PrevAppId, IPAddress, PrevIPAddress, Risk_Score, ObservedIPsOfUPN
| sort by UserPrincipalName asc, TimeGenerated asc
```
