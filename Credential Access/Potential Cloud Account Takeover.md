# Potential Cloud Account Takeover

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk), [Mastodon](https://infosec.exchange/@cyb3rmonk) )


**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-azure-ad-account-takeover-attacks-b2652bb65a4c)

Language: Azure KQL

Products: Microsoft Sentinel

Required: SigninLogs, AADNonInteractiveUserSignInLogs


## Description

Below query detects if a user signs in from an IP address that has not been observed in the last X days AND the sign-in happens in close proximity of the user's latest sign-in time.



**Query:**
---

```C#
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/detecting-azure-ad-account-takeover-attacks-b2652bb65a4c
//
// Description  : Detect if a user signs in from an IP address that has not been observed in the last X days AND the sign-in happens in close proximity of the user's latest sign-in time. It's an indication of account takeover
//
// Query parameters:
//
let query_period = 3h; // change it according to your needs
let look_back = 14d;
let SuspiciousUPNs =
    union SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(query_period)
    | summarize dcount(IPAddress) by UserPrincipalName
    | where dcount_IPAddress > 1
    ;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(look_back)
| where UserPrincipalName in (SuspiciousUPNs)
| summarize arg_min(TimeGenerated, *), LastSeen = max(TimeGenerated), count(), SigninTypes = make_set(Category), AppsUsed = make_set(AppDisplayName), AppCount = dcount(AppId) by UserPrincipalName, IPAddress
| lookup kind=leftouter SuspiciousUPNs on UserPrincipalName
| where dcount_IPAddress > 1
| where TimeGenerated > ago(query_period)
| project-reorder TimeGenerated, LastSeen, UserPrincipalName, dcount_IPAddress, AppCount, AppsUsed, SigninTypes
```
