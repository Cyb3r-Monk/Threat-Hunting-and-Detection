# Potentially Relayed NTLM Authentication - Microsoft Sentinel

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-kerberos-relaying-e6be66fa647c)

Language: Azure KQL

Products: Microsoft Sentinel

Required: SecurityEvent (EID 4769 from DC, EID 4624 from servers)


## Description

The below query detects Kerberos logons of computer accounts where there isn't any ticket request in the last 12h (10h is the default ticket expiration) coming from the same IpAddress with the same TargetUserName. The query can be enriched further if needed.



## How to use the query
The delay between the DC logs and the server logs can be different and it can cause false positives. Consider analysing the logon events between last 1h and 5m or so (`TimeGenerated > ago(1h) and TimeGenerated < ago(5m)`)


**Query:**
---

```C#
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/detecting-kerberos-relaying-e6be66fa647c
//
// Description: This query detects Kerberos logons of computer accounts where there isn't any ticket request in the last 12h (10h is the default ticket expiration) coming from the same IpAddress with the same TargetUserName. The query can be enriched further if needed. 
//
// Query parameters:
//
let Ticket_Requests = materialize ( 
SecurityEvent
| where TimeGenerated > ago(12h)
| where EventID == 4769
| where EventData has '<Data Name="Status">0x0</Data>'
| where EventData !has'<Data Name="IpAddress">::1</Data>'
| parse EventData with * 'TargetUserName">' TargetUserName '</Data' * 'TargetDomainName">' TargetDomainName '</Data' * 'ServiceName">' ServiceName '<' * 'IpAddress">::ffff:' IpAddress '<' * 'Status">' Status '<' *
| where TargetUserName !has ServiceName
| where TargetUserName contains "$"
| where ServiceName has "$"
| project TimeGenerated, TargetUserName=tolower(TargetUserName), TargetDomainName, ServiceName=tolower(replace_string(ServiceName, '$', '')), IpAddress, Status
)
;
let Suspicious_Logons = 
    Ticket_Requests
    | join kind=rightanti (
        SecurityEvent
        | where TimeGenerated > ago(1h)
        | where EventID == 4624
        | where AuthenticationPackageName == "Kerberos"
        | where IpAddress !in ('-', '::1', '127.0.0.1')
        | where IpAddress !startswith "169.254."
        | where Account endswith_cs "$"
        | project TimeGenerated, Computer = tolower(replace_regex(Computer, @'(\w+)\..*', @'\1')), Account, TargetUserName=tolower(TargetUserName), IpAddress
        | where TargetUserName !has Computer
        ) on IpAddress, $left.ServiceName==$right.Computer
        ;
Suspicious_Logons
| join kind=leftouter  (
    Ticket_Requests
    | extend TargetUserName = replace_regex(TargetUserName, @'(\w+\$)@.*', @'\1')
    ) on IpAddress, TargetUserName
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), count(), dcount(ServiceName) by TargetUserName, IpAddress
// Filter results
// we don't expect a successful ticket request coming from the rogue(attacker) device befor the relaying attack.
// If there is at least one ticket request coming from the suspicious IP with the same TargetUserName, assume it's a legitimate activity.
| where isempty(dcount_ServiceName)
```