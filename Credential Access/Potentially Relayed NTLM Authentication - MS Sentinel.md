# Potentially Relayed NTLM Authentication - Microsoft Sentinel

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-ntlm-relay-attacks-d92e99e68fb9)

Language: Azure KQL

Products: Microsoft Sentinel

Required: SecurityEvent (machine and user logon events)


## Description

The below query detects NTLM logons where Network Address in the logon event doesn't match the Workstation Name's IP. This indicates potentially relayed NTLM authentication. It analyzes only the logons with domain accounts having admin privileges.



## How to use the query
Populate the `domains` and `SNAT_Subnets` lists accordingly and run the query. If you want to create an analytic rule, take `rule_frequency` and `lookback` parameters into account for handling ingestion delays.



**Query:**
---

```C#
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/detecting-ntlm-relay-attacks-d92e99e68fb9
//
// Description: This query detects NTLM logons where Network Address in the NTLM logon event doesn't match the Workstation Name's IP. 
//				      This indicates potentially relayed NTLM authentication. The query analyzes only the logons with domain accounts having admin privileges. 
//
// Query parameters:
//
let ingestion_delay = 2h;
let rule_frequency = 2h;
let lookback = 1d;
// Specify domains in NETBIOS name and full domain format
let domains = dynamic(["PUT YOUR AD DOMAINS HERE!", "contoso","contoso.local"]);
// Exclude authentications coming from  device performing SNAT.
// Exclude devices that always perform NTLM authentication
let SNAT_Subnets = datatable (subnet: string) [
    "1.0.0.0/26", "1.1.1.1/32"
];
// Get NTLM relay candidates
let NTLMRelayCandidates = materialize ( 
    SecurityEvent
    | where TimeGenerated > ago(rule_frequency + ingestion_delay)
    | where EventID == 4624
    | where AccountType == "User"
    | where AuthenticationPackageName == "NTLM"
    | where LogonType == 3
    | where TargetDomainName in~ (domains)
    | where isnotempty(IpAddress) and IpAddress !in ('-', '::1', '127.0.0.1')
    | where isnotempty(WorkstationName) and WorkstationName <> '-'
    | where IpPort <> 0 and Computer !has WorkstationName
    | where ElevatedToken <> '%%1843'// exclude non-admin logon sessions
    | extend delay = ingestion_time() - TimeGenerated
    | summarize hint.strategy=shuffle arg_max(TimeGenerated, *) by Computer, Account, IpAddress, WorkstationName
    // Machine logon events have the IP address of the machine, exclude results where the IPAddress in the NTLM logon matches the IPAddress in Machine logon event
    | join hint.strategy=shuffle kind=leftanti 
        (
        SecurityEvent
        | where TimeGenerated > ago(lookback)
        | where EventID == 4624
        | where AccountType == "Machine"
        | where isnotempty(IpAddress) and IpAddress !in ('-', '::1', '127.0.0.1')
        | distinct TargetUserName, IpAddress
        | extend TargetUserName = toupper(replace(@'([A-z0-9-]+)\.?.*', @'\1', TargetUserName))
        )
        on $left.WorkstationName == $right.TargetUserName, IpAddress // filter condition
        // Filter out excluded IP subnets.
        | evaluate ipv4_lookup(SNAT_Subnets, IpAddress, subnet, return_unmatched = true)
        | where isempty(subnet) // remove results that matched a SNAT subnet.
    )
;
// Windows 2012 doesn't have elevated token info in NTLM logon events.
// Filter relayed authentications where the session has admin privileges
let Computers=
    NTLMRelayCandidates| summarize make_set(Computer);
//
let Accounts = 
    NTLMRelayCandidates| summarize make_set(TargetUserName);
// There must be a 4672 event for an admin logon with the same logon id
NTLMRelayCandidates
| join hint.strategy=shuffle kind=inner 
    (
    SecurityEvent
    | where TimeGenerated > ago(rule_frequency + ingestion_delay) 
    | where Computer in (Computers)
    | where SubjectUserName in (Accounts)
    | where EventID == 4672
    | where AccountType == "User"
    | project Computer, Account, SubjectLogonId, PrivilegeList
    )
    on $left.TargetLogonId==$right.SubjectLogonId, Account, Computer
| extend Origin = WorkstationName, RelayingDeviceIP = IpAddress, Target = Computer
| project-reorder TimeGenerated, Computer, Origin, RelayingDeviceIP, Target, Account, PrivilegeList1
// more filtering can be done based on the privilege list, specific computers or accounts.
```
