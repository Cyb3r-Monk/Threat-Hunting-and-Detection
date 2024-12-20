# Potential NTLM Relay Attack to Domain Controller

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-petitpotam-and-other-domain-controller-account-takeovers-d3364bd9ee0a)

Language: Azure KQL

Products: Microsoft Defender for Endpoint (MDE/M365D)

Required: DeviceLogonEvents


## Description

Below query detects NTLM authentication coming from Domain Controller machine accounts. This is not an expected behavior and it's an indication of NTLM relay attack.  
If NTLM Relaying is done towards a Linux machine, this query won't detect that. The attacker must have access to a Linux device in that case though.



## How to use the query
Populate the `DCs`(must be FQDN of the DCs) lists and run the query



**Query:**
---

```C#
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/detecting-petitpotam-and-other-domain-controller-account-takeovers-d3364bd9ee0a
//
// Description  : NTLM authentication coming from Domain Controller machine accounts. This is not an expected behavior and it's an indication of NTLM relay attack.   
//                If NTLM Relaying is done towards a Linux machine, this query won't detect that. The attacker must have access to a Linux device in that case though. 
//
// Query parameters:
//
// put FQDNs of the DCs into the list
let DCs = dynamic(["yourdc1.yourdomain.local","yourdc2.yourdomain.local"]);
DeviceLogonEvents
| where Protocol == "NTLM"
| where AccountName endswith "$"
| where DCs has replace_string(AccountName,"$","")
```
