# Suspicious TGT Request with a DC Account
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-petitpotam-and-other-domain-controller-account-takeovers-d3364bd9ee0a)

Language: Azure KQL

Products: Azure Sentinel

Required: SecurityEvent


## Description

Below query detects TGT requests from a DC account with an IP that doesn't belong to a DC. It detect PetitPotam and any other attacks that uses a stolen DC certificate/account to perform operations.   
If you make it a detection rule, take ingestion delay into account. 



## How to use the query
Populate the lists `DCs`(must be FQDN of the DCs) and `DC_IPs`(both IPv4 and IPv6) and run the query



**Query:**
---

```C#
// Author       : Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Link to original post:
// https://posts.bluraven.io/detecting-petitpotam-and-other-domain-controller-account-takeovers-d3364bd9ee0a
//
// Description  : This query detects if a computer account of a Domain Controller is stolen and used from a Non-DC device. 
//                computer account of a DC can bu used to obtain a TGT.
//
// Query parameters:
//
// list of DCs
let DCs = dynamic(["yourdc1.yourdomain.local"]);
// list of DC IPs
let DC_IPs = dynamic(["IP of the DCs including IPv6 addresses"]);
//
SecurityEvent
| where EventID == 4768
| where Computer in~ (DCs)
| where TargetUserName endswith "$"
| where DCs has replace_string(TargetUserName,"$","")
| where IpAddress <> "::1"
| extend IpAddress = replace_string(IpAddress, "::ffff:", "")
| where IpAddress !in (DC_IPs)
| project-reorder Computer, TargetUserName, IpAddress
```
