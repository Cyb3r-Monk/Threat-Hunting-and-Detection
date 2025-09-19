# Potential Actor Token Abuse In Entra ID

**Author:** Cyb3rMonk ( [Website](https://academy.bluraven.io), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

Language: Kusto Query Language (KQL)

Products: Microsoft Sentinel / Defender XDR

Tables  : AuditLogs


## Description

The query below detects activities where Actoken Token is used but the activity doesn't originate from Microsoft 365 IP addresses. Service to Service (S2S) operations are expected to originate from Microsoft IP addresses. 

> [!WARNING]  
> You may still see some false positives where the IP address belongs to your environment.

## References 
- [CVE-2025-55241](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55241)
- https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/




**Query:**
---

```KQL
// Description: Detect any activity that uses Actor Token and doesn't originate from Microsoft IP (S2S oprations should originate from Microsfot IP). 
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://academy.bluraven.io)
//
// Query Parameters
let M365IPRanges = toscalar ( externaldata (all:dynamic) ["https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"]
    with (format=multijson, ingestionMapping='[{"Column":"all", "Properties":{"Path":"$"}}]')
| evaluate bag_unpack(all)
| mv-expand IPSubnet = ips to typeof(string)
| where isnotempty(IPSubnet)
| project IPSubnet
| summarize make_set(IPSubnet)
)
;
AuditLogs
| where TimeGenerated > ago(30d)
| where InitiatedBy has "user"
| where isnotempty(InitiatedBy.user.ipAddress)
| where isnotempty(InitiatedBy.user.userPrincipalName) // remove this if you want to see operations not having UPN (for hunting purposes)
| where InitiatedBy.user.displayName has_any ( "Office 365 Exchange Online", "Skype for Business Online", "Dataverse", "Office 365 SharePoint Online", "Microsoft Dynamics ERP")
| extend ActivityIPAddress = tostring(InitiatedBy.user.ipAddress), Service = tostring(InitiatedBy.user.displayName), UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| where not (ipv4_is_in_any_range(ActivityIPAddress, M365IPRanges) or ipv6_is_in_any_range(ActivityIPAddress, M365IPRanges))
| project-reorder TimeGenerated, Service, UserPrincipalName, ActivityIPAddress, OperationName
```