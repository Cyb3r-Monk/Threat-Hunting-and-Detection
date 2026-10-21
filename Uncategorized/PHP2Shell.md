# Detection Opportunities for PHP2Shell (CVE-2026-54121)

**Author:** Cyb3rMonk ( [Website](https://academy.bluraven.io), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

Language: Kusto Query Language (KQL)


### NOTE
The query focuses on PHP processes. You should already be monitoring for Web Shell attacks. 

### Newly observed PHP process activities
Broad hunting query for newly observed PHP process activities

```KQL
// Description: Broad hunting query for newly observed PHP process activities
//              Add additional exclusions based on your environment
//
search in (Device*Events) InitiatingProcessFileName:"php*" and TimeGenerated > ago(14d)
| where not (ActionType startswith "File" and FileName !endswith ".php")
| where not (ActionType startswith "Image" and FileName endswith ".dll")
| where not (RemoteIP in ("::1", "127.0.0.1"))
| where not (ProcessCommandLine == "conhost.exe 0xffffffff -ForceV1")
| summarize 
    FirstSeen = min(TimeGenerated) 
    by DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine,
       RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| where FirstSeen >= ago(24h)
```

