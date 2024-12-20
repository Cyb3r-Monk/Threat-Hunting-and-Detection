# T1566.002 Spearphishing Link - Rare URL Clicks
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Original Post**: [Medium](https://posts.bluraven.io/hunting-for-phishing-links-using-sysmon-and-kql-e87d1118ce5e)

Language: Azure KQL

Products: Azure Sentinel

Required: Sysmon process Events.
 

## Description

Below query analyzes URLs that are opened from applications like Outlook, Word, Excel, Powerpoint, and Adobe PDF apps. It finds rare URLs that might be a phishing attempt.  
It is strongly recommended to enrich results with prevalence information using firewall or proxy logs.  You can reduce the noise by filtering specific parent processes according to your needs.  
  
You can further improve the results using logic apps or scripting to get extra information about the URL(age, certificate, VT score etc.)
  
  
Keep in mind that there ways to bypass controls by hosting the phishing links inside a document stored in the cloud. You don't have any visibility with Sysmon in this scenario.

**Query:**

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post:
// https://posts.bluraven.io/hunting-for-phishing-links-using-sysmon-and-kql-e87d1118ce5e
//
//
// Query parameters:
// Define how manys days of data you want to analyze.
// Consider covering weekends
let lookback = 3d;
// Define how many user might receive the same phishing URL(based on URL or URLHost).
let PhishingTargetMax = 5;
// Get all URLs that were clicked
let PotentialPhishingLinks = materialize ( 
    Event
    | where TimeGenerated > ago(lookback)
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 1
    // Get only the relevant events to improve the query performance during parsing
    | where RenderedDescription has_any ("http://", "https://") and RenderedDescription has_any ("msedge.exe", "chrome.exe", "firefox.exe","brave.exe")
    | extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
    | extend EventData = parse_xml(EventData).DataItem.EventData.Data
    | mv-expand bagexpansion=array EventData
    | evaluate bag_unpack(EventData)
    | extend Key=tostring(['@Name']), Value=['#text']
    | evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type)
    | extend RuleName = column_ifexists("RuleName", ""), TechniqueId = column_ifexists("TechniqueId", ""),
            TechniqueName = column_ifexists("TechniqueName", ""),
            ParentImage = tostring(ParentImage),
            OriginalFileName = tostring(OriginalFileName),
            CommandLine = tostring(CommandLine),
            Computer = tostring(Computer)
    | parse RuleName with * 'technique_id=' TechniqueId ',' * 'technique_name=' TechniqueName
    // Extract URL and URLHost 
    | extend URL = extract("((http|https):\\/\\/.*)\\s?",1,tostring(CommandLine))
    | extend URLHost = tostring(parse_url(URL).Host)
    )
    ;
// Perform frequency analysis.
// WARNING!!: Phishing URLs can be customized per target user or not. 
// Perform 2 different analysis (one for URL, one for URLHost)
//// Frequency analysis by URLHost  ////
PotentialPhishingLinks
| summarize Prevalence = dcount(Computer) by URLHost, ParentImage
| where Prevalence <= PhishingTargetMax
//// Get event details back. ////
| join kind=inner PotentialPhishingLinks on URLHost
// Filter only the last 1 day of events (if you perform analysis everyday)
| where TimeGenerated > ago(1d)
| project-reorder TimeGenerated, Prevalence, Computer, ParentImage, OriginalFileName , URLHost, URL, CommandLine
//// Frequency analysis by URL (comment out the above 8 lines, uncomment the below 8 lines) ////
// PotentialPhishingLinks
// | summarize Prevalence = dcount(Computer) by URL, ParentImage
// | where Prevalence <= PhishingTargetMax
// //// Get event details back. ////
// | join kind=inner PotentialPhishingLinks on URL
// // Filter only the last 1 day of events (if you perform analysis everyday)
// | where TimeGenerated > ago(1d)
// | project-reorder TimeGenerated, Prevalence, Computer, ParentImage, OriginalFileName, URLHost , URL, CommandLine
```
