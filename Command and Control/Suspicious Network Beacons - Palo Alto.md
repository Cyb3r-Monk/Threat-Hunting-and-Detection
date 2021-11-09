# Suspicious Network Beacons - Palo Alto
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Part-1 (Medium)](https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-machine-learning-and-277c4c30304f), 
[Part-2 (Medium)](https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-ml-and-kql-part-2-bff46cfc1e7e)

Language: Azure KQL

Products: Azure Sentinel

Required: Palo Alto FW logs. You may need to modify the query depending on the CEF fields(DeviceCustomNumber3, DeviceCustomString2).


## Description

Below query detects suspicious beaconing activity by analyzing Palo Alto FW logs.

### Attention!
Palo Alto FW can log session start and end. If you enable both session start and end logging, modify the query accordingly.

## How to use the query
We first need to define boundaries for the beacons you want to detect. Defining the boundaries based on the Empire beacon behavior covers Cobalt Strike and others.
### Hunting with the jitter only
In this scenario, we want to detect all beacons without filtering them based on the sleep interval. Just change the JitterThreshold and run the query.
### Hunting with the jitter and sleep interval
In this scenario, we want to filter beacons based on the jitter and sleep interval thresholds. 
#### Example: Beacons that have at least 15-minute(900s) sleep with %25 jitter
JitterThreshold = 25
TimeDeltaThresholdMin = 900 -  (900*25/100) = 675 = 11 minutes, 15 seconds

Optionally, we want to set an upper boundary for the sleep interval:
TimeDeltaThresholdMax = 900 + (900*25/100) = 1125= 18 minutes, 45 seconds

Based on these values, we can filter the results.

**Query:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post:
// Part-1: https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-machine-learning-and-277c4c30304f
// Part-2: https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-ml-and-kql-part-2-bff46cfc1e7e
//
// Read the blog to understand how this query works and how to analyze the results.
// This query may not be able to detect beacons that have large sleep values like 6h-1d. Refactoring and additional analysis are required. 
//
// Query parameters:
let starttime = 1d;
let endtime = 1s;
// Set the minimum beacon sleep. Increase it to get less results. the format is (hour,minute,second.milisecond).
// Be careful when changing the value. run " print ['timespan'] = make_timespan(0, x, y) " to verify you have the correct value set. 
let TimeDeltaThresholdMin = make_timespan(0,0,0.001); 
let TotalEventsThresholdMin = 15;
let TotalEventsThresholdMax=toint(((totimespan(starttime) - totimespan(endtime))/TimeDeltaThresholdMin));
let JitterThreshold = 50; // jitter in percentage. Set to filter out false positives: small threshold means tighter filtering/fewer results.
// Outlier thresholds. 1.5 means the value is a normal outlier, 3 means the value is far far out.
let OutlierThresholdMax = 2; //increase or decrease this value to get more or less results
// Time delta data set can have some outliers. Define how many outliers are acceptable for a beacon. Values between 1 to 3 should be fine.
let OutlierCountMax = 2; // increasing the value provides more results.
// Define how many devices can have the same beacon. 
let CompromisedDeviceCountMax = 10; // increasing the value provides more results. 
// Get all beacon candidates just by jitter filtering.
let BeaconCandidates = materialize (
    CommonSecurityLog
    | where DeviceVendor == "Palo Alto Networks"
    | where TimeGenerated between (ago(starttime)..ago(endtime)) and isnotempty(SourceUserName)
    | where Activity == "TRAFFIC" and DeviceAction == "allow"
    | where not(ipv4_is_private(DestinationIP))
    | where not (DestinationHostName has_any ("www.msftconnecttest.com","mp.microsoft.com")) // exclude known trusted destinations. 
    | summarize hint.strategy=shuffle make_set(TimeGenerated), make_list(SentBytes), make_list(ReceivedBytes), TotalDuration=sum(DeviceCustomNumber3) by  SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort, ApplicationProtocol, URLCategory=DeviceCustomString2
    | where array_length( set_TimeGenerated) > TotalEventsThresholdMin and array_length(set_TimeGenerated) < TotalEventsThresholdMax
    | project SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort, ApplicationProtocol, URLCategory, list_SentBytes, list_ReceivedBytes, TimeGenerated = array_sort_asc(set_TimeGenerated), TotalDuration
    | mv-apply TimeGenerated to typeof(datetime) on 
    (     
        extend nextTimeGenerated = next(TimeGenerated, 1), nextSourceUserName = next(SourceUserName, 1),nextSourceHostName = next(SourceHostName, 1) , nextDestinationHostCF = next(DestinationHostName, 1), nextDestinationIP = next(DestinationIP, 1)
        | extend TimeDeltaInSeconds = datetime_diff('second',nextTimeGenerated,TimeGenerated)
        | where SourceUserName == nextSourceUserName and nextSourceHostName == SourceHostName and nextDestinationHostCF == DestinationHostName and nextDestinationIP == DestinationIP
        | project TimeGenerated, TimeDeltaInSeconds, SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort
        | summarize count(), min(TimeGenerated), max(TimeGenerated),
                    percentiles(TimeDeltaInSeconds, 5, 25, 50, 75, 95), // percentiles analyzes the distribution of the values. Can be used for making a decision or FP tuning.
                    TimeDeltaList=make_list(TimeDeltaInSeconds) by SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort
        | extend (TimeDeltaInSeconds_min,TimeDeltaInSeconds_min_index,TimeDeltaInSeconds_max,TimeDeltaInSeconds_max_index,TimeDeltaInSeconds_avg,TimeDeltaInSeconds_stdev,TimeDeltaInSeconds_variance) = series_stats(TimeDeltaList)
        | extend JitterPercentage = (TimeDeltaInSeconds_stdev/TimeDeltaInSeconds_avg)*100,
                 BeaconSleepMin = TimeDeltaInSeconds_avg - TimeDeltaInSeconds_stdev,
                 BeaconSleepMax = TimeDeltaInSeconds_avg + TimeDeltaInSeconds_stdev
        // Filter out impossible beacons based on jitter threshold defined.
        | where JitterPercentage <= JitterThreshold
    )
)
;
// Get potential suspicious beacons based on CompromisedDeviceCountMax
let PotentialBeacons = materialize 
    (
    BeaconCandidates
    | summarize dcount(SourceUserName) by DestinationHostName, DestinationPort
    // Filter out beacon destinations if many devices are connecting to the same destination (like windows update)
    | where dcount_SourceUserName <= CompromisedDeviceCountMax
    | join kind=inner BeaconCandidates on DestinationHostName, DestinationPort
    | project-away *1
    )
    ;
// Get candidates that can't be beacons based on outlier analysis on the time delta
let ImpossibleBeaconsByTimeDelta = materialize 
    (
    PotentialBeacons
    | extend outliers = series_outliers(TimeDeltaList)
    | mv-expand TimeDeltaList, outliers to typeof(double)
    | where outliers > OutlierThresholdMax or outliers < (-1 * OutlierCountMax) // outlier can be negative or positive.
    | summarize count(), make_set(outliers) by SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort, ApplicationProtocol, URLCategory
    | where count_ > OutlierCountMax
    )
    ;
// Get candidates that can't be beacons based on outlier analysis on the sent bytes
let ImpossibleBeaconsBySentBytes = materialize 
    (
    PotentialBeacons
    | extend outliers = series_outliers(list_SentBytes)
    | mv-expand list_SentBytes, outliers to typeof(double)
    | where outliers > OutlierThresholdMax or outliers < (-1 * OutlierCountMax) // outlier can be negative or positive.
    | summarize count(), make_set(outliers) by SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort, ApplicationProtocol, URLCategory
    | where count_ > OutlierCountMax
    )
    ;
// Get all potentially suspicious beacons
let SuspiciousBeacons = materialize (
    PotentialBeacons
    | join kind=leftantisemi ImpossibleBeaconsByTimeDelta on SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort, ApplicationProtocol, URLCategory
    | join kind=leftantisemi ImpossibleBeaconsBySentBytes on SourceHostName, SourceUserName, DestinationHostName, DestinationIP, DestinationPort, ApplicationProtocol, URLCategory
    // if the logs have extra information, they can be used for filtering the nonmalicious destinations
    // | where URLCategory !in ("Advertising","Web search","Video Streaming")
    // | where ApplicationProtocol !in ("Dropbox")
    );
// get prevalence data for the destinations(last14d)
let DestinationList = 
    SuspiciousBeacons
    | summarize make_set(DestinationHostName)
    ;
let PrevalanceData = 
    CommonSecurityLog
    | where TimeGenerated between (ago(14d) .. ago(endtime)) // analyze the duration before the last beacon connection
    | where DestinationHostName in (DestinationList)
    | summarize hint.strategy=shuffle DestinationPrevalence = dcount(SourceUserName) by DestinationHostName
    ;
// Enrich suspicious beacons with the historical prevalence data for prioritization
SuspiciousBeacons
| join kind=leftouter PrevalanceData on DestinationHostName
| sort by DestinationPrevalence asc
| project-reorder DestinationPrevalence
```
