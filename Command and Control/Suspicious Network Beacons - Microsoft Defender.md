# Suspicious Network Beacons - Microsoft Defender(MDE/M365D)
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Part-1 (Medium)](https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-machine-learning-and-277c4c30304f), 
[Part-2 (Medium)](https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-ml-and-kql-part-2-bff46cfc1e7e)

Language: Azure KQL

Products: Microsoft 365 Defender / Microsoft Defender for Endpoint

Required: DeviceNetworkEvents  

**WARNING!**: Since MDE doesn't log every single network connection, there is a chance of FALSE NEGATIVES. 


## Description

Below query detects suspicious beaconing activity by analyzing DeviceNetworkEvents data.

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
// WARNING!: Since MDE doesn't log every single network connection, there is a chance of FALSE NEGATIVES. 
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
let OutlierCountMax = 3; // increasing the value provides more results.
// Define how many devices can have the same beacon. 
let CompromisedDeviceCountMax = 10; // increasing the value provides more results. 
// Get all beacon candidates just by jitter filtering.
let BeaconCandidates = materialize (
    DeviceNetworkEvents
    | where Timestamp between (ago(starttime)..ago(endtime))
    | where RemoteIPType !in ("Reserved", "Private", "LinkLocal", "Loopback")
    | where isnotempty(RemoteIP) and RemoteIP !in ("0.0.0.0") 
    | where not (ipv4_is_private(RemoteIP))
    | where ActionType in ("ConnectionSuccess", "CsonnectionRequest", "CsonnectionFailed") // Fix the typos if you want to inlcude connreq. and connfail. 
    | summarize hint.strategy=shuffle make_set(Timestamp) by DeviceId, DeviceName,InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, RemoteIP, RemotePort
    | where array_length(set_Timestamp) > TotalEventsThresholdMin and array_length(set_Timestamp) < TotalEventsThresholdMax
    | project DeviceId, DeviceName,InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, RemoteIP, RemotePort, Timestamp=array_sort_asc(set_Timestamp)
    | mv-apply Timestamp to typeof(datetime) on 
    (     
        extend nextTimestamp = next(Timestamp, 1), nextInitiatingProcessAccountName = next(InitiatingProcessAccountName, 1), nextDeviceId = next(DeviceId, 1), nextDeviceName = next(DeviceName, 1), nextRemoteIP = next(RemoteIP, 1), nextRemotePort = next(RemotePort, 1), nextInitiatingProcessFileName = next(InitiatingProcessFileName, 1)
        | extend TimeDeltaInSeconds = datetime_diff('second',nextTimestamp,Timestamp)
        | where nextInitiatingProcessAccountName == InitiatingProcessAccountName and nextDeviceId == DeviceId and nextDeviceName == DeviceName and nextInitiatingProcessFileName == InitiatingProcessFileName and nextRemoteIP == RemoteIP and nextRemotePort == RemotePort
        | project Timestamp, TimeDeltaInSeconds, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort
        // compute statistical values including standard deviation
        | summarize count(), min(Timestamp), max(Timestamp), Duration=datetime_diff("second", max(Timestamp), min(Timestamp)), 
            percentiles(TimeDeltaInSeconds, 5, 25, 50, 75, 95), 
            TimeDeltaList=make_list(TimeDeltaInSeconds) by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort
        | extend (TimeDeltaInSeconds_min,TimeDeltaInSeconds_min_index,TimeDeltaInSeconds_max,TimeDeltaInSeconds_max_index,TimeDeltaInSeconds_avg,TimeDeltaInSeconds_stdev,TimeDeltaInSeconds_variance)=series_stats(TimeDeltaList)
        | extend Jitter=(TimeDeltaInSeconds_stdev/TimeDeltaInSeconds_avg)*100,
                 BeaconSleepMin=TimeDeltaInSeconds_avg - TimeDeltaInSeconds_stdev,
                 BeaconSleepMax=TimeDeltaInSeconds_avg + TimeDeltaInSeconds_stdev
        // Filter out impossible beacons based on jitter threshold defined.
        | where Jitter < JitterThreshold
    )
    // Try to enricht IP with the hostname
    | join kind=leftouter
        (
        DeviceNetworkEvents
        | where Timestamp > ago(starttime+1d)
        // Extract domain from the RemoteUrl
        | extend Host=tostring(parse_url(iif(RemoteUrl !startswith "http", strcat(@'http://',RemoteUrl),RemoteUrl)).Host)
        | extend domain = reverse(replace(@'([A-z0-9-]+\.[A-z0-9-]+\.[A-z0-9-]+)\..*',@'\1',reverse(Host)))
        | project domain, RemoteIP
        | summarize Domains = make_set(domain) by RemoteIP
        ) on RemoteIP
        | project-reorder DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain
)
;
// Get potentially suspicious beacons based on CompromisedDeviceCountMax
let PotentialBeacons = materialize (
    BeaconCandidates
    | summarize dcount(DeviceId) by InitiatingProcessFileName, RemoteIP, RemotePort
    // Filter out beacon destinations if many devices are connecting to it (like windows update)
    | where dcount_DeviceId <= CompromisedDeviceCountMax
    | join kind=inner BeaconCandidates on InitiatingProcessFileName, RemoteIP, RemotePort
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
    | summarize count(), make_set(outliers) by DeviceId, DeviceName,InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, RemoteIP, RemotePort
    | where count_ > OutlierCountMax
    )
    ;
// Remove ImpossibleBeaconsByTimeDelta from potentially suspicious beacons. 
PotentialBeacons
| join kind=leftantisemi ImpossibleBeaconsByTimeDelta on DeviceId, DeviceName,InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, RemoteIP, RemotePort
| extend Timestamp = min_Timestamp // just to make it easy to jump to the device timeline etc. 
// if the logs have extra information, they can be used for filtering the nonmalicious destinations
| order by Jitter asc, TimeDeltaInSeconds_avg asc
```
