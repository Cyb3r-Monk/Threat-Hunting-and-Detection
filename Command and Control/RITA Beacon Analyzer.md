# RITA Beacon Analyzer
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Original Post**: [Medium](https://posts.bluraven.io/implementing-rita-using-kql-8ccb0ee8eeae)

Language: Azure KQL

Products: Azure Sentinel

Required: VMConnection


## Description

Below query analyzes network connections and applies the same algorithm of RITA beacon analyzer. You can go to [Azure Demo Logs Blade](https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs/DemoLogsBlade) and run the query directly to see how it works.



## How to use the query
Depending on the logs you have, customize the query accordingly. Some of the sections that require modification are highlighted with `//**` (There might be missing sections).  
In short, you need to define columns of the network connections and then modify the sections that use those columns.  

## Need help?  
If you open an issue and provide a sample log, I can create the query for you. 


**Query:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post:
// https://posts.bluraven.io/implementing-rita-using-kql-8ccb0ee8eeae
//
// Read the blog to understand how this query works and how to analyze the results.
// This query may not be able to detect beacons that have large sleep values like 6h-1d.  
//
// Query parameters:
let starttime = 1d;
let endtime = 1m;
let TotalEventsThresholdMin = 24; // A beacon should have at least 24 connections (1h sleep)
let DurationThreshold_minutes = 180; // only show beacons that had 180 minutes of duration
let ScoreThreshold = 0.85; // show beacons that have a score greater than 0.85 (max score is 1)
let MaxJitterInSeconds = 30.0; // covers beacons that have 30 seconds jitter
let MaxDataJitterinBytes = 32.0; // covers beacons that have 30 seconds data(sent bytes) jitter
// Define how many devices can have the same beacon. 
let CompromisedDeviceCountMax = 5; // increasing the value generates more results.
//get process and DNS information from the VMConnections table to enrich the potential beacon results
let connectionInfo = VMConnection | where TimeGenerated > ago(30d) | where isnotempty(RemoteDnsCanonicalNames) |  summarize ProcessList = make_set(ProcessName), RemoteDnsCanonicalNames=make_set(tostring(RemoteDnsCanonicalNames)) by RemoteIp; 
let AllBeacons = materialize (
    // Start: condition for the network traffix (fw/proxy/etc)
    VMConnection
    | where TimeGenerated between (ago(starttime)..ago(endtime))
    | where Direction == "outbound"
    // End: condition for the network traffic
    // Prepare data set for analysis. Shrink(zip) results per source-destination pair(put timestamp and sentbytes into lists and you have 1 row for each session)
    | summarize hint.strategy=shuffle start=min(TimeGenerated), end=max(TimeGenerated), make_list(TimeGenerated), make_list(BytesSent), TotalBytesSent = sum(toreal(BytesSent)), TotalBytesReceived = sum(toreal(BytesReceived)) 
                by  Computer,SourceIp, DestinationIp, DestinationPort, Protocol //**
    | extend duration_minutes=datetime_diff("minute", end, start), 
             duration_seconds=datetime_diff("second", end, start)
    | where duration_minutes >= DurationThreshold_minutes // filter by duration
    | where array_length( list_TimeGenerated) >= TotalEventsThresholdMin // filter by connection count
    // Keep data set as small as possibble
    | project duration_minutes, duration_seconds, TotalBytesSent,TotalBytesReceived, Computer, DestinationIp, Protocol, 
              DestinationPort=iif(isempty(DestinationPort),0,DestinationPort), BytesSent = list_BytesSent, TimeGenerated = array_sort_asc(list_TimeGenerated), ConnectionCount = array_length(list_TimeGenerated) //**
    // Start analysis: unzip results by timestamp and sentbytes. then start calculating scores per session.
    | mv-apply TimeGenerated to typeof(datetime), BytesSent to typeof(real) on
    (     
        extend nextTimeGenerated = next(TimeGenerated, 1), nextComputer = next(Computer, 1), nextDestinationIp = next(DestinationIp, 1), nextProtocol = next(Protocol, 1), nextDestinationPort = next(DestinationPort, 1) //**
        | extend TimeDeltaInseconds = datetime_diff('second',nextTimeGenerated,TimeGenerated) // interactive beacons make several connection in a second, using second is better.
        | where Computer == nextComputer and DestinationIp == nextDestinationIp and Protocol == nextProtocol  and DestinationPort == nextDestinationPort  //** 
        | project TimeGenerated, TimeDeltaInseconds, Computer, DestinationIp, Protocol, DestinationPort, BytesSent, duration_minutes, duration_seconds //**
        // Calculate percentiles. 
        | summarize count(), min(TimeGenerated), max(TimeGenerated),
                    percentiles(TimeDeltaInseconds, 5, 25, 50, 75, 95), 
                    percentiles(BytesSent, 5, 25, 50, 75, 95), 
                    TimeDeltaList=make_list(TimeDeltaInseconds), 
                    BytesSentList=make_list(BytesSent)
                    by Computer, DestinationIp, Protocol, DestinationPort, duration_minutes, duration_seconds //**
        // assign variables Low, Mid and High for timedelta and sentbytes
        | extend tsLow = (percentile_TimeDeltaInseconds_25), tsMid = (percentile_TimeDeltaInseconds_50), tsHigh = (percentile_TimeDeltaInseconds_75), 
                 dsLow = (percentile_BytesSent_25), dsMid = (percentile_BytesSent_50), dsHigh = (percentile_BytesSent_75)
        // calculate Bowley variables
        | extend tsBowleyNum = tsLow + tsHigh - 2*tsMid, tsBowleyDen = tsHigh - tsLow, 
                 dsBowleyNum = dsLow + dsHigh - 2*dsMid, dsBowleyDen = dsHigh - dsLow
        // calculate Bowley's skewness
        | extend tsSkew = iif(tsBowleyDen != 0 and tsMid != tsLow and tsMid != tsHigh, toreal(tsBowleyNum) / toreal(tsBowleyDen), 0.0), 
                 dsSkew = iif(dsBowleyDen != 0 and dsMid != dsLow and dsMid != dsHigh, toreal(dsBowleyNum) / toreal(dsBowleyDen), 0.0)
        // calculate skewness scores
        | extend tsSkewScore  = 1.0 - toreal(abs(tsSkew)), 
                 dsSkewScore  = 1.0 - toreal(abs(dsSkew))
        // start of MADM calculation 
        | mv-expand TimeDeltaList, BytesSentList
        // generate temp lists for timedelta and sentbytes. we already have Median values. just need to calculate absolute distance from the Median
        | extend temp_tsdelta = abs(TimeDeltaList - tsMid), 
                 temp_dsdelta = abs(BytesSentList - dsMid) 
        // calculate MADM of timedelta and sentbytes
        | summarize tsMadm = percentiles(temp_tsdelta,50), 
                    dsMadm = percentiles(temp_dsdelta,50), 
                    TimeDeltaList = make_list(TimeDeltaList) 
                    by Computer, DestinationIp, Protocol, DestinationPort, min_TimeGenerated, max_TimeGenerated, duration_minutes, duration_seconds, tsLow, tsMid, tsHigh, dsLow, dsMid, dsHigh, tsSkewScore,dsSkewScore //**
        // calculate MADM, smallness(sentbytes) and connection count scores
        | extend tsMadmScore  = iif((1.0 - toreal(tsMadm)/MaxJitterInSeconds) < 0, 0.0, 1.0 - toreal(tsMadm)/MaxJitterInSeconds), 
                 dsMadmScore  = iif((1.0 - toreal(dsMadm)/MaxDataJitterinBytes) < 0, 0.0, 1.0 - toreal(dsMadm)/MaxDataJitterinBytes), 
                 dsSmallnessScore  = iif((1.0 - toreal(dsHigh)/65535.0) < 0, 0.0, 1.0 - toreal(dsHigh)/65535.0),
                 tsConnCountScore = iif(toreal(array_length(TimeDeltaList))/(toreal(duration_seconds)/90.0) > 1.0 , 1.0, toreal(array_length(TimeDeltaList))/(toreal(duration_seconds)/90.0))
        // calculate sum of the scores(timedelta and sentbytes)
        | extend tsSum = tsSkewScore + tsMadmScore + tsConnCountScore, 
                 dsSum = dsSkewScore + dsMadmScore + dsSmallnessScore
        // calculate timedelta, sentbytes and the overall score.
        | extend tsScore = ceiling((tsSum/3.0)*1000) / 1000, 
                 dsScore = ceiling((dsSum/3.0)*1000) / 1000, 
                 score = ceiling(((tsSum+dsSum)/6.0)*1000) / 1000
        // filter results based on the score threshold
        | where score >= ScoreThreshold
    )
)
;
// Not all beacons are malicious, get only ones that are potentially malicious
let PotentialBeacons = materialize 
    (
    AllBeacons
    | summarize dcount(Computer) by  DestinationIp
    // Filter out beacon destinations if many devices are connecting to the same destination (like windows update)
    | where dcount_Computer <= CompromisedDeviceCountMax
    | join kind=inner AllBeacons on DestinationIp
    | project-away *1
    )
    ;
// Analyze prevalence of the DestinationIP
let DestinationList = PotentialBeacons | summarize make_set(DestinationIp);
let PrevalanceData = VMConnection | where TimeGenerated between (ago(starttime + 5d)..ago(endtime)) | where DestinationIp  in (DestinationList)| summarize hint.strategy=shuffle DestinationPrevalence = dcount(Computer) by  DestinationIp; //*
// Enrich beacons with prevlance data
PotentialBeacons
| join kind=leftouter PrevalanceData on DestinationIp
| where DestinationIp != "127.0.0.1" and not(ipv4_is_private(DestinationIp)) 
| join kind=leftouter connectionInfo on $left.DestinationIp == $right.RemoteIp 
| project-reorder score, min_TimeGenerated, max_TimeGenerated, Computer, DestinationIp, RemoteDnsCanonicalNames, ProcessList,  Protocol, DestinationPort, ConnectionCount, duration_minutes, TotalBytesReceived, TotalBytesSent  
| sort by score desc, ConnectionCount desc, DestinationPrevalence asc
```
