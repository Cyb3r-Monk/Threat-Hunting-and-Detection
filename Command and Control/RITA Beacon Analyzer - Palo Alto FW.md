# RITA Beacon Analyzer for Palo Alto Firewall
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )


**Link to Original Post**: [Medium](https://posts.bluraven.io/implementing-rita-using-kql-8ccb0ee8eeae)

Language: Azure KQL

Products: Azure Sentinel

Required: CommonSecurityLog (Palo Alto Firewall Logs)


## Description

Below query analyzes Palo Alto Firewall logs and applies the same algorithm of RITA beacon analyzer.



## How to use the query
Change the parameters based on your needs. The query can easily be converted for the other products' logs.  
If you have user name in the logs, replace SourceIP with the SourceUserName for better precision.



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
let MaxJitterInSeconds = 60.0; // covers beacons that have max 60 seconds jitter(consider increasing this for better coverage)
let MaxDataJitterinBytes = 32.0; // covers beacons that have max 32 bytes jitter in  data(sent bytes)
// Define how many devices can have the same beacon. 
let CompromisedDeviceCountMax = 5; // number of devices that can be compromised at the same time and have the same beacon. Increasing the value generates more results.
let AllBeacons = materialize (
    CommonSecurityLog
    | where TimeGenerated between (ago(starttime)..ago(endtime))
    | where DeviceVendor == "Palo Alto Networks"
    | where Activity == "TRAFFIC"
    | where DeviceAction == "allow"
    | where DeviceEventClassID == "start" // chek your logging configuration, PaloAlto can log session start/end or both
    // Prepare data set for analysis. Shrink(zip) results per source-destination pair(put timestamp and sentbytes into lists and you have 1 row for each session)
    | summarize hint.strategy=shuffle start=min(TimeGenerated), end=max(TimeGenerated), make_list(TimeGenerated), make_list(SentBytes), TotalSentBytes = sum(toreal(SentBytes)), TotalReceivedBytes = sum(toreal(ReceivedBytes)) 
                by  SourceIP, DestinationIP, DestinationPort, Protocol //**
    | extend duration_minutes=datetime_diff("minute", end, start), 
             duration_seconds=datetime_diff("second", end, start)
    | where duration_minutes >= DurationThreshold_minutes // filter by duration
    | where array_length( list_TimeGenerated) >= TotalEventsThresholdMin // filter by connection count
    // Keep data set as small as possibble
    | project duration_minutes, duration_seconds, TotalSentBytes,TotalReceivedBytes, SourceIP, DestinationIP, Protocol, 
              DestinationPort=iif(isempty(DestinationPort),0,DestinationPort), SentBytes = list_SentBytes, TimeGenerated = array_sort_asc(list_TimeGenerated), ConnectionCount = array_length(list_TimeGenerated) //**
    // Start analysis: unzip results by timestamp and sentbytes. then start calculating scores per session.
    | mv-apply TimeGenerated to typeof(datetime), SentBytes to typeof(real) on
    (     
        extend nextTimeGenerated = next(TimeGenerated, 1), nextSourceIP = next(SourceIP, 1), nextDestinationIP = next(DestinationIP, 1), nextProtocol = next(Protocol, 1), nextDestinationPort = next(DestinationPort, 1) //**
        | extend TimeDeltaInseconds = datetime_diff('second',nextTimeGenerated,TimeGenerated) // interactive beacons make several connection in a second, using second is better.
        | where SourceIP == nextSourceIP and DestinationIP == nextDestinationIP and Protocol == nextProtocol  and DestinationPort == nextDestinationPort  //** 
        | project TimeGenerated, TimeDeltaInseconds, SourceIP, DestinationIP, Protocol, DestinationPort, SentBytes, duration_minutes, duration_seconds //**
        // Calculate percentiles. 
        | summarize count(), min(TimeGenerated), max(TimeGenerated),
                    percentiles(TimeDeltaInseconds, 5, 25, 50, 75, 95), 
                    percentiles(SentBytes, 5, 25, 50, 75, 95), 
                    TimeDeltaList=make_list(TimeDeltaInseconds), 
                    SentBytesList=make_list(SentBytes)
                    by SourceIP, DestinationIP, Protocol, DestinationPort, duration_minutes, duration_seconds //**
        // assign variables Low, Mid and High for timedelta and sentbytes
        | extend tsLow = (percentile_TimeDeltaInseconds_25), tsMid = (percentile_TimeDeltaInseconds_50), tsHigh = (percentile_TimeDeltaInseconds_75), 
                 dsLow = (percentile_SentBytes_25), dsMid = (percentile_SentBytes_50), dsHigh = (percentile_SentBytes_75)
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
        | mv-expand TimeDeltaList, SentBytesList
        // generate temp lists for timedelta and sentbytes. we already have Median values. just need to calculate absolute distance from the Median
        | extend temp_tsdelta = abs(TimeDeltaList - tsMid), 
                 temp_dsdelta = abs(SentBytesList - dsMid) 
        // calculate MADM of timedelta and sentbytes
        | summarize tsMadm = percentiles(temp_tsdelta,50), 
                    dsMadm = percentiles(temp_dsdelta,50), 
                    TimeDeltaList = make_list(TimeDeltaList) 
                    by SourceIP, DestinationIP, Protocol, DestinationPort, min_TimeGenerated, max_TimeGenerated, duration_minutes, duration_seconds, tsLow, tsMid, tsHigh, dsLow, dsMid, dsHigh, tsSkewScore,dsSkewScore //**
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
    | summarize dcount(SourceIP) by  DestinationIP
    // Filter out beacon destinations if many devices are connecting to the same destination (like windows update)
    | where dcount_SourceIP <= CompromisedDeviceCountMax
    | join kind=inner AllBeacons on DestinationIP
    | project-away *1
    )
    ;
// Analyze prevalence of the DestinationIP
let DestinationList = PotentialBeacons | summarize make_set(DestinationIP);
let PrevalanceData = CommonSecurityLog | where TimeGenerated between (ago(starttime + 5d)..ago(endtime)) | where DestinationIP  in (DestinationList)| summarize hint.strategy=shuffle DestinationPrevalence = dcount(Computer) by  DestinationIP; //*
// Enrich beacons with prevalence data
PotentialBeacons
| join kind=leftouter PrevalanceData on DestinationIP
| project-reorder score, min_TimeGenerated, max_TimeGenerated, SourceIP, DestinationIP, Protocol, DestinationPort, ConnectionCount, duration_minutes, TotalReceivedBytes, TotalSentBytes
| sort by score desc, ConnectionCount desc, DestinationPrevalence asc
```
