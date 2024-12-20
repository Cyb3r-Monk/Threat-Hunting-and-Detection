# RITA Beacon Analyzer for Windows Firewall Events
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

Required: WindowsFirewall or SecurityEvent (EID 5156)


## Description

Below queries analyze Windows Firewall logs and applies RITA beacon analyzer algorithm for C2 beaconing detection.



## How to use the query
Change the parameters based on your needs. Consider enriching results since only the IP address information is available in event logs.



**Query for EID 5156:**
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
let MaxJitterInseconds = 30.0; // covers beacons that have max 30 seconds jitter(consider increasing this for better coverage)
// Define how many devices can have the same beacon. 
let CompromisedDeviceCountMax = 5; // number of devices that can be compromised at the same time and have the same beacon. Increasing the value generates more results.
let AllBeacons = materialize (
    SecurityEvent
    | where TimeGenerated between (ago(starttime)..ago(endtime))
    | where EventID == 5156
    | where EventData has_cs '<Data Name="Protocol">6</Data>' // TCP connections only
    | where EventData has_cs '<Data Name="Direction">%%14593</Data>' // Outbound direction
    | where EventData !has_cs '<Data Name="DestAddress">127.0.0.1</Data>'
    | where EventData !has_cs '<Data Name="DestAddress">169.254.'
    | parse EventData with * 'DestAddress">' DestinationIP '<' *
    | where not(ipv4_is_private(DestinationIP)) // analyze only outbound connections to the internet
    | parse EventData with * '"ProcessID">' ProcessId '<' * 'Application">' Application '<' * 'Direction">' Direction '<' * 'SourceAddress">' SourceIP '<' * 'SourcePort">' SourcePort '<' 
        * 'DestPort">' DestinationPort '<' * 'Protocol">' Protocol '<' * 'LayerName">' LayerName '<' * 'RemoteUserID">' RemoteUserID '<' * 'RemoteMachineID">' RemoteMachineID '<' *
    // Prepare data set for analysis.
    | summarize hint.strategy=shuffle start=min(TimeGenerated), end=max(TimeGenerated), make_list(TimeGenerated) 
        by Computer, Application, Protocol, DestinationIP, DestinationPort
    | where array_length(list_TimeGenerated) >= TotalEventsThresholdMin
    | extend
        duration_minutes=datetime_diff("minute", end, start),
        duration_seconds=datetime_diff("second", end, start)
    | where duration_minutes >= DurationThreshold_minutes
    // Keep data set as small as possibble, remove unnecessary columns.
    | project
        duration_minutes,
        duration_seconds,
        ConnRate = toreal(array_length(list_TimeGenerated)) / toreal(duration_minutes),
        Computer,
        Application,
        DestinationIP,
        DestinationPort,
        Protocol,
        TimeGenerated = array_sort_asc(list_TimeGenerated),
        ConnectionCount = array_length(list_TimeGenerated)
    // Start analysis: 
    | mv-apply TimeGenerated to typeof(datetime) on 
        (     
        extend
            nextTimeGenerated = next(TimeGenerated, 1),
            nextComputer = next(Computer, 1),
            nextApplication = next(Application, 1),
            nextProtocol = next(Protocol, 1),
            nextDestinationIP = next(DestinationIP, 1),
            nextDestinationPort = next(DestinationPort, 1)
        | extend TimeDeltaInSeconds = datetime_diff('second', nextTimeGenerated, TimeGenerated)
        | where Computer == nextComputer
            and nextProtocol == Protocol
            and nextDestinationIP == DestinationIP
            and nextDestinationPort == DestinationPort
            and nextApplication == Application
        | project
            TimeGenerated,
            TimeDeltaInSeconds,
            Computer,
            Application,
            Protocol,
            DestinationIP,
            DestinationPort,
            duration_minutes,
            duration_seconds
        // Calculate percentiles.
        | summarize hint.strategy=shuffle count(), min(TimeGenerated), max(TimeGenerated), 
            percentiles(TimeDeltaInSeconds, 10, 25, 50, 75, 90),
            TimeDeltaList=make_list(TimeDeltaInSeconds)
            by
            Computer,
            Application,
            Protocol,
            DestinationIP,
            DestinationPort,
            duration_minutes,
            duration_seconds
        | extend
            tsLow = (percentile_TimeDeltaInSeconds_10),
            tsMid = (percentile_TimeDeltaInSeconds_50),
            tsHigh = (percentile_TimeDeltaInSeconds_90)
        // calculate Bowley variables
        | extend tsBowleyNum = tsLow + tsHigh - 2 * tsMid, tsBowleyDen = tsHigh - tsLow
        // calculate Bowley's skewness
        | extend tsSkew = iif(tsBowleyDen != 0 and tsMid != tsLow and tsMid != tsHigh, toreal(tsBowleyNum) / toreal(tsBowleyDen), 0.0)
        // calculate skewness scores
        | extend tsSkewScore  = 1.0 - toreal(abs(tsSkew))
        // start of MADM calculation 
        | mv-expand TimeDeltaList
        | extend temp_tsdelta = abs(TimeDeltaList - tsMid)
        // calculate MADM of timedelta and sentbytes
        | summarize hint.strategy=shuffle tsMadm = percentiles(temp_tsdelta, 50), TimeDeltaList = make_list(TimeDeltaList)
            by
            tsLow,
            tsMid,
            tsHigh,
            Computer,
            Application,
            Protocol,
            DestinationIP,
            DestinationPort,
            count_,
            min_TimeGenerated,
            max_TimeGenerated,
            tsBowleyNum,
            tsBowleyDen,
            tsSkewScore,
            duration_minutes,
            duration_seconds
        // calculate MADM, smallness(sentbytes) and connection count score
        | extend tsMadmScore  = iif((1.0 - toreal(tsMadm) / MaxJitterInseconds) < 0, 0.0, 1.0 - toreal(tsMadm) / MaxJitterInseconds)
        | extend tsConnCountScore = iif(toreal(array_length(TimeDeltaList)) / (toreal(duration_seconds) / 90.0) > 1.0, 1.0, toreal(array_length(TimeDeltaList)) / (toreal(duration_seconds) / 90.0))
        // calculate sum of the scores(timedelta and sentbytes)
        | extend tsSum = tsSkewScore + tsMadmScore + tsConnCountScore
        // calculate timedelta, sentbytes and the overall score.
        | extend tsScore = ceiling((tsSum / 3.0) * 1000) / 1000
        // filter results based on the score threshold
        | where tsScore >= ScoreThreshold
        // calculate jitter. not used for filtering for now. 
        | extend tsJitter=iif(tsMid > 0, toreal(tsMadm) / toreal(tsMid) * 100, 0.0)
        )
    )
;
let PotentialBeacons = materialize 
    (
    AllBeacons
    | summarize hint.strategy=shuffle dcount(Computer) by Protocol, DestinationIP, DestinationPort
    | where dcount_Computer <= CompromisedDeviceCountMax
    | join kind=inner AllBeacons on Protocol, DestinationIP, DestinationPort
    | project-away *1
    )
;
PotentialBeacons
| project-away TimeDeltaList
| sort by tsScore desc, ConnectionCount desc
| project-reorder tsScore, ConnectionCount, dcount_Computer, Protocol, Computer, Application
```

---

**Query for EID 5156:**
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
let MaxJitterInseconds = 30.0; // covers beacons that have max 30 seconds jitter(consider increasing this for better coverage)
// Define how many devices can have the same beacon. 
let CompromisedDeviceCountMax = 5; // number of devices that can be compromised at the same time and have the same beacon. Increasing the value generates more results.
let AllBeacons = materialize (
    WindowsFirewall
    | where TimeGenerated between (ago(starttime)..ago(endtime))
    | where CommunicationDirection == "SEND"
    | where FirewallAction == "ALLOW"
    | where Protocol == "TCP"
    | where DestinationIP <> '127.0.0.1'
    | where not(ipv4_is_private(DestinationIP))
    // Prepare data set for analysis.
    | summarize hint.strategy=shuffle start=min(TimeGenerated), end=max(TimeGenerated), make_list(TimeGenerated) 
        by Computer, DestinationIP, Protocol, DestinationPort
    | where array_length(list_TimeGenerated) >= TotalEventsThresholdMin
    | extend
        duration_minutes=datetime_diff("minute", end, start),
        duration_seconds=datetime_diff("second", end, start)
    | where duration_minutes >= DurationThreshold_minutes
    // Keep data set as small as possibble, remove unnecessary columns.
    | project
        duration_minutes,
        duration_seconds,
        ConnRate = toreal(array_length(list_TimeGenerated)) / toreal(duration_minutes),
        Computer,
        DestinationIP,
        DestinationPort,
        Protocol,
        TimeGenerated = array_sort_asc(list_TimeGenerated),
        ConnectionCount = array_length(list_TimeGenerated)
    // Start analysis: 
    | mv-apply TimeGenerated to typeof(datetime) on 
        (     
        extend
            nextTimeGenerated = next(TimeGenerated, 1),
            nextComputer = next(Computer, 1),
            nextProtocol = next(Protocol, 1),
            nextDestinationIP = next(DestinationIP, 1),
            nextDestinationPort = next(DestinationPort, 1)
        | extend TimeDeltaInSeconds = datetime_diff('second', nextTimeGenerated, TimeGenerated)
        | where Computer == nextComputer
            and nextProtocol == Protocol
            and nextDestinationIP == DestinationIP
            and nextDestinationPort == DestinationPort
        | project
            TimeGenerated,
            TimeDeltaInSeconds,
            Computer,
            Protocol,
            DestinationIP,
            DestinationPort,
            duration_minutes,
            duration_seconds
        // Calculate percentiles.
        | summarize hint.strategy=shuffle count(), min(TimeGenerated), max(TimeGenerated), 
            percentiles(TimeDeltaInSeconds, 10, 25, 50, 75, 90),
            TimeDeltaList=make_list(TimeDeltaInSeconds)
            by
            Computer,
            Protocol,
            DestinationIP,
            DestinationPort,
            duration_minutes,
            duration_seconds
        | extend
            tsLow = (percentile_TimeDeltaInSeconds_10),
            tsMid = (percentile_TimeDeltaInSeconds_50),
            tsHigh = (percentile_TimeDeltaInSeconds_90)
        // calculate Bowley variables
        | extend tsBowleyNum = tsLow + tsHigh - 2 * tsMid, tsBowleyDen = tsHigh - tsLow
        // calculate Bowley's skewness
        | extend tsSkew = iif(tsBowleyDen != 0 and tsMid != tsLow and tsMid != tsHigh, toreal(tsBowleyNum) / toreal(tsBowleyDen), 0.0)
        // calculate skewness scores
        | extend tsSkewScore  = 1.0 - toreal(abs(tsSkew))
        // start of MADM calculation 
        | mv-expand TimeDeltaList
        | extend temp_tsdelta = abs(TimeDeltaList - tsMid)
        // calculate MADM of timedelta and sentbytes
        | summarize hint.strategy=shuffle tsMadm = percentiles(temp_tsdelta, 50), TimeDeltaList = make_list(TimeDeltaList)
            by
            tsLow,
            tsMid,
            tsHigh,
            Computer,
            Protocol,
            DestinationIP,
            DestinationPort,
            count_,
            min_TimeGenerated,
            max_TimeGenerated,
            tsBowleyNum,
            tsBowleyDen,
            tsSkewScore,
            duration_minutes,
            duration_seconds
        // calculate MADM, smallness(sentbytes) and connection count score
        | extend tsMadmScore  = iif((1.0 - toreal(tsMadm) / MaxJitterInseconds) < 0, 0.0, 1.0 - toreal(tsMadm) / MaxJitterInseconds)
        | extend tsConnCountScore = iif(toreal(array_length(TimeDeltaList)) / (toreal(duration_seconds) / 90.0) > 1.0, 1.0, toreal(array_length(TimeDeltaList)) / (toreal(duration_seconds) / 90.0))
        // calculate sum of the scores(timedelta and sentbytes)
        | extend tsSum = tsSkewScore + tsMadmScore + tsConnCountScore
        // calculate timedelta, sentbytes and the overall score.
        | extend tsScore = ceiling((tsSum / 3.0) * 1000) / 1000
        // filter results based on the score threshold
        | where tsScore >= ScoreThreshold
        // calculate jitter. not used for filtering for now. 
        | extend tsJitter=iif(tsMid > 0, toreal(tsMadm) / toreal(tsMid) * 100, 0.0)
        )
    )
;
let PotentialBeacons = materialize 
    (
    AllBeacons
    | summarize hint.strategy=shuffle dcount(Computer) by Protocol, DestinationIP, DestinationPort
    | where dcount_Computer <= CompromisedDeviceCountMax
    | join kind=inner AllBeacons on Protocol, DestinationIP, DestinationPort
    | project-away *1
    )
;
PotentialBeacons
| project-away TimeDeltaList
| sort by tsScore desc, ConnectionCount desc
| project-reorder tsScore, ConnectionCount, dcount_Computer, Protocol, Computer
```