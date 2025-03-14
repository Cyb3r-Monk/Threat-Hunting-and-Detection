# Suspicious Network Beacons - Microsoft Defender for Endpoint Aggregated Reports
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Blog Post**: [https://academy.bluraven.io/blog/beaconing-detection-using-mde-aggregated-report-telemetry](https://academy.bluraven.io/blog/beaconing-detection-using-mde-aggregated-report-telemetry), 


Language: KQL

Products: Microsoft 365 Defender / Microsoft Defender for Endpoint

Required: DeviceNetworkEvents  



## Description

Below query detects suspicious beaconing activity by analyzing DeviceNetworkEvents Aggregated Reports telemetry. Use it as a starting point and refine further as it may generate too many results.


**Query:**
---

```KQL
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post: https://academy.bluraven.io/blog/beaconing-detection-using-mde-aggregated-report-telemetry
//
// Query parameters:
let lookback = 3d;
let min_uniform_count = 4 * (lookback / 1d); // (4 uniform distribution per lookback)
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType endswith "AggregatedReport"
| where ipv4_is_private(RemoteIP) == false
| extend ConnectionCount = toint(parse_json(AdditionalFields).uniqueEventsAggregated)
| project Timestamp = bin(Timestamp, 1h), DeviceName, InitiatingProcessFileName, RemoteIP, ConnectionCount
| sort by Timestamp asc 
| summarize Timestamp = make_list(Timestamp), ConnCounts = make_list(ConnectionCount) by DeviceName, InitiatingProcessFileName, RemoteIP
| extend count_of_hours = array_length(Timestamp)
| extend anomalies_decomposed = series_decompose_anomalies(ConnCounts, 1.5, -1),
        series_stats(ConnCounts)
| mv-apply anomaly = anomalies_decomposed to typeof(int) on (
                summarize inliner_count = countif(anomaly !in (-1, 1)), outlier_count = countif(anomaly in (-1, 1))
    )
| where inliner_count >= min_uniform_count and series_stats_ConnCounts_avg > 45 // avg=45 is roughly 1 min sleep with some jitter
| sort by series_stats_ConnCounts_avg desc 
| extend FirstConnection = Timestamp[0], LastConnection=Timestamp[-1], avg_conn_count=toint(series_stats_ConnCounts_avg)
| project-reorder FirstConnection, LastConnection, DeviceName, InitiatingProcessFileName, RemoteIP, count_of_hours, inliner_count, outlier_count, avg_conn_count
```
