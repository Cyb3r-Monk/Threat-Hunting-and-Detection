# Suspicious Driver Load
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-edr-bypass-malicious-drivers-kernel-callbacks-f5e6bf8f7481)

Language: Azure KQL

Products: MDE/M365D

Tables  : DeviceEvents, DeviceFileCertificateInfo


## Description

Below query detects suspicious(unusual/rare) driver loads. Further checks are required on detected files to confirm malicious activity.


**Query:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to blog post:
// https://posts.bluraven.io/detecting-edr-bypass-malicious-drivers-kernel-callbacks-f5e6bf8f7481
//
// Query parameters:
// Query at least 7d of data to reduce false positives(if you have many.
DeviceEvents
| where ActionType == "DriverLoad"
| distinct SHA1 // get SHA1 of the drivers
// get certificate information of the drivers
| join kind=inner
    (
    DeviceFileCertificateInfo
    // get only the files having certificate older than "7/30/2015" 
    | where CertificateCreationTime < todatetime("7/30/2015") or CertificateExpirationTime < todatetime("7/30/2015")
    ) on SHA1
    // use prevalence. assuming malicious driver has been installed on max 5 machines.
    | summarize dcount(DeviceId) by SHA1
    | where dcount_DeviceId <= 5
    // get file profile 
    | invoke FileProfile(SHA1,1000)
    // filter out the files having GlobalPrevalence > 500 (FP reduction)
    | where GlobalPrevalence <= 500
    // get certificate details back
    | join DeviceFileCertificateInfo on SHA1
```
