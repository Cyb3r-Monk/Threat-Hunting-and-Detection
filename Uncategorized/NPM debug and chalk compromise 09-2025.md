# Compromised NPM Packages on 08-09-2025

**Author:** Cyb3rMonk ( [Website](https://academy.bluraven.io), [Twitter](https://twitter.com/Cyb3rMonk) )

## Quick Links

* Blu Raven Academy Home - [https://academy.bluraven.io](https://academy.bluraven.io/?utm_source=githubthderepo)
  
* Blu Raven Academy Courses - [https://academy.bluraven.io/courses](https://academy.bluraven.io/courses/?utm_source=githubthderepo)

* Blu Raven Academy Pricing - [https://academy.bluraven.io/pricing](https://academy.bluraven.io/pricing/?utm_source=githubthderepo)

* Blu Raven Academy Blog - [https://academy.bluraven.io/blog](https://academy.bluraven.io/blog/?utm_source=githubthderepo)

## Details

Language: Kusto Query Language (KQL)

Products: Microsoft Sentinel

Tables  : CommonSecurityLog (or where you store your Web Proxy logs)


## Description

The query below detects access to compromised npm packages shared by [aikido.dev](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised) using the Web Proxy logs. Use the first filter if you want to perform a broader search without checking the version. 

- Verify SSL inspection is enabled for `registry.npmjs.org` 
- Using DeviceNetworkEvents & CommandLine data may be misleading as the installed package might be legitimate but have a dependency to the compromised package.



**Query:**
---

```KQL
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://academy.bluraven.io)
//
// Query parameters:
CommonSecurityLog
| where DestinationHostName == "registry.npmjs.org"
// | where RequestURL has_any ("backslash","chalk-template","supports-hyperlinks","has-ansi","simple-swizzle","color-string","error-ex","color-name","is-arrayish","slice-ansi","color-convert","wrap-ansi","ansi-regex","supports-color","strip-ansi","chalk","debug","ansi-styles", "proto-tinker-wc")
| where RequestURL has_all ("backslash", "0.2.1") or
   RequestURL has_all ("chalk-template", "1.1.1") or
   RequestURL has_all ("supports-hyperlinks", "4.1.1") or
   RequestURL has_all ("has-ansi", "6.0.1") or
   RequestURL has_all ("simple-swizzle", "0.2.3") or
   RequestURL has_all ("color-string", "2.1.1") or
   RequestURL has_all ("error-ex", "1.3.3") or
   RequestURL has_all ("color-name", "2.0.1") or
   RequestURL has_all ("is-arrayish", "0.3.3") or
   RequestURL has_all ("slice-ansi", "7.1.1") or
   RequestURL has_all ("color-convert", "3.1.1") or
   RequestURL has_all ("wrap-ansi", "9.0.1") or
   RequestURL has_all ("ansi-regex", "6.2.1") or
   RequestURL has_all ("supports-color", "10.2.1") or
   RequestURL has_all ("strip-ansi", "7.1.1") or
   RequestURL has_all ("chalk", "5.6.1") or
   RequestURL has_all ("debug", "4.4.2") or
   RequestURL has_all ("ansi-styles", "6.2.2") or
   RequestURL has_all ("proto-tinker-wc", "0.1.87")
| project-reorder TimeGenerated, SourceUserName, RequestURL
```