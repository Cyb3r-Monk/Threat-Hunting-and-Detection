# DLL Hijacking: Loading from an Unusual Directory

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Medium](https://posts.bluraven.io/detecting-dll-hijacking-attacks-part-1-bdb354685164)


Language: Azure KQL

Products: MDE/M365D

Tables  : DeviceImageLoadEvents, DeviceFileCertificateInfo

Techniques:
- T1574.001:	DLL Search Order Hijacking
- T1574.002:	DLL Side-Loading
- T1574.007:	Path Interception by PATH Environment Variable
- T1574.008:	Path Interception by Search Order Hijacking
- T1574.009:	Path Interception by Unquoted Path

## Description

Below query detects DLL Hijacking scenario of planting a DLL having an invalid signature in a different folder and making an application load it instead of the original DLL.


## How the Query Works
Applications load DLLs from known directories. When hijacking occurs, the application starts loading the DLL from a different directory. The query performs historical comparison of directories where DLLs are loaded from and detects DLLs when they are loaded from an unusual directory. Because there are randomly named directories, the query performs normalization on them to reduce false positives. In-house/custom developed applications may still generate FPs. You can filter them out if needed. If you still get lots of FPs because of randomly named directories, uncomment the section mentioned in the query.



**Query:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post: https://posts.bluraven.io/detecting-dll-hijacking-attacks-part-1-bdb354685164
// Description: This query detects DLL Hijacking scenario of planting a DLL having an invalid signature in a different
//              folder and making an application load it instead of the original DLL.
//
// Query parameters:
let WinDevices = materialize (
    DeviceInfo
    | where Timestamp > ago(8d)
    | where OSPlatform startswith_cs "Windows"
    | summarize make_set(DeviceId)
    )
    ;
// Get Filenames that have more than 1 SHA1 and loaded by the same process
let FileNames = materialize (
    DeviceImageLoadEvents
    | where Timestamp > ago(8d)
    | where DeviceId in (WinDevices)
    | where isnotempty(SHA1) and isnotempty(InitiatingProcessFileName)
    | project FileName = tolower(FileName), SHA1, Process = tolower(InitiatingProcessFileName), DLLDir = tolower(tostring(parse_path(FolderPath).DirectoryPath)), ProcessDir = tolower(tostring(parse_path(InitiatingProcessFolderPath).DirectoryPath))
    | where DLLDir in ("c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs") or (not(DLLDir startswith "c:\\windows"))
    | where ProcessDir in ("c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs") or ProcessDir has_all ("Users","AppData") or ProcessDir has_any ("Program Files")
    | summarize hint.strategy=shuffle dcount(SHA1) by FileName, Process
    | where dcount_SHA1 > 1
    )
    ;
// From the Filenames, get SHA1 values and filter Filename-SHA1 if its loaded by a few proecsses and on a few devices
// Also, get first and last time of load of the file(based on SHA1, filename)
let Files = materialize (
    FileNames
    | join hint.strategy=shuffle kind=rightsemi (
        DeviceImageLoadEvents
        | where Timestamp > ago(8d)
        | where DeviceId in (WinDevices)
        | project Timestamp, DeviceName, FileName = tolower(FileName), SHA1, Process = tolower(InitiatingProcessFileName), DLLDir = tolower(tostring(parse_path(FolderPath).DirectoryPath)), ProcessDir = tolower(tostring(parse_path(InitiatingProcessFolderPath).DirectoryPath))
        | where DLLDir in ("c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs") or (not(DLLDir startswith "c:\\windows"))
        | where ProcessDir in ("c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs") or ProcessDir has_all ("Users","AppData") or ProcessDir has_any ("Program Files")
        | summarize hint.strategy=shuffle dcount(DeviceName), Process = make_set(Process), FirstLoad = min(Timestamp), LastLoad = max(Timestamp), count() by FileName, SHA1
        | where dcount_DeviceName < 3 and array_length(Process) < 3
        | mv-expand Process to typeof(string)
        )
        on FileName, Process
    )
    ;
// Files: Potentially suspicious files seen in the last 8d
// Next step: suspicious file (based on SHA1) should have been loaded from a location different than the other files(SHA1s) based on the same filename
// The suspicious file should have also been loaded recently
// Get files loaded in the last day (from the potentially suspicious files)
let Hashes = materialize (
    Files
    | where FirstLoad > ago(1d)
    | join (
        DeviceFileCertificateInfo
        | where Timestamp > ago(30d)
        | where not(IsTrusted )
        | summarize arg_max(Timestamp,*) by SHA1
        | project-away Timestamp, DeviceId, DeviceName) on SHA1
    | project-away SHA11
    )
    ;
// Get all image loads of the files that have the same name with the files in Hashes table(Hashes table only has the suspicious hash with its name from the last day)
Hashes
| join hint.strategy=shuffle kind=inner (
    DeviceImageLoadEvents
    | where Timestamp > ago(8d)
    | where DeviceId in (WinDevices)
    | project Timestamp, DeviceName, SHA1, FolderPath, FileName = tolower(FileName), Process = tolower(InitiatingProcessFileName), DLLDirectory = strcat(tolower(tostring(parse_path(FolderPath).DirectoryPath)), '\\'), ProcessDir = tolower(tostring(parse_path(InitiatingProcessFolderPath).DirectoryPath))
    | where DLLDirectory  in ("c:\\windows\\", "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\") or (not(DLLDirectory startswith "c:\\windows\\"))
    | where ProcessDir in ("c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs") or ProcessDir has_all ("Users","AppData") or ProcessDir has_any ("Program Files")
    | extend NormalizedDLLDirectory = replace(@'(c|d):\\users\\.*?\\', @'c:\\users\\userxx\\',DLLDirectory)
    | extend NormalizedDLLDirectory = replace(@'\{.*\}', @'\{xxxxxxxxxx\}',NormalizedDLLDirectory) //{fe07d7-d438-4dd9-bb0f-5721658f4f}
    | extend NormalizedDLLDirectory = replace(@'\\[A-Za-z0-9-]+-[A-Za-z0-9]+\\', @'\\xxxxxxxxxx\\',NormalizedDLLDirectory ) //\fe07d7-d438-4dd9-bb0f-5721658f4f\
    | extend NormalizedDLLDirectory = replace(@'\d+\.\d+\.\d+\.\d+', @'X.Y.Z.T',NormalizedDLLDirectory) // ex: Edge\Application\104.0.1293.47\process.exe
    | extend NormalizedDLLDirectory = replace(@'-\d+\.\d+\.\d+', @'-X.Y.Z',NormalizedDLLDirectory)
    | extend NormalizedDLLDirectory = replace(@'c:\\windows\\assembly\\nativeimages_v\d\.\d\.\d+_\d{2}\\.*', @'c:\\windows\\assembly\\nativeimages_vX.Y.Z_T\\oneoffewsubfolders\\', NormalizedDLLDirectory)
    | extend NormalizedDLLDirectory = replace(@'c:\\programdata\\.*?\\microsoft\\teams\\',@'c:\\programdata\\userxxx\\microsoft\\teams\\',NormalizedDLLDirectory)
    | summarize hint.strategy=shuffle by FileName, SHA1, NormalizedDLLDirectory
    )
    on FileName
    | project-rename OtherSHA1 = SHA11
    // Flag suspicious hash
    | extend Suspicious = iff(SHA1==OtherSHA1, 'TRUE', 'FALSE')
    // group properties of suspicious and previous files separately
    // we are looking for a filename that was loaded from previously unknown location
    | summarize hint.strategy=shuffle PreviousDirs = make_set_if(NormalizedDLLDirectory, Suspicious == 'FALSE'),
                NewDir = make_set_if(NormalizedDLLDirectory, Suspicious == 'TRUE'),
                PreviousSHA1s = make_set_if(OtherSHA1, Suspicious == 'FALSE'),
                NewSHA1 = make_set_if(SHA1, Suspicious == 'TRUE')
                by  FileName
    // compare the directory of the suspicous file with the previous directories
    | extend diff = set_difference(NewDir, PreviousDirs)
    // filter if the new(suspicious) file is loaded from previously known directory
    | where diff != '[]'
    | order by FileName
    // if you get lots of false positives, uncomment the below section.
    // this section compares the directory names in an alternative way.
    // | mv-expand NewDir to typeof(string), PreviousDirs to typeof(string)
    // | extend prev = split(PreviousDirs, '\\'), new = split(NewDir, '\\')
    // | extend diff_new = set_difference(new, prev)
    // | extend diff_count = array_length(diff_new)
    // | where diff_count > 1
    // | project-away prev, new, diff_count, diff
    // get file profile info and filter based on global prevalence
    | mv-expand NewSHA1 to typeof(string)
    | invoke FileProfile(NewSHA1, 1000)
    | where GlobalPrevalence < 200 or isempty(GlobalPrevalence)
```