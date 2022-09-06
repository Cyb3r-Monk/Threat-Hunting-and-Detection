# DLL Hijacking - HijackLibs

**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )


Language: Azure KQL

Products: MDE/M365D

Tables  : DeviceImageLoadEvents


## Description

Below query detects DLL Hijacking that involves the DLLs and Processes shared by [Wietze](https://twitter.com/Wietze) in the [HijackLibs](https://github.com/wietze/HijackLibs) repo. False Positives(especially zoom.exe) and some false negatives might happen since the query is prepared in a semi-automated way.

**NOTE:** The query uses the HijakLibs data as of 2022/08/14 18:36. It will be updated on a regular basis.

## How Query Works
All YAML files are parsed into a CSV file only with the DLL Name, ExpectedLocations and VulnerableExecutables fields. The CSV file can be find here

Since the YAML files have `%System32%`, `%APPDATA%`, `%VERSION%`, etc. as conditions, events in the DeviceImageLoadEvents are normalized so that Process and Directory information matches the information in the YAML files. Then, Image loads that contain the DLLs in the YAML files are queried by joinin the HijackLibs.csv. Lastly, the query result is joined with the HijackLibs again to filter out the expected locations.



**Query:**
---

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
//
// Query parameters:
let HijackLibs = externaldata(DLLName:string, ExpectedLocation:string, Process: string )
[@"https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/raw/main/Defense%20Evasion/HijackLibs.csv"]
with (format="csv", ignoreFirstRecord=True);
//
HijackLibs
| join hint.strategy=shuffle kind=rightsemi(
    DeviceImageLoadEvents
    | extend DLLDir =  case(FolderPath startswith "C:\\windows\\system32\\driverstore\\filerepository\\prnms002.inf", replace_regex(tolower(FolderPath), @'c:\\windows\\system32\\driverstore\\filerepository\\prnms002\.inf_.*\\amd64', @'%SYSTEM32%\\driverstore\\filerepository\\prnms002.inf_%VERSION%\\amd64'),
                            FolderPath has_all ('Windows Kits', 'bin', 'x86'), '%PROGRAMFILES%\\windows kits\\10\\bin\\%VERSION%\\x86',
                            FolderPath has_all ('Windows Kits', 'bin', 'x64'), '%PROGRAMFILES%\\windows kits\\10\\bin\\%VERSION%\\x64',
                            FolderPath has_all ('Windows Kits', 'bin', 'arm64'), '%PROGRAMFILES%\\Windows Kits\\10\\bin\\%VERSION%\\arm64',
                            FolderPath has_all ('Program Files', 'Edge', 'Application'),  tolower('%PROGRAMFILES%\\microsoft\\edge\\application\\%VERSION%'),
                            FolderPath has_all ('Program Files', 'Microsoft Office', 'root'),  tolower('%PROGRAMFILES%\\microsoft office\\root\\office%VERSION%'),
                            FolderPath contains '\\Microsoft Office\\Office',  tolower('%PROGRAMFILES%\\Microsoft Office\\OFFICE%VERSION%'),
                            FolderPath has_all ('ProgramData', 'Microsoft', 'Windows Defender', 'Platform'), tolower('%PROGRAMDATA%\\Microsoft\\Windows Defender\\Platform\\%VERSION%'),
                            FolderPath startswith "C:\\Program Files (x86)", tolower(replace_string(tolower(FolderPath), 'c:\\program files (x86)', '%programfiles%')),
                            FolderPath startswith "C:\\Program Files", tolower(replace_string(tolower(FolderPath), 'c:\\program files', '%programfiles%')),
                            FolderPath startswith "C:\\WINDOWS\\SysWow64", tolower(replace_string(tolower(FolderPath), 'c:\\windows\\syswow64', '%syswow64%')),
                            FolderPath startswith "C:\\WINDOWS\\System32", tolower(replace_string(tolower(FolderPath), 'c:\\windows\\system32', '%system32%')),
                            FolderPath startswith "C:\\ProgramData", tolower(replace_string(tolower(FolderPath), 'c:\\programdata', '%programdata%')),
                            FolderPath has "AppData\\Local", tolower(replace_regex(tolower(FolderPath), @'c:\\users\\.*\\appdata\\local', '%localappdata%')),
                            FolderPath has "AppData\\Roaming", tolower(replace_regex(tolower(FolderPath), @'c:\\users\\.*\\appdata\\roaming', '%appdata%')),
                            tolower(FolderPath)),
            Process = case( InitiatingProcessFolderPath has_all ('WindowsApps', 'msteams.exe'), tolower('%PROGRAMFILES%\\WindowsApps\\MicrosoftTeams%VERSION%\\msteams.exe'),
                            InitiatingProcessFolderPath has_all ('Windows Kits', 'x86', 'oleview.exe'), tolower('%PROGRAMFILES%\\Windows Kits\\10\\bin\\%VERSION%\\x86\\oleview.exe'),
                            InitiatingProcessFolderPath has_all ('Windows Kits', 'x64', 'oleview.exe'), tolower('%PROGRAMFILES%\\Windows Kits\\10\\bin\\%VERSION%\\x64\\oleview.exe'),
                            InitiatingProcessFolderPath has_all ('Windows Kits', 'arm64', 'oleview.exe'), tolower('%PROGRAMFILES%\\Windows Kits\\10\\bin\\%VERSION%\\arm64\\oleview.exe'),
                            InitiatingProcessFolderPath has_all ('Program Files', 'trend micro', 'pwmsvc.exe'), tolower('%PROGRAMFILES%\\trend micro\\passwordmanager\\pwmsvc.exe'),
                            InitiatingProcessFolderPath has_all ('Program Files', 'trend micro', 'coreserviceshell.exe'), tolower('%PROGRAMFILES%\\trend micro\\amsp\\coreserviceshell.exe'),
                            InitiatingProcessFolderPath has_all ('Program Files', 'EdgeWebView', 'Application', 'msedgewebview2.exe'),  tolower('%PROGRAMFILES%\\Microsoft\\EdgeWebView\\Application\\%VERSION%\\msedgewebview2.exe'),
                            InitiatingProcessFolderPath has_all ('Program Files', 'Microsoft Office', 'root'),  tolower(replace_regex(InitiatingProcessFolderPath, @'.*?\\Microsoft Office\\root\\Office.*\\(.*)', @'%PROGRAMFILES%\\Microsoft Office\\root\\Office%VERSION%\\\1')),
                            InitiatingProcessFolderPath has_all ('Program Files', 'Microsoft Office', 'outlook.exe'),  tolower('%PROGRAMFILES%\\Microsoft Office\\OFFICE%VERSION%\\outlook.exe'),
                            InitiatingProcessFolderPath has_all ('Program Files', 'Microsoft', 'Windows Defender', 'MsMpEng'),   tolower('%PROGRAMDATA%\\Microsoft\\Windows Defender\\Platform\\%VERSION%\\MsMpEng.exe'),
                            InitiatingProcessFolderPath startswith "C:\\Program Files (x86)", tolower(replace_string(tolower(InitiatingProcessFolderPath), 'c:\\program files (x86)', '%programfiles%')),
                            InitiatingProcessFolderPath startswith "C:\\Program Files", tolower(replace_string(tolower(InitiatingProcessFolderPath), 'c:\\program files', '%programfiles%')),
                            InitiatingProcessFolderPath startswith "C:\\WINDOWS", tolower(replace_string(tolower(InitiatingProcessFolderPath), 'c:\\windows', '%windir%')),
                            InitiatingProcessFolderPath startswith "C:\\WINDOWS\\System32", tolower(replace_string(tolower(InitiatingProcessFolderPath), 'c:\\windows\\system32', '%system32%')),
                            InitiatingProcessFolderPath startswith "C:\\ProgramData", tolower(replace_string(tolower(InitiatingProcessFolderPath), 'c:\\programdata', '%programdata%')),
                            InitiatingProcessFolderPath has "AppData\\Local", tolower(replace_regex(tolower(InitiatingProcessFolderPath), @'c:\\users\\.*\\appdata\\local', '%localappdata%')),
                            InitiatingProcessFolderPath has "AppData\\Roaming", tolower(replace_regex(tolower(InitiatingProcessFolderPath), @'c:\\users\\.*\\appdata\\roaming', '%appdata%')),
                            tolower(InitiatingProcessFolderPath)),
            DLLName = tolower(FileName)
    )
    on Process, DLLName
    | extend DLLDir = tostring(parse_path(DLLDir).DirectoryPath)
    | join kind=leftanti HijackLibs on Process, DLLName, $left.DLLDir==$right.ExpectedLocation
```