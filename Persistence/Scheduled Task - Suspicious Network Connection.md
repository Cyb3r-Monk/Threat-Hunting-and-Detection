# Scheduled Task - Suspicious Network Connection
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

**Link to Original Post**: [Medium](https://mergene.medium.com/hunting-for-the-behavior-scheduled-tasks-9efe0b8ade40)

Language: Azure KQL

Products: MDATP/MDE/M365D


## Description

Below query performs process tree analysis for Scheduled Tasks on MDE/MDATP/M365D and displays anomalous trees. Then, it gets all network connections made by every single process in each anomalous process tree.
Before using the query, do a quick analysis on commandlines of the processes spawned by Scheduled Tasks. There might be specific processes executing with a unique argument on each device. You need to whitelist them to get better results.

**Query:**

```C#
// Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
// Link to original post: https://mergene.medium.com/hunting-for-the-behavior-scheduled-tasks-9efe0b8ade40
// Hypothesis: The goal of the persistence is keeping the C2 channel active.
// This query performs process tree analysis for Scheduled Tasks on MDE/MDATP/M365D and displays anomalous trees.
// Then, it gets all network connections made by every single process in each anomalous process tree.
// Before using the query, do a quick analysis on commandlines of the processes spawned by Scheduled Tasks. 
// There might be specific processes executing with a unique argument on each device. You need to whitelist them to get better results.
let timeframe=7d;
let whitelisted_cmdlines = dynamic(["put_whiltested_commandlines_here"]);
let whitelist_folderpath = dynamic(["put_whitelisted_folderpaths-here"]);
let _process_tree_data = materialize ( 
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where InitiatingProcessFileName == "svchost.exe" and InitiatingProcessCommandLine == "svchost.exe -k netsvcs -p -s Schedule"
    | where not( ProcessCommandLine  has_any  (whitelisted_cmdlines ))
    | where not (FolderPath has_any (whitelist_folderpath))
    | summarize dcount(DeviceId), count() by ProcessCommandLine, FileName
    | where dcount_DeviceId <= 5
    | join kind=inner (
        DeviceProcessEvents
        | where Timestamp > ago(timeframe)
        | where InitiatingProcessFileName == "svchost.exe" and InitiatingProcessCommandLine == "svchost.exe -k netsvcs -p -s Schedule"
        | where not( ProcessCommandLine  has_any  (whitelisted_cmdlines ))
        | where not (FolderPath has_any (whitelist_folderpath))
        ) on ProcessCommandLine
        | project DeviceId,DeviceName, Timestamp,
              InitiatingProcessG3ParentFileName=FileName,InitiatingProcessG3ParentSHA1=SHA1,InitiatingProcessG3ParentId=ProcessId, InitiatingProcessG3ParentCommandLine=ProcessCommandLine,InitiatingProcessG3ParentCreationTime=todatetime(ProcessCreationTime),
              InitiatingProcessG4ParentFileName=InitiatingProcessFileName,InitiatingProcessG4ParentSHA1=InitiatingProcessSHA1,InitiatingProcessG4ParentId=InitiatingProcessId,InitiatingProcessG4ParentCommandLine=InitiatingProcessCommandLine, InitiatingProcessG4ParentCreationTime=todatetime(InitiatingProcessCreationTime)
        // Start iteration
        // 1st iteration of join. From now on, query all processes, rename fields, and join accordingly
        | join kind=leftouter (
            DeviceProcessEvents
            | where Timestamp > ago(timeframe)
            | project DeviceId, InitiatingProcessG2ParentFileName=FileName,InitiatingProcessG2ParentFolderPath=FolderPath,InitiatingProcessG2ParentSHA1=SHA1, InitiatingProcessG2ParentId=ProcessId,  InitiatingProcessG2ParentCommandLine=ProcessCommandLine, InitiatingProcessG2ParentCreationTime=todatetime(ProcessCreationTime), 
                      InitiatingProcessG3ParentFileName=InitiatingProcessFileName,InitiatingProcessG3ParentFolderPath=InitiatingProcessFolderPath,InitiatingProcessG3ParentSHA1=InitiatingProcessSHA1, InitiatingProcessG3ParentId=InitiatingProcessId,  InitiatingProcessG3ParentCommandLine=InitiatingProcessCommandLine, InitiatingProcessG3ParentCreationTime=todatetime(InitiatingProcessCreationTime)
            ) 
            on DeviceId , InitiatingProcessG3ParentFileName, InitiatingProcessG3ParentId, InitiatingProcessG3ParentCreationTime
            // 2nd iteration of join.
            | join kind=leftouter (
                DeviceProcessEvents
                | where Timestamp > ago(timeframe)
                | project DeviceId, InitiatingProcessG1ParentFileName=FileName,InitiatingProcessG1ParentFolderPath=FolderPath,InitiatingProcessG1ParentSHA1=SHA1, InitiatingProcessG1ParentId=ProcessId,  InitiatingProcessG1ParentCommandLine=ProcessCommandLine, InitiatingProcessG1ParentCreationTime=todatetime(ProcessCreationTime), 
                          InitiatingProcessG2ParentFileName=InitiatingProcessFileName,InitiatingProcessG2ParentFolderPath=InitiatingProcessFolderPath,InitiatingProcessG2ParentSHA1=InitiatingProcessSHA1, InitiatingProcessG2ParentId=InitiatingProcessId,  InitiatingProcessG2ParentCommandLine=InitiatingProcessCommandLine, InitiatingProcessG2ParentCreationTime=todatetime(InitiatingProcessCreationTime)
                ) 
                on DeviceId , InitiatingProcessG2ParentFileName , InitiatingProcessG2ParentId, InitiatingProcessG2ParentCreationTime
                // 3rd iteration of join.
                | join kind=leftouter (
                    DeviceProcessEvents
                    | where Timestamp > ago(timeframe)
                    | project DeviceId, InitiatingProcessParentFileName=FileName,InitiatingProcessParentFolderPath=FolderPath,InitiatingProcessParentSHA1=SHA1, InitiatingProcessParentId=ProcessId,  InitiatingProcessParentCommandLine=ProcessCommandLine, InitiatingProcessParentCreationTime=ProcessCreationTime, 
                              InitiatingProcessG1ParentFileName=InitiatingProcessFileName,InitiatingProcessG1ParentFolderPath=InitiatingProcessFolderPath,InitiatingProcessG1ParentSHA1=InitiatingProcessSHA1, InitiatingProcessG1ParentId=InitiatingProcessId,  InitiatingProcessG1ParentCommandLine=InitiatingProcessCommandLine, InitiatingProcessG1ParentCreationTime=todatetime(InitiatingProcessCreationTime)
                    ) 
                    on DeviceId , InitiatingProcessG1ParentFileName , InitiatingProcessG1ParentId, InitiatingProcessG1ParentCreationTime
                    // 4th iteration of join
                    | join kind=leftouter (
                        DeviceProcessEvents
                        | where Timestamp > ago(timeframe)
                        | project DeviceId, InitiatingProcessFileName=FileName,InitiatingProcessSHA1=SHA1, InitiatingProcessId=ProcessId,  InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessCreationTime=ProcessCreationTime, 
                                  InitiatingProcessParentFileName=InitiatingProcessFileName,InitiatingProcessParentSHA1=InitiatingProcessSHA1, InitiatingProcessParentId=InitiatingProcessId,  InitiatingProcessParentCommandLine=InitiatingProcessCommandLine, InitiatingProcessParentCreationTime=InitiatingProcessCreationTime
                        ) 
                        on DeviceId , InitiatingProcessParentFileName , InitiatingProcessParentId, InitiatingProcessParentCreationTime
                        // 5th iteration of join
                        | join kind=leftouter (
                            DeviceProcessEvents
                            | where Timestamp > ago(timeframe)
                            | project Timestamp, DeviceId, FileName,SHA1, ProcessId, ProcessCommandLine, ProcessCreationTime, 
                                      InitiatingProcessFileName,InitiatingProcessSHA1, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessCreationTime
                            ) 
                            on DeviceId , InitiatingProcessFileName , InitiatingProcessId, InitiatingProcessCreationTime
);
// Use the cached results and find the rare patterns based on process names.
// New fields "ProcessVersionInfoOriginalFileName" and "InitiatingProcessVersionInfoInternalFileName" can be used as well. 
_process_tree_data
| where Timestamp > ago(1d) // get only the trees from last 1d. 
// get the last occurence of the rare patterns. 
| summarize arg_max(Timestamp,*), pattern_count=count() by DeviceId, InitiatingProcessG3ParentFileName, InitiatingProcessG2ParentFileName, InitiatingProcessG1ParentFileName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName
// We need to put all process nodes to the same column so that we can apply join for each process node. 
| extend N_InitiatingProcessFileName = pack_array(InitiatingProcessG3ParentFileName,InitiatingProcessG2ParentFileName,InitiatingProcessG1ParentFileName,InitiatingProcessParentFileName,InitiatingProcessFileName,FileName),
         N_InitiatingProcessCommandLine = pack_array(InitiatingProcessG3ParentCommandLine, InitiatingProcessG2ParentCommandLine, InitiatingProcessG1ParentCommandLine, InitiatingProcessParentCommandLine, InitiatingProcessCommandLine, ProcessCommandLine),
         N_InitiatingProcessId = pack_array(InitiatingProcessG3ParentId,InitiatingProcessG2ParentId,InitiatingProcessG1ParentId,InitiatingProcessParentId,InitiatingProcessId,ProcessId),
         N_InitiatingProcessCreationTime = pack_array(InitiatingProcessG3ParentCreationTime,InitiatingProcessG2ParentCreationTime,InitiatingProcessG1ParentCreationTime,InitiatingProcessParentCreationTime,InitiatingProcessCreationTime,ProcessCreationTime)
// apply mv-expand so that all process nodes are put into the same columns.
| mv-expand N_InitiatingProcessFileName, N_InitiatingProcessCommandLine, N_InitiatingProcessId, N_InitiatingProcessCreationTime
// generate a key for the join with DeviceNetworkEvents, remove rows if the process info is null(mv-expand results in some null values)
| extend join_key = strcat(DeviceId,'-',N_InitiatingProcessFileName,'-',N_InitiatingProcessId,'-',tostring(N_InitiatingProcessCreationTime))
| where isnotnull(N_InitiatingProcessId)
// generate join key for the DeviceNetworkEvents and apply join and exclude internal trafic(you may want to check internal traffic for lateral movement)
| join kind=inner (DeviceNetworkEvents | where Timestamp > ago(timeframe)| extend join_key = strcat(DeviceId,'-', InitiatingProcessFileName,'-', InitiatingProcessId,'-', tostring(InitiatingProcessCreationTime)) ) on join_key
| where RemoteIP !in ("::1","127.0.0.1","::ffff:127.0.0.1") and RemoteIPType <> "Private"
| where not(RemoteUrl has_any("corel.com","ocsp.digicert.com","avast.com"))
| where ActionType != "ListeningConnectionCreated"
| project-reorder pattern_count, RemoteUrl, RemoteIP, RemotePort
```
