# Process Tree Analysis
**Author:** [Cyb3rMonk](https://medium.com/@mergene)

**Link to Original Post**: [Medium](https://mergene.medium.com/detecting-threats-with-process-tree-analysis-without-machine-learning-838d85f78b2c)

Language: Azure KQL, Splunk SPL
Products: MDATP/MDE, Azure Sentinel (Sysmon), Splunk (Sysmon)


## Description

Below queries perform process tree analysis on MDE/MDATP, Azure Sentinel (Sysmon), and Splunk (Sysmon) and displays anomalous trees. 
All queries run smoothly even in the large environments. Detailed explanation is [here](https://mergene.medium.com/detecting-threats-with-process-tree-analysis-without-machine-learning-838d85f78b2c)

**Query for MDATP/MDE:**

```C#
let timeframe = 48h;
// Define of which processes you want to generate process tree
let _selected_processes = dynamic(["winword.exe","excel.exe","powerpnt.exe","acrord32.exe", "FoxitPhantomPDF.exe","MicrosoftPdfReader.exe","SumatraPDF.exe"]); 
// First, generate the process tree and store it in the cache.
// Renaming fields accordingly to generate a tree up to 7th level
// In each step, project only the required fields to optimize resource usage
let _process_tree_data= materialize 
( DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where InitiatingProcessFileName in~ (_selected_processes )
    | project DeviceId,DeviceName, 
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
_process_tree_data
|summarize count() by FileName,InitiatingProcessFileName,InitiatingProcessParentFileName,InitiatingProcessG1ParentFileName,InitiatingProcessG2ParentFileName,InitiatingProcessG3ParentFileName,InitiatingProcessG4ParentFileName
| where count_ < 10 // If the count of a pattern is less than 10, it is anomalous. Threshold can be changed.
// Now, join the anomalous patterns with the original results to get the details. 
| join kind=inner _process_tree_data on FileName,InitiatingProcessFileName,InitiatingProcessParentFileName,InitiatingProcessG1ParentFileName,InitiatingProcessG2ParentFileName,InitiatingProcessG3ParentFileName,InitiatingProcessG4ParentFileName
// Now, join the anomalous patterns with the original results to get the details. 
|project Timestamp=case(isnotempty(Timestamp),Timestamp,isnotempty(InitiatingProcessParentCreationTime),InitiatingProcessParentCreationTime,isnotempty(InitiatingProcessG1ParentCreationTime),InitiatingProcessG1ParentCreationTime,
    isnotempty(InitiatingProcessG2ParentCreationTime),InitiatingProcessG2ParentCreationTime,isnotempty(InitiatingProcessG3ParentCreationTime),InitiatingProcessG3ParentCreationTime,InitiatingProcessG4ParentCreationTime),
    count_ , DeviceId, DeviceName, 
    InitiatingProcessG4ParentFileName,InitiatingProcessG3ParentFileName,InitiatingProcessG2ParentFileName,InitiatingProcessG1ParentFileName,InitiatingProcessParentFileName,InitiatingProcessFileName,FileName,
    InitiatingProcessG4ParentCommandLine, InitiatingProcessG3ParentCommandLine, InitiatingProcessG2ParentCommandLine, InitiatingProcessG1ParentCommandLine, InitiatingProcessCommandLine, ProcessCommandLine,
    InitiatingProcessG4ParentId,  InitiatingProcessG4ParentCreationTime,
    InitiatingProcessG3ParentId, InitiatingProcessG3ParentFolderPath ,InitiatingProcessG3ParentSHA1,  InitiatingProcessG3ParentCreationTime,
    InitiatingProcessG2ParentId,InitiatingProcessG2ParentFolderPath,InitiatingProcessG2ParentSHA1, InitiatingProcessG2ParentCreationTime,
    InitiatingProcessG1ParentId,InitiatingProcessG1ParentFolderPath,InitiatingProcessG1ParentSHA1,  InitiatingProcessG1ParentCreationTime,
    InitiatingProcessParentId, InitiatingProcessParentFolderPath,InitiatingProcessParentSHA1, InitiatingProcessParentCommandLine ,InitiatingProcessParentCreationTime,
    InitiatingProcessId, InitiatingProcessSHA1,  InitiatingProcessCreationTime,
    ProcessId, SHA1,  ProcessCreationTime
| order by Timestamp, DeviceName, InitiatingProcessG4ParentCreationTime , InitiatingProcessG3ParentCreationTime , InitiatingProcessG2ParentCreationTime , InitiatingProcessG1ParentCreationTime , InitiatingProcessCreationTime
```

**Query for Azure Sentinel (Sysmon):**

```C#
let _timeframe = 1d;
// define of which processes you want to generate process tree
let _selected_processes = dynamic(["winword.exe","excel.exe","powerpnt.exe","acrord32.exe", "FoxitPhantomPDF.exe","MicrosoftPdfReader.exe","SumatraPDF.exe"]); 
// Sysmon logs are not parsed automatically, below function parses the Sysmon EventID=1 logs. 
let parse_sysmon_1 = (T:(TimeGenerated:datetime,EventID:int, Source:string,RenderedDescription:string, EventData:string))
{
T 
| where TimeGenerated > ago(_timeframe)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key=tostring(['@Name']), Value=['#text']
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)
| extend RuleName = column_ifexists("RuleName", ""), TechniqueId = column_ifexists("TechniqueId", ""),  TechniqueName = column_ifexists("TechniqueName", "")
| parse RuleName with * 'technique_id=' TechniqueId ',' * 'technique_name=' TechniqueName
};
// First, generate the process tree and store it in the cache
let _process_tree_data = materialize (
    // First, get only the processes created by selected process
    Event
    | invoke parse_sysmon_1() //parsing the sysmon logs
    // Get only the required fields. Rrenaming fields accordingly to generate a tree up to 5th level
    | project Computer,G2_ParentProcessId=tostring(ProcessId),G2_ParentProcess=tostring(OriginalFileName),G2_ParentProcessGuid=tostring(ProcessGuid),G2_ParentProcessCommandLine=tostring(CommandLine),
            G3_ParentProcessId=tostring(ParentProcessId),G3_ParentProcess=tostring(parse_path(tostring(ParentImage)).Filename),G3_ParentProcessGuid=tostring(ParentProcessGuid),G3_ParentProcessCommandLine=tostring(ParentCommandLine)
    | where G3_ParentProcess in~ (_selected_processes)
    // Start iteration
    // First iteration of join. From now on, query all processes, rename fields, and join accordingly
    | join kind=leftouter 
        (
            Event
            | invoke parse_sysmon_1()
            | project G1_ParentProcessId=tostring(ProcessId),G1_ParentProcess=tostring(OriginalFileName),G1_ParentProcessGuid=tostring(ProcessGuid),G1_ParentProcessCommandLine=tostring(CommandLine),
                G2_ParentProcessId=tostring(ParentProcessId),G2_ParentProcess=tostring(parse_path(tostring(ParentImage)).Filename),G2_ParentProcessGuid=tostring(ParentProcessGuid),G2_ParentProcessCommandLine=tostring(ParentCommandLine)
        ) on G2_ParentProcessGuid
        // Second iteration of join.
        | join kind=leftouter 
            (
                Event
                | invoke parse_sysmon_1()
                | project ParentProcessId=tostring(ProcessId),ParentProcess=tostring(OriginalFileName),ParentProcessGuid=tostring(ProcessGuid),ParentProcessCommandLine=tostring(CommandLine),
                        G1_ParentProcessId=tostring(ParentProcessId),G1_ParentProcess=tostring(parse_path(tostring(ParentImage)).Filename),G1_ParentProcessGuid=tostring(ParentProcessGuid),G1_ParentProcessCommandLine=tostring(ParentCommandLine)
            ) on G1_ParentProcessGuid
            // Third iteration of join.
            | join kind=leftouter
                (
                    Event
                    | invoke parse_sysmon_1()
                    | project ProcessId=tostring(ProcessId),Process=tostring(OriginalFileName),ProcessGuid=tostring(ProcessGuid),ProcessCommandLine=tostring(CommandLine),
                            ParentProcessId=tostring(ParentProcessId),ParentProcess=tostring(parse_path(tostring(ParentImage)).Filename),ParentProcessGuid=tostring(ParentProcessGuid),ParentProcessCommandLine=tostring(ParentCommandLine)
                ) on ParentProcessGuid
            );
// Use the cached results and find the rare patterns based on process names.
_process_tree_data
| summarize count() by Process, ParentProcess, G1_ParentProcess, G2_ParentProcess, G3_ParentProcess
| where count_ < 10 // If the count of a pattern is less than 10, it is anomalous. Threshold can be changed.
// Now, join the anomalous patterns with the original results to get the details. 
| join kind=inner _process_tree_data on Process, ParentProcess, G1_ParentProcess, G2_ParentProcess, G3_ParentProcess
| project-reorder Computer, count_, G3_ParentProcess, G2_ParentProcess, G1_ParentProcess, ParentProcess, Process, 
                  G3_ParentProcessCommandLine, G2_ParentProcessCommandLine, G1_ParentProcessCommandLine, ParentProcessCommandLine, ProcessCommandLine,
                  G3_ParentProcessId, G2_ParentProcessId, G1_ParentProcessId, ParentProcessId, ProcessId
```

**Query for Splunk (Sysmon):**
```C#
```define of which processes you want to generate process tree and analyse ```
index="sysmon" EventCode=1 (ParentImage="*cmd.exe" OR ParentImage="*svchost.exe") 
``` Extract Process from ParentImage.```
| rex field=ParentImage "(?<G3_ParentProcess>[^\\\]+)$" 
```  To generate tree up to 5th level, renaming fields accordingly. ```
| rename ProcessId as G2_ParentProcessId, OriginalFileName as G2_ParentProcess ,ProcessGuid as G2_ParentProcessGuid,CommandLine as G2_ParentProcessCommandLine,ParentProcessId as G3_ParentProcessId, ParentProcessGuid as G3_ParentProcessGuid,ParentCommandLine as G3_ParentProcessCommandLine 
``` get only the required fields. this reduces the resource usage and improves the performance```
| fields G3_ParentProcessGuid, G3_ParentProcessId, G3_ParentProcess, G3_ParentProcessCommandLine, G2_ParentProcessGuid, G2_ParentProcessId, G2_ParentProcess, G2_ParentProcessCommandLine | fields - _*
  ``` first iteration of join. this time, all process events are searched. same extraction, renaming and selecting fields. ```
  | join type=left G2_ParentProcessGuid 
    [search index="sysmon" EventCode=1 | rex field=ParentImage "(?<G2_ParentProcess>[^\\\]+)$" 
     | rename ProcessId as G1_ParentProcessId, OriginalFileName as G1_ParentProcess, ProcessGuid as G1_ParentProcessGuid, CommandLine as G1_ParentProcessCommandLine, ParentProcessId as G2_ParentProcessId, ParentProcessGuid as G2_ParentProcessGuid,ParentCommandLine as G2_ParentProcessCommandLine 
     | fields G2_ParentProcessGuid, G2_ParentProcessId, G2_ParentProcess, G2_ParentProcessCommandLine, G1_ParentProcessGuid, G1_ParentProcessId, G1_ParentProcess, G1_ParentProcessCommandLine | fields - _* ]
     ``` second itetaration of join. same stuff as the first iteration ```
	 | join type=left G1_ParentProcessGuid 
	   [search index="sysmon" EventCode=1 | rex field=ParentImage "(?<G1_ParentProcess>[^\\\]+)$" 
	    | rename ProcessId as ParentProcessId, OriginalFileName as ParentProcess, ProcessGuid as ParentProcessGuid, CommandLine as ParentProcessCommandLine, ParentProcessId as G1_ParentProcessId, ParentProcessGuid as G1_ParentProcessGuid,ParentCommandLine as G1_ParentProcessCommandLine 
	    | fields G1_ParentProcessGuid, G1_ParentProcessId, G1_ParentProcess, G1_ParentProcessCommandLine, ParentProcessGuid, ParentProcessId, ParentProcess, ParentProcessCommandLine | fields - _*]
	    ``` third itetaration of join. same stuff. ```
		| join type=left ParentProcessGuid 
		  [search index="sysmon" EventCode=1 | rex field=ParentImage "(?<ParentProcess>[^\\\]+)$" 
		   | rename OriginalFileName as Process, CommandLine as ProcessCommandLine, ParentCommandLine as ParentProcessCommandLine 
		   | fields ParentProcessGuid, ParentProcessId, ParentProcess, ParentProcessCommandLine, ProcessGuid, ProcessId, Process, ProcessCommandLine | fields - _* ]
``` before calculating the stas, we need to fill null values with a string ```
| fillnull value=NULL
``` Get rare process trees. ```
| eventstats count by G3_ParentProcess, G2_ParentProcess, G1_ParentProcess, ParentProcess, Process | where count <8
```
