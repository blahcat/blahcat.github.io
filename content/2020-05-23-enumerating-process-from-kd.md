date: 2020-05-23 00:00:00
modified: 2020-05-23 00:00:00
title: Enumerating processes from KD
author: hugsy
category: cheatsheet
tags: windows, kernel, process


This is tiny Post-It post to remind of different ways to enumerate processes from KD:

 - using `nt!PsActiveProcessHead`
```
dx Debugger.Utility.Collections.FromListEntry( *(nt!_LIST_ENTRY*)&(nt!PsActiveProcessHead), "nt!_EPROCESS", "ActiveProcessLinks")
```

 - using `afd!AfdEndpointListHead`
```
dx Debugger.Utility.Collections.FromListEntry( *(nt!_LIST_ENTRY*)&(afd!AfdEndpointListHead), "nt!_EPROCESS", "ActiveProcessLinks")
```

 - using `nt!KiProcessListHead`
```
dx Debugger.Utility.Collections.FromListEntry( *(nt!_LIST_ENTRY*)&(nt!KiProcessListHead), "nt!_KPROCESS", "ProcessListEntry").Select( p => new {Process = (nt!_EPROCESS*)&p )
```

 - using `nt!HandleTableListHead`
```
dx Debugger.Utility.Collections.FromListEntry(*(nt!_LIST_ENTRY*)&nt!HandleTableListHead, "nt!_HANDLE_TABLE", "HandleTableList").Where(h => h.QuotaProcess != 0).Select( qp => new {Process= qp.QuotaProcess} )
```