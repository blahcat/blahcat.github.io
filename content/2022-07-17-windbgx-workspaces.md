date: 2022-07-17 00:00:00
modified: 2022-07-17 00:00:00
title: WinDbgX undocumented workspace options
author: hugsy
category: minis
tags: windows, windbg

How to use WinDbgX workspaces to make debugging even easier.

## Workspaces

WinDbgX workspaces (suffixed `.debugTargets`) are nothing more than XML files that instructs WinDbgX how to process with the current debugging session.
Saved workspaces can be found in `%LOCALAPPDATA%\DBG\Targets`

```xml
<?xml version="1.0" encoding="utf-8"?>
<TargetConfig Name="C:\Windows\System32\notepad.exe" LastUsed="2022-07-14T23:44:46.0958299Z">
  <EngineConfig />
  <EngineOptions>
    <Property name="DebugChildProcesses" value="false" />
  </EngineOptions>
  <TargetOptions>
    <Option name="LaunchProcess">
      <Property name="Executable" value="C:\Windows\System32\notepad.exe" />
      <Property name="Arguments" value="" />
    </Option>
  </TargetOptions>
</TargetConfig>
```


## Useful Workspaces

Unfortunately the DTD is not documented [and probably will never be](https://twitter.com/timmisiak/status/1547264830574174209), but all it takes is a quick look at the `DbgX.Interfaces.Internal.dll` .NET library to see the namespace `Dbgx.Interfaces.Target.Options` which holds [all the supported options](https://gist.github.com/hugsy/742066e1fe6e8b078d65f66f790c52b7#:~:text=%5B-,OptionName,-%3D%20%22AttachProcess).

Some examples:

### Launch `notepad` process and auto-execute commands

Also put a dummy breakpoint at 0x4242424242424242. Also forge a fake history, useful for avoiding copy/paste of commands between session!

```xml
<?xml version="1.0" encoding="utf-8"?>
<TargetConfig Name="C:\Windows\System32\notepad.exe" LastUsed="2022-07-14T23:44:46.0958299Z">
  <EngineConfig />
  <EngineOptions>
    <Property name="DebugChildProcesses" value="false" />
  </EngineOptions>
  <TargetOptions>
    <Option name="LaunchProcess">
      <Property name="Executable" value="C:\Windows\System32\notepad.exe" />
      <Property name="Arguments" value="" />
    </Option>
    <Option name="ExecuteCommand">
      <Property name="Command" value="bu 4242424242424242" />
    </Option>
    <Option name="RestorecommendHistory">
      <Property name="History">
        <Property value="dx @$curprocess.Environment.EnvironmentBlock.ProcessParameters" />
      </Property>
    </Option>
  </TargetOptions>
</TargetConfig>
```

### Attach (and auto-elevate) a service by Name

Here with `CryptSvc`. Also make the border red so we can find the window easily!

```xml
<?xml version="1.0" encoding="utf-8"?>
<TargetConfig Name="Attach Service" LastUsed="2031-01-01T05:23:58.2908827Z" AccentColor="#FFFF0000">
    <EngineConfig />
    <EngineOptions />
    <TargetOptions>
        <Option name="AttachService">
            <Property name="Elevate" value="true" />
            <Property name="ServiceName" value="CryptSvc" />
        </Option>
    </TargetOptions>
</TargetConfig>
```
![image](https://user-images.githubusercontent.com/590234/179410823-7b10187c-cd85-46cc-a8c5-f44ff61a5db5.png)

### Setup a ARM64 Qemu debugging profile

[Using EXDI](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/configuring-the-exdi-debugger-transport), and the provided `ExdiGdbSrv.dll` (in `C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2206.19001.0_x64__8wekyb3d8bbwe\amd64\ExdiGdbSrv.dll`)

```
regsvr32 ExdiGdbSrv.dll
```

You can check out `C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2206.19001.0_x64__8wekyb3d8bbwe\amd64\exdiConfigData.xml` to see all the targets already created.
```xml
<ExdiTargets CurrentTarget = "QEMU">
[...]
  <!-- QEMU SW simulator GDB server configuration -->
  <ExdiTarget Name = "QEMU">
    <ExdiGdbServerConfigData agentNamePacket = "" uuid = "72d4aeda-9723-4972-b89a-679ac79810ef" displayCommPackets = "yes" debuggerSessionByCore = "no" enableThrowExceptionOnMemoryErrors = "yes" qSupportedPacket="qSupported:xmlRegisters=aarch64,i386">
      <ExdiGdbServerTargetData targetArchitecture = "ARM64" targetFamily = "ProcessorFamilyARM64" numberOfCores = "1" EnableSseContext = "no" heuristicScanSize = "0xffe" targetDescriptionFile = "target.xml" />
      <GdbServerConnectionParameters MultiCoreGdbServerSessions = "no" MaximumGdbServerPacketLength = "1024" MaximumConnectAttempts = "3" SendPacketTimeout = "100" ReceivePacketTimeout = "3000">
        <Value HostNameAndPort="LocalHost:1234" />
      </GdbServerConnectionParameters>
      <ExdiGdbServerMemoryCommands GdbSpecialMemoryCommand = "no" PhysicalMemory = "no" SupervisorMemory = "no" HypervisorMemory = "no" SpecialMemoryRegister = "no" SystemRegistersGdbMonitor = "no" SystemRegisterDecoding = "no">
      </ExdiGdbServerMemoryCommands>
[...]
```

And create the workspace:
```xml
<?xml version="1.0" encoding="utf-8"?>
<TargetConfig Name="WinDbg Is Awesome" LastUsed="2019-07-16T05:23:58.2908827Z" AccentColor="#FFCA5100">
  <EngineConfig />
  <EngineOptions />
  <TargetOptions>
    <Option name="KernelConnect">
      <Property name="ConnectionString" value="exdi:CLSID={72d4aeda-9723-4972-b89a-679ac79810ef},Kd=NtBaseAddr,DataBreaks=Exdi" />
      <Property name="ConnectionType" value="EXDI" />
      <Property name="QuietMode" value="false" />
      <Property name="InitialBreak" value="true" />
    </Option>
  </TargetOptions>
</TargetConfig>
```

Enjoy 🍻
