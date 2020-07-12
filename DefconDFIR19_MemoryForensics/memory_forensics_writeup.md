
# DEFCON DFIR 2019 Memory Forensics 

A year late but nonetheless a very good practice opportunity and a lot of lessons learned. This is my writeup on the DEFCON DFIR 2019 memory forensic image.

### Memory Image 

I got the image from [here](https://www.dropbox.com/sh/4qfk1miauqbvqst/AAAVCI1G8Sc8xMoqK_TtmSbia?dl=0), which was shared in an awesome write up by [Jai Minton](https://www.jaiminton.com/Defcon/DFIR-2019) // spoiler alert.  

### My Setup  

- [SIFT Workstation](https://digital-forensics.sans.org/community/downloads) Ubuntu 16.04 on virtual box
- Windows 10 host

### Lets GO

**get your volatility on - 5 Points  | What is the SHA1 hash of memory file?**

Multiple ways to get this done: 
- Powershell Get-FileHash if you're doing it on windows 
- Gtkhash is a cool tool to have on liunx OR 
- Use sha1sum, sha265sum, MD5sum.. on a bash shell 
```
Hash = c95e8cc8c946f95a109ea8e47a6800de10a27abd
```

**pr0file - 10 Points | What is the most suitable profile?**

Volatility allows identification of OS, service pack hardware architecture and other info using the “imageinfo” plugin. It suggests multiple profiles that fit the image, usually the first one is the most suitable. But we can get a more accurate result with kdbgscan.
As opposed to imageinfo which simply provides profile suggestions, kdbgscan is designed to positively identify the correct profile. 
```
Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP0x64, Win7SP1x64, Win2008R2SP0x64, Win2008R2SP1x64
                     AS Layer1 : AMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/noah/defcon-dfir/triage.mem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800029f80a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff800029f9d00L
                KPCR for CPU 1 : 0xfffff880009ee000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-03-22 05:46:00 UTC+0000
     Image local date and time : 2019-03-22 01:46:00 -0400
```

```
$ volatility -f triage.mem kdbgscan
Volatility Foundation Volatility Framework 2.5
**************************************************
Instantiating KDBG using: /home/noah/defcon-dfir/triage.mem WinXPSP2x86 (5.1.0 32bit)
Offset (P)                    : 0x29f80a0
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win7SP1x64
PsActiveProcessHead           : 0x2a2e590
PsLoadedModuleList            : 0x2a4c890
KernelBase                    : 0xfffff80002808000

**************************************************
```

```
Profile to use = Win7SP1x64
```

**hey, write this down - 12 Points | What is the process id of notepad.exe ?**

-	Run volatility psscan or pslist plugin 
    - Pslist : similar to running tasklist, task manager on windows. Works based on the linked list structure of running processes, so does not show processes that have been removed from the linked list. // basically you can’t see hidden processes 
    - Psscan: searches memory for EPROCESS structure that represent processes and lists them. // shows everything (psscan2 and psscan3 also exist for more difficult to detect processes) 

![](/DefconDFIR19_MemoryForensics/files/pslist.jpg)

```
Process ID of notepad.exe = 3032
```

**wscript can haz children - 14 Points | Name child processes of wscript.exe**

- Run volatility with pstree plugin. Thing to note, pstree uses result of pslist and then shows a parent child relationship

![](/DefconDFIR19_MemoryForensics/files/pstree.jpg)

```
Wscript.exe child process = UWkpjFjDzM.exe // suspicious process  PID 3496
```

**tcpip settings - 18 Points | What is the IP address of the machine at the time the RAM dump was created?**

-	Run volatility with netscan plugin. Netscan for all network artifacts 
-	_volatility -f triage.mem --profile=Win7SP1x64 netscan_

```
IP address of the machine = 10.0.0.101
```

**intel - 18 Points | Based on the answer regarding to the infected PID, can you determine what the IP of the attacker was?**

-	The suspicious process that we found earlier was UWkpjFjDzM.exe with PID 3496 
-	Netscan results show the same process establishing a connection

![](/DefconDFIR19_MemoryForensics/files/netscan.jpg)
```
IP address of the machine = 10.0.0.106
```

**i <3 windows dependencies - 20 Points | What process name is VCRUNTIME140.dll associated with?**

-	Run volatility with dlllist plugin which shows a list of all loaded dlls by process and grep based on dll name VCRUNTIME140.dll. Grepping a chunk of preceding  text shows the associated service and its PID

![](/DefconDFIR19_MemoryForensics/files/dlllist.jpg)
```
Process name = OfficeClickToRun | PID: 1136
```

**mal-ware-are-you - 20 Points | What is the MD5 value of the potential malware on the system ?**

-	We know that the suspicious executable on the host is UWkpjFjDzM.exe from question 4. Lesson learned, it’s a good practice to note PIDs of processes as the investigation goes along. 
-	Run volatility procdump plugin along with PID 3496 to dump a copy of the executable 
![](/DefconDFIR19_MemoryForensics/files/procdump.jpg)

-	GtkHash is a handy tool to get all 3 types of hashes of a file 

![](/DefconDFIR19_MemoryForensics/files/gtkhash.jpg)
```
MD5 value = 690ea20bc3bdfb328e23005d9a80c290
```

**lm-get bobs hash - 24 Points | What is the LM Hash of bobs account ?**

-	LM hash how older version of windows stored user’s passwords. It is based on DES and has a number of faults and is comparatively easier to crack.
-	[Wiki shows how LM hash is computed](https://en.wikipedia.org/wiki/LAN_Manager#:~:text=LM%20hash%20(also%20known%20as,used%20to%20store%20user%20passwords))
-	Use Volatility’s “hivelist” and “hashdump” plugin
    - Hivelist: lists all available registry hives and their virtual + physical offsets. We will require this offset value to conduct the dump using hashdump 
    - Hashdump: dumps all LM and NTLM hashes 
    
![](/DefconDFIR19_MemoryForensics/files/hashdump.jpg)
```
Bob’s LM hash = aad3b435b51404eeaad3b435b51404ee
```

**vad the impaler - 25 Points|What protections does the VAD mode at 0xfffffa800577ba10 have ?**

-	VAD stands for Virtual Address Descriptor. The Virtual Address Descriptor tree is used by the Windows memory manager to describe memory ranges used by a process as they are allocated. When a process allocates memory with VirutalAlloc, the memory manager creates an entry in the VAD tree.
-	Volatility’s vadinfo plugin displays the extended information about a process’s VAD nodes. 
    - [VADInfo](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#vadinfo)
    
![](/DefconDFIR19_MemoryForensics/files/vadinfo.jpg)
```
Protection = PAGE_READONLY
```

**more vads?! - 25 Points | What protections did the VAD starting at 0x00000000033c0000 and ending at 0x00000000033dffff have ?**

-	In the earlier output we see that the first line on the VAD has a line “VAD node @ 0xfffffa800577ba10 Start <offset> End <offset> Tag Vad” 
-	Grepping based on the string START and END along with the given offsets should do the trick 

![](/DefconDFIR19_MemoryForensics/files/vadinfo2.jpg)
```
Protection = PAGE_NOACCESS
```

**vacation bible school - 25 Points | There was a VBS script run on the machine. What is the name of the script?**

-	wscript - Windows Script Host provides an environment in which users can execute scripts in a variety of languages that use a variety of object models tdllo perform tasks.
-	Volatility’s dlllist plugin displays a process's loaded DLLs.
-	Run the command for wscript PID. (recap on pslist)

![](/DefconDFIR19_MemoryForensics/files/vbsscript.jpg)
```
VBS Script = vhjReUDEuumrX.vbs
```

**thx microsoft - 25 Points | An application was run at 2019-03-07 23:06:58 UTC, what is the name of the program ?**

-	Amcache and Shimcache can provide a timeline of which program was executed and when it was first run and last modified
-	The Amcache.hve file is a registry file that stores the information of executed applications.
-	Shimcache, also known as AppCompatCache, is a component of the Application Compatibility Database, which was created by Microsoft (beginning in Windows XP) and used by the operating system to identify application compatibility issues.
-	https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
-	Volatility has a shimcache plugin that helps lists the above

![](/DefconDFIR19_MemoryForensics/files/shimcache.jpg)

```
Program run = Skype.exe
```

**lightbulb moment - 35 Points | What was written in notepad.exe in the time of the memory dump?**

-	Volatility allows dumping memory of processes using the “memdump” plugin 
-	Here dumping PID 3032 and running strings will allow us to see what was written in notepad.exe
    - _volatility -f triage.mem --profile=Win7SP1x64 memdump -p 3032 --dump-dir ~/defcon-dfir/dlldump/_
-	As this is for a CTF, the question here is to find a specific flag so we can run a grep for the string “flag” and find the answer 

```
String = REDBULL_IS_LIFE
```

**8675309 - 35 Points | What is the short name of the file at file record 59045?**

-	File and directories information in Windows systems are stored in MFT(Master File Table)
-	Volatility makes it easy to parse this information using the “mftparser” plugin. 

![](/DefconDFIR19_MemoryForensics/files/mftparser.jpg)

```
Short Name = EMPLOY~1.XLS
```

**whats-a-metasploit? - 50 Points | This box was exploited and its running meterpreter. What PID was infected?**

-	Meterpreter is a payload within the Metasploit Framework that provides control over an exploited target system, running as a DLL loaded inside of any process on a target machine
-	The default Metasploit port is 4444.
-	Looking at netscan results from before we see connection to 10.0.0.106 on port 4444

![](/DefconDFIR19_MemoryForensics/files/meterpreter1.jpg)
-	In order to confirm that PID 3496 is responsible for the meterpreter session we can also use the “procdump” plugin to dump the process’s executable and then check it. 
-	VT submission confirms this.
-	Another check I learnt we could do is use the yarascan plugin to scan the memory image. 
-	[Found a sample yara rule here to check for meterpreter](https://www.forensicfocus.com/articles/finding-metasploits-meterpreter-traces-with-memory-forensics/)

```
rule meterpreter_flag
{
meta: 
author = "tester"
description = "meterpreter detected!!!" 

strings:
$a = {6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72}
$b = "stdapi_" ascii nocase 

condition: 

$a and $b
} 
```

-	The signature “6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72” is basically looking for the default “metsrv.dll” which is used by meterpreter
-	[Here’s a good blog on how it all works](https://blog.rapid7.com/2015/03/25/stageless-meterpreter-payloads/)

![](/DefconDFIR19_MemoryForensics/files/yarascan.jpg)
