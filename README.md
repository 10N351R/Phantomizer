![alt text](https://github.com/10N351R/Phantomizer/blob/main/Phantomizer_logo.png)

# Phantomizer
Author: 10N351R, Base Functions Borrowed From: mrd0x

Phantomizer is a post-exploitation utility for Windows targets that has the ability to run executables stored in `C:/Windows/System32` with spoofed arguments to avoid disclosing "true" arguments to startup-based and runtime-based process monitors and logging solutions.


**Note:**

I built this as I am currently a student progressing through the [Maldev Academy curriculum](https://maldevacademy.com/). I was really interested in these techniques and I adapted some snippets from the course into a this format. I can't take full credit for all of the code that I have used in Phantomizer because some of it is from course materials and is not original to me. Phantomizer hasn't been thoroughly tested so avoid using it in real red-team engagements. Currently it has no AV/EDR evasion mechanisms built-in so it will probably get flagged.

Phantomizer is provided for educational and informational purposes only. Users are solely responsible for ensuring compliance with applicable laws and regulations when using Phantomizer. Be safe and enjoy!

  -10N351R 

## How Phantomizer Works
To understand how Phantomizer spoofs arguments from process monitors, it is important to know how process monitors assimilate information. Primarily, process monitors employ two main methods to extract important information such as command line arguments, from a process' Process Environment Block (PEB).

### Startup Monitoring 
Startup monitoring is a method of process monitoring that relies on reading command line arguments from a target process' `PEB` structure upon creation of the process regardless of if the process is in a suspended state. This method of monitoring is relatively straightforward and is used by tools such as Process Monitor (Procmon).

### Runtime Monitoring
In contrast to startup monitoring, runtime monitoring relies on extracting command line arguments from a process' `PEB` structure as the process is actively running. This is considered a more "advanced" and accurate monitoring method compared to startup monitoring. This method allows a monitoring process to view the actual real-time values of a target process' minimizing the chance of retrieving out-of-date information from a target process' `PEB` structure. This method is used by tools such as Process Hacker and Process Explorer.

### Phantomizer's Evasion Mechanisms 
Phantomizer uses two different strategies for evading process monitors, tailored for each monitoring method.

### Defeating Startup Monitoring
To defeat startup monitoring, Phantomizer employs a method that entails creating a new process in a "suspended" state. A process started in this state has it's main thread paused and will only resume execution when the `ResumeThread` function is called. This is key in circumventing process monitors reliant on startup monitoring, as they solely retrieve a target process' PEB upon initialization, disregarding its state.

To defeat this Phantomizer manipulates a newly created, suspended, target process' `PEB` structure (more specifically the `CommandLine.Buffer` nested member) before resuming the process. Since the monitor only sees the arguments supplied at process creation, it neglects the patched `PEB` structure  effectively allowing Phantomizer to hide any argument from monitors.

Upon resuming the main thread of the target process, it executes the stored command line argument from its `CommandLine.Buffer` assuming it has the privileges to do so.

Here is a technical diagram of how startup monitoring is bypassed.
//image coming soon//

### Defeating Runtime Monitoring
To defeat startup monitoring, Phantomizer utilizes the same method for bypassing startup monitors but with additional modifications to limit the byte count retrievable by a process monitor from the target process' `PEB` structure. 

At a high level, runtime monitors grab the value of `PEB->CommandLine.Buffer` that is currently being used during execution. Runtime monitors read `CommandLine.Buffer` only to the amount of bytes specified by another `PEB` structure member called `CommandLine.Length`. This additional member is what allows Phantomizer to manipulate how much of a command line argument a runtime monitor is able to see. 

Once again Phantomizer manipulates the newly created, suspended, target process' `PEB->CommandLine.Length` member to only be long enough to reveal the target process (no arguments) to be executed before resuming the process. For example this patch will reduce an runtime monitor's ability to read command line arguments from `powershell.exe -NoExit evil.exe` to `powershell.exe`. 

Upon resuming the process executes it's full command line arguments as normal as the alteration only changed the externally viewable `PEB->CommandLine.Length`, leaving the data stored in `PEB->CommandLine.Buffer` unaltered.

Here is a technical diagram of how runtime monitoring is bypassed.
//image coming soon//

## Syntax
Phantomizer works in a question/anwser syntax.

Here is an example flow.
| Prompt                                                                                               | Example Response                                 | Comment                                     |
|------------------------------------------------------------------------------------------------------|--------------------------------------------------|---------------------------------------------|
| [#] Enter the target executable stored in C:\Windows\System32 you will be calling (ending in ".exe"):| powershell.exe                                   | the name executable to be run               |
| [#] Enter a FULL FALSE COMMAND to appear in logs:                                                    | powershell.exe full false command -c fakeexe.exe | this is a false command will be visible in logs       |
| [#] Enter the FULL TRUE COMMAND to be executed:                                                      | powershell.exe -NoInteractive evil.exe           | this is the intended command to be executed |
| [#] Enter 'y' to confirm, 'n' to re-enter, or 'q' to quit:                                           | y                                                |                                             |

## Demo
Running Phantomizer
![alt text](https://github.com/10N351R/Phantomizer/blob/main/Images/20240308173432.png)

Process tree viewed in Process Hacker
![alt text](https://github.com/10N351R/Phantomizer/blob/main/Images/20240308174445.png)

Verifying that the payload (calc.exe) successfully executed in Task Manager
![alt_text](https://github.com/10N351R/Phantomizer/blob/main/Images/20240308175114.png)

Viewing the event in Process Monitor (Procmon)
![alt_text](https://github.com/10N351R/Phantomizer/blob/main/Images/20240308173715.png)

Viewing the powershell instance properties in Process Hacker
![alt_text](https://github.com/10N351R/Phantomizer/blob/main/Images/20240308173923.png)

Viewing the conhost instance properties in Process Hacker
![alt_text](https://github.com/10N351R/Phantomizer/blob/main/Images/20240308174124.png)

## Known Issues
- Entering NULL information into any of the prompts will cause Phantomizer to fail

## Update Plans
- Add support for issuing multiple commands in one Phantomizer instance
- Add checks for successful true command execution
