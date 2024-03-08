![alt text](https://github.com/10N351R/Phantomizer/blob/main/Phantomizer_logo.png)

# Phantomizer
Author: 10N351R, Base Functions Borrowed From: mrd0x

Phantomizer is a post-exploitation utility for Windows targets that has the ability to run executables stored in C:/Windows/System32 with spoofed arguments to avoid disclosing "true" arguments to startup-based and runtime-based process monitors and logging solutions.

## How Phantomizer Works

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

## Syntax
Phantomizer works in a question/anwser syntax.

Here is an example flow.
| Prompt                                                                                               | Example Response                                 | Comment                                     |
|------------------------------------------------------------------------------------------------------|--------------------------------------------------|---------------------------------------------|
| [#] Enter the target executable stored in C:\Windows\System32 you will be calling (ending in ".exe"):| powershell.exe                                   | the name executable to be run               |
| [#] Enter a FULL FALSE COMMAND to appear in logs:                                                    | powershell.exe full false command -c fakeexe.exe | this is a false command will be visible in logs       |
| [#] Enter the FULL TRUE COMMAND to be executed:                                                      | powershell.exe -NoInteractive evil.exe           | this is the intended command to be executed |
| [#] Enter 'y' to confirm, 'n' to re-enter, or 'q' to quit:                                           | y                                                |                                             |

## Known Issues
- Entering NULL information into any of the prompts will cause Phantomizer to fail

## Update Plans
- Add support for issuing multiple commands in one Phantomizer instance
- Add checks for successful true command execution
