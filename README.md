# ASREnum

Just some simple code to enumerate Attack Surface Reduction rules by reading the registry.

```
.\ASREnum.exe

RULES IN ENABLED MODE
=====================
Block abuse of exploited vulnerable signed drivers
Block Adobe Reader from creating child processes
Block all Office applications from creating child processes
Block credential stealing from the Windows local securit authority subsystem (lsass.exe)
Block executable content from email client and webmail
Block execution of potentially obfuscated scripts
Block JavaScript or VBScript from launching downloaded executable content
Block Office applications from creating executable content
Block Office applications from injecting code into other processes
Block Office communication application from creating child processes
Block persistence through WMI event subscription
Block process creations originating from PSExec and WMI commands
Block untrusted and unsigned processes that run from USB
Block Win32 API calls from Office macros
Use advanced protection against ransomware

RULES IN WARN MODE
==================

RULES IN AUDIT MODE
===================

RULES IN DISABLED MODE (EXPLICIT)
=================================

RULES IN DISABLED MODE (IMPLICIT)
=================================
Block executable files from running unless they meet a prevalence, age, or trusted list criterion

```
