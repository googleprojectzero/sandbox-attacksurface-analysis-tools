NtObjectManager - Managed .NET Powershell Module

(c) Google Inc. 2015, 2016, 2017
Developed by James Forshaw

You can load the using the Import-Module Cmdlet. You'll need to disable signing 
requirements however.

For example copy the module to %USERPROFILE%\Documents\WindowsPowerShell\Modules
then load the module with:

Import-Module NtObjectManager

You can now do things like listing the NT object manager namespace using:

Get-ChildItem NtObject:\

Also see help for various commons such as Get-NtProcess, Get-NtType or New-File.

Patches are welcome to add missing functions or fix bugs, see the CONTRIBUTING file 
in the root of the solution.

Thanks to the people who were willing to test it and give feedback:
* Matt Graeber
* Lee Holmes
* Casey Smith
* Jared Atkinson