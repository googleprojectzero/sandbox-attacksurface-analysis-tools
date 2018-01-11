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

Building for PowerShell Core 6.0/.NET Core 2.0
-----------------------------------------

In order to build for PowerShell Core 6.0 you first need to build the .NET Framework
version of the module, or pull the latest version of NtObjectManager from the PowerShell
Gallery. Next build the .NET Core version of the module using the dotnet command line tool:

dotnet build NtObjectManager\NtObjectManager.Core.csproj -c Release

Now copy the files NtObjectManager.dll and NtApiDotNet.dll from the output folder to
the folder Core inside the original NtObjectManager module module directory.

Thanks to the people who were willing to test it and give feedback:
* Matt Graeber
* Lee Holmes
* Casey Smith
* Jared Atkinson