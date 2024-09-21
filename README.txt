sandbox-attacksurface-analysis-tools version 2.

(c) Google LLC. 2015 - 2024
Developed by James Forshaw

This is a small suite of PowerShell tools to test various properties of sandboxes on Windows. Many of the
tools take a -ProcessId flag which is used to specify the PID of a sandboxed process. The tool will impersonate
the token of that process and determine what access is allowed from that location. Also it's recommended
to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.

EditSection: View and manipulate memory sections.
TokenViewer: View and manipulate various process token values.
NtCoreLib: A basic managed library to access NT system calls and objects.
NtCoreLib.Forms: A few simple forms to view security descriptors and tokens.
NtObjectManager: A powershell module which uses NtApiDotNet to expose the NT object manager.
ViewSecurityDescriptor: View the security descriptor from an SDDL string or an inherited object.

You can load the using the Import-Module Cmdlet. You'll need to disable signing requirements however.

For example copy the module to %USERPROFILE%\Documents\WindowsPowerShell\Modules then load the module with:

Import-Module NtObjectManager

You can now do things like listing the NT object manager namespace using:

Get-ChildItem NtObject:\

Also see help for various commons such as Get-NtProcess, Get-NtType or New-File.

The tools can be built with Visual Studio 2022. 

Release Notes:
2.0.0.
--------
* Major refactor.
