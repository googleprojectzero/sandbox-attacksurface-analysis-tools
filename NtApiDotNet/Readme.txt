NtApiDotNet - Managed .NET library for accessing NT API

(c) Google Inc. 2015, 2016
Developed by James Forshaw

This library is written entirely in C# to allow managed applications easy access to
various native NT API routines. It's used as the core of the sandbox analysis tools
as well as a Powershell Module. The purpose of this library is to make it easier to 
call into the NT API, handling things like variable length structures and lifetime
management.

The majority of the exposed classes and methods have XML documentation, which can 
be used for intellisense or converted into real documentation. Most of the low-level
APIs are not documented however, see the code for usage examples.

In addition to my own reverse engineering efforts and MSDN documentation the following
people or resources have proven invaluable in determing API functionality.

Process Hacker Sources: http://processhacker.sourceforge.net/
Windows NT/2000 Native API Reference: Gary Nebbett (ISBN 9781578701995)
Alex Ionescu
And others I've no doubt forgotten.

NOTE: It's still a work in progress and it's not designed to act as a documentation
source for the entire NT API. There will be bits missing. Patches are welcome to 
add missing functions or fix bugs, see the CONTRIBUTING file in the root of the solution.
