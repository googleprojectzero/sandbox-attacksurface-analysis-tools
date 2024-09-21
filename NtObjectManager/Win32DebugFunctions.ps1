#  Copyright 2021 Google Inc. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

$native_dir = if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    switch([NtCoreLib.NtSystemInfo]::ProcessorInformation.ProcessorArchitecture) {
        "AMD64" { 
            "$PSScriptRoot\x64"
        }
        "Intel" {
            "$PSScriptRoot\x86"
        }
        "ARM64" {
            "$PSScriptRoot\ARM64"
        }
        "ARM" {
            "$PSScriptRoot\ARM"
        }
        default {
            ""
        }
    }
} else {
    ""
}

if ("" -ne $native_dir -and (Test-Path "$native_dir\dbghelp.dll")) {
    [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::DefaultDbgHelpPath = "$native_dir\dbghelp.dll"
}

<#
.SYNOPSIS
Creates a symbol resolver for a process.
.DESCRIPTION
This cmdlet creates a new symbol resolver for the given process.
.PARAMETER Process
The process to create the symbol resolver on. If not specified then the current process is used.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the
default of 'srv*https://msdl.microsoft.com/download/symbols'
.PARAMETER Flags
Flags for the symbol resolver.
.PARAMETER TraceWriter
Specify the output text writer for symbol tracing when enabled by the flags.
.OUTPUTS
NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver - The symbol resolver. Dispose after use.
.EXAMPLE
New-SymbolResolver
Get a symbol resolver for the current process with default settings.
.EXAMPLE
New-SymbolResolver -SymbolPath "c:\symbols"
Get a symbol resolver specifying for the current process specifying symbols in c:\symbols.
.EXAMPLE
New-SymbolResolver -Process $p -DbgHelpPath "c:\path\to\dbghelp.dll" -SymbolPath "srv*c:\symbols*https://blah.com/symbols"
Get a symbol resolver specifying a dbghelp path and symbol path and a specific process.
#>
function New-SymbolResolver {
    Param(
        [NtCoreLib.NtProcess]$Process,
        [string]$DbgHelpPath,
        [string]$SymbolPath,
        [NtCoreLib.Win32.Debugger.Symbols.SymbolResolverFlags]$Flags = 0,
        [System.IO.TextWriter]$TraceWriter
    )
    if ($null -eq $Process) {
        $Process = Get-NtProcess -Current
    }
    [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::Create($Process, $DbgHelpPath, $SymbolPath, $Flags, $TraceWriter)
}

<#
.SYNOPSIS
Sets the global symbol resolver paths.
.DESCRIPTION
This cmdlet sets the global symbol resolver paths. This allows you to specify symbol resolver paths for cmdlets which support it.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath c:\windbg\x64\dbghelp.dll
Specify the global dbghelp path.
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath dbghelp.dll -SymbolPath "c:\symbols"
Specify the global dbghelp path using c:\symbols to source the symbol files.
#>
function Set-GlobalSymbolResolver {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$DbgHelpPath,
        [parameter(Position = 1)]
        [string]$SymbolPath
    )

    [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::DefaultDbgHelpPath = $DbgHelpPath
    if ("" -ne $SymbolPath) {
        [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::DefaultSymbolPath = $SymbolPath
    }
}

<#
.SYNOPSIS
Start a Win32 debug console.
.DESCRIPTION
This cmdlet starts a Win32 debug console and prints the debug output to the shell.
.PARAMETER Global
Capture debug output for session 0.
.PARAMETER Variable
The name of a variable to put the read debug events into.
.INPUTS
None
.OUTPUTS
None
#>
function Start-Win32DebugConsole {
    param(
        [switch]$Global,
        [string]$Variable
    )

    $res = @()
    try {
        Use-NtObject($console = New-Win32DebugConsole -Global:$Global) {
            $psvar = if ("" -ne $Variable) {
                Set-Variable -Name $Variable -Value @() -Scope global
                Get-Variable -Name $Variable
            }
            while($true) {
                $result = Read-Win32DebugConsole -Console $console -TimeoutMs 1000
                if ($null -ne $result.Output) {
                    if ($null -ne $psvar) {
                        $psvar.Value += @($result)
                    }
                    Write-Host "[$($result.ProcessId)] - $($result.Output.Trim())"
                }
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Create a new Win32 debug console.
.DESCRIPTION
This cmdlet creates Win32 debug console. You can then read debug events using Read-Win32DebugConsole.
.PARAMETER Global
Capture debug output for session 0.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Debugger.Win32DebugConsole
#>
function New-Win32DebugConsole {
    param(
        [switch]$Global
    )

    $session_id = if ($Global) {
        0
    } else {
        (Get-NtProcess -Current).SessionId
    }
    [NtCoreLib.Win32.Debugger.Win32DebugConsole]::Create($session_id)
}

<#
.SYNOPSIS
Reads a debug event from the Win32 debug console.
.DESCRIPTION
This cmdlet reads a Win32 debug event from a console.
.PARAMETER Console
The console to read from.
.PARAMETER TimeoutMs
The timeout to read in milliseconds. The default is to wait indefinitely.
.PARAMETER Async
Read the string asynchronously.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Debugger.Win32DebugString
System.Threading.Tasks.Task[Win32DebugString]
#>
function Read-Win32DebugConsole {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Debugger.Win32DebugConsole]$Console,
        [int]$TimeoutMs = -1,
        [switch]$Async
    )

    if ($Async) {
        $Console.ReadAsync($TimeoutMs)
    } else {
        $Console.Read($TimeoutMs)
    }
}
