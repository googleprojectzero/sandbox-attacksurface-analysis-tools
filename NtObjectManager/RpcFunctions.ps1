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

<#
.SYNOPSIS
Get a list of ALPC Ports that can be opened by a specified token.
.DESCRIPTION
This cmdlet checks for all ALPC ports on the system and tries to determine if one or more specified tokens can connect to them.
If no tokens are specified then the current process token is used. This function searches handles for existing ALPC Port servers as you can't directly open the server object and just connecting might show inconsistent results.
.PARAMETER ProcessId
Specify a list of process IDs to open for their tokens.
.PARAMETER ProcessName
Specify a list of process names to open for their tokens.
.PARAMETER ProcessCommandLine
Specify a list of command lines to filter on find for the process tokens.
.PARAMETER Token
Specify a list token objects.
.PARAMETER Process
Specify a list process objects to use for their tokens.
.INPUTS
None
.OUTPUTS
NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult
.NOTES
For best results run this function as an administrator with SeDebugPrivilege available.
.EXAMPLE
Get-AccessibleAlpcPort
Get all ALPC Ports connectable by the current token.
.EXAMPLE
Get-AccessibleAlpcPort -ProcessIds 1234,5678
Get all ALPC Ports connectable by the process tokens of PIDs 1234 and 5678
#>
function Get-AccessibleAlpcPort {
    Param(
        [alias("ProcessIds")]
        [Int32[]]$ProcessId,
        [alias("ProcessNames")]
        [string[]]$ProcessName,
        [alias("ProcessCommandLines")]
        [string[]]$ProcessCommandLine,
        [alias("Tokens")]
        [NtApiDotNet.NtToken[]]$Token,
        [alias("Processes")]
        [NtApiDotNet.NtProcess[]]$Process
    )
    $access = Get-NtAccessMask -AlpcPortAccess Connect -ToGenericAccess
    Get-AccessibleObject -FromHandle -ProcessId $ProcessId -ProcessName $ProcessName `
        -ProcessCommandLine $ProcessCommandLine -Token $Token -Process $Process -TypeFilter "ALPC Port" -AccessRights $access
}

<#
.SYNOPSIS
Gets the endpoints for a RPC interface from the local endpoint mapper or by brute force.
.DESCRIPTION
This cmdlet gets the endpoints for a RPC interface from the local endpoint mapper. Not all RPC interfaces
are registered in the endpoint mapper so it might not show. You can use the -FindAlpcPort command to try
and brute force an ALPC port for the interface.
.PARAMETER InterfaceId
The UUID of the RPC interface.
.PARAMETER InterfaceVersion
The version of the RPC interface.
.PARAMETER Server
Parsed NDR server.
.PARAMETER Binding
A RPC binding string to query all endpoints from.
.PARAMETER AlpcPort
An ALPC port name. Can contain a full path as long as the string contains \RPC Control\ (case sensitive).
.PARAMETER FindAlpcPort
Use brute force to find a valid ALPC endpoint for the interface.
.INPUTS
None or NtApiDotNet.Ndr.NdrRpcServerInterface
.OUTPUTS
NtApiDotNet.Win32.RpcEndpoint[]
.EXAMPLE
Get-RpcEndpoint
Get all RPC registered RPC endpoints.
.EXAMPLE
Get-RpcEndpoint $Server
Get RPC endpoints for a parsed NDR server interface.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F"
Get RPC endpoints for a specified interface ID ignoring the version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0"
Get RPC endpoints for a specified interface ID and version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0" -FindAlpcPort
Get ALPC RPC endpoints for a specified interface ID and version by brute force.
.EXAMPLE
Get-RpcEndpoint -Binding "ncalrpc:[RPC_PORT]"
Get RPC endpoints for exposed over ncalrpc with name RPC_PORT.
.EXAMPLE
Get-RpcEndpoint -AlpcPort "RPC_PORT"
Get RPC endpoints for exposed over ALPC with name RPC_PORT.
#>
function Get-RpcEndpoint {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [Guid]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [Version]$InterfaceVersion,
        [parameter(Mandatory, ParameterSetName = "FromServer", ValueFromPipeline)]
        [NtApiDotNet.Ndr.NdrRpcServerInterface]$Server,
        [parameter(Mandatory, ParameterSetName = "FromBinding")]
        [string]$Binding,
        [parameter(Mandatory, ParameterSetName = "FromAlpc")]
        [string]$AlpcPort,
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromServer")]
        [switch]$FindAlpcPort,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromId")]
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcClient")]
        [string]$SearchBinding = "",
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromId")]
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcClient")]
        [string[]]$ProtocolSequence = @(),
        [parameter(Mandatory, ParameterSetName = "FromRpcClient")]
        [NtApiDotNet.Win32.Rpc.RpcClientBase]$Client
    )

    PROCESS {
        $eps = switch ($PsCmdlet.ParameterSetName) {
            "All" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($SearchBinding)
            }
            "FromId" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($SearchBinding, $InterfaceId)
            }
            "FromIdAndVersion" {
                if ($FindAlpcPort) {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::FindAlpcEndpointForInterface($InterfaceId, $InterfaceVersion)
                }
                else {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($SearchBinding, $InterfaceId, $InterfaceVersion)
                }
            }
            "FromServer" {
                if ($FindAlpcPort) {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::FindAlpcEndpointForInterface($Server.InterfaceId, $Server.InterfaceVersion)
                }
                else {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($Server)
                }
            }
            "FromBinding" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpointsForBinding($Binding)
            }
            "FromAlpc" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpointsForAlpcPort($AlpcPort)
            }
            "FromRpcClient" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($SearchBinding, $Client.InterfaceId, $Client.InterfaceVersion)
            }
        }

        if ($ProtocolSequence.Count -gt 0) {
            $eps = $eps | Where-Object {$_.ProtocolSequence -in $ProtocolSequence}
        }
        $eps | Write-Output
    }
}

<#
.SYNOPSIS
Get the RPC servers from a DLL.
.DESCRIPTION
This cmdlet parses the RPC servers from a DLL. Note that in order to parse 32 bit DLLs you must run this module in 32 bit PowerShell.
.PARAMETER FullName
The path to the DLL.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the
default of 'srv*https://msdl.microsoft.com/download/symbols'
.PARAMETER AsText
Return the results as text rather than objects.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.PARAMETER ParseClients
Also parse client interface information, otherwise only servers are returned.
.PARAMETER IgnoreSymbols
Don't resolve any symbol information.
.PARAMETER SerializedPath
Path to a serialized representation of the RPC servers.
.PARAMETER ResolveStructureNames
If private symbols available try and resolve the names of structures and parameters.
.PARAMETER SymSrvFallback
Specify to use a built-in fallback for symbol server resolving when using the system dbghelp DLL. You also need to specify a local cache directory in SymbolPath.
.INPUTS
string[] List of paths to DLLs.
.OUTPUTS
RpcServer[] The parsed RPC servers.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll
Get the list of RPC servers from rpcss.dll.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -AsText
Get the list of RPC servers from rpcss.dll, return it as text.
.EXAMPLE
Get-ChildItem c:\windows\system32\*.dll | Get-RpcServer
Get the list of RPC servers from all DLLs in system32, return it as text.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -DbgHelpPath c:\windbg\x64\dbghelp.dll
Get the list of RPC servers from rpcss.dll, specifying a different DBGHELP for symbol resolving.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, specifying a different symbol path.
.EXAMPLE
Get-RpcServer -SerializedPath rpc.bin
Get the list of RPC servers from the serialized file rpc.bin.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymSrvFallback -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, use symbol server fallback with c:\symbols as the cache directory.
#>
function Get-RpcServer {
    [CmdletBinding(DefaultParameterSetName = "FromDll")]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = "FromDll")]
        [alias("Path")]
        [string]$FullName,
        [parameter(ParameterSetName = "FromDll")]
        [string]$DbgHelpPath,
        [parameter(ParameterSetName = "FromDll")]
        [string]$SymbolPath,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$AsText,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$RemoveComments,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$ParseClients,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$IgnoreSymbols,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$ResolveStructureNames,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$SymSrvFallback,
        [parameter(Mandatory = $true, ParameterSetName = "FromSerialized")]
        [string]$SerializedPath
    )

    BEGIN {
        if ($DbgHelpPath -eq "") {
            $DbgHelpPath = $Script:GlobalDbgHelpPath
        }
        if ($SymbolPath -eq "") {
            $SymbolPath = $env:_NT_SYMBOL_PATH
            if ($SymbolPath -eq "") {
                $SymbolPath = $Script:GlobalSymbolPath
            }
        }

        $ParserFlags = [NtApiDotNet.Win32.RpcServerParserFlags]::None
        if ($ParseClients) {
            $ParserFlags = $ParserFlags -bor [NtApiDotNet.Win32.RpcServerParserFlags]::ParseClients
        }
        if ($IgnoreSymbols) {
            $ParserFlags = $ParserFlags -bor [NtApiDotNet.Win32.RpcServerParserFlags]::IgnoreSymbols
        }
        if ($ResolveStructureNames) {
            $ParserFlags = $ParserFlags -bor [NtApiDotNet.Win32.RpcServerParserFlags]::ResolveStructureNames
        }
        if ($SymSrvFallback) {
            $ParserFlags = $ParserFlags -bor [NtApiDotNet.Win32.RpcServerParserFlags]::SymSrvFallback
        }
    }

    PROCESS {
        try {
            if ($PSCmdlet.ParameterSetName -eq "FromDll") {
                $FullName = Resolve-Path -LiteralPath $FullName -ErrorAction Stop
                Write-Progress -Activity "Parsing RPC Servers" -CurrentOperation "$FullName"
                $servers = [NtApiDotNet.Win32.RpcServer]::ParsePeFile($FullName, $DbgHelpPath, $SymbolPath, $ParserFlags)
                if ($AsText) {
                    foreach ($server in $servers) {
                        $text = $server.FormatAsText($RemoveComments)
                        Write-Output $text
                    }
                }
                else {
                    Write-Output $servers
                }
            }
            else {
                $FullName = Resolve-Path -LiteralPath $SerializedPath -ErrorAction Stop
                Use-NtObject($stm = [System.IO.File]::OpenRead($FullName)) {
                    while ($stm.Position -lt $stm.Length) {
                        [NtApiDotNet.Win32.RpcServer]::Deserialize($stm) | Write-Output
                    }
                }
            }
        }
        catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Set a list RPC servers to a file for storage.
.DESCRIPTION
This cmdlet serializes a list of RPC servers to a file. This can be restored using Get-RpcServer -SerializedPath.
.PARAMETER Path
The path to the output file.
.PARAMETER Server
The list of servers to serialize.
.INPUTS
RpcServer[] List of paths to DLLs.
.OUTPUTS
None
.EXAMPLE
Set-RpcServer -Server $server -Path rpc.bin
Serialize servers to file rpc.bin.
#>
function Set-RpcServer {
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer[]]$Server,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$Path
    )

    BEGIN {
        "" | Set-Content -Path $Path
        $Path = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        $stm = [System.IO.File]::Create($Path)
    }

    PROCESS {
        try {
            foreach ($s in $Server) {
                $s.Serialize($stm)
            }
        }
        catch {
            Write-Error $_
        }
    }

    END {
        $stm.Close()
    }
}

<#
.SYNOPSIS
Format the RPC servers as text.
.DESCRIPTION
This cmdlet formats a list of RPC servers as text.
.PARAMETER RpcServer
The RPC servers to format.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.PARAMETER CppFormat
Format output in C++ pseudo syntax rather than C++.
.INPUTS
RpcServer[] The RPC servers to format.
.OUTPUTS
string[] The formatted RPC servers.
.EXAMPLE
Format-RpcServer $rpc
Format list of RPC servers in $rpc.
.EXAMPLE
Format-RpcServer $rpc -RemoveComments
Format list of RPC servers in $rpc without comments.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll | Format-RpcServer
Get the list of RPC servers from rpcss.dll and format them.
#>
function Format-RpcServer {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer[]]$RpcServer,
        [switch]$RemoveComments,
        [switch]$CppFormat
    )

    PROCESS {
        foreach ($server in $RpcServer) {
            $server.FormatAsText($RemoveComments, $CppFormat) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets a list of ALPC RPC servers.
.DESCRIPTION
This cmdlet gets a list of ALPC RPC servers. This relies on being able to access the list of ALPC ports in side a process so might need elevated privileges.
.PARAMETER ProcessId
The ID of a process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.RpcAlpcServer[]
.EXAMPLE
Get-RpcAlpcServer
Get all ALPC RPC servers.
.EXAMPLE
Get-RpcAlpcServer -ProcessId 1234
Get all ALPC RPC servers in process ID 1234.
#>
function Get-RpcAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [int]$ProcessId
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    switch ($PsCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.RpcAlpcServer]::GetAlpcServers()
        }
        "FromProcessId" {
            [NtApiDotNet.Win32.RpcAlpcServer]::GetAlpcServers($ProcessId)
        }
    }
}

<#
.SYNOPSIS
Get a RPC client object based on a parsed RPC server.
.DESCRIPTION
This cmdlet creates a new RPC client from a parsed RPC server. The client object contains methods
to call RPC methods. The client starts off disconnected. You need to pass the client to Connect-RpcClient to
connect to the server. If you specify an interface ID and version then a generic client will be created which
allows simple calls to be made without requiring the NDR data.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER IgnoreCache
Specify to ignore the compiled client cache and regenerate the source code.
.PARAMETER InterfaceId
Specify the interface ID for a generic client.
.PARAMETER InterfaceVersion
Specify the interface version for a generic client.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Flags
Specify optional flags for the built client class.
.PARAMETER EnableDebugging
Specify to enable debugging on the compiled code.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Rpc.RpcClientBase
.EXAMPLE
Get-RpcClient -Server $Server
Create a new RPC client from a parsed RPC server.
#>
function Get-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromServer")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer", ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer]$Server,
        [parameter(ParameterSetName = "FromServer")]
        [string]$NamespaceName,
        [parameter(ParameterSetName = "FromServer")]
        [string]$ClientName,
        [parameter(ParameterSetName = "FromServer")]
        [switch]$IgnoreCache,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [string]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [Version]$InterfaceVersion,
        [parameter(ParameterSetName = "FromServer")]
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [parameter(ParameterSetName = "FromServer")]
        [NtApiDotNet.Win32.Rpc.RpcClientBuilderFlags]$Flags = "GenerateConstructorProperties, StructureReturn, HideWrappedMethods, UnsignedChar, NoNamespace",
        [switch]$EnableDebugging
    )

    BEGIN {
        if (Get-IsPSCore) {
            if ($null -ne $Provider) {
                Write-Warning "PowerShell Core doesn't support arbitrary providers. Using in-built C#."
            }
            $Provider = New-Object NtObjectManager.Utils.CoreCSharpCodeProvider
        }
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromServer") {
            $args = [NtApiDotNet.Win32.Rpc.RpcClientBuilderArguments]::new();
            $args.NamespaceName = $NamespaceName
            $args.ClientName = $ClientName
            $args.Flags = $Flags
            $args.EnableDebugging = $EnableDebugging

            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::CreateClient($Server, $args, $IgnoreCache, $Provider)
        }
        else {
            [NtApiDotNet.Win32.RpcClient]::new($InterfaceId, $InterfaceVersion)
        }
    }
}

<#
.SYNOPSIS
Connects a RPC client to an endpoint.
.DESCRIPTION
This cmdlet connects a RPC client to an endpoint. You can specify what transport to use based on the protocol sequence.
.PARAMETER Client
Specify the RPC client to connect.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence this client will connect through.
.PARAMETER EndpointPath
Specify the endpoint string. If not specified this will lookup the endpoint from the endpoint mapper.
.PARAMETER NetworkAddress
Specify the network address. If not specified the local system will be used.
.PARAMETER SecurityQualityOfService
Specify the security quality of service for the connection.
.PARAMETER Credentials
Specify user credentials for the RPC client authentication.
.PARAMETER ServicePrincipalName
Specify service principal name for the RPC client authentication.
.PARAMETER AuthenticationLevel
Specify authentication level for the RPC client authentication.
.PARAMETER AuthenticationType
Specify authentication type for the RPC client authentication.
.PARAMETER AuthenticationCapabilities
Specify authentication capabilities for the RPC client authentication.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.PARAMETER FindAlpcPort
Specify to search for an ALPC port for the RPC client.
.PARAMETER Force
Specify to for the client to connect even if the client is already connected to another transport.
.INPUTS
NtApiDotNet.Win32.Rpc.RpcClientBase[]
.OUTPUTS
NtApiDotNet.Win32.Rpc.RpcClientBase[]
.EXAMPLE
Connect-RpcClient -Client $Client
Connect an RPC ALPC client, looking up the path using the endpoint mapper.
.EXAMPLE
Connect-RpcClient -Client $Client -EndpointPath "\RPC Control\ABC"
Connect an RPC ALPC client with an explicit path.
.EXAMPLE
Connect-RpcClient -Client $Client -SecurityQualityOfService $(New-NtSecurityQualityOfService -ImpersonationLevel Anonymous)
Connect an RPC ALPC client with anonymous impersonation level.
.EXAMPLE
Connect-RpcClient -Client $Client -ProtocolSequence "ncalrpc"
Connect an RPC ALPC client from a specific protocol sequence.
.EXAMPLE
Connect-RpcClient -Client $Client -Endpoint $ep
Connect an RPC client to a specific endpoint.
.EXAMPLE
Connect-RpcClient -Client $Client -FindAlpcPort
Connect an RPC ALPC client, looking up the path using brute force.
#>
function Connect-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.Rpc.RpcClientBase]$Client,
        [parameter(Position = 1, ParameterSetName = "FromProtocol")]
        [string]$EndpointPath,
        [parameter(ParameterSetName = "FromProtocol")]
        [string]$ProtocolSequence = "ncalrpc",
        [parameter(ParameterSetName = "FromProtocol")]
        [string]$NetworkAddress,
        [parameter(Position = 1, Mandatory, ParameterSetName = "FromEndpoint")]
        [NtApiDotNet.Win32.RpcEndpoint]$Endpoint,
        [parameter(Mandatory, ParameterSetName = "FromFindEndpoint")]
        [switch]$FindAlpcPort,
        [parameter(ParameterSetName = "FromBindingString")]
        [string]$StringBinding,
        [NtApiDotNet.SecurityQualityOfService]$SecurityQualityOfService,
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationCredentials]$Credentials,
        [string]$ServicePrincipalName,
        [NtApiDotNet.Win32.Rpc.Transport.RpcAuthenticationLevel]$AuthenticationLevel = "None",
        [NtApiDotNet.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType = "None",
        [NtApiDotNet.Win32.Rpc.Transport.RpcAuthenticationCapabilities]$AuthenticationCapabilities = "None",
        [switch]$PassThru,
        [switch]$Force
    )

    BEGIN {
        $security = New-Object NtApiDotNet.Win32.Rpc.Transport.RpcTransportSecurity
        $security.SecurityQualityOfService = $SecurityQualityOfService
        $security.Credentials = $Credentials
        $security.ServicePrincipalName = $ServicePrincipalName
        $security.AuthenticationLevel = $AuthenticationLevel
        $security.AuthenticationType = $AuthenticationType
        $security.AuthenticationCapabilities = $AuthenticationCapabilities
    }

    PROCESS {
        if ($Force) {
            Disconnect-RpcClient -Client $Client
        }
        switch ($PSCmdlet.ParameterSetName) {
            "FromProtocol" {
                $Client.Connect($ProtocolSequence, $EndpointPath, $NetworkAddress, $security)
            }
            "FromEndpoint" {
                $Client.Connect($Endpoint, $security)
            }
            "FromFindEndpoint" {
                foreach ($ep in $(Get-ChildItem "NtObject:\RPC Control")) {
                    try {
                        $name = $ep.Name
                        Write-Progress -Activity "Finding ALPC Endpoint" -CurrentOperation "$name"
                        $Client.Connect("ncalrpc", $name, $security)
                    }
                    catch {
                        Write-Information $_
                    }
                }
            }
            "FromBindingString" {
                $Client.Connect($StringBinding, $security)
            }
        }

        if ($PassThru) {
            $Client | Write-Output
        }
    }
}

<#
.SYNOPSIS
Disconnect an RPC client.
.DESCRIPTION
This cmdlet disconnects a RPC client from an endpoint.
.PARAMETER Client
Specify the RPC client to disconnect.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.INPUTS
NtApiDotNet.Win32.Rpc.RpcClientBase[]
.OUTPUTS
NtApiDotNet.Win32.Rpc.RpcClientBase[]
.EXAMPLE
Disconnect-RpcClient -Client $Client
Disconnect an RPC ALPC client.
#>
function Disconnect-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.Rpc.RpcClientBase]$Client,
        [switch]$PassThru
    )

    PROCESS {
        $Client.Disconnect()

        if ($PassThru) {
            $Client | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format a RPC client as source code based on a parsed RPC server.
.DESCRIPTION
This cmdlet gets source code for a RPC client from a parsed RPC server.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER Flags
Specify to flags for the source creation.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER OutputPath
Specify optional output directory to write formatted client.
.PARAMETER GroupByName
Specify when outputting to a directory to group by the name of the server executable.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcClient -Server $Server
Get the source code for a RPC client from a parsed RPC server.
.EXAMPLE
$servers | Format-RpcClient
Get the source code for RPC clients from a list of parsed RPC servers.
.EXAMPLE
$servers | Format-RpcClient -OutputPath rpc_output
Get the source code for RPC clients from a list of parsed RPC servers and output as separate source code files.
#>
function Format-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer[]]$Server,
        [string]$NamespaceName,
        [string]$ClientName,
        [NtApiDotNet.Win32.Rpc.RpcClientBuilderFlags]$Flags = 0,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [string]$OutputPath,
        [switch]$GroupByName
    )

    BEGIN {
        $file_ext = "cs"
        if ($null -ne $Provider) {
            $file_ext = $Provider.FileExtension
        }

        if ("" -ne $OutputPath) {
            mkdir $OutputPath -ErrorAction Ignore | Out-Null
        }
    }

    PROCESS {
        $args = [NtApiDotNet.Win32.Rpc.RpcClientBuilderArguments]::new();
        $args.NamespaceName = $NamespaceName
        $args.ClientName = $ClientName
        $args.Flags = $Flags

        foreach ($s in $Server) {
            $src = if ($null -eq $Provider) {
                [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource($s, $args)
            }
            else {
                [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource($s, $args, $Provider, $Options)
            }

            if ("" -eq $OutputPath) {
                $src | Write-Output
            }
            else {
                if ($GroupByName) {
                    $path = Join-Path -Path $OutputPath -ChildPath $s.Name.ToLower()
                    mkdir $path -ErrorAction Ignore | Out-Null
                } else {
                    $path = $OutputPath
                }
                $path = Join-Path -Path $path -ChildPath "$($s.InterfaceId)_$($s.InterfaceVersion).$file_ext"
                $src | Set-Content -Path $path
            }
        }
    }
}

<#
.SYNOPSIS
Format RPC complex types to an encoder/decoder source code file.
.DESCRIPTION
This cmdlet gets source code for encoding and decoding RPC complex types.
.PARAMETER ComplexType
Specify the list of complex types to format.
.PARAMETER Server
Specify the server containing the list of complex types to format.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER EncoderName
Specify the class name of the encoder.
.PARAMETER DecoderName
Specify the class name of the decoder.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER Pointer
Specify to always wrap complex types in an unique pointer.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcComplexType -Server $Server
Get the source code for RPC complex types client from a parsed RPC server.
.EXAMPLE
Format-RpcComplexType -ComplexType $ComplexTypes
Get the source code for RPC complex types client from a list of types.
#>
function Format-RpcComplexType {
    [CmdletBinding(DefaultParameterSetName = "FromTypes")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromTypes")]
        [NtApiDotNet.Ndr.NdrComplexTypeReference[]]$ComplexType,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer")]
        [NtApiDotNet.Win32.RpcServer]$Server,
        [string]$NamespaceName,
        [string]$EncoderName,
        [string]$DecoderName,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [switch]$Pointer
    )

    PROCESS {
        $types = switch ($PsCmdlet.ParameterSetName) {
            "FromTypes" { $ComplexType }
            "FromServer" { $Server.ComplexTypes }
        }
        if ($null -eq $Provider) {
            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource([NtApiDotNet.Ndr.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer) | Write-Output
        }
        else {
            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource([NtApiDotNet.Ndr.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer, $Provider, $Options) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a new RPC context handle.
.DESCRIPTION
This cmdlet creates a new RPC context handle for calling RPC APIs.
.PARAMETER Uuid
The UUID for the context handle.
.PARAMETER Attributes
The attribute flags for the context handle.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Ndr.NdrContextHandle
.EXAMPLE
New-RpcContextHandle
Creates a new RPC context handle.
#>
function New-RpcContextHandle {
    param(
        [guid]$Uuid = [guid]::Empty,
        [int]$Attributes = 0
    )
    [NtApiDotNet.Ndr.Marshal.NdrContextHandle]::new($Attributes, $Uuid)
}

<#
.SYNOPSIS
Get an RPC string binding from its parts.
.DESCRIPTION
This cmdlet gets an RPC string binding based on its component parts.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence .
.PARAMETER Endpoint
Specify the endpoint string.
.PARAMETER NetworkAddress
Specify the network address.
.PARAMETER ObjectUuid
Specify the object UUID.
.PARAMETER Options
Specify the options.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Get-RpcStringBinding --ProtocolSequence "ncalrpc"
Connect an RPC ALPC string binding from a specific protocol sequence.
#>
function Get-RpcStringBinding {
    [CmdletBinding(DefaultParameterSetName = "FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$ProtocolSequence,
        [parameter(Position = 1)]
        [string]$Endpoint,
        [parameter(Position = 2)]
        [string]$NetworkAddress,
        [parameter(Position = 3)]
        [Guid]$ObjectUuid = [guid]::Empty,
        [parameter(Position = 4)]
        [string]$Options
    )

    $objuuid_str = ""
    if ($ObjectUuid -ne [guid]::Empty) {
        $objuuid_str = $ObjectUuid.ToString()
    }

    [NtApiDotNet.Win32.Rpc.RpcUtils]::ComposeStringBinding($objuuid_str, $ProtocolSequence, $NetworkAddress, $Endpoint, $Options)
}

<#
.SYNOPSIS
Creates a NDR parser for a process.
.DESCRIPTION
This cmdlet creates a new NDR parser for the given process.
.PARAMETER Process
The process to create the NDR parser on. If not specified then the current process is used.
.PARAMETER SymbolResolver
Specify a symbol resolver for the parser. Note that this should be a resolver for the same process as we're parsing.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
NtApiDotNet.Ndr.NdrParser - The NDR parser.
.EXAMPLE
$ndr = New-NdrParser
Get an NDR parser for the current process.
.EXAMPLE
New-NdrParser -Process $p -SymbolResolver $resolver
Get an NDR parser for a specific process with a known resolver.
#>
function New-NdrParser {
    Param(
        [NtApiDotNet.NtProcess]$Process,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    [NtApiDotNet.Ndr.NdrParser]::new($Process, $SymbolResolver, $ParserFlags)
}

function Convert-HashTableToIidNames {
    Param(
        [Hashtable]$IidToName,
        [NtApiDotNet.Ndr.NdrComProxyDefinition[]]$Proxy
    )
    $dict = [System.Collections.Generic.Dictionary[Guid, string]]::new()
    if ($null -ne $IidToName) {
        foreach ($pair in $IidToName.GetEnumerator()) {
            $guid = [Guid]::new($pair.Key)
            $dict.Add($guid, $pair.Value)
        }
    }

    if ($null -ne $Proxy) {
        foreach ($p in $Proxy) {
            $dict.Add($p.Iid, $p.Name)
        }
    }

    if (!$dict.ContainsKey("00000000-0000-0000-C000-000000000046")) {
        $dict.Add("00000000-0000-0000-C000-000000000046", "IUnknown")
    }

    if (!$dict.ContainsKey("00020400-0000-0000-C000-000000000046")) {
        $dict.Add("00020400-0000-0000-C000-000000000046", "IDispatch")
    }

    return $dict
}

<#
.SYNOPSIS
Parses COM proxy information from a DLL.
.DESCRIPTION
This cmdlet parses the COM proxy information from a specified DLL.
.PARAMETER Path
The path to the DLL containing the COM proxy information.
.PARAMETER Clsid
Optional CLSID for the object used to find the proxy information.
.PARAMETER Iids
Optional list of IIDs to parse from the proxy information.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed proxy information and complex types.
.EXAMPLE
$p = Get-NdrComProxy c:\path\to\proxy.dll
Parse the proxy information from c:\path\to\proxy.dll
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID.
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046" -Iid "00000001-0000-0000-c000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID, only returning a specific IID.
#>
function Get-NdrComProxy {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [Guid]$Clsid = [Guid]::Empty,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [Guid[]]$Iid,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -NdrParserFlags $ParserFlags) {
        $proxies = $parser.ReadFromComProxyFile($Path, $Clsid, $Iid)
        $props = @{
            Path         = $Path;
            Proxies      = $proxies;
            ComplexTypes = $parser.ComplexTypes;
            IidToNames   = Convert-HashTableToIidNames -Proxy $proxies;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an NDR procedure.
.DESCRIPTION
This cmdlet formats a parsed NDR procedure.
.PARAMETER Procedure
The procedure to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.OUTPUTS
string - The formatted procedure.
.EXAMPLE
Format-NdrProcedure $proc
Format a procedure.
.EXAMPLE
$procs = | Format-NdrProcedure
Format a list of procedures from a pipeline.
.EXAMPLE
Format-NdrProcedure $proc -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a procedure with a known IID to name mapping.
#>
function Format-NdrProcedure {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true)]
        [NtApiDotNet.Ndr.NdrProcedureDefinition]$Procedure,
        [Hashtable]$IidToName
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
    }

    PROCESS {
        $fmt = $formatter.FormatProcedure($Procedure)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Format an NDR complex type.
.DESCRIPTION
This cmdlet formats a parsed NDR complex type.
.PARAMETER ComplexType
The complex type to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.OUTPUTS
string - The formatted complex type.
.EXAMPLE
Format-NdrComplexType $type
Format a complex type.
.EXAMPLE
$ndr.ComplexTypes | Format-NdrComplexType
Format a list of complex types from a pipeline.
.EXAMPLE
Format-NdrComplexType $type -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a complex type with a known IID to name mapping.
#>
function Format-NdrComplexType {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Ndr.NdrComplexTypeReference[]]$ComplexType,
        [Hashtable]$IidToName
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
    }

    PROCESS {
        foreach ($t in $ComplexType) {
            $formatter.FormatComplexType($t) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format an NDR COM proxy.
.DESCRIPTION
This cmdlet formats a parsed NDR COM proxy.
.PARAMETER Proxy
The proxy to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER DemangleComName
A script block which demangles a COM name (for WinRT types)
.OUTPUTS
string - The formatted proxy.
.EXAMPLE
Format-NdrComProxy $proxy
Format a COM proxy.
.EXAMPLE
$proxies = | Format-NdrComProxy
Format a list of COM proxies from a pipeline.
.EXAMPLE
Format-NdrComProxy $proxy -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a COM proxy with a known IID to name mapping.
#>
function Format-NdrComProxy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Ndr.NdrComProxyDefinition]$Proxy,
        [Hashtable]$IidToName,
        [ScriptBlock]$DemangleComName
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = if ($null -eq $DemangleComName) {
            [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
        }
        else {
            [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict, [Func[string, string]]$DemangleComName)
        }
    }

    PROCESS {
        $fmt = $formatter.FormatComProxy($Proxy)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Parses RPC server information from an executable.
.DESCRIPTION
This cmdlet parses the RPC server information from a specified executable with a known offset.
.PARAMETER Path
The path to the executable containing the RPC server information.
.PARAMETER Offset
The offset into the executable where the RPC_SERVER_INTERFACE structure is loaded.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed RPC server information and complex types.
.EXAMPLE
$p = Get-NdrRpcServerInterface c:\path\to\server.dll 0x18000
Parse the RPC server information from c:\path\to\proxy.dll with offset 0x18000
#>
function Get-NdrRpcServerInterface {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [parameter(Mandatory, Position = 1)]
        [int]$Offset,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -ParserFlags $ParserFlags) {
        $rpc_server = $parser.ReadFromRpcServerInterface($Path, $Offset)
        $props = @{
            Path         = $Path;
            RpcServer    = $rpc_server;
            ComplexTypes = $parser.ComplexTypes;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an RPC server interface type.
.DESCRIPTION
This cmdlet formats a parsed RPC server interface type.
.PARAMETER RpcServer
The RPC server interface to format.
.OUTPUTS
string - The formatted RPC server interface.
.EXAMPLE
Format-NdrRpcServerInterface $type
Format an RPC server interface type.
#>
function Format-NdrRpcServerInterface {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [NtApiDotNet.Ndr.NdrRpcServerInterface]$RpcServer
    )

    BEGIN {
        $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create()
    }

    PROCESS {
        $fmt = $formatter.FormatRpcServerInterface($RpcServer)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Get NDR complex types from memory.
.DESCRIPTION
This cmdlet parses NDR complex type information from a location in memory.
.PARAMETER PicklingInfo
Specify pointer to the MIDL_TYPE_PICKLING_INFO structure.
.PARAMETER StubDesc
Specify pointer to the MIDL_STUB_DESC structure.
.PARAMETER StublessProxy
Specify pointer to the MIDL_STUBLESS_PROXY_INFO structure.
.PARAMETER OffsetTable
Specify pointer to type offset table.
.PARAMETER TypeIndex
Specify list of type index into type offset table.
.PARAMETER TypeFormat
Specify list of type format string addresses for the types.
.PARAMETER TypeOffset
Specify list of type offsets into the format string for the types.
.PARAMETER Process
Specify optional process which contains the types.
.PARAMETER Module
Specify optional module base address for the types. If set all pointers
are relative offsets from the module address.
.INPUTS
None
.OUTPUTS
NdrComplexTypeReference[]
#>
function Get-NdrComplexType {
    [CmdletBinding(DefaultParameterSetName="FromDecode3")]
    Param(
        [Parameter(Mandatory)]
        [long]$PicklingInfo,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [long]$StubDesc,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [long[]]$TypeFormat,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [int[]]$TypeOffset,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$StublessProxy,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$OffsetTable,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [int[]]$TypeIndex,
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [NtApiDotNet.NtProcess]$Process,
        [NtApiDotNet.Ndr.NdrParserFlags]$Flags = "IgnoreUserMarshal"
    )

    $base_address = 0
    if ($null -ne $Module) {
        $base_address = $Module.DangerousGetHandle().ToInt64()
    }

    switch($PSCmdlet.ParameterSetName) {
        "FromDecode2" {
            $type_offset = $TypeFormat | % { $_ + $base_address }
            [NtApiDotNet.Ndr.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $type_offset, $Flags) | Write-Output
        }
        "FromDecode2Offset" {
            [NtApiDotNet.Ndr.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $TypeOffset, $Flags) | Write-Output
        }
        "FromDecode3" {
            [NtApiDotNet.Ndr.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StublessProxy+$base_address, $OffsetTable+$base_address, $TypeIndex, $Flags) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets an ALPC server port.
.DESCRIPTION
This cmdlet gets an ALPC server port by name. As you can't directly open the server end of the port this function goes through
all handles and tries to extract the port from the hosting process. This might require elevated privileges, especially debug
privilege, to work correctly.
.PARAMETER Path
The path to the ALPC server port to get.
.PARAMETER ProcessId
The process ID of the process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtAlpc
.EXAMPLE
Get-NtAlpcServer
Gets all ALPC server objects accessible to the current process.
.EXAMPLE
Get-NtAlpcServer "\RPC Control\atsvc"
Gets the "\RPC Control\atsvc" ALPC server.
.EXAMPLE
Get-NtAlpcServer -ProcessId 1234
Gets all ALPC servers from PID 1234.
#>
function Get-NtAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId
    )

    if (![NtApiDotNet.NtToken]::EnableDebugPrivilege()) {
        Write-Warning "Can't enable debug privilege, results might be incomplete"
    }

    if ($PSCmdlet.ParameterSetName -ne "FromProcessId") {
        $ProcessId = -1
    }
    $hs = Get-NtHandle -ObjectTypes "ALPC Port" -ProcessId $ProcessId | Where-Object Name -ne ""

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            Write-Output $hs.GetObject()
        }
        "FromProcessId" {
            Write-Output $hs.GetObject()
        }
        "FromPath" {
            foreach ($h in $hs) {
                if ($h.Name -eq $Path) {
                    Write-Output $h.GetObject()
                    break
                }
            }
        }
    }
}
