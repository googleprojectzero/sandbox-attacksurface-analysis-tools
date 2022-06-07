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
Gets the executable manifest for a PE file.
.DESCRIPTION
This cmdlet extracts the manifes from a PE file and extracts basic information such as UIAccess
setting or Auto Elevation.
.PARAMETER Path
Filename to get the executable manifest from.
.INPUTS
List of filenames
.OUTPUTS
NtApiDotNet.Win32.ExecutableManifest
.EXAMPLE
Get-ExecutableManifest abc.dll
Gets manifest from file abc.dll.
.EXAMPLE
Get-ChildItem $env:windir\*.exe -Recurse | Get-ExecutableManifest
Gets all manifests from EXE files, recursively under Windows.
.EXAMPLE
Get-ChildItem $env:windir\*.exe -Recurse | Get-ExecutableManifest | Where-Object AutoElevate | Select-Object FullPath
Get the full path of all executables with Auto Elevate manifest configuration.
#>
function Get-ExecutableManifest {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$Path
    )
    PROCESS {
        $fullpath = Resolve-Path -LiteralPath $Path
        $manifest = [NtApiDotNet.Win32.ExecutableManifest]::GetManifests($fullpath)
        Write-Output $manifest
    }
}

<#
.SYNOPSIS
Loads a DLL into memory.
.DESCRIPTION
This cmdlet loads a DLL into memory with specified flags.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER Flags
Specify the flags for loading.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.SafeLoadLibraryHandle
#>
function Import-Win32Module {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1)]
        [NtApiDotNet.Win32.LoadLibraryFlags]$Flags = 0
    )

    if (Test-Path $Path) {
        $Path = Resolve-Path $Path
    }

    [NtApiDotNet.Win32.SafeLoadLibraryHandle]::LoadLibrary($Path, $Flags) | Write-Output
}

<#
.SYNOPSIS
Gets an existing DLL from memory.
.DESCRIPTION
This cmdlet finds an existing DLL from memory.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER Address
Specify the address of the module.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.SafeLoadLibraryHandle
#>
function Get-Win32Module {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName = "FromAddress")]
        [IntPtr]$Address
    )

    if ($PSCmdlet.ParameterSetName -eq "FromPath") {
        if (Test-Path $Path) {
            $Path = Resolve-Path $Path
        }
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]::GetModuleHandle($Path) | Write-Output
    }
    else {
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]::GetModuleHandle($Address) | Write-Output
    }
}

<#
.SYNOPSIS
Gets the exports from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of exports from a loaded DLL or a single exported function.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER ProcAddress
Specify the name of the function to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DllExport[] or int64.
#>
function Get-Win32ModuleExport {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [string]$ProcAddress = ""
    )

    if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags LoadLibraryAsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleExport -Module $lib -ProcAddress $ProcAddress
            }
        }
    }
    else {
        if ($ProcAddress -eq "") {
            $Module.Exports | Write-Output
        }
        else {
            $Module.GetProcAddress($ProcAddress, $true).Result.ToInt64() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets the imports from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of imports from a loaded DLL.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER DllName
Specify a name of a DLL to only show imports from.
.PARAMETER ResolveApiSet
Specify to resolve API set names to the DLl names.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DllImport[]
#>
function Get-Win32ModuleImport {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [string]$DllName,
        [switch]$ResolveApiSet
    )

    $imports = if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags LoadLibraryAsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleImport -Module $lib -ResolveApiSet:$ResolveApiSet
            }
        }
    }
    else {
        if ($ResolveApiSet) {
            $Module.ApiSetImports
        } else {
            $Module.Imports
        }
    }

    if ($DllName -ne "") {
        $imports | Where-Object DllName -eq $DllName | Select-Object -ExpandProperty Functions | Write-Output
    }
    else {
        $imports | Write-Output
    }
}

<#
.SYNOPSIS
Download a symbol file from a symbol server for a module.
.DESCRIPTION
This cmdlet extracts the debug information from a loaded module and downloads the symbol file from a symbol server.
.PARAMETER Module
Specify the loaded module.
.PARAMETER Path
Specify the path to the module.
.PARAMETER OutPath
Specify the output path to write the symbol file to. If you specify a directory it will use the original filename. Defaults to current directory.
.PARAMETER SymbolServerUrl
Specify the URL for the symbol server. Defaults to the Microsoft public symbol server.
.PARAMETER Mirror
Specify that the output file should be a mirror of the symbol path. Useful to create a local symbol cache.
.INPUTS
None
.OUTPUTS
None
#>
function Get-Win32ModuleSymbolFile {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(Position = 1)]
        [string]$OutPath,
        [string]$SymbolServerUrl = "https://msdl.microsoft.com/download/symbols",
        [switch]$Mirror
    )

    if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags LoadLibraryAsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleSymbolFile -Module $lib -OutPath $OutPath -SymbolServerUrl $SymbolServerUrl -Mirror:$Mirror
            }
        }
    }
    else {
        $debug_data = $Module.DebugData
        $name = $debug_data.PdbName
        if ($Mirror) {
            if (!(Test-Path -Path $OutPath -PathType Container)) {
                Write-Error "Output path must be a directory when using mirror."
                return
            }

            $OutPath = $debug_data.GetSymbolPath((Resolve-Path $OutPath))
            New-Item -Type Directory -Path (Split-Path $OutPath -Parent) -Force -ErrorAction Stop | Out-Null
        } else {
            if ("" -eq $OutPath) {
                $OutPath = $name
            } else {
                if (Test-Path -Path $OutPath -PathType Container) {
                    $OutPath = Join-Path $OutPath $name
                }
            }
        }
        $url = $debug_data.GetSymbolPath($SymbolServerUrl)
        Invoke-WebRequest -Uri $url -OutFile $OutPath -ErrorAction Stop
        Write-Verbose "Wrote symbol file to $OutPath"
    }
}

<#
.SYNOPSIS
Gets the resources from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of resources from a loaded DLL.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER DontLoadResource
Specify to not load the resource data. Ignored if getting a specific type.
.PARAMETER Type
Specify the type of resource to get.
.PARAMETER Name
Specify the name of resource tot get. Must be combined with the Type.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Image.ImageResource
#>
function Get-Win32ModuleResource {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [switch]$DontLoadResource,
        [ValidateNotNullOrEmpty()]
        [string]$Type,
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if ($PSBoundParameters.Keys -contains 'Type') {
                        $true
                }
                else {
                    throw "Must specify a type when using a name."
                }
            })]
        [string]$Name
    )

    try {
        $lib = if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            Import-Win32Module -Path $Path -Flags LoadLibraryAsDataFile
        } else {
            $Module.AddRef()
        }

        Use-NtObject($lib) {
            if ("" -ne $Type) {
                if ("" -ne $Name) {
                    $lib.LoadResource($Name, $Type)
                } else {
                    $lib.GetResources($Type, !$DontLoadResource) | Write-Output
                }
            } else {
                $lib.GetResources(!$DontLoadResource) | Write-Output
            }
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get the embedded signature information from a file.
.DESCRIPTION
This cmdlet gets the embedded authenticode signature information from a file. This differs
from Get-AuthenticodeSignature in that it doesn't take into account catalog signing which is
important for tracking down PP and PPL executables.
.PARAMETER FullName
The path to the file to extract the signature from.
#>
function Get-EmbeddedAuthenticodeSignature {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$FullName
    )
    PROCESS {
        $content_type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Unknown
        try {
            $path = Resolve-Path $FullName
            $content_type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($path)
        }
        catch {
            Write-Error $_
        }

        if ($content_type -ne "Authenticode") {
            return
        }

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($path)
        $all_certs = [NtApiDotNet.Win32.Security.Authenticode.AuthenticodeUtils]::GetCertificates($path) | Write-Output
        $ppl = $false
        $pp = $false
        $tcb = $false
        $system = $false
        $dynamic = $false
        $elam = $false
        $store = $false
        $ium = $false
        $enclave = $false

        foreach ($eku in $cert.EnhancedKeyUsageList) {
            switch ($eku.ObjectId) {
                "1.3.6.1.4.1.311.10.3.22" { $ppl = $true }
                "1.3.6.1.4.1.311.10.3.24" { $pp = $true }
                "1.3.6.1.4.1.311.10.3.23" { $tcb = $true }
                "1.3.6.1.4.1.311.10.3.6" { $system = $true }
                "1.3.6.1.4.1.311.61.4.1" { $elam = $true }
                "1.3.6.1.4.1.311.76.5.1" { $dynamic = $true }
                "1.3.6.1.4.311.76.3.1" { $store = $true }
                "1.3.6.1.4.1.311.10.3.37" { $ium = $true }
                "1.3.6.1.4.1.311.10.3.42" { $enclave = $true }
            }
        }

        $page_hash = [NtApiDotNet.Win32.Security.Authenticode.AuthenticodeUtils]::ContainsPageHash($path)

        $props = @{
            Path                  = $Path;
            Certificate           = $cert;
            AllCertificates       = $all_certs;
            ProtectedProcess      = $pp;
            ProtectedProcessLight = $ppl;
            Tcb                   = $tcb;
            SystemComponent       = $system;
            DynamicCodeGeneration = $dynamic;
            Elam                  = $elam;
            Store                 = $store;
            IsolatedUserMode      = $ium;
            HasPageHash           = $page_hash;
            Enclave               = $enclave;
        }

        if ($elam) {
            $certs = [NtApiDotNet.Win32.Security.Authenticode.AuthenticodeUtils]::GetElamInformation($path, $false)
            if ($certs.IsSuccess)
            {
                $props["ElamCerts"] = $certs.Result
            }
        }

        if ($ium) {
            $policy = [NtApiDotNet.Win32.Security.Authenticode.ImagePolicyMetadata]::CreateFromFile($Path, $false)
            if ($policy.IsSuccess) {
                $props["TrustletPolicy"] = $policy.Result
            }
        }
        if ($ium -or $enclave) {
            $enclave = [NtApiDotNet.Win32.Security.Authenticode.AuthenticodeUtils]::GetEnclaveConfiguration($path, $false)
            if ($enclave.IsSuccess) {
                $props["EnclaveConfig"] = $enclave.Result
                $props["EnclavePrimaryImage"] = $enclave.Result.PrimaryImage
                $props["Enclave"] = $true
            }
        }

        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}
