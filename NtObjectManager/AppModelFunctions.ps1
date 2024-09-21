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
Get an appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet gets an appcontainer profile for a specified package name.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.PARAMETER OpenAlways
Specify to open the profile even if it doesn't exist.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.AppModel.AppContainerProfile
.EXAMPLE
Get-AppContainerProfile
Get appcontainer profiles for all installed packages.
.EXAMPLE
Get-AppContainerProfile -Name Package_aslkjdskjds
Get an appcontainer profile from a package name.
#>
function Get-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "All")]
        [switch]$AllUsers,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(ParameterSetName = "FromName")]
        [switch]$OpenAlways
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.AppModel.AppContainerProfile]::GetAppContainerProfiles() | Write-Output
        }
        "FromName" {
            if ($OpenAlways) {
                $prof = [NtCoreLib.Win32.AppModel.AppContainerProfile]::OpenExisting($Name, $false)
                if (!$prof.IsSuccess) {
                    $prof = [NtCoreLib.Win32.AppModel.AppContainerProfile]::Open($Name)
                }
                $prof | Write-Output
            } else {
                [NtCoreLib.Win32.AppModel.AppContainerProfile]::OpenExisting($Name) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Create a new appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet create a new appcontainer profile for a specified package name. If the profile already exists it'll open it.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.PARAMETER DisplayName
Specify the profile display name.
.PARAMETER Description
Specify the profile description.
.PARAMETER DeleteOnClose
Specify the profile should be deleted when closed.
.PARAMETER TemporaryProfile
Specify to create a temporary profile. Close the profile after use to delete it.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.AppModel.AppContainerProfile
.EXAMPLE
New-AppContainerProfile -Name Package_aslkjdskjds
Create a new AppContainer profile with a specified name.
.EXAMPLE
Get-AppContainerProfile -TemporaryProfile
Create a new temporary profile.
#>
function New-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Position = 1, ParameterSetName = "FromName")]
        [string]$DisplayName = "DisplayName",
        [parameter(Position = 2, ParameterSetName = "FromName")]
        [string]$Description = "Description",
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromTemp")]
        [NtCoreLib.Security.Authorization.Sid[]]$Capabilities,
        [parameter(ParameterSetName = "FromName")]
        [switch]$DeleteOnClose,
        [parameter(Mandatory, ParameterSetName = "FromTemp")]
        [switch]$TemporaryProfile
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromName" {
            $prof = [NtCoreLib.Win32.AppModel.AppContainerProfile]::Create($Name, $DisplayName, $Description, $Capabilities)
            if ($null -ne $prof) {
                $prof.DeleteOnClose = $DeleteOnClose
                Write-Output $prof
            }
        }
        "FromTemp" {
            [NtCoreLib.Win32.AppModel.AppContainerProfile]::CreateTemporary($Capabilities) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Delete an appcontainer profile.
.DESCRIPTION
This cmdlet deletes an appcontainer profile for a specified package name or from its profile.
.PARAMETER Name
Specify appcontainer name to delete.
.PARAMETER Profile
Specify appcontainer profile to delete.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-AppContainerProfile -Name "profile_to_remove"
Delete an appcontainer profiles by name.
.EXAMPLE
Remove-AppContainerProfile -Profile $prof
Delete an appcontainer profiles from an existing profile.
#>
function Remove-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProfile")]
        [NtCoreLib.Win32.AppModel.AppContainerProfile]$Profile,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromProfile" {
            $Profile.Delete()
        }
        "FromName" {
            [NtCoreLib.Win32.AppModel.AppContainerProfile]::Delete($Name)
        }
    }
}

<#
.SYNOPSIS
Start an application model application.
.DESCRIPTION
This cmdlet starts an application model application from it's application model ID.
.PARAMETER AppModelId
Specify the application model ID.
.PARAMETER Argument
Specify the argument for the application.
.PARAMETER PassThru
Specify to pass through a process object for the application.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtProcess
.EXAMPLE
Start-AppModelApplication -AppModelId "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
Start the Windows calculator.
#>
function Start-AppModelApplication {
    param(
        [parameter(Mandatory, Position = 0)]
        [string]$AppModelId,
        [parameter(Position = 1)]
        [string]$Argument = "",
        [switch]$PassThru
    )
    try {
        $app_id = [NtCoreLib.Win32.AppModel.AppModelUtils]::ActivateApplication($AppModelId, $Argument)
        if ($PassThru) {
            Get-NtProcess -ProcessId $app_id
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Query an app model policy for the a process.
.DESCRIPTION
This cmdlet queries the app model policy for a process.
.PARAMETER Process
Specify the process to get the app model policy for.
.PARAMETER Policy
Specify a specific policy to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.AppModelPolicy_PolicyValue
.EXAMPLE
Get-AppModelApplicationPolicy -Process $proc
Query all app model policies.
#>
function Get-AppModelApplicationPolicy {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromPolicy")]
        [NtCoreLib.AppModelPolicy_Type[]]$Policy
    )

    try {
        Use-NtObject($token = Get-NtToken -Process $proc) {
            switch($PSCmdlet.ParameterSetName) {
                "All" {
                    $token.AppModelPolicyDictionary | Write-Output
                }
                "FromPolicy" {
                    foreach($pol in $Policy) {
                        $token.GetAppModelPolicy($pol) | Write-Output
                    }
                }
            }
        }
    } catch {
        Write-Error $_
    }
}

function Check-FullTrust {
    param([xml]$Manifest)
    if ($Manifest -eq $null) {
        return $false
    }
    $nsmgr = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
    $nsmgr.AddNamespace("rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")
    $Manifest.SelectSingleNode("//rescap:Capability[@Name='runFullTrust']", $nsmgr) -ne $null
}

function Get-AppExtensions {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [xml]$Manifest
    )
    PROCESS {
        if ($Manifest -eq $null) {
            return
        }
        $nsmgr = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
        $nsmgr.AddNamespace("desktop", "http://schemas.microsoft.com/appx/manifest/desktop/windows10")
        $nodes = $Manifest.SelectNodes("//desktop:Extension[@Category='windows.fullTrustProcess']", $nsmgr)
        foreach($node in $nodes) {
            Write-Output $node.GetAttribute("Executable")
        }
    }
}

function Get-FullTrustApplications {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [xml]$Manifest,
        [parameter(Mandatory)]
        [string]$PackageFamilyName
    )
    PROCESS {
        if ($Manifest -eq $null) {
            return
        }
        $nsmgr = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
        $nsmgr.AddNamespace("app", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
        $nodes = $Manifest.SelectNodes("//app:Application[@EntryPoint='Windows.FullTrustApplication']", $nsmgr)
        foreach($node in $nodes) {
            $id = $node.GetAttribute("Id")
            $props = @{
                ApplicationUserModelId="$PackageFamilyName!$id";
                Executable=$node.GetAttribute("Executable");
            }

            Write-Output $(New-Object psobject -Property $props)
        }
    }
}

function Read-DesktopAppxManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Package,
        [switch]$AllUsers
    )
    PROCESS {
        $Manifest = Get-AppxPackageManifest $Package
        if (-not $(Check-FullTrust $Manifest)) {
            return
        }
        $install_location = $Package.InstallLocation
        $profile_dir = ""
        if (-not $AllUsers) {
            $profile_dir = "$env:LOCALAPPDATA\Packages\$($Package.PackageFamilyName)"
        }

        $has_registry = (Test-Path "$install_location\registry.dat") -or `
            (Test-Path "$install_location\user.dat") -or `
            (Test-Path "$install_location\userclasses.dat")

        $vfs_files = @{}
        $vfs_root = "$install_location\VFS"
        if (Test-Path $vfs_root) {
            foreach($f in (Get-ChildItem $vfs_root)) {
                $name = $f.Name
                $vfs_files[$name] = Get-ChildItem -Recurse "$vfs_root\$name"
            }
        }

        $props = @{
            Name=$Package.Name;
            Architecture=$Package.Architecture;
            Version=$Package.Version;
            Publisher=$Package.Publisher;
            PackageFamilyName=$Package.PackageFamilyName;
            InstallLocation=$install_location;
            Manifest=Get-AppxPackageManifest $Package;
            Applications=Get-FullTrustApplications $Manifest $Package.PackageFamilyName;
            Extensions=Get-AppExtensions $Manifest;
            VFSFiles=$vfs_files;
            HasRegistry=$has_registry;
            ProfileDir=$profile_dir;
        }

        New-Object psobject -Property $props
    }
}

<#
.SYNOPSIS
Get a list AppX packages with Desktop Bridge components.
.DESCRIPTION
This cmdlet gets a list of installed AppX packages which are either directly full trust applications or 
have an extension which can be used to run full trust applications.
.PARAMETER AllUsers
Specify getting information for all users, needs admin privileges.
.INPUTS
None
.OUTPUTS
Package results.
.EXAMPLE
Get-AppxDesktopBridge
Get all desktop bridge AppX packages for current user.
.EXAMPLE
Get-AppxDesktopBridge -AllUsers
Get all desktop bridge AppX packages for all users.
#>
function Get-AppxDesktopBridge {
    param([switch]$AllUsers)
    Get-AppxPackage -AllUsers:$AllUsers -PackageTypeFilter Main | Read-DesktopAppxManifest -AllUsers:$AllUsers
}

<#
.SYNOPSIS
Get list of package SIDs granted loopback exceptions.
.DESCRIPTION
This cmdlet gets the list of package SIDs which have been granted loopback exceptions.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid[]
.EXAMPLE
Get-AppModelLoopbackException
Get the list of loopback exception package SIDs.
#>
function Get-AppModelLoopbackException {
    [NtCoreLib.Win32.AppModel.AppModelUtils]::GetLoopbackException()
}

<#
.SYNOPSIS
Add a package SID to the list of granted loopback exceptions.
.DESCRIPTION
This cmdlet adds a package SID to the list of granted loopback exceptions.
.PARAMETER PackageSid
The package SID to add. Can be an SDDL SID or a name.
.INPUTS
string[]
.OUTPUTS
None
.EXAMPLE
Add-AppModelLoopbackException -PackageSid $package_sid
Add $package_sid to the list of loopback exceptions.
.EXAMPLE
Add-AppModelLoopbackException -PackageSid "ABC"
Add package "ABC" to the list of loopback exceptions.
#>
function Add-AppModelLoopbackException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$PackageSid
    )
    PROCESS {
        try {
            $sid = [NtCoreLib.Win32.Security.Win32Security]::GetPackageSidFromName($PackageSid)
            [NtCoreLib.Win32.AppModel.AppModelUtils]::AddLoopbackException($sid)
        } catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Remove a package SID from the list of granted loopback exceptions.
.DESCRIPTION
This cmdlet removes a package SID from the list of granted loopback exceptions.
.PARAMETER PackageSid
The package SID to remove.
.INPUTS
string[]
.OUTPUTS
None
.EXAMPLE
Remove-AppModelLoopbackException -PackageSid $package_sid
Remove $package_sid from the list of loopback exceptions.
.EXAMPLE
Remove-AppModelLoopbackException -PackageSid "ABC"
Remove package "ABC" from the list of loopback exceptions.
#>
function Remove-AppModelLoopbackException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$PackageSid
    )
    PROCESS {
        try {
            $sid = [NtCoreLib.Win32.Security.Win32Security]::GetPackageSidFromName($PackageSid)
            [NtCoreLib.Win32.AppModel.AppModelUtils]::RemoveLoopbackException($sid)
        } catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Gets the execution alias information from a name.
.DESCRIPTION
This cmdlet looks up an execution alias and tries to parse its reparse point to extract internal information.
.PARAMETER AliasName
The alias name to lookup. Can be either a full path to the alias or a name which will be found in the WindowsApps
folder.
.EXAMPLE
Get-ExecutionAlias ubuntu.exe
Get the ubuntu.exe execution alias from local appdata.
.EXAMPLE
Get-ExecutionAlias c:\path\to\alias.exe
Get the alias.exe execution alias from an absolute path.
#>
function Get-ExecutionAlias {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$AliasName
    )

    if (Test-Path $AliasName) {
        $path = Resolve-Path $AliasName
    }
    else {
        $path = $env:LOCALAPPDATA + "\Microsoft\WindowsApps\$AliasName"
    }

    Use-NtObject($file = Get-NtFile -Path $path -Win32Path -Options OpenReparsePoint, SynchronousIoNonAlert `
            -Access GenericRead, Synchronize) {
        $file.GetReparsePoint()
    }
}

<#
.SYNOPSIS
Creates a new execution alias information or updates and existing one.
.DESCRIPTION
This cmdlet creates a new execution alias for a packaged application.
.PARAMETER PackageName
The name of the UWP package.
.PARAMETER EntryPoint
The entry point of the application
.PARAMETER Target
The target executable path
.PARAMETER AppType
The application type.
.PARAMETER Version
Version number
.EXAMPLE
Set-ExecutionAlias c:\path\to\alias.exe -PackageName test -EntryPoint test!test -Target c:\test.exe -Flags 48 -Version 3
Set the alias.exe execution alias.
#>
function Set-ExecutionAlias {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$PackageName,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$EntryPoint,
        [Parameter(Mandatory = $true, Position = 3)]
        [string]$Target,
        [NtCoreLib.Kernel.IO.ExecutionAliasAppType]$AppType = "Desktop",
        [Int32]$Version = 3
    )

    $rp = [NtCoreLib.Kernel.IO.ExecutionAliasReparseBuffer]::new($Version, $PackageName, $EntryPoint, $Target, $AppType)
    Use-NtObject($file = New-NtFile -Path $Path -Win32Path -Options OpenReparsePoint, SynchronousIoNonAlert `
            -Access GenericWrite, Synchronize -Disposition OpenIf) {
        $file.SetReparsePoint($rp)
    }
}
