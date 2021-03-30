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
Connect to a SAM server.
.DESCRIPTION
This cmdlet connects to a SAM server for a specified system and access rights.
.PARAMETER ServerName
Specify the target system.
.PARAMETER Access
Specify the access rights on the server.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Sam.SamServer
.EXAMPLE
Connect-SamServer
Connect to the local SAM server with maximum access.
.EXAMPLE
Connect-SamServer -ServerName "PRIMARYDC"
Connect to the SAM server on the system PRIMARYDC with maximum access.
.EXAMPLE
Connect-SamServer -Access EnumerateDomains
Connect to the local SAM server with EnumerateDomains access.
#>
function Connect-SamServer { 
    [CmdletBinding()]
    param(
        [NtApiDotNet.Win32.Security.Sam.SamServerAccessRights]$Access = "MaximumAllowed",
        [string]$ServerName
    )

    [NtApiDotNet.Win32.Security.Sam.SamServer]::Connect($ServerName, $Access)
}

<#
.SYNOPSIS
Get a domain object from a SAM server.
.DESCRIPTION
This cmdlet opens a domain object from a SAM server.
.PARAMETER Access
Specify the access rights on the domain object.
.PARAMETER InfoOnly
Specify to only get domain information not objects.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Sam.SamDomain
.EXAMPLE
Get-SamDomain -Server $server
Get all accessible domain objects from the server.
.EXAMPLE
Get-SamDomain -Server $server -InfoOnly
Get all Information only domain from the server.
.EXAMPLE
Get-SamDomain -Server $server -Name "FLUBBER"
Get the FLIBBER domain object from the server.
#>
function Get-SamDomain { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Sam.SamServer]$Server,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromNameInfoOnly")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [Parameter(Mandatory, ParameterSetName="FromSidInfoOnly")]
        [NtApiDotNet.Sid]$DomainId,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [NtApiDotNet.Win32.Security.Sam.SamDomainAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [Parameter(Mandatory, ParameterSetName="FromNameInfoOnly")]
        [Parameter(Mandatory, ParameterSetName="FromSidInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Server.EnumerateDomains() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                DomainId = $Server.LookupDomain($_.Name)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Server.OpenAccessibleDomains($Access) | Write-Output
            }
            "FromName" {
                $Server.OpenDomain($Name, $Access)
            }
            "FromSid" {
                $Server.OpenDomain($DomainId, $Access)
            }
        }
    }
}
