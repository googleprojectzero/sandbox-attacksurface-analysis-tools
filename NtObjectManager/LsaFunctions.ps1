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
Get current authentication packages.
.DESCRIPTION
This cmdlet gets the list of current authentication packages.
.PARAMETER Name
The name of the authentication package.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationPackage
.EXAMPLE
Get-LsaPackage
Get all authentication packages.
.EXAMPLE
Get-LsaPackage -Name NTLM
Get the NTLM authentication package.
#>
function Get-LsaPackage {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.Security.Authentication.AuthenticationPackage]::Get() | Write-Output
        }
        "FromName" {
            [NtApiDotNet.Win32.Security.Authentication.AuthenticationPackage]::FromName($Name) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Read's user credentials from the shell.
.DESCRIPTION
This cmdlet reads the user credentials from the shell and encodes the password.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.UserCredentials
.EXAMPLE
$user_creds = Read-LsaCredential
Read user credentials from the shell.
#>
function Read-LsaCredential {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [string]$UserName,
        [Parameter(Position = 1)]
        [string]$Domain,
        [Parameter(Position = 2)]
        [NtObjectManager.Utils.PasswordHolder]$Password
    )

    $creds = [NtApiDotNet.Win32.Security.Authentication.UserCredentials]::new()
    if ($UserName -eq "") {
        $UserName = Read-Host -Prompt "UserName"
    }
    $creds.UserName = $UserName
    if ($Domain -eq "") {
        $Domain = Read-Host -Prompt "Domain"
    }
    $creds.Domain = $Domain
    if ($null -ne $Password) {
        $creds.Password = $Password.Password
    }
    else {
        $creds.Password = Read-Host -AsSecureString -Prompt "Password"
    }
    $creds | Write-Output
}

<#
.SYNOPSIS
Get user credentials.
.DESCRIPTION
This cmdlet gets user credentials and encodes the password.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use, can be a string or a StringString.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.UserCredentials
.EXAMPLE
$user_creds = Get-LsaCredential -UserName "ABC" -Domain "DOMAIN" -Password "pwd"
Get user credentials from components.
#>
function Get-LsaCredential {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [string]$UserName,
        [Parameter(Position = 1)]
        [string]$Domain,
        [Parameter(Position = 2)]
        [alias("SecurePassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password
    )

    $creds = [NtApiDotNet.Win32.Security.Authentication.UserCredentials]::new()
    if ($UserName -ne "") {
        $creds.UserName = $UserName
    }
    
    if ($Domain -ne "") {
        $creds.Domain = $Domain
    }

    if ($null -ne $Password) {
        $creds.Password = $Password.Password
    }
    $creds
}

<#
.SYNOPSIS
Get Schannel credentials.
.DESCRIPTION
This cmdlet gets Schannel credentials.
.PARAMETER Flags
The flags for the credentials.
.PARAMETER SessionLifespan
The lifespan of a session in milliseconds.
.PARAMETER Certificate
The list of certificates to use. Needs to have a private key.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.Schannel.SchannelCredentials
.EXAMPLE
$creds = Get-LsaSchannelCredential -Certificate $cert
Get credentials with a certificate.
#>
function Get-LsaSchannelCredential {
    [CmdletBinding()]
    Param(
        [NtApiDotNet.Win32.Security.Authentication.Schannel.SchannelCredentialsFlags]$Flags = 0,
        [int]$SessionLifespan = 0,
        [X509Certificate[]]$Certificate
    )

    $creds = [NtApiDotNet.Win32.Security.Authentication.Schannel.SchannelCredentials]::new()
    $creds.Flags = $Flags
    $creds.SessionLifespan = $SessionLifespan
    foreach($cert in $Certificate) {
        $creds.AddCertificate($cert)
    }
    $creds
}

<#
.SYNOPSIS
Get CredSSP credentials.
.DESCRIPTION
This cmdlet gets CredSSP credentials. This is only needed if you want both Schannel and user credentials. Otherwise
just use Get-LsaSchannelCredential or Get-LsaCredential.
.PARAMETER Schannel
The Schannel credentials.
.PARAMETER User
The user credentials.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.CredSSP.CredSSPCredentials
.EXAMPLE
$creds = Get-LsaCredSSPCredential -Schannel $schannel -User $user
Get credentials from a schannel and user credentials object.
#>
function Get-LsaCredSSPCredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position=0)]
        [NtApiDotNet.Win32.Security.Authentication.Schannel.SchannelCredentials]$Schannel,
        [Parameter(Mandatory, Position=1)]
        [NtApiDotNet.Win32.Security.Authentication.UserCredentials]$User
    )

    [NtApiDotNet.Win32.Security.Authentication.CredSSP.CredSSPCredentials]::new($Schannel, $User)
}

<#
.SYNOPSIS
Create a new credentials handle.
.DESCRIPTION
This cmdlet creates a new authentication credentials handle.
.PARAMETER Package
The name of the package to use.
.PARAMETER UseFlag
The use flags for the credentials.
.PARAMETER AuthId
Optional authentication ID to authenticate.
.PARAMETER Principal
Optional principal to authentication.
.PARAMETER Credential
Optional Credentials for the authentication.
.PARAMETER ReadCredential
Specify to read the credentials from the console if not specified explicitly.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.CredentialHandle
.EXAMPLE
$h = New-LsaCredentialHandle -Package "NTLM" -UseFlag Both
Get a credential handle for the NTLM package for both directions.
.EXAMPLE
$h = New-LsaCredentialHandle -Package "NTLM" -UseFlag Both -UserName "user" -Password "pwd"
Get a credential handle for the NTLM package for both directions with a username password.
.EXAMPLE
$h = New-LsaCredentialHandle -Package "NTLM" -UseFlag Inbound -ReadCredential
Get a credential handle for the NTLM package for outbound directions and read credentials from the shell.
#>
function New-LsaCredentialHandle {
    [CmdletBinding(DefaultParameterSetName="FromCreds")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Package,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.SecPkgCredFlags]$UseFlag,
        [Nullable[NtApiDotNet.Luid]]$AuthId,
        [string]$Principal,
        [Parameter(ParameterSetName="FromCreds")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationCredentials]$Credential,
        [Parameter(ParameterSetName="FromParts")]
        [switch]$ReadCredential,
        [Parameter(ParameterSetName="FromParts")]
        [string]$UserName,
        [Parameter(ParameterSetName="FromParts")]
        [string]$Domain,
        [Parameter(ParameterSetName="FromParts")]
        [alias("SecurePassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password
    )

    if ($PSCmdlet.ParameterSetName -eq "FromParts") {
        if ($ReadCredential) {
            $Credential = Read-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        } else {
            $Credential = Get-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        }
    }

    [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]::Create($Principal, $Package, $AuthId, $UseFlag, $Credential) | Write-Output
}

$package_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    (Get-LsaPackage).Name | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { "'$_'" }
}

Register-ArgumentCompleter -CommandName New-LsaCredentialHandle -ParameterName Package -ScriptBlock $package_completer

<#
.SYNOPSIS
Create a new authentication client.
.DESCRIPTION
This cmdlet creates a new authentication client.
.PARAMETER CredHandle
The credential handle to use.
.PARAMETER RequestAttribute
Request attributes.
.PARAMETER Target
Optional SPN target.
.PARAMETER DataRepresentation
Data representation format.
.PARAMETER ChannelBinding
Optional channel binding token.
.PARAMETER NoInit
Don't initialize the client authentication context.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext
#>
function New-LsaClientContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]$CredHandle,
        [NtApiDotNet.Win32.Security.Authentication.InitializeContextReqFlags]$RequestAttribute = 0,
        [string]$Target,
        [byte[]]$ChannelBinding,
        [NtApiDotNet.Win32.Security.Authentication.SecDataRep]$DataRepresentation = "Native",
        [switch]$NoInit
    )

    [NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext]::new($CredHandle, `
            $RequestAttribute, $Target, $ChannelBinding, $DataRepresentation, !$NoInit)
}

<#
.SYNOPSIS
Create a new authentication server.
.DESCRIPTION
This cmdlet creates a new authentication server.
.PARAMETER CredHandle
The credential handle to use.
.PARAMETER RequestAttribute
Request attributes.
.PARAMETER DataRepresentation
Data representation format.
.PARAMETER ChannelBinding
Optional channel binding token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.ServerAuthenticationContext
#>
function New-LsaServerContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]$CredHandle,
        [NtApiDotNet.Win32.Security.Authentication.AcceptContextReqFlags]$RequestAttribute = 0,
        [NtApiDotNet.Win32.Security.Authentication.SecDataRep]$DataRepresentation = "Native",
        [byte[]]$ChannelBinding
    )

    [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]::new($CredHandle, `
            $RequestAttribute, $ChannelBinding, $DataRepresentation)
}

<#
.SYNOPSIS
Update an authentication client.
.DESCRIPTION
This cmdlet updates an authentication client. Returns true if the authentication is complete.
.PARAMETER Client
The authentication client.
.PARAMETER Server
The authentication server to extract token from.
.PARAMETER Token
The next authentication token.
.PARAMETER InputBuffer
A list of additional input buffers.
.PARAMETER OutputBuffer
A list of additional output buffers.
.PARAMETER NoToken
Specify to update with no token in the input buffer.
.PARAMETER PassThru
Specify to passthrough the new context token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Update-LsaClientContext {
    [CmdletBinding(DefaultParameterSetName="FromToken")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext]$Client,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]$Server,
        [Parameter(Mandatory, ParameterSetName="FromNoToken")]
        [switch]$NoToken,
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$InputBuffer = @(),
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$OutputBuffer = @(),
        [switch]$PassThru
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromContext" {
            $Client.Continue($Server.Token, $InputBuffer, $OutputBuffer)
        }
        "FromToken" {
            $Client.Continue($Token, $InputBuffer, $OutputBuffer)
        }
        "FromNoToken" {
            $Client.Continue($InputBuffer, $OutputBuffer)
        }
    }
    if ($PassThru) {
        $Client.Token
    }
}

<#
.SYNOPSIS
Update an authentication server.
.DESCRIPTION
This cmdlet updates an authentication server. Returns true if the authentication is complete.
.PARAMETER Server
The authentication server.
.PARAMETER Client
The authentication client to extract token from.
.PARAMETER Token
The next authentication token.
.PARAMETER InputBuffer
A list of additional input buffers.
.PARAMETER OutputBuffer
A list of additional output buffers.
.PARAMETER NoToken
Specify to update with no token in the input buffer.
.PARAMETER PassThru
Specify to passthrough the new context token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Update-LsaServerContext {
    [CmdletBinding(DefaultParameterSetName="FromToken")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]$Server,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext]$Client,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Mandatory, ParameterSetName="FromNoToken")]
        [switch]$NoToken,
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$InputBuffer = @(),
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$OutputBuffer = @(),
        [switch]$PassThru
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromContext" {
            $Server.Continue($Client.Token, $InputBuffer, $OutputBuffer)
        }
        "FromToken" {
            $Server.Continue($Token, $InputBuffer, $OutputBuffer)
        }
        "FromNoToken" {
            $Server.Continue($InputBuffer, $OutputBuffer)
        }
    }
    if ($PassThru) {
        $Server.Token
    }
}

<#
.SYNOPSIS
Get access token for the authentication.
.DESCRIPTION
This cmdlet gets the access token for authentication, once complete.
.PARAMETER Server
The authentication server.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtToken
#>
function Get-LsaAccessToken {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]$Server
    )

    $Server.GetAccessToken() | Write-Output
}

<#
.SYNOPSIS
Gets an authentication token.
.DESCRIPTION
This cmdlet gets an authentication token from a context or from 
an array of bytes.
.PARAMETER Context
The authentication context to extract token from. If combined with Token will parse according to
the type of context.
.PARAMETER Token
The array of bytes for the new token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Get-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromBytes")]
        [byte[]]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [Parameter(ParameterSetName="FromBytes")]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromContext") {
            $Context.Token | Write-Output
        } else {
            if ($null -ne $Context) {
                [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]::Parse($Context, $Token)
            } else {
                [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]::new($Token)
            }
        }
    }
}

<#
.SYNOPSIS
Tests an authentication context to determine if it's complete.
.DESCRIPTION
This cmdlet tests and authentication context to determine if it's complete.
.PARAMETER Context
The authentication context to test.
.INPUTS
None
.OUTPUTS
bool
#>
function Test-LsaContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context
    )

    return $Context.Done
}

<#
.SYNOPSIS
Format an authentication token.
.DESCRIPTION
This cmdlet formats an authentication token. Defaults to
a hex dump if format unknown.
.PARAMETER Context
The authentication context to extract token from.
.PARAMETER Token
The authentication token to format.
.PARAMETER AsBytes
Always format as a hex dump.
.PARAMETER AsDER
Always format as a ASN.1 DER structure.
.INPUTS
None
.OUTPUTS
string
#>
function Format-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [switch]$AsBytes,
        [switch]$AsDER
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromContext") {
            $Token = $Context.Token
        }
        if ($AsBytes) {
            $ba = $Token.ToArray()
            if ($ba.Length -gt 0) {
                Out-HexDump -Bytes $ba -ShowAll
            }
        } elseif ($AsDER) {
            $ba = $Token.ToArray()
            if ($ba.Length -gt 0) {
                Format-ASN1DER -Bytes $ba
            }
        } else {
            $Token.Format() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Exports an authentication token to a file.
.DESCRIPTION
This cmdlet exports an authentication token to a file.
.PARAMETER Context
The authentication context to extract token from.
.PARAMETER Token
The authentication token to export.
.PARAMETER Path
The path to the file to export.
.INPUTS
None
.OUTPUTS
None
#>
function Export-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [Parameter(Position = 1, Mandatory)]
        [string]$Path
    )

    if ($PSCmdlet.ParameterSetName -eq "FromContext") {
        $Token = $Context.Token
    }

    $Token.ToArray() | Set-Content -Path $Path -Encoding Byte
}

<#
.SYNOPSIS
Imports an authentication token to a file.
.DESCRIPTION
This cmdlet imports an authentication token from a file.
.PARAMETER Path
The path to the file to import.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Import-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path
    )

    $token = [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken][byte[]](Get-Content -Path $Path -Encoding Byte)
    Write-Output $token
}

<#
.SYNOPSIS
Decrypt an Authentication Token.
.DESCRIPTION
This cmdlet attempts to decrypt an authentication token. The call will return the decrypted token.
This is primarily for Kerberos.
.PARAMETER Key
Specify a keys for decryption.
.PARAMETER Token
The authentication token to decrypt.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Unprotect-LsaAuthToken {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationKey[]]$Key
    )
    $Token.Decrypt($Key) | Write-Output
}

<#
.SYNOPSIS
Get a signature from an authentication context for some message.
.DESCRIPTION
This cmdlet uses an authentication context to generate a message signature. It can be verified using Test-LsaContextSignature.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to sign.
.PARAMETER SequenceNumber
Specify the sequence number for the signature to prevent replay.
.PARAMETER Buffer
Specify the list of buffers to sign.
.INPUTS
byte[]
.OUTPUTS
byte[]
#>
function Get-LsaContextSignature {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName="FromBytes")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Position = 2)]
        [int]$SequenceNumber = 0
    )

    BEGIN {
        $sig_data = New-Object byte[] -ArgumentList 0
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromBytes") {
            $sig_data += $Message
        }
    }

    END {
        switch($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                $Context.MakeSignature($sig_data, $SequenceNumber)
            } 
            "FromBuffers" {
                $Context.MakeSignature($Buffer, $SequenceNumber)
            }
        }
    }
}

<#
.SYNOPSIS
Verify a signature from an authentication context for some message.
.DESCRIPTION
This cmdlet uses an authentication context to verify a  signature.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to verify.
.PARAMETER Signature
Specify signature to verify.
.PARAMETER SequenceNumber
Specify the sequence number for the signature to prevent replay.
.PARAMETER Buffer
Specify the list of buffers to sign.
.INPUTS
None
.OUTPUTS
bool
#>
function Test-LsaContextSignature {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBytes")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Mandatory, Position = 2)]
        [byte[]]$Signature,
        [parameter(Position = 3)]
        [int]$SequenceNumber = 0
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromBytes" {
            $Context.VerifySignature($Message, $Signature, $SequenceNumber)
        }
        "FromBuffers" {
            $Context.VerifySignature($Buffer, $Signature, $SequenceNumber)
        }
    }
}

<#
.SYNOPSIS
Encrypt some message for an authentication context.
.DESCRIPTION
This cmdlet uses an authentication context to encrypt some message. It returns both the encrypted message and a signature.
It can be decrypted using Unprotect-LsaContextMessage. If you use buffers only the signature is returned from the command
and the encrypted data is updated in place.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to encrypt.
.PARAMETER SequenceNumber
Specify the sequence number for the encryption to prevent replay.
.PARAMETER QualityOfProtection
Specify flags for the encryption operation. For example wrap but don't encrypt.
.PARAMETER NoSignature
Specify to not automatically generate a signature buffer.
.INPUTS
byte[]
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.EncryptedMessage
#>
function Protect-LsaContextMessage {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName="FromBytes")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Position = 2)]
        [int]$SequenceNumber = 0,
        [NtApiDotNet.Win32.Security.Authentication.SecurityQualityOfProtectionFlags]$QualityOfProtection = 0,
        [switch]$NoSignature
    )

    BEGIN {
        $enc_data = New-Object byte[] -ArgumentList 0
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromBytes") {
            $enc_data += $Message
        }
    }

    END {
        switch($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                if ($NoSignature) {
                    $buf = New-LsaSecurityBuffer -Type Data -Byte $enc_data
                    $Context.EncryptMessageNoSignature([NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]@($buf), $QualityOfProtection, $SequenceNumber)
                } else {
                    $Context.EncryptMessage($enc_data, $QualityOfProtection, $SequenceNumber)
                }
            }
            "FromBuffers" {
                if ($NoSignature) {
                    $Context.EncryptMessageNoSignature($Buffer, $QualityOfProtection, $SequenceNumber)
                } else {
                    $Context.EncryptMessage($Buffer, $QualityOfProtection, $SequenceNumber)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Decrypt some message from an authentication context.
.DESCRIPTION
This cmdlet uses an authentication context to decrypt some message as well as verify a signature.
If using buffers the data is decrypted in place.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to decrypt.
.PARAMETER Signature
Specify signature to verify.
.PARAMETER SequenceNumber
Specify the sequence number for the encryption to prevent replay.
.PARAMETER NoSignature
Specify to not include a signature automatically in the buffers.
.INPUTS
None
.OUTPUTS
byte[]
#>
function Unprotect-LsaContextMessage {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBytes")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBytesNoSig")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffersNoSig")]
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromBytes")]
        [parameter(Mandatory, Position = 2, ParameterSetName="FromBuffers")]
        [byte[]]$Signature,
        [parameter(Mandatory, ParameterSetName="FromBuffersNoSig")]
        [parameter(Mandatory, ParameterSetName="FromBytesNoSig")]
        [switch]$NoSignature,
        [parameter(Position = 3)]
        [int]$SequenceNumber = 0
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromBytes" {
            $msg = [NtApiDotNet.Win32.Security.Authentication.EncryptedMessage]::new($Message, $Signature)
            $Context.DecryptMessage($msg, $SequenceNumber)
        }
        "FromBuffers" {
            $Context.DecryptMessage($Buffer, $Signature, $SequenceNumber)
        }
        "FromBuffersNoSig" {
            $Context.DecryptMessageNoSignature($Buffer, $SequenceNumber)
        }
        "FromBytesNoSig" {
            $buf = New-LsaSecurityBuffer -Type Data -Byte $Message
            $Context.DecryptMessageNoSignature([NtApiDotNet.Win32.Security.Buffers.SecurityBuffer[]]@($buf), $SequenceNumber)
            $buf.ToArray() | Write-Output -NoEnumerate
        }
    }
}

<#
.SYNOPSIS
Create a new security buffer based on existing data or for output.
.DESCRIPTION
This cmdlet creates a new security object either containing existing data for input/output or and output only buffer.
.PARAMETER Type
Specify the type of the buffer.
.PARAMETER Byte
Specify the existing bytes for the buffer.
.PARAMETER Size
Specify the size of a buffer for an output buffer.
.PARAMETER ChannelBinding
Specify a channel binding token.
.PARAMETER Token
Specify a buffer which is an authentication token.
.PARAMETER String
Specify a buffer derived from a string.
.PARAMETER Encoding
Specify the character encoding when making a buffer from a string.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Buffers.SecurityBuffer
#>
function New-LsaSecurityBuffer {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromSize")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromString")]
        [parameter(ParameterSetName="FromEmpty")]
        [NtApiDotNet.Win32.Security.Buffers.SecurityBufferType]$Type = 0,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSize")]
        [int]$Size,
        [parameter(Mandatory, ParameterSetName="FromEmpty")]
        [switch]$Empty,
        [parameter(Mandatory, ParameterSetName="FromChannelBinding")]
        [byte[]]$ChannelBinding,
        [Parameter(Mandatory, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [parameter(Mandatory, ParameterSetName="FromString")]
        [string]$String,
        [parameter(ParameterSetName="FromString")]
        [string]$Encoding = "Unicode",
        [parameter(ParameterSetName="FromBytes")]
        [parameter(ParameterSetName="FromString")]
        [Parameter(ParameterSetName="FromToken")]
        [switch]$ReadOnly,
        [parameter(ParameterSetName="FromBytes")]
        [parameter(ParameterSetName="FromString")]
        [Parameter(ParameterSetName="FromToken")]
        [switch]$ReadOnlyWithChecksum
    )

    $type_flags = if ($PSCmdlet.ParameterSetName -eq "FromToken") {
        [NtApiDotNet.Win32.Security.Buffers.SecurityBufferType]::Token
    } else {
        $Type
    }
    if ($ReadOnly) {
        $type_flags = $type_flags -bor [NtApiDotNet.Win32.Security.Buffers.SecurityBufferType]::ReadOnly
    }
    if ($ReadOnlyWithChecksum) {
        $type_flags = $type_flags -bor [NtApiDotNet.Win32.Security.Buffers.SecurityBufferType]::ReadOnlyWithChecksum
    }

    switch($PSCmdlet.ParameterSetName) {
        "FromBytes" {
            [NtApiDotNet.Win32.Security.Buffers.SecurityBufferInOut]::new($type_flags, $Byte)
        }
        "FromSize" {
            [NtApiDotNet.Win32.Security.Buffers.SecurityBufferOut]::new($type_flags, $Size)
        }
        "FromEmpty" {
            [NtApiDotNet.Win32.Security.Buffers.SecurityBufferOut]::new($type_flags, 0)
        }
        "FromChannelBinding" {
            [NtApiDotNet.Win32.Security.Buffers.SecurityBufferChannelBinding]::new($ChannelBinding)
        }
        "FromToken" {
            [NtApiDotNet.Win32.Security.Buffers.SecurityBufferInOut]::new($type_flags, $Token.ToArray())
        }
        "FromString" {
            [NtApiDotNet.Win32.Security.Buffers.SecurityBufferInOut]::new($type_flags, [System.Text.Encoding]::GetEncoding($Encoding).GetBytes($String))
        }
    }
}

<#
.SYNOPSIS
Convert a security buffer to another format.
.DESCRIPTION
This cmdlet converts a security buffer to another format, either a byte array, string or authentication token.
.PARAMETER Buffer
The buffer to convert.
.PARAMETER AsString
Specify to convert the string as bytes.
.PARAMETER Encoding
Specify the character encoding when converting to a string.
.PARAMETER AsToken
Specify to convert the buffer to an authentication token.
.INPUTS
NtApiDotNet.Win32.Security.Buffers.SecurityBuffer
.OUTPUTS
byte[]
string
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function ConvertFrom-LsaSecurityBuffer {
    [CmdletBinding(DefaultParameterSetName="ToBytes")]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.Security.Buffers.SecurityBuffer]$Buffer,
        [parameter(Mandatory, ParameterSetName="ToString")]
        [switch]$AsString,
        [parameter(ParameterSetName="ToString")]
        [string]$Encoding = "Unicode",
        [parameter(Mandatory, ParameterSetName="ToToken")]
        [switch]$AsToken
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "ToBytes" {
                $Buffer.ToArray() | Write-Output -NoEnumerate
            }
            "ToString" {
                [System.Text.Encoding]::GetEncoding($Encoding).GetString($Buffer.ToArray())
            }
            "ToToken" {
                Get-LsaAuthToken -Token $Buffer.ToArray()
            }
        }
    }
}

<#
.SYNOPSIS
Get an LSA policy object.
.DESCRIPTION
This cmdlet gets an LSA policy object for a specified system and access rights.
.PARAMETER SystemName
Specify the target system.
.PARAMETER Access
Specify the access rights on the policy.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Policy.LsaPolicy
.EXAMPLE
Get-LsaPolicy
Get the local LSA policy object with maximum access.
.EXAMPLE
Get-LsaPolicy -SystemName "PRIMARYDC"
Get the LSA policy object on the system PRIMARYDC with maximum access.
.EXAMPLE
Get-LsaPolicy -Access LookupNames
Get the local LSA policy object with LookupNames access.
#>
function Get-LsaPolicy { 
    [CmdletBinding()]
    param(
        [NtApiDotNet.Win32.Security.Policy.LsaPolicyAccessRights]$Access = "MaximumAllowed",
        [string]$SystemName
    )

    [NtApiDotNet.Win32.Security.Policy.LsaPolicy]::Open($SystemName, $Access)
}

<#
.SYNOPSIS
Get an account object from an LSA policy.
.DESCRIPTION
This cmdlet opens an account object from a LSA policy.
.PARAMETER Policy
Specify the policy to get the account from.
.PARAMETER Access
Specify the access rights on the account object.
.PARAMETER InfoOnly
Specify to only get account information not objects.
.PARAMETER Sid
Specify to get account by SID.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Policy.LsaAccount
.EXAMPLE
Get-LsaAccount -Policy $policy
Get all accessible account objects in the policy.
.EXAMPLE
Get-LsaAccount -Policy $policy -InfoOnly
Get all information only account objects in the policy.
.EXAMPLE
Get-LsaAccount -Policy $policy -Sid "S-1-2-3-4"
Get the account object by SID.
#>
function Get-LsaAccount { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromSid")]
        [NtApiDotNet.Sid]$Sid,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromSid")]
        [NtApiDotNet.Win32.Security.Policy.LsaAccountAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Policy.EnumerateAccounts() | Write-Output
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Policy.OpenAccessibleAccounts($Access) | Write-Output
            }
            "FromSid" {
                $Policy.OpenAccount($Sid, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a trusted domain object from an LSA policy.
.DESCRIPTION
This cmdlet opens a trusted domain object from a LSA policy.
.PARAMETER Policy
Specify the policy to get the trusted domain from.
.PARAMETER Access
Specify the access rights on the trusted domain object.
.PARAMETER InfoOnly
Specify to only get trusted domain information not objects.
.PARAMETER Sid
Specify to get trusted domain by SID.
.PARAMETER Name
Specify to get trusted domain by name.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Policy.LsaTrustedDomain
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy
Get all accessible trusted domain objects in the policy.
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy -InfoOnly
Get all information only trusted domain objects in the policy.
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy -Sid "S-1-2-3"
Get the trusted domain object by SID.
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy -Name "domain.local"
Get the trusted domain object by name.
#>
function Get-LsaTrustedDomain { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtApiDotNet.Sid]$Sid,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromName")]
        [NtApiDotNet.Win32.Security.Policy.LsaTrustedDomainAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Policy.EnumerateTrustedDomains() | Write-Output
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Policy.OpenAccessibleTrustedDomains($Access) | Write-Output
            }
            "FromSid" {
                $Policy.OpenTrustedDomain($Sid, $Access)
            }
            "FromName" {
                $Policy.OpenTrustedDomain($Name, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a secret object from an LSA policy.
.DESCRIPTION
This cmdlet opens a secret object from a LSA policy.
.PARAMETER Policy
Specify the policy to get the secret from.
.PARAMETER Access
Specify the access rights on the secret object.
.PARAMETER Name
Specify to get trusted domain by name.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Policy.LsaSecret
.EXAMPLE
Get-LsaSecret -Policy $policy -Name '$SECRET_NAME'
Get the secret by name.
#>
function Get-LsaSecret { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1)]
        [string]$Name,
        [NtApiDotNet.Win32.Security.Policy.LsaSecretAccessRights]$Access = "MaximumAllowed"
    )

    $Policy.OpenSecret($Name, $Access)
}

<#
.SYNOPSIS
Lookup one or more SIDs by name from the policy.
.DESCRIPTION
This cmdlet looks up one or more SIDs from a LSA policy.
.PARAMETER Policy
Specify the policy to get the SIDs from.
.PARAMETER Name
Specify the names to lookup.
.PARAMETER Flags
Specify flags for the looked up names.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SidName[]
.EXAMPLE
Get-LsaSid -Policy $policy -Name 'Administrator'
Lookup the name Administrator in the policy.
#>
function Get-LsaSid { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1)]
        [string[]]$Name,
        [NtApiDotnet.Win32.Security.Policy.LsaLookupNameOptionFlags]$Flags = 0
    )

    $Policy.LookupNames($Name, $Flags) | Write-Output
}

<#
.SYNOPSIS
Lookup one or more names by SID from the policy.
.DESCRIPTION
This cmdlet looks up one or more names from a LSA policy.
.PARAMETER Policy
Specify the policy to get the names from.
.PARAMETER Sid
Specify the SIDs to lookup.
.PARAMETER Flags
Specify flags for the looked up SIDs.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SidName[]
.EXAMPLE
Get-LsaName -Policy $policy -Sid 'S-1-5-32-544'
Lookup the SID S-1-5-32-544 in the policy.
#>
function Get-LsaName { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1)]
        [NtApiDotNet.Sid[]]$Sid,
        [NtApiDotnet.Win32.Security.Policy.LsaLookupSidOptionFlags]$Flags = 0
    )

    if ($Flags -ne 0) {
        $Policy.LookupSids2($Sid, $Flags) | Write-Output
    } else {
        $Policy.LookupSids($Sid) | Write-Output
    }
}

<#
.SYNOPSIS
Get a LSA private data (secret) object.
.DESCRIPTION
This cmdlet gets the private data from an LSA policy.
.PARAMETER SystemName
Specify the target system.
.PARAMETER Name
Specify the name of the private data.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Get-LsaPrivateData -Name "MYSECRET"
Get the LSA private data MYSECRET.
.EXAMPLE
Get-LsaPrivateData -Name "MYSECRET" -SystemName PRIMARYDC
Get the LSA private data MYSECRET from the PRIMARYDC.
#>
function Get-LsaPrivateData { 
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Name,
        [string]$SystemName
    )

    [NtApiDotNet.Win32.Security.Win32Security]::LsaRetrievePrivateData($SystemName, $Name)
}

<#
.SYNOPSIS
Set a LSA private data (secret) object.
.DESCRIPTION
This cmdlet sets the private data for an LSA policy.
.PARAMETER SystemName
Specify the target system.
.PARAMETER Name
Specify the name of the private data.
.PARAMETER Data
Specify the data to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-LsaPrivateData -Name "MYSECRET" -Data 0, 1, 2, 3
Set the LSA private data MYSECRET.
.EXAMPLE
Set-LsaPrivateData -Name "MYSECRET" -SystemName PRIMARYDC -Data 0, 1, 2, 3
Set the LSA private data MYSECRET on PRIMARYDC.
#>
function Set-LsaPrivateData { 
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Name,
        [Parameter(Position = 1, Mandatory)]
        [byte[]]$Data,
        [string]$SystemName
    )

    [NtApiDotNet.Win32.Security.Win32Security]::LsaStorePrivateData($SystemName, $Name, $Data)
}

# Alias old functions. Remove eventually.
Set-Alias -Name Get-AuthPackage -Value Get-LsaPackage
Set-Alias -Name Read-AuthCredential -Value Read-LsaCredential
Set-Alias -Name Get-AuthCredential -Value Get-LsaCredential
Set-Alias -Name Get-AuthCredentialHandle -Value New-LsaCredentialHandle
Set-Alias -Name Get-AuthClientContext -Value New-LsaClientContext
Set-Alias -Name Get-AuthServerContext -Value New-LsaServerContext
Set-Alias -Name Update-AuthClientContext -Value Update-LsaClientContext
Set-Alias -Name Update-AuthServerContext -Value Update-LsaServerContext
Set-Alias -Name Get-AuthAccessToken -Value Get-LsaAccessToken
Set-Alias -Name Get-AuthToken -Value Get-LsaAuthToken
Set-Alias -Name Test-AuthContext -Value Test-LsaContext
Set-Alias -Name Format-AuthToken -Value Format-LsaAuthToken
Set-Alias -Name Export-AuthToken -Value Export-LsaAuthToken
Set-Alias -Name Import-AuthToken -Value Import-LsaAuthToken
Set-Alias -Name Unprotect-AuthToken -Value Unprotect-LsaAuthToken
