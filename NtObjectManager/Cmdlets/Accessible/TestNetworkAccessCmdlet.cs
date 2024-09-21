//  Copyright 2019 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtCoreLib;
using NtCoreLib.Security.Token;
using System;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Net.Sockets;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="synopsis">Test whether network access is allowed based on a specific token.</para>
/// <para type="description">This cmdlet tests network access for a particular token. This can either
/// be network client access or network server access.</para>
/// </summary>
/// <example>
///   <code>Test-NetworkAccess -HostName www.google.com -Port 80</code>
///   <para>Test network access for the current user to www.google.com:80.</para>
/// </example>
/// <example>
///   <code>Test-NetworkAccess -Listen 1234</code>
///   <para>Test network access for the current user by listening on port 1234.</para>
/// </example>
/// <example>
///   <code>Test-NetworkAccess -HostName www.google.com -Port 80 -ProcessId 1234</code>
///   <para>Test network access for the process 1234 to www.google.com:80.</para>
/// </example>
/// <example>
///   <code>Test-NetworkAccess -HostName www.google.com -Port 80 -Token $token</code>
///   <para>Test network access for a specified token to www.google.com:80.</para>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "NetworkAccess", DefaultParameterSetName = "ForConnect")]
public class TestNetworkAccessCmdlet : PSCmdlet
{
    private NtProcess GetProcess()
    {
        if (Process != null)
        {
            return Process.Duplicate(ProcessAccessRights.QueryLimitedInformation);
        }
        else if (ProcessId != 0)
        {
            return NtProcess.Open(ProcessId, ProcessAccessRights.QueryLimitedInformation);
        }
        return NtProcess.Current;
    }

    private NtToken GetToken()
    {
        if (Token != null)
        {
            if (Token.TokenType == TokenType.Impersonation)
            {
                return Token.Duplicate();
            }
            return Token.DuplicateToken(SecurityImpersonationLevel.Impersonation);
        }

        using var proc = GetProcess();
        using var token = NtToken.OpenProcessToken(proc, TokenAccessRights.Duplicate);
        return token.DuplicateToken(SecurityImpersonationLevel.Impersonation);
    }

    private bool FilterAddress(IPAddress address)
    {
        if (IPv6 && address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return true;
        }
        if (!IPv6 && address.AddressFamily == AddressFamily.InterNetwork)
        {
            return true;
        }
        return false;
    }

    private IPEndPoint ResolveEndpoint()
    {
        if (Port < 1 || Port > 65535)
        {
            throw new ArgumentException("Must specify a port between 1 and 65535 inclusive");
        }

        if (string.IsNullOrEmpty(HostName))
        {
            return new IPEndPoint(IPv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, Port);
        }

        if (IPAddress.TryParse(HostName, out IPAddress address))
        {
            return new IPEndPoint(address, Port);
        }
        var entry = Dns.GetHostEntry(HostName);
        return new IPEndPoint(entry.AddressList.Where(FilterAddress).First(), Port);
    }

    /// <summary>
    /// <para type="description">Specify to test listening on a port.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "ForListen")]
    public SwitchParameter Listen { get; set; }

    /// <summary>
    /// <para type="description">Specify to the host for connecting or listening.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "ForConnect")]
    [Parameter(ParameterSetName = "ForListen")]
    public string HostName { get; set; }

    /// <summary>
    /// <para type="description">Specify to the host for connecting or listening.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "ForConnect")]
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "ForListen")]
    public int Port { get; set; }

    /// <summary>
    /// <para type="description">Specify a process to get the token from.</para>
    /// </summary>
    [Parameter]
    public NtProcess Process { get; set; }

    /// <summary>
    /// <para type="description">Specify a process ID to get the token from.</para>
    /// </summary>
    [Parameter]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify the token to use for the test.</para>
    /// </summary>
    [Parameter]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify to use IPv6 instead of IPv4.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter IPv6 { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        using var token = GetToken();
        IPEndPoint ep = ResolveEndpoint();
        using (token.Impersonate())
        {
            try
            {
                if (ParameterSetName == "ForListen")
                {
                    TcpListener listener = new(ep);
                    listener.Start();
                    try
                    {
                        WriteWarning($"Make a connection to {ep}");
                        while (!listener.Server.Poll(1000, SelectMode.SelectRead))
                        {
                            if (Stopping)
                            {
                                return;
                            }
                        }
                        using (listener.AcceptTcpClient())
                        {
                            WriteObject(true);
                        }
                    }
                    finally
                    {
                        listener.Stop();
                    }
                }
                else
                {
                    using (TcpClient client = new())
                    {
                        client.Connect(ep);
                    }
                    WriteObject(true);
                }
            }
            catch
            {
                WriteObject(false);
            }
        }
    }
}
