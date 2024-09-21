//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Set a NT token on a process or thread.</para>
/// <para type="description">This cmdlet sets a token on a process or thread.</para>
/// </summary>
/// <example>
///   <code>Set-NtToken -Token $token -Process $process</code>
///   <para>Set a process' primary token.</para>
/// </example>
/// <example>
///   <code>Set-NtToken -Token $token -Process $process -Duplicate</code>
///   <para>Set a process' primary token, duplicating it before use.</para>
/// </example>
/// <example>
///   <code>Set-NtToken -Token $token -ProcessId 1234</code>
///   <para>Set a process' primary token from its PID.</para>
/// </example>
/// <example>
///   <code>Set-NtToken -Token $token -Thread $thread</code>
///   <para>Set a thread's impersonation token.</para>
/// </example>
/// <example>
///   <code>Set-NtToken -Token $token -Thread $thread -Duplicate -ImpersonationLevel Identification</code>
///   <para>Set a thread's impersonation token, duplicating as an Identification level token first..</para>
/// </example>
/// <example>
///   <code>Set-NtToken -Token $token -ThreadId 1234</code>
///   <para>Set a thread's impersonation token from its TID.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Set, "NtToken", DefaultParameterSetName = "Process")]
public class SetNtTokenCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the process to set the token on.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "Process")]
    public NtProcess Process { get; set; }

    /// <summary>
    /// <para type="description">Specify the process to set the token on.as a PID.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ProcessId"), Alias("pid")]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify the thread to set the token on.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "Thread")]
    public NtThread Thread { get; set; }

    /// <summary>
    /// <para type="description">Specify the thread to set the token on as a TID.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "ThreadId"), Alias("tid")]
    public int ThreadId { get; set; }

    /// <summary>
    /// <para type="description">Duplicate the token before setting it.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Duplicate { get; set; }

    /// <summary>
    /// <para type="description">Specify the token to set.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify the impersonation level of the token to assign if -Duplicate is specified.</para>
    /// </summary>
    [Parameter(ParameterSetName = "Thread"), Parameter(ParameterSetName = "ThreadId")]
    public SecurityImpersonationLevel ImpersonationLevel { get; set; }

    /// <summary>
    /// <para type="description">Specify the integrity level of the token to set if -Duplicate is specified.</para>
    /// </summary>
    [Parameter]
    public TokenIntegrityLevel? IntegrityLevel { get; set; }

    private bool IsProcess()
    {
        switch (ParameterSetName)
        {
            case "Process":
            case "ProcessId":
                return true;
            case "Thread":
            case "ThreadId":
                return false;
            default:
                throw new ArgumentException("Invalid parameter set.");
        }
    }

    private NtToken GetToken()
    {
        if (!Duplicate)
            return Token.Duplicate();

        TokenType type = IsProcess() ? TokenType.Primary : TokenType.Impersonation;

        using var token = Token.DuplicateToken(type, ImpersonationLevel, TokenAccessRights.MaximumAllowed);
        if (IntegrityLevel.HasValue)
        {
            token.IntegrityLevel = IntegrityLevel.Value;
        }
        return token.Duplicate();
    }

    private NtProcess GetProcess()
    {
        if (ParameterSetName == "Process")
            return Process.Duplicate(ProcessAccessRights.SetInformation);
        return NtProcess.Open(ProcessId, ProcessAccessRights.SetInformation);
    }

    private NtThread GetThread()
    {
        if (ParameterSetName == "Thread")
            return Thread.Duplicate(ThreadAccessRights.Impersonate);
        return NtThread.Open(ThreadId, ThreadAccessRights.Impersonate);
    }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        using var token = GetToken();
        if (IsProcess())
        {
            using var proc = GetProcess();
            proc.SetToken(token);
        }
        else
        {
            using var thread = GetThread();
            thread.Impersonate(token);
        }
    }
}
