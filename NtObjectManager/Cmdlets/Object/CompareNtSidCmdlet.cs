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
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.CodeIntegrity;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Compare two SIDs against various criteria.</para>
/// <para type="description">This cmdlet compares two SIDs against various criteria. The default is to compare for equality,
/// however you can test Integrity Level or Trust Level SIDs for which dominates.</para>
/// </summary>
/// <example>
///   <code>Compare-NtSid $sid1 $sid2</code>
///   <para>Checks both SIDs are equal.</para>
/// </example>
/// <example>
///   <code>Compare-NtSid $sid -KnownSid World</code>
///   <para>Checks the SID equals the World SID.</para>
/// </example>
/// <example>
///   <code>Compare-NtSid $sid -IntegrityLevel Low</code>
///   <para>Checks if the left IL SID dominates Low IL.</para>
/// </example>
/// /// <example>
///   <code>Compare-NtSid $sid1 $sid2 -Dominates</code>
///   <para>Checks if the left SID dominates the right.</para>
/// </example>
/// <example>
///   <code>Compare-NtSid $sid -TrustType Protected -TrustLevel WinTcb</code>
///   <para>Checks if the left Trust SID dominates the ProtectedLight-Windows Trust Level.</para>
/// </example>
/// <example>
///   <code>Compare-NtSid $sid1 $sid2 -Prefix</code>
///   <para>Checks left SID is prefixed by the right. Note that both SIDs must be the same length, you probably want StartsWith.</para>
/// </example>
/// <example>
///   <code>Compare-NtSid $sid1 $sid2 -StartsWith</code>
///   <para>Checks left SID starts with the right. The right SID should be shorter than the left.</para>
/// </example>
[Cmdlet(VerbsData.Compare , "NtSid", DefaultParameterSetName = "EqualSid")]
[OutputType(typeof(bool))]
public class CompareNtSidCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the left SID to compare.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public Sid Left { get; set; }

    /// <summary>
    /// <para type="description">Specify the right SID to compare.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "DominateSid")]
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "PrefixSid")]
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "StartsWithSid")]
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "EqualSid")]
    public Sid Right { get; set; }

    /// <summary>
    /// <para type="description">Specify the right SID to compare.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "PrefixSidKnown")]
    [Parameter(Mandatory = true, ParameterSetName = "StartsWithSidKnown")]
    [Parameter(Mandatory = true, ParameterSetName = "EqualSidKnown")]
    public KnownSidValue KnownSid { get; set; }

    /// <summary>
    /// <para type="description">Specify the right SID to compare.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "DominateIntegrity")]
    public TokenIntegrityLevel IntegrityLevel { get; set; }

    /// <summary>
    /// <para type="description">Specify protected type for Trust SID.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "DominateTrust")]
    public ProcessTrustType TrustType { get; set; }

    /// <summary>
    /// <para type="description">Specify level for Trust SID.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "DominateTrust")]
    public ProcessTrustLevel TrustLevel { get; set; }

    /// <summary>
    /// <para type="description">Check if the left SID dominates the right. Supports IL or Trust Level SIDs.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "DominateSid")]
    public SwitchParameter Dominates { get; set; }

    /// <summary>
    /// <para type="description">Check if prefix of one SID matches another.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "PrefixSid")]
    [Parameter(Mandatory = true, ParameterSetName = "PrefixSidKnown")]
    public SwitchParameter Prefix { get; set; }

    /// <summary>
    /// <para type="description">Check if one SID starts with another.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "StartsWithSid")]
    [Parameter(Mandatory = true, ParameterSetName = "StartsWithSidKnown")]
    public SwitchParameter StartsWith { get; set; }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteObject(CheckSid());
    }

    private bool CheckDominateSid(Sid right)
    {
        if (NtSecurity.IsIntegritySid(Left))
        {
            return Left.Dominates(right);
        }
        else if (NtSecurity.IsProcessTrustSid(Left))
        {
            return Left.DominatesForTrust(right);
        }
        return false;
    }


    private Sid GetRightSid()
    {
        switch (ParameterSetName)
        {
            case "EqualSid":
            case "DominateSid":
            case "PrefixSid":
            case "StartsWithSid":
                return Right;
            case "PrefixSidKnown":
            case "StartsWithSidKnown":
            case "EqualSidKnown":
                return KnownSids.GetKnownSid(KnownSid);
            case "DominateIntegrity":
                return NtSecurity.GetIntegritySid(IntegrityLevel);
            case "DominateTrust":
                return NtSecurity.GetTrustLevelSid(TrustType, TrustLevel);
            default:
                throw new ArgumentException("Unknown SID type");
        }
    }

    private bool IsDominates()
    {
        switch (ParameterSetName)
        {
            case "DominateSid":
            case "DominateIntegrity":
            case "DominateTrust":
                return true;
            default:
                return false;
        }
    }

    private bool CheckSid()
    {
        Sid right = GetRightSid();
        if (IsDominates())
        {
            return CheckDominateSid(right);
        }
        else if (Prefix)
        {
            return Left.EqualPrefix(right);
        }
        else if (StartsWith)
        {
            return Left.StartsWith(right);
        }
        return Left.Equals(right);
    }
}
