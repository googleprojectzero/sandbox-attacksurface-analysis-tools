//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtCoreLib.Security.Authorization;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Compare two security descriptors against each other.</para>
/// <para type="description">This cmdlet compares two security descriptors against each other. Returns a boolean result.</para>
/// </summary>
/// <example>
///   <code>Compare-NtSecurityDescriptor $sd1 $sd2</code>
///   <para>Checks both security descriptors are equal.</para>
/// </example>
/// <example>
///   <code>Compare-NtSecurityDescriptor $sd1 $sd2 -Report</code>
///   <para>Checks both security descriptors are equal and report the differences.</para>
/// </example>
[Cmdlet(VerbsData.Compare, "NtSecurityDescriptor")]
[OutputType(typeof(bool))]
public class CompareNtSecurityDescriptorCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the left security descriptor to compare.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public SecurityDescriptor Left { get; set; }

    /// <summary>
    /// <para type="description">Specify the right security descriptor to compare.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true)]
    public SecurityDescriptor Right { get; set; }

    /// <summary>
    /// <para type="description">Specify to print what differs between the two security descriptors if they do not match.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Report { get; set; }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteObject(CheckSd());
    }

    private void CompareSid(string sid_name, Sid left, Sid right)
    {
        if (left is null && right is null)
            return;
        if (left is null)
        {
            WriteWarning($"{sid_name} left not present.");
            return;
        }

        if (right is null)
        {
            WriteWarning($"{sid_name} right not present.");
            return;
        }

        if (!left.Equals(right))
        {
            WriteWarning($"{sid_name} SIDs mismatch, left {left} right {right}.");
        }
    }

    private void CompareAcls(string acl_name, Acl left, Acl right)
    {
        if (left is null && right is null)
            return;

        if (left is null)
        {
            WriteWarning($"{acl_name} left not present.");
            return;
        }

        if (right is null)
        {
            WriteWarning($"{acl_name} right not present.");
            return;
        }

        if (left.Count != right.Count)
        {
            WriteWarning($"{acl_name} ACE count mismatch, left {left.Count} right {right.Count}");
            return;
        }

        for (int i = 0; i < left.Count; ++i)
        {
            if (!left[i].Equals(right[i]))
            {
                WriteWarning($"{acl_name} ACE {i} mismatch.");
                WriteWarning($"Left : {left[i]}");
                WriteWarning($"Right: {right[i]}");
            }
        }
    }

    private bool CheckSd()
    {
        IStructuralEquatable left = Left.ToByteArray();
        if (left.Equals(Right.ToByteArray(), EqualityComparer<byte>.Default))
            return true;

        if (!Report)
            return false;

        if (Left.Control != Right.Control)
        {
            WriteWarning($"Control mismatch, left {Left.Control} right {Right.Control}");
        }

        if (Left.RmControl != Right.RmControl)
        {
            WriteWarning($"RmControl mismatch, left {Left.RmControl} right {Right.RmControl}");
        }

        CompareSid("Owner", Left.Owner?.Sid, Right.Owner?.Sid);
        CompareSid("Group", Left.Group?.Sid, Right.Group?.Sid);
        CompareAcls("DACL", Left.Dacl, Right.Dacl);
        CompareAcls("SACL", Left.Sacl, Right.Sacl);

        return false;
    }
}
