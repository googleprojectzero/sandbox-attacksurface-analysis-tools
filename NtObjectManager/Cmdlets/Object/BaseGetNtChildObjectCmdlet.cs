//  Copyright 2016 Google Inc. All Rights Reserved.
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
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// Base class for child object visitor.
/// </summary>
/// <typeparam name="O">The type of NT object.</typeparam>
/// <typeparam name="A">The access rights type.</typeparam>
public abstract class BaseGetNtChildObjectCmdlet<O, A> : PSCmdlet where A : Enum where O : NtObject
{
    /// <summary>
    /// <para type="description">Specify an object to get children from, should be a directory.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public O Object { get; set; }

    /// <summary>
    /// <para type="description">Specify the access when opening a child.</para>
    /// </summary>
    [Parameter]
    public A Access { get; set; }

    /// <summary>
    /// <para type="description">Get children recursively.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Recurse { get; set; }

    /// <summary>
    /// <para type="description">When recursing specify the maximum depth of recursion. -1 indicates no limit.</para>
    /// </summary>
    [Parameter]
    public int MaxDepth { get; set; }

    /// <summary>
    /// <para type="description">Specify a script block to run for every child. The file object will automatically 
    /// be disposed once the vistor has executed. If you want to cancel enumeration return $false.</para>
    /// </summary>
    [Parameter]
    public ScriptBlock Visitor { get; set; }

    /// <summary>
    /// <para type="description">Specify a script block to filter child objects. Return $true to keep the object.</para>
    /// </summary>
    [Parameter]
    public ScriptBlock Filter { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public BaseGetNtChildObjectCmdlet()
    {
        Access = (A)Enum.ToObject(typeof(A), (uint)GenericAccessRights.MaximumAllowed);
        MaxDepth = -1;
    }

    /// <summary>
    /// Function to visit child objects.
    /// </summary>
    /// <param name="visitor">The visitor function to execute.</param>
    /// <returns>True if visited all children, false if cancelled.</returns>
    protected abstract bool VisitChildObjects(Func<O, bool> visitor);

    private static bool? InvokeScriptBlock(ScriptBlock script_block, params object[] args)
    {
        if (script_block.InvokeWithArg<object>(null, args) is bool b)
        {
            return b;
        }
        return null;
    }

    private bool WriteObjectVisitor(O obj)
    {
        WriteObject(obj.DuplicateObject());
        return !Stopping;
    }

    private bool ScriptBlockVisitor(O obj)
    {
        bool? result = InvokeScriptBlock(Visitor, obj);
        if (result.HasValue)
        {
            return result.Value;
        }
        
        return !Stopping;
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        Func<O, bool> visitor;
        if (Visitor != null)
        {
            visitor = ScriptBlockVisitor;
        }
        else
        {
            visitor = WriteObjectVisitor;
        }

        if (Filter != null)
        {
            VisitChildObjects(o =>
            {
                bool? result = InvokeScriptBlock(Filter, o);
                if (result.HasValue && result.Value)
                {
                    return visitor(o);
                }
                return !Stopping;
            });
        }
        else
        {
            VisitChildObjects(visitor);
        }
    }
}
