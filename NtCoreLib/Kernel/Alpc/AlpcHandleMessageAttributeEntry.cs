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

using NtCoreLib.Security.Authorization;

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Handle attribute entry.
/// </summary>
public class AlpcHandleMessageAttributeEntry
{
    /// <summary>
    /// Handle flags.
    /// </summary>
    public AlpcHandleAttrFlags Flags { get; set; }
    /// <summary>
    /// The NT object.
    /// </summary>
    public int Handle { get; set; }
    /// <summary>
    /// The object type for the handle.
    /// </summary>
    public AlpcHandleObjectType ObjectType { get; set; }
    /// <summary>
    /// Desired access for the handle.
    /// </summary>
    public AccessMask DesiredAccess { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="attr">Handle attribute to initialize from.</param>
    public AlpcHandleMessageAttributeEntry(AlpcHandleAttr attr)
    {
        Flags = attr.Flags;
        Handle = attr.Handle.ToInt32();
        ObjectType = attr.ObjectType;
        DesiredAccess = attr.DesiredAccess;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="attr">Handle attribute to initialize from.</param>
    public AlpcHandleMessageAttributeEntry(AlpcHandleAttr32 attr)
    {
        Flags = attr.Flags;
        Handle = attr.Handle;
        ObjectType = attr.ObjectType;
        DesiredAccess = attr.DesiredAccess;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="info">Information structure to initialize from.</param>
    public AlpcHandleMessageAttributeEntry(AlpcMessageHandleInformation info)
    {
        Flags = info.Flags;
        Handle = info.Handle;
        ObjectType = info.ObjectType;
        DesiredAccess = info.GrantedAccess;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcHandleMessageAttributeEntry()
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="obj">The object to construct the entry from.</param>
    public AlpcHandleMessageAttributeEntry(NtObject obj)
    {
        Flags = AlpcHandleAttrFlags.SameAccess | AlpcHandleAttrFlags.SameAttributes;
        Handle = obj.Handle.DangerousGetHandle().ToInt32();
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="obj">The object to construct the entry from.</param>
    /// <param name="desired_access">The desired access for the attribute. If 0 then just copies the access.</param>
    public AlpcHandleMessageAttributeEntry(NtObject obj, AccessMask desired_access)
    {
        Flags = AlpcHandleAttrFlags.SameAttributes;
        DesiredAccess = desired_access;
        if (DesiredAccess.IsEmpty)
        {
            Flags |= AlpcHandleAttrFlags.SameAccess;
        }
        Handle = obj.Handle.DangerousGetHandle().ToInt32();
    }
}
