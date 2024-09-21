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

using System;

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Class representing a data view message attribute.
/// </summary>
public sealed class AlpcDataViewMessageAttribute : AlpcMessageAttribute
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcDataViewMessageAttribute()
        : base(AlpcMessageAttributeFlags.View)
    {
    }

    internal AlpcDataViewMessageAttribute(long view_base, long view_size, long section_handle,
        AlpcDataViewAttrFlags flags) : this()
    {
        Flags = flags;
        ViewBase = view_base;
        ViewSize = view_size;
        SectionHandle = section_handle;
    }

    /// <summary>
    /// View flags.
    /// </summary>
    public AlpcDataViewAttrFlags Flags { get; set; }
    /// <summary>
    /// Handle to section.
    /// </summary>
    public long SectionHandle { get; set; }
    /// <summary>
    /// View base.
    /// </summary>
    public long ViewBase { get; set; }
    /// <summary>
    /// View size.
    /// </summary>
    public long ViewSize { get; set; }

    internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
    {
        buffer.SetViewAttribute(this);
    }

    internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
    {
        buffer.GetViewAttribute(this);
    }

    internal void FromStruct(AlpcDataViewAttr attr)
    {
        Flags = attr.Flags;
        SectionHandle = attr.SectionHandle.Value;
        ViewBase = attr.ViewBase.ToInt64();
        ViewSize = attr.ViewSize.ToInt64();
    }

    internal AlpcDataViewAttr ToStruct()
    {
        return new AlpcDataViewAttr()
        {
            Flags = Flags,
            SectionHandle = SectionHandle,
            ViewBase = new IntPtr(ViewBase),
            ViewSize = new IntPtr(ViewSize)
        };
    }
}
