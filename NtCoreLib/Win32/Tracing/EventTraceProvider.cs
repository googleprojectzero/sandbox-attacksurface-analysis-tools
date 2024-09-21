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

using System;
using NtCoreLib.Security.Authorization;

namespace NtCoreLib.Win32.Tracing;

/// <summary>
/// Source of an event trace provider.
/// </summary>
public enum EventTraceProviderSource
{
    /// <summary>
    /// Unknown source.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// From WMI.
    /// </summary>
    WMI,
    /// <summary>
    /// From NtTraceControl.
    /// </summary>
    TraceControl,
    /// <summary>
    /// From the security key.
    /// </summary>
    Security
}

/// <summary>
/// Class to represent an Event Trace Provider.
/// </summary>
public sealed class EventTraceProvider
{
    private readonly Lazy<SecurityDescriptor> _security_descriptor;

    /// <summary>
    /// The ID of the provider.
    /// </summary>
    public Guid Id { get; }
    /// <summary>
    /// The name of the provider.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// Whether the provider is defined as an XML file or a MOF.
    /// </summary>
    public bool FromXml { get; }
    /// <summary>
    /// The provider security descriptor (only available as admin).
    /// </summary>
    public SecurityDescriptor SecurityDescriptor => _security_descriptor.Value;
    /// <summary>
    /// Indicates the source of the provider.
    /// </summary>
    public EventTraceProviderSource Source { get; }

    internal EventTraceProvider(Guid id)
        : this(id, id.ToString(), false)
    {
        Source = EventTraceProviderSource.TraceControl;
    }

    internal EventTraceProvider(Guid id, SecurityDescriptor security_descriptor)
        : this(id, id.ToString(), false)
    {
        Source = EventTraceProviderSource.Security;
        _security_descriptor = new Lazy<SecurityDescriptor>(() => security_descriptor);
    }

    internal EventTraceProvider(Guid id, string name, bool from_xml)
    {
        Id = id;
        Name = name;
        FromXml = from_xml;
        _security_descriptor = new Lazy<SecurityDescriptor>(() => EventTraceUtils.QueryTraceSecurity(Id, false).GetResultOrDefault());
        Source = EventTraceProviderSource.WMI;
    }
}
