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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using NtCoreLib.Utilities.Misc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Utilities.Collections;

/// <summary>
/// Represents a list where the elements can be trivially disposed in one go.
/// </summary>
/// <typeparam name="T">An IDisposable implementing type</typeparam>
public class DisposableList<T> : List<T>, IDisposable where T : IDisposable
{
    /// <summary>
    /// Constructor
    /// </summary>
    public DisposableList()
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="capacity">The initial capacity of the list</param>
    public DisposableList(int capacity) : base(capacity)
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="collection">A collection to initialize the list</param>
    public DisposableList(IEnumerable<T> collection) : base(collection)
    {
    }

    /// <summary>
    /// Add a resource to the list and return a reference to it.
    /// </summary>
    /// <typeparam name="R">The type of resource to add.</typeparam>
    /// <param name="resource">The resource object.</param>
    /// <returns>The added resource.</returns>
    public R AddResource<R>(R resource) where R : T
    {
        Add(resource);
        return resource;
    }

    /// <summary>
    /// Add a resource to the list and return a reference to it.
    /// </summary>
    /// <typeparam name="R">The type of resource to add.</typeparam>
    /// <returns>The added resource.</returns>
    public R AddResource<R>() where R : T, new()
    {
        return AddResource(new R());
    }

    /// <summary>
    /// Convert this list to an array then clear it to the disposal no longer happens.
    /// </summary>
    /// <returns>The elements as an array.</returns>
    /// <remarks>After doing this the current list will be cleared.</remarks>
    [ReliabilityContract(Consistency.MayCorruptProcess, Cer.MayFail)]
    public T[] ToArrayAndClear()
    {
        T[] ret = ToArray();
        Clear();
        return ret;
    }

    /// <summary>
    /// Detach a detachable reference and add it to the list.
    /// </summary>
    /// <typeparam name="R">The type of resource to detach.</typeparam>
    /// <returns>The detached resource.</returns>
    public R Detach<R>(DetachableContainer<R> container) where R : class, T
    {
        return AddResource(container.Detach());
    }

    #region IDisposable Support
    private bool disposedValue = false;

    /// <summary>
    /// Dispose method
    /// </summary>
    public void Dispose()
    {
        if (!disposedValue)
        {
            foreach (IDisposable entry in this)
            {
                if (entry != null)
                {
                    entry.Dispose();
                }
            }

            disposedValue = true;
        }
    }
    #endregion
}

/// <summary>
/// Implementation of disposable list which just accepts IDisposable objects.
/// </summary>
public sealed class DisposableList : DisposableList<IDisposable>
{
    /// <summary>
    /// Constructor
    /// </summary>
    public DisposableList()
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="capacity">The initial capacity of the list</param>
    public DisposableList(int capacity) : base(capacity)
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="collection">A collection to initialize the list</param>
    public DisposableList(IEnumerable<IDisposable> collection) : base(collection)
    {
    }

    /// <summary>
    /// Adds a delegate which will be called when the list is disposed.
    /// </summary>
    /// <param name="action">The delegate to call on dispose.</param>
    /// <remarks>This can be used to add more complex disposable.</remarks>
    public void CallOnDispose(Action action)
    {
        Add(new CallOnDispose(action));
    }

    internal SidAndAttributes[] CreateSidAndAttributes(IEnumerable<UserGroup> sids)
    {
        if (sids == null)
        {
            return new SidAndAttributes[0];
        }
        return sids.Select(s => new SidAndAttributes()
        {
            Sid = AddResource(s.Sid.ToSafeBuffer()).DangerousGetHandle(),
            Attributes = s.Attributes
        }).ToArray();
    }

    internal SidAndAttributes[] CreateSidAndAttributes(IEnumerable<Sid> sids)
    {
        if (sids == null)
        {
            return new SidAndAttributes[0];
        }

        return CreateSidAndAttributes(sids.Select(s => new UserGroup(s, GroupAttributes.Enabled)));
    }
}

internal static class DisposableListUtils
{
    internal static SafeSidBufferHandle AddSid(this DisposableList list, Sid sid)
    {
        if (sid == null)
        {
            return SafeSidBufferHandle.Null;
        }
        return list.AddResource(sid.ToSafeBuffer());
    }

    internal static SafeStructureInOutBuffer<T> AddStructure<T>(this DisposableList list, T value) where T : class, new()
    {
        if (value == null)
        {
            return SafeStructureInOutBuffer<T>.Null;
        }
        return list.AddResource(new SafeStructureInOutBuffer<T>(value));
    }

    internal static SafeStructureInOutBuffer<T> AddStructureRef<T>(this DisposableList list, T value) where T : struct
    {
        return list.AddResource(new SafeStructureInOutBuffer<T>(value));
    }

    internal static SafeBuffer AddSecurityDescriptor(this DisposableList list, SecurityDescriptor sd)
    {
        if (sd == null)
        {
            return SafeHGlobalBuffer.Null;
        }
        return list.AddResource(sd.ToSafeBuffer());
    }

    internal static SafeBuffer AddNulTerminatedUnicodeString(this DisposableList list, string str)
    {
        return list.AddBytes(Encoding.Unicode.GetBytes(str + "\0"));
    }

    internal static SafeBuffer AddBytes(this DisposableList list, byte[] ba)
    {
        if (ba == null)
        {
            return SafeHGlobalBuffer.Null;
        }
        return list.AddResource(new SafeHGlobalBuffer(ba));
    }

    internal static SafeBuffer AddList<T>(this DisposableList list, IEnumerable<T> values) where T : new()
    {
        return values.ToArray().ToBuffer();
    }

    internal static IntPtr AddBuffer(this DisposableList list, SafeBuffer buffer)
    {
        if (buffer == null)
            return IntPtr.Zero;
        return list.AddResource(buffer).DangerousGetHandle();
    }

}

/// <summary>
/// Disposable list of safe handles
/// </summary>
public sealed class SafeHandleList : DisposableList<SafeHandle>
{
    /// <summary>
    /// Constructor
    /// </summary>
    public SafeHandleList()
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="capacity">The initial capacity of the list</param>
    public SafeHandleList(int capacity) : base(capacity)
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="collection">A collection to initialize the list</param>
    public SafeHandleList(IEnumerable<SafeHandle> collection) : base(collection)
    {
    }

    /// <summary>
    /// Move the handle list to a new disposable list.
    /// </summary>
    /// <returns>The list of handles which have been moved.</returns>
    /// <remarks>After doing this the current list will be cleared.</remarks>
    [ReliabilityContract(Consistency.MayCorruptProcess, Cer.MayFail)]
    public SafeHandleList DangerousMove()
    {
        return new SafeHandleList(ToArrayAndClear());
    }
}
