//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    internal static class StackHolder
    {
        static Stack<DisposableList<IDisposable>> _stack = new Stack<DisposableList<IDisposable>>();

        internal static bool Add(params IDisposable[] objects)
        {
            if (objects == null)
            {
                return false;
            }
            
            lock (_stack)
            {
                DisposableList<IDisposable> list = _stack.Count > 0 ? _stack.Peek() : null;
                if (list != null)
                {
                    lock (list)
                    {
                        list.AddRange(objects);
                        return true;
                    }
                }
            }
            
            return false;
        }

        internal static DisposableList<IDisposable> Push(IDisposable[] objects)
        {
            lock (_stack)
            {
                DisposableList<IDisposable> list = new DisposableList<IDisposable>();
                if (objects != null)
                {
                    list.AddRange(objects);
                }
                _stack.Push(list);
                return list;
            }
        }

        internal static void Pop()
        {
            lock (_stack)
            {
                if (_stack.Count > 0)
                {
                    DisposableList<IDisposable> list = _stack.Pop();
                    lock (list)
                    {
                        list.Dispose();
                    }
                }
            }
        }

        internal static void Clear()
        {
            lock (_stack)
            {
                while (_stack.Count > 0)
                {
                    var list = _stack.Pop();
                    lock (list)
                    {
                        list.Dispose();
                    }
                }
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Push a new dispose list onto the stack.</para>
    /// <para type="description">This cmdlet pushes a new dispose list on the stack of dispose lists.
    /// A dispose list can be used as a container for disposable objects (such as NtObjects) which you want to maintain the lifetime of
    /// without assigning them to individual variables or an arbitrary list.
    /// </para>
    /// </summary>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Push, "NtDisposeList")]
    public class PushNtDisposableList : Cmdlet
    {
        /// <summary>
        /// <para type="description">A list of objects which implement IDisposable to automatically add to the pushed list. This can be taken from the pipeline.</para>
        /// </summary>
        [Parameter(ValueFromPipeline = true, Position = 0)]
        public IDisposable[] Objects { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(StackHolder.Push(Objects), true);
        }
    }

    /// <summary>
    /// <para type="synopsis">Pop the current dispose list onto the stack.</para>
    /// <para type="description">This cmdlet pops the last dispose list off the stack of dispose lists.
    /// Once the list has been pops all objects contained in the list will have their Dispose methods called.
    /// A dispose list can be used as a container for disposable objects (such as NtObjects) which you want to maintain the lifetime of
    /// without assigning them to individual variables or an arbitrary list.
    /// </para>
    /// </summary>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Pop, "NtDisposeList")]
    public class PopNtDisposableList : Cmdlet
    {
        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            StackHolder.Pop();
        }
    }

    /// <summary>
    /// <para type="synopsis">Add a list of disposable objects to the current list onto the stack.</para>
    /// <para type="description">This adds a list of disposable objects to the last list on the stack which was created using Push-DisposableList.
    /// A dispose list can be used as a container for disposable objects (such as NtObjects) which you want to maintain the lifetime of
    /// without assigning them to individual variables or an arbitrary list.
    /// </para>
    /// </summary>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Add, "NtDisposeList")]
    public class AddNtDisposableList : Cmdlet
    {
        /// <summary>
        /// <para type="description">A list of objects which implement IDisposable to add to the current list. This can be taken from the pipeline.</para>
        /// </summary>
        [Parameter(ValueFromPipeline = true, Mandatory = true, Position=0)]
        public IDisposable[] Objects { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (!StackHolder.Add(Objects))
            {
                WriteWarning("No list on the top of the stack");
            }
            WriteObject(Objects, true);
        }
    }

    /// <summary>
    /// <para type="synopsis">Clears all dispose lists on the stack and disposes all their objects.</para>
    /// <para type="description">This will enumerate all disposable lists on the stack and dispose them.</para>
    /// </summary>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Clear, "NtDisposeList")]
    public class ClearNtDisposableList : Cmdlet
    {
        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            StackHolder.Clear();
        }
    }
}
