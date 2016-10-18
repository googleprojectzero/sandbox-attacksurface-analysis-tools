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

    [Cmdlet(VerbsCommon.Push, "DisposeList")]
    public class PushDisposableList : Cmdlet
    {
        [Parameter(ValueFromPipeline = true)]
        public IDisposable[] Objects { get; set; }

        
        protected override void ProcessRecord()
        {
            WriteObject(StackHolder.Push(Objects), true);
        }
    }

    [Cmdlet(VerbsCommon.Pop, "DisposeList")]
    public class PopDisposableList : Cmdlet
    {
        [Parameter(ValueFromPipeline = true)]
        public IDisposable[] Objects { get; set; }

        protected override void ProcessRecord()
        {
            StackHolder.Pop();
        }
    }

    [Cmdlet(VerbsCommon.Add, "DisposeList")]
    public class AddDisposableList : Cmdlet
    {
        [Parameter(ValueFromPipeline = true, Mandatory = true, Position=0)]
        public IDisposable[] Objects { get; set; }

        protected override void ProcessRecord()
        {
            if (!StackHolder.Add(Objects))
            {
                WriteWarning("No list on the top of the stack");
            }
            WriteObject(Objects, true);
        }
    }

    [Cmdlet(VerbsCommon.Clear, "DisposeList")]
    public class ClearDisposableList : Cmdlet
    {
        [Parameter(ValueFromPipeline = true)]
        public IDisposable[] Objects { get; set; }

        protected override void ProcessRecord()
        {
            StackHolder.Clear();
        }
    }
}
