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
using System.Collections.Generic;

namespace NtApiDotNet
{
    /// <summary>
    /// The base class for a debug event.
    /// </summary>
    public abstract class DebugEvent : IDisposable
    {
        #region Private Members
        private readonly NtDebug _debug;
        #endregion

        /// <summary>
        /// Process ID for the event.
        /// </summary>
        public int ProcessId { get; }

        /// <summary>
        /// Thread ID for the event.
        /// </summary>
        public int ThreadId { get; }

        /// <summary>
        /// The event code.
        /// </summary>
        public DbgState State { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="debug_event">The current debug event.</param>
        /// <param name="debug">The debug port associated with this event.</param>
        protected DebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
        {
            ProcessId = debug_event.AppClientId.UniqueProcess.ToInt32();
            ThreadId = debug_event.AppClientId.UniqueThread.ToInt32();
            State = debug_event.NewState;
            _debug = debug;
        }

        /// <summary>
        /// Continue the debugged process.
        /// </summary>
        /// <param name="continue_status">The continue status code.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Continue(NtStatus continue_status, bool throw_on_error)
        {
            return _debug.Continue(ProcessId, ThreadId, continue_status, throw_on_error);
        }

        /// <summary>
        /// Continue the debugged process.
        /// </summary>
        /// <param name="continue_status">The continue status code.</param>
        public void Continue(NtStatus continue_status)
        {
            _debug.Continue(ProcessId, ThreadId, continue_status);
        }

        /// <summary>
        /// Continue the debugged process with a success code.
        /// </summary>
        public void Continue()
        {
            Continue(NtStatus.DBG_CONTINUE);
        }

        /// <summary>
        /// Dispose the event.
        /// </summary>
        public virtual void Dispose()
        {
        }

        internal static DebugEvent FromDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
        {
            switch (debug_event.NewState)
            {
                case DbgState.CreateProcessStateChange:
                    return new CreateProcessDebugEvent(debug_event, debug);
                case DbgState.CreateThreadStateChange:
                    return new CreateThreadDebugEvent(debug_event, debug);
                case DbgState.BreakpointStateChange:
                case DbgState.ExceptionStateChange:
                case DbgState.SingleStepStateChange:
                    return new ExceptionDebugEvent(debug_event, debug);
                case DbgState.ExitProcessStateChange:
                    return new ExitProcessDebugEvent(debug_event, debug);
                case DbgState.ExitThreadStateChange:
                    return new ExitThreadDebugEvent(debug_event, debug);
                case DbgState.LoadDllStateChange:
                    return new LoadDllDebugEvent(debug_event, debug);
                case DbgState.UnloadDllStateChange:
                    return new UnloadDllDebugEvent(debug_event, debug);
                default:
                    return new UnknownDebugEvent(debug_event, debug);
            }
        }
    }

    /// <summary>
    /// Debug event for the Create Process event.
    /// </summary>
    public sealed class CreateProcessDebugEvent : DebugEvent
    {
        /// <summary>
        /// Subsystem key for the process.
        /// </summary>
        public int ProcessSubSystemKey { get; }
        /// <summary>
        /// Handle to the process file (if available).
        /// </summary>
        public NtFile File { get; }
        /// <summary>
        /// Base of image file.
        /// </summary>
        public long BaseOfImage { get; }
        /// <summary>
        /// Debug info file offset.
        /// </summary>
        public int DebugInfoFileOffset { get; }
        /// <summary>
        /// Debug info file size.
        /// </summary>
        public int DebugInfoSize { get; }
        /// <summary>
        /// Subsystem key for the thread.
        /// </summary>
        public int ThreadSubSystemKey { get; }
        /// <summary>
        /// Start address of the thread.
        /// </summary>
        public long ThreadStartAddress { get; }
        /// <summary>
        /// Handle to the process (if available).
        /// </summary>
        public NtProcess Process { get; }
        /// <summary>
        /// Handle to the thread (if available).
        /// </summary>
        public NtThread Thread { get; }

        internal CreateProcessDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug) 
            : base(debug_event, debug)
        {
            var info = debug_event.StateInfo.CreateProcess;
            Process = info.HandleToProcess == IntPtr.Zero ? null : NtProcess.FromHandle(info.HandleToProcess);
            Thread = info.HandleToThread == IntPtr.Zero ? null : NtThread.FromHandle(info.HandleToThread);
            var new_proc = info.NewProcess;
            ProcessSubSystemKey = new_proc.SubSystemKey;
            File = new_proc.FileHandle == IntPtr.Zero ? null : NtFile.FromHandle(new_proc.FileHandle);
            BaseOfImage = new_proc.BaseOfImage.ToInt64();
            DebugInfoFileOffset = new_proc.DebugInfoFileOffset;
            DebugInfoSize = new_proc.DebugInfoSize;
            var thread = new_proc.InitialThread;
            ThreadSubSystemKey = thread.SubSystemKey;
            ThreadStartAddress = thread.StartAddress.ToInt64();
        }

        /// <summary>
        /// Dispose the event.
        /// </summary>
        public override void Dispose()
        {
            Process?.Dispose();
            Thread?.Dispose();
            File?.Dispose();
        }
    }

    /// <summary>
    /// Debug event for the Create Thread event.
    /// </summary>
    public sealed class CreateThreadDebugEvent : DebugEvent
    {
        /// <summary>
        /// Subsystem key for the thread.
        /// </summary>
        public int ThreadSubSystemKey { get; }
        /// <summary>
        /// Start address of the thread.
        /// </summary>
        public long ThreadStartAddress { get; }
        /// <summary>
        /// Handle to the thread (if available).
        /// </summary>
        public NtThread Thread { get; }

        internal CreateThreadDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
            : base(debug_event, debug)
        {
            var info = debug_event.StateInfo.CreateThread;
            Thread = info.HandleToThread == IntPtr.Zero ? null : NtThread.FromHandle(info.HandleToThread);
            var thread = info.NewThread;
            ThreadSubSystemKey = thread.SubSystemKey;
            ThreadStartAddress = thread.StartAddress.ToInt64();
        }

        /// <summary>
        /// Dispose the event.
        /// </summary>
        public override void Dispose()
        {
            Thread?.Dispose();
        }
    }

    /// <summary>
    /// Debug event for the Exit Thread event.
    /// </summary>
    public sealed class ExitThreadDebugEvent : DebugEvent
    {
        /// <summary>
        /// Exit status code.
        /// </summary>
        public NtStatus ExitStatus { get; }

        internal ExitThreadDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
            : base(debug_event, debug)
        {
            ExitStatus = debug_event.StateInfo.ExitThread.ExitStatus;
        }
    }

    /// <summary>
    /// Debug event for the Exit Process event.
    /// </summary>
    public sealed class ExitProcessDebugEvent : DebugEvent
    {
        /// <summary>
        /// Exit status code.
        /// </summary>
        public NtStatus ExitStatus { get; }

        internal ExitProcessDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
            : base(debug_event, debug)
        {
            ExitStatus = debug_event.StateInfo.ExitProcess.ExitStatus;
        }
    }

    /// <summary>
    /// Debug event for load DLL event.
    /// </summary>
    public sealed class LoadDllDebugEvent : DebugEvent
    {
        /// <summary>
        /// DLL file handle.
        /// </summary>
        public NtFile File { get; }
        /// <summary>
        /// Base of loaded DLL.
        /// </summary>
        public long BaseOfDll { get; }
        /// <summary>
        /// Debug info offset.
        /// </summary>
        public int DebugInfoFileOffset { get; }
        /// <summary>
        /// Debug info size.
        /// </summary>
        public int DebugInfoSize { get; }
        /// <summary>
        /// Address of name.
        /// </summary>
        public long NamePointer { get; }

        internal LoadDllDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
                : base(debug_event, debug)
        {
            var info = debug_event.StateInfo.LoadDll;
            File = info.FileHandle == IntPtr.Zero ? null : NtFile.FromHandle(info.FileHandle);
            BaseOfDll = info.BaseOfDll.ToInt64();
            DebugInfoFileOffset = info.DebugInfoFileOffset;
            DebugInfoSize = info.DebugInfoSize;
            NamePointer = info.NamePointer.ToInt64();
        }

        /// <summary>
        /// Dispose the event.
        /// </summary>
        public override void Dispose()
        {
            File?.Dispose();
        }
    }

    /// <summary>
    /// Debug event for unload DLL event.
    /// </summary>
    public sealed class UnloadDllDebugEvent : DebugEvent
    {
        /// <summary>
        /// Base of loaded DLL.
        /// </summary>
        public long BaseAddress { get; }

        internal UnloadDllDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
                : base(debug_event, debug)
        {
            var info = debug_event.StateInfo.UnloadDll;
            BaseAddress = info.BaseAddress.ToInt64();
        }
    }

    /// <summary>
    /// Debug event for exception event.
    /// </summary>
    public sealed class ExceptionDebugEvent : DebugEvent
    {
        /// <summary>
        /// Indicates if this is a first chance exception.
        /// </summary>
        public bool FirstChance { get; }
        /// <summary>
        /// Exception code.
        /// </summary>
        public NtStatus Code { get; }
        /// <summary>
        /// Exception flags.
        /// </summary>
        public NtStatus Flags { get; }
        /// <summary>
        /// Pointer to next exception in the chain.
        /// </summary>
        public long RecordChain { get; }
        /// <summary>
        /// Address of exception.
        /// </summary>
        public long Address { get; }
        /// <summary>
        /// Additional parameters for exception.
        /// </summary>
        public IList<long> Parameters { get; }

        internal ExceptionDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
                : base(debug_event, debug)
        {
            var info = debug_event.StateInfo.Exception;
            FirstChance = info.FirstChance != 0;
            var exp = info.ExceptionRecord;
            Code = exp.ExceptionCode;
            Flags = exp.ExceptionFlags;
            RecordChain = exp.ExceptionRecordChain.ToInt64();
            Address = exp.ExceptionAddress.ToInt64();
            List<long> ps = new List<long>
            {
                exp.ExceptionInformation0.ToInt64(),
                exp.ExceptionInformation1.ToInt64(),
                exp.ExceptionInformation2.ToInt64(),
                exp.ExceptionInformation3.ToInt64(),
                exp.ExceptionInformation4.ToInt64(),
                exp.ExceptionInformation5.ToInt64(),
                exp.ExceptionInformation6.ToInt64(),
                exp.ExceptionInformation7.ToInt64(),
                exp.ExceptionInformation8.ToInt64(),
                exp.ExceptionInformation9.ToInt64(),
                exp.ExceptionInformationA.ToInt64(),
                exp.ExceptionInformationB.ToInt64(),
                exp.ExceptionInformationC.ToInt64(),
                exp.ExceptionInformationD.ToInt64(),
                exp.ExceptionInformationE.ToInt64()
            };
            ps.RemoveRange(exp.NumberParameters, ps.Count - exp.NumberParameters);
            Parameters = ps.AsReadOnly();
        }
    }

    /// <summary>
    /// Debug event when we don't handle the state.
    /// </summary>
    public sealed class UnknownDebugEvent : DebugEvent
    {
        /// <summary>
        /// The raw debug event.
        /// </summary>
        public DbgUiWaitStatusChange DebugEvent { get; }

        internal UnknownDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug) 
            : base(debug_event, debug)
        {
            DebugEvent = debug_event;
        }
    }
}
