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
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Debugger
{
    /// <summary>
    /// Class to capture Win32 debug output.
    /// </summary>
    public sealed class Win32DebugConsole : IDisposable
    {
        #region Private Members
        private readonly int _session_id;
        private readonly NtEvent _buffer_ready;
        private readonly NtEvent _data_ready;
        private readonly NtWaitHandle _data_ready_wait;
        private readonly NtSection _buffer;
        private readonly NtMappedSection _mapped_buffer;
        private readonly Dictionary<int, DisposableList<NtSymbolicLink>> _symlinks;

        private const string BUFFER_EVENT_NAME = "DBWIN_BUFFER_READY";
        private const string DATA_EVENT_NAME = "DBWIN_DATA_READY";
        private const string SECTION_NAME = "DBWIN_BUFFER";
        private const string MUTEX_NAME = "DBWinMutex";

        private Win32DebugConsole(int session_id, NtEvent buffer_ready, NtEvent data_ready, 
            NtSection buffer, NtMappedSection mapped_buffer)
        {
            _session_id = session_id;
            _buffer_ready = buffer_ready;
            _data_ready = data_ready;
            _buffer = buffer;
            _mapped_buffer = mapped_buffer;
            _data_ready_wait = data_ready.DuplicateAsWaitHandle();
            _symlinks = new Dictionary<int, DisposableList<NtSymbolicLink>>();
        }

        private static SecurityDescriptor CreateSecurityDescriptor()
        {
            SecurityDescriptor ret = new SecurityDescriptor();
            ret.AddAccessAllowedAce(GenericAccessRights.GenericAll, KnownSids.BuiltinAdministrators);
            ret.AddAccessAllowedAce(GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite | GenericAccessRights.GenericExecute, KnownSids.World);
            ret.AddAccessAllowedAce(GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite | GenericAccessRights.GenericExecute, KnownSids.Restricted);
            ret.AddAccessAllowedAce(GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite | GenericAccessRights.GenericExecute, KnownSids.Null);
            ret.AddAccessAllowedAce(GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite | GenericAccessRights.GenericExecute, KnownSids.AllApplicationPackages);
            ret.AddAccessAllowedAce(GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite | GenericAccessRights.GenericExecute, KnownSids.AllRestrictedApplicationPackages);
            ret.AddAccessAllowedAce(GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite | GenericAccessRights.GenericExecute, KnownSids.WriteRestricted);
            ret.AddAccessAllowedAce(GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite | GenericAccessRights.GenericExecute, KnownSids.Anonymous);
            ret.IntegrityLevel = TokenIntegrityLevel.Untrusted;
            return ret;
        }

        private static string GetSessionString(int session_id, string name)
        {
            return $@"\Sessions\BNOLINKS\{session_id}\{name}";
        }

        private static ObjectAttributes CreateObjectAttributes(int session_id, string name, bool open_if = false)
        {
            return new ObjectAttributes(GetSessionString(session_id, name), 
                open_if ? AttributeFlags.OpenIf : AttributeFlags.None , (NtObject)null, null, CreateSecurityDescriptor());
        }

        private static NtResult<NtEvent> CreateEvent(int session_id, string name, bool throw_on_error)
        {
            using (var obja = CreateObjectAttributes(session_id, name))
            {
                return NtEvent.Create(obja, EventType.SynchronizationEvent, false, EventAccessRights.MaximumAllowed, throw_on_error);
            }
        }

        private static NtResult<NtSection> CreateSection(int session_id, bool throw_on_error)
        {
            using (var obja = CreateObjectAttributes(session_id, SECTION_NAME))
            {
                return NtSection.Create(obja, SectionAccessRights.MaximumAllowed, new LargeInteger(64 * 1024), 
                    MemoryAllocationProtect.ReadWrite, SectionAttributes.Commit, null, throw_on_error);
            }
        }

        private static NtResult<NtMutant> CreateMutant(int session_id)
        {
            using (var obja = CreateObjectAttributes(session_id, MUTEX_NAME, true))
            {
                return NtMutant.Create(obja, false, MutantAccessRights.MaximumAllowed, false);
            }
        }

        private NtResult<NtSymbolicLink> CreateSymlink(int session_id, string name, bool throw_on_error)
        {
            using (var obja = CreateObjectAttributes(session_id, name))
            {
                return NtSymbolicLink.Create(obja, SymbolicLinkAccessRights.MaximumAllowed, 
                    GetSessionString(_session_id, name), throw_on_error);
            }
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Create an instance of the Win32 debug console.
        /// </summary>
        /// <param name="session_id">The session ID for the console. Set to 0 to capture global output.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Win32 debug console.</returns>
        public static NtResult<Win32DebugConsole> Create(int session_id, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                using (var mutant = CreateMutant(session_id))
                {
                    // Wait 2 seconds for mutex, if it's not released just try and do it anyway.
                    if (mutant.IsSuccess)
                        mutant.Result.Wait(NtWaitTimeout.FromSeconds(2));
                    try
                    {
                        var buffer_ready = list.AddResource(CreateEvent(session_id, BUFFER_EVENT_NAME, throw_on_error));
                        if (!buffer_ready.IsSuccess)
                            return buffer_ready.Cast<Win32DebugConsole>();
                        var data_ready = list.AddResource(CreateEvent(session_id, DATA_EVENT_NAME, throw_on_error));
                        if (!data_ready.IsSuccess)
                            return data_ready.Cast<Win32DebugConsole>();
                        var buffer = list.AddResource(CreateSection(session_id, throw_on_error));
                        if (!buffer.IsSuccess)
                            return buffer.Cast<Win32DebugConsole>();
                        var mapped_buffer = list.AddResource(buffer.Result.MapRead(throw_on_error));
                        if (!mapped_buffer.IsSuccess)
                            return mapped_buffer.Cast<Win32DebugConsole>();
                        var ret = new Win32DebugConsole(session_id, buffer_ready.Result, data_ready.Result, buffer.Result, mapped_buffer.Result);
                        list.Clear();
                        buffer_ready.Result.Set();
                        return ret.CreateResult();
                    }
                    finally
                    {
                        if (mutant.IsSuccess)
                            mutant.Result.Release(false);
                    }
                }
            }
        }

        /// <summary>
        /// Create an instance of the Win32 debug console.
        /// </summary>
        /// <param name="session_id">The session ID for the console. Set to 0 to capture global output.</param>
        /// <returns>The Win32 debug console.</returns>
        public static Win32DebugConsole Create(int session_id)
        {
            return Create(session_id, true).Result;
        }

        /// <summary>
        /// Create an instance of the Win32 debug console for current session.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Win32 debug console.</returns>
        public static NtResult<Win32DebugConsole> Create(bool throw_on_error)
        {
            var session_id = NtProcess.Current.GetSessionId(throw_on_error);
            if (!session_id.IsSuccess)
                return session_id.Cast<Win32DebugConsole>();

            return Create(session_id.Result, throw_on_error);
        }

        /// <summary>
        /// Create an instance of the Win32 debug console for current session.
        /// </summary>
        /// <returns>The Win32 debug console.</returns>
        public static Win32DebugConsole Create()
        {
            return Create(true).Result;
        }

        /// <summary>
        /// Create an instance of the Win32 debug console for the global session.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Win32 debug console.</returns>
        public static NtResult<Win32DebugConsole> CreateGlobal(bool throw_on_error)
        {
            return Create(0, throw_on_error);
        }

        /// <summary>
        /// Create an instance of the Win32 debug console for the global  session.
        /// </summary>
        /// <returns>The Win32 debug console.</returns>
        public static Win32DebugConsole CreateGlobal()
        {
            return CreateGlobal(true).Result;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a debug string from for the console asynchronously.
        /// </summary>
        /// <param name="timeout_ms">The timeout in milliseconds.</param>
        /// <param name="cancellation_token">Cancellation token.</param>
        /// <returns>The Win32 debug string. If timed out then Output property is null.</returns>
        public async Task<Win32DebugString> ReadAsync(int timeout_ms, CancellationToken cancellation_token)
        {
            if (!await _data_ready_wait.WaitAsync(timeout_ms, cancellation_token))
                return default;
            int pid = _mapped_buffer.Read<int>(0);
            string output = _mapped_buffer.ReadNulTerminatedAnsiString(4);
            _buffer_ready.Set();
            return new Win32DebugString(pid, output);
        }

        /// <summary>
        /// Read a debug string from for the console asynchronously.
        /// </summary>
        /// <param name="timeout_ms">The timeout in milliseconds.</param>
        /// <returns>The Win32 debug string. If timed out then Output property is null.</returns>
        public Task<Win32DebugString> ReadAsync(int timeout_ms)
        {
            return ReadAsync(timeout_ms, CancellationToken.None);
        }

        /// <summary>
        /// Read a debug string from for the console asynchronously.
        /// </summary>
        /// <returns>The Win32 debug string. If timed out then Output property is null.</returns>
        public Task<Win32DebugString> ReadAsync()
        {
            return ReadAsync(Timeout.Infinite);
        }

        /// <summary>
        /// Read a debug string from for the console.
        /// </summary>
        /// <param name="timeout_ms">The timeout in milliseconds.</param>
        /// <returns>The Win32 debug string. If timed out then Output property is null.</returns>
        public Win32DebugString Read(int timeout_ms)
        {
            NtWaitTimeout timeout = timeout_ms < 0 ? NtWaitTimeout.Infinite : NtWaitTimeout.FromMilliseconds(timeout_ms);
            if (_data_ready.Wait(timeout) != NtStatus.STATUS_SUCCESS)
                return default;
            int pid = _mapped_buffer.Read<int>(0);
            string output = _mapped_buffer.ReadNulTerminatedAnsiString(4);
            _buffer_ready.Set();
            return new Win32DebugString(pid, output);
        }

        /// <summary>
        /// Read a debug string from for the console.
        /// </summary>
        /// <returns>The Win32 debug string. If timed out then Output property is null.</returns>
        public Win32DebugString Read()
        {
            return Read(Timeout.Infinite);
        }

        /// <summary>
        /// Attach the debug console to another session.
        /// </summary>
        /// <param name="session_id">The session ID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus AttachToSession(int session_id, bool throw_on_error)
        {
            if (session_id == _session_id || _symlinks.ContainsKey(session_id))
                return NtStatus.STATUS_SUCCESS;

            using (var list = new DisposableList<NtResult<NtSymbolicLink>>())
            {
                var buffer_ready = list.AddResource(CreateSymlink(session_id, BUFFER_EVENT_NAME, throw_on_error));
                if (!buffer_ready.IsSuccess)
                    return buffer_ready.Status;
                var data_ready = list.AddResource(CreateSymlink(session_id, DATA_EVENT_NAME, throw_on_error));
                if (!data_ready.IsSuccess)
                    return data_ready.Status;
                var buffer = list.AddResource(CreateSymlink(session_id, SECTION_NAME, throw_on_error));
                if (!buffer.IsSuccess)
                    return buffer.Status;
                _symlinks[session_id] = list.ToArrayAndClear().Select(s => s.Result).ToDisposableList();
            }

            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Attach the debug console to another session.
        /// </summary>
        /// <param name="session_id">The session ID.</param>
        public void AttachToSession(int session_id)
        {
            AttachToSession(session_id, true);
        }

        /// <summary>
        /// Dispose debug console.
        /// </summary>
        public void Dispose()
        {
            _buffer_ready?.Dispose();
            _data_ready?.Dispose();
            _buffer?.Dispose();
            _mapped_buffer?.Dispose();
            _data_ready_wait?.Dispose();
            foreach (var list in _symlinks.Values)
            {
                list.Dispose();
            }
        }
        #endregion
    }
}
