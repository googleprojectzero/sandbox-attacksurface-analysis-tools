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
using System.Threading;
using System.Threading.Tasks;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to add additional methods to a file for a named pipe.
    /// </summary>
    public class NtNamedPipeFile : NtFile
    {
        internal NtNamedPipeFile(SafeKernelObjectHandle handle, IoStatus io_status)
            : base(handle, io_status)
        {
        }

        /// <summary>
        /// Listen for a new connection to this named pipe server.
        /// </summary>
        public void Listen()
        {
            FsControl(NtWellKnownIoControlCodes.FSCTL_PIPE_LISTEN, null, null);
        }

        /// <summary>
        /// Listen for a new connection to this named pipe server asynchronously.
        /// </summary>
        /// <param name="token">An optional cancellation token.</param>
        /// <returns>The async task to complete.</returns>
        public Task ListenAsync(CancellationToken token)
        {
            return FsControlAsync(NtWellKnownIoControlCodes.FSCTL_PIPE_LISTEN, null, null, token);
        }

        /// <summary>
        /// Listen for a new connection to this named pipe server asynchronously.
        /// </summary>
        /// <returns>The async task to complete.</returns>
        public Task ListenAsync()
        {
            return ListenAsync(CancellationToken.None);
        }

        /// <summary>
        /// Disconnect this named pipe server.
        /// </summary>
        public void Disconnect()
        {
            FsControl(NtWellKnownIoControlCodes.FSCTL_PIPE_DISCONNECT, null, null);
        }

        /// <summary>
        /// Disconnect this named pipe server asynchronously.
        /// </summary>
        /// <param name="token">An optional cancellation token.</param>
        /// <returns>The async task to complete.</returns>
        public Task DisconnectAsync(CancellationToken token)
        {
            return FsControlAsync(NtWellKnownIoControlCodes.FSCTL_PIPE_DISCONNECT, null, null, token);
        }

        /// <summary>
        /// Disconnect this named pipe server asynchronously.
        /// </summary>
        /// <returns>The async task to complete.</returns>
        public Task DisconnectAsync()
        {
            return DisconnectAsync(CancellationToken.None);
        }

        /// <summary>
        /// Impersonate the client of the named pipe.
        /// </summary>
        /// <returns>The impersonation context. Dispose to revert to self.</returns>
        public ThreadImpersonationContext Impersonate()
        {
            FsControl(NtWellKnownIoControlCodes.FSCTL_PIPE_IMPERSONATE, null, null);
            return new ThreadImpersonationContext(NtThread.Current.Duplicate());
        }

        /// <summary>
        /// Disables impersonation on a named pipe.
        /// </summary>
        public void DisableImpersonation()
        {
            FsControl(NtWellKnownIoControlCodes.FSCTL_PIPE_DISABLE_IMPERSONATE, null, null);
        }

        /// <summary>
        /// Get the default named pipe ACL for the current caller.
        /// </summary>
        /// <returns>The default named pipe ACL.</returns>
        public static Acl GetDefaultNamedPipeAcl()
        {
            IntPtr acl = IntPtr.Zero;
            try
            {
                NtRtl.RtlDefaultNpAcl(out acl).ToNtException();
                return new Acl(acl, false);
            }
            finally
            {
                if (acl != IntPtr.Zero)
                {
                    NtHeap.Current.Free(HeapAllocFlags.None, acl.ToInt64());
                }
            }
        }
    }

    /// <summary>
    /// A pair of named pipes.
    /// </summary>
    public sealed class NtNamedPipeFilePair : IDisposable
    {
        /// <summary>
        /// Read pipe for the pair.
        /// </summary>
        public NtNamedPipeFile ReadPipe { get; }
        /// <summary>
        /// Write pipe for the pair.
        /// </summary>
        public NtFile WritePipe { get; }

        internal NtNamedPipeFilePair(NtNamedPipeFile read_pipe,
            NtFile write_pipe)
        {
            ReadPipe = read_pipe;
            WritePipe = write_pipe;
        }

        void IDisposable.Dispose()
        {
            ReadPipe?.Dispose();
            WritePipe?.Dispose();
        }
    }
}
