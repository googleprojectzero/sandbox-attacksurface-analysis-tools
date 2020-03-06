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
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NtApiDotNet
{
    /// <summary>
    /// Pipe attribute type.
    /// </summary>
    public enum PipeAttributeType
    {
        /// <summary>
        /// The pipe attributes.
        /// </summary>
        Pipe,
        /// <summary>
        /// The pipe connect attributes.
        /// </summary>
        Connection = 1,
        /// <summary>
        /// The pipe handle attributes.
        /// </summary>
        Handle = 2
    }

    /// <summary>
    /// Class to add additional methods to a file for a named pipe. This is a base class for server and client types.
    /// </summary>
    public abstract class NtNamedPipeFileBase : NtFile
    {
        #region Constructors
        internal NtNamedPipeFileBase(SafeKernelObjectHandle handle, IoStatus io_status)
            : base(handle, io_status)
        {
            _pipe_information = new Lazy<NtResult<FilePipeInformation>>(() 
                => Query(FileInformationClass.FilePipeInformation, new FilePipeInformation(), false));
            _pipe_local_information = new Lazy<NtResult<FilePipeLocalInformation>>(()
                => Query(FileInformationClass.FilePipeLocalInformation, new FilePipeLocalInformation(), false));
        }

        internal NtNamedPipeFileBase(SafeKernelObjectHandle handle)
            : base(handle)
        {
        }
        #endregion

        #region Private Members
        private Lazy<NtResult<FilePipeInformation>> _pipe_information;
        private Lazy<NtResult<FilePipeLocalInformation>> _pipe_local_information;

        private static NtIoControlCode GetAttributeToIoCtl(PipeAttributeType attribute_type)
        {
            switch (attribute_type)
            {
                case PipeAttributeType.Pipe:
                    return NtWellKnownIoControlCodes.FSCTL_PIPE_GET_PIPE_ATTRIBUTE;
                case PipeAttributeType.Connection:
                    return NtWellKnownIoControlCodes.FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE;
                case PipeAttributeType.Handle:
                    return NtWellKnownIoControlCodes.FSCTL_PIPE_GET_HANDLE_ATTRIBUTE;
                default:
                    throw new ArgumentException("Invalid attribute type");
            }
        }

        private static NtIoControlCode SetAttributeToIoCtl(PipeAttributeType attribute_type)
        {
            switch (attribute_type)
            {
                case PipeAttributeType.Pipe:
                    return NtWellKnownIoControlCodes.FSCTL_PIPE_SET_PIPE_ATTRIBUTE;
                case PipeAttributeType.Connection:
                    return NtWellKnownIoControlCodes.FSCTL_PIPE_SET_CONNECTION_ATTRIBUTE;
                case PipeAttributeType.Handle:
                    return NtWellKnownIoControlCodes.FSCTL_PIPE_SET_HANDLE_ATTRIBUTE;
                default:
                    throw new ArgumentException("Invalid attribute type");
            }
        }

        private static T GetLazyResult<T>(Lazy<NtResult<T>> lazy)
        {
            if (!lazy.Value.IsSuccess)
            {
                return default;
            }
            return lazy.Value.Result;
        }

        private FilePipeLocalInformation QueryCurrentInfo()
        {
            return Query<FilePipeLocalInformation>(FileInformationClass.FilePipeLocalInformation);
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Get a named attribute from the pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to query.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The attribute value as a byte array.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<byte[]> GetAttribute(PipeAttributeType attribute_type, string name, bool throw_on_error)
        {
            NtIoControlCode ioctl = GetAttributeToIoCtl(attribute_type);

            int size = 128;
            byte[] name_buffer = Encoding.ASCII.GetBytes(name + "\0");
            while (size < 4096)
            {
                var result = FsControl(ioctl, name_buffer, size, false);
                if (result.IsSuccess)
                {
                    return result;
                }

                if (result.Status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                {
                    result.Status.ToNtException(throw_on_error);
                    return result;
                }

                size *= 2;
            }

            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<byte[]>(throw_on_error);
        }

        /// <summary>
        /// Set a named attribute for a pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to set.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The status code for the attribute.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus SetAttribute(PipeAttributeType attribute_type, string name, byte[] value, bool throw_on_error)
        {
            NtIoControlCode ioctl = SetAttributeToIoCtl(attribute_type);
            byte[] name_bytes = Encoding.ASCII.GetBytes(name);
            MemoryStream stm = new MemoryStream();
            stm.Write(name_bytes, 0, name_bytes.Length);
            stm.WriteByte(0);
            stm.Write(value, 0, value.Length);

            return FsControl(ioctl, stm.ToArray(), 0, throw_on_error).Status;
        }

        /// <summary>
        /// Set a named attribute for a pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to set.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value to set.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetAttribute(PipeAttributeType attribute_type, string name, byte[] value)
        {
            SetAttribute(attribute_type, name, value, true);
        }

        /// <summary>
        /// Set a named attribute for a pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to set.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The status code for the attribute.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus SetAttribute(PipeAttributeType attribute_type, string name, int value, bool throw_on_error)
        {
            return SetAttribute(attribute_type, name, BitConverter.GetBytes(value), throw_on_error);
        }

        /// <summary>
        /// Set a named attribute for a pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to set.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value to set.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetAttribute(PipeAttributeType attribute_type, string name, int value)
        {
            SetAttribute(attribute_type, name, value, true);
        }

        /// <summary>
        /// Set a named attribute for a pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to set.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The status code for the attribute.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus SetAttribute(PipeAttributeType attribute_type, string name, string value, bool throw_on_error)
        {
            return SetAttribute(attribute_type, name, Encoding.Unicode.GetBytes(value + "\0"), throw_on_error);
        }

        /// <summary>
        /// Set a named attribute for a pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to set.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value to set.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetAttribute(PipeAttributeType attribute_type, string name, string value)
        {
            SetAttribute(attribute_type, name, value, true);
        }

        /// <summary>
        /// Get a named attribute from the pipe.
        /// </summary>
        /// <param name="attribute_type">The attribute type to query.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <returns>The attribute value as a byte array.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public byte[] GetAttribute(PipeAttributeType attribute_type, string name)
        {
            return GetAttribute(attribute_type, name, true).Result;
        }

        /// <summary>
        /// Get a named attribute from the pipe as an integer.
        /// </summary>
        /// <param name="attribute_type">The attribute type to query.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The attribute value as an integer.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<int> GetAttributeInt(PipeAttributeType attribute_type, string name, bool throw_on_error)
        {
            var result = GetAttribute(attribute_type, name, throw_on_error);
            if (result.IsSuccess && result.Result.Length == 4)
            {
                return BitConverter.ToInt32(result.Result, 0).CreateResult();
            }
            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<int>(throw_on_error);
        }

        /// <summary>
        /// Get a named attribute from the pipe as an integer.
        /// </summary>
        /// <param name="attribute_type">The attribute type to query.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <returns>The attribute value as an integer.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int GetAttributeInt(PipeAttributeType attribute_type, string name)
        {
            return GetAttributeInt(attribute_type, name, true).Result;
        }

        /// <summary>
        /// Get a named attribute from the pipe as an integer.
        /// </summary>
        /// <param name="attribute_type">The attribute type to query.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The attribute value as an integer.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<string> GetAttributeString(PipeAttributeType attribute_type, string name, bool throw_on_error)
        {
            var result = GetAttribute(attribute_type, name, throw_on_error);
            if (result.IsSuccess && ((result.Result.Length & 1) == 0))
            {
                return Encoding.Unicode.GetString(result.Result).TrimEnd('\0').CreateResult();
            }
            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<string>(throw_on_error);
        }

        /// <summary>
        /// Get a named attribute from the pipe as an integer.
        /// </summary>
        /// <param name="attribute_type">The attribute type to query.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <returns>The attribute value as an integer.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public string GetAttributeString(PipeAttributeType attribute_type, string name)
        {
            return GetAttributeString(attribute_type, name, true).Result;
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Pipe completion mode.
        /// </summary>
        public NamedPipeCompletionMode CompletionMode => GetLazyResult(_pipe_information).CompletionMode;
        /// <summary>
        /// Pipe read mode.
        /// </summary>
        public NamedPipeReadMode ReadMode => GetLazyResult(_pipe_information).ReadMode;
        /// <summary>
        /// Pipe type.
        /// </summary>
        public NamedPipeType PipeType => GetLazyResult(_pipe_local_information).NamedPipeType;
        /// <summary>
        /// Pipe configuration.
        /// </summary>
        public NamedPipeConfiguration Configuration => GetLazyResult(_pipe_local_information).NamedPipeConfiguration;
        /// <summary>
        /// Maximum instances of the pipe, -1 is unlimited.
        /// </summary>
        public int MaximumInstances => GetLazyResult(_pipe_local_information).MaximumInstances;
        /// <summary>
        /// Current pipe instances.
        /// </summary>
        public int CurrentInstances => QueryCurrentInfo().CurrentInstances;
        /// <summary>
        /// Inbound quota.
        /// </summary>
        public int InboundQuota => GetLazyResult(_pipe_local_information).InboundQuota;
        /// <summary>
        /// Available bytes to read.
        /// </summary>
        public int ReadDataAvailable => QueryCurrentInfo().ReadDataAvailable;
        /// <summary>
        /// Outbound quota.
        /// </summary>
        public int OutboundQuota => GetLazyResult(_pipe_local_information).OutboundQuota;
        /// <summary>
        /// Available outbound quota.
        /// </summary>
        public int WriteQuotaAvailable => QueryCurrentInfo().WriteQuotaAvailable;
        /// <summary>
        /// Connect state of the named pipe.
        /// </summary>
        public NamedPipeState ConnectState => QueryCurrentInfo().NamedPipeState;
        /// <summary>
        /// Type of pipe endpoint.
        /// </summary>
        public NamedPipeEnd EndPointType => GetLazyResult(_pipe_local_information).NamedPipeEnd;
        #endregion
    }

    /// <summary>
    /// Class to add additional methods to a file for a named pipe server.
    /// </summary>
    public class NtNamedPipeFile : NtNamedPipeFileBase
    {
        internal NtNamedPipeFile(SafeKernelObjectHandle handle, IoStatus io_status)
            : base(handle, io_status)
        {
        }

        internal NtNamedPipeFile(SafeKernelObjectHandle handle)
            : base(handle)
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
        /// Get client process ID.
        /// </summary>
        public int ClientProcessId => GetAttributeInt(PipeAttributeType.Connection, "ClientProcessId");

        /// <summary>
        /// Get client session ID. If this is 0 then the client is local, otherwise it's set by the SMB server.
        /// </summary>
        public int ClientSessionId => GetAttributeInt(PipeAttributeType.Connection, "ClientSessionId");

        /// <summary>
        /// Get client computer name.
        /// </summary>
        public string ClientComputerName => GetAttributeString(PipeAttributeType.Connection, "ClientComputerName");

        /// <summary>
        /// Get the default named pipe ACL for the current caller.
        /// </summary>
        /// <returns>The default named pipe ACL.</returns>
        public static Acl GetDefaultNamedPipeAcl()
        {
            NtRtl.RtlDefaultNpAcl(out SafeProcessHeapBuffer acl).ToNtException();
            using (acl)
            {
                return new Acl(acl.DangerousGetHandle(), false);
            }
        }
    }

    /// <summary>
    /// Class to add additional methods to a file for a named pipe client.
    /// </summary>
    public sealed class NtNamedPipeFileClient : NtNamedPipeFileBase
    {
        internal NtNamedPipeFileClient(SafeKernelObjectHandle handle, IoStatus io_status)
            : base(handle, io_status)
        {
        }

        internal NtNamedPipeFileClient(SafeKernelObjectHandle handle)
            : base(handle)
        {
        }

        /// <summary>
        /// Disables impersonation on a named pipe.
        /// </summary>
        public void DisableImpersonation()
        {
            FsControl(NtWellKnownIoControlCodes.FSCTL_PIPE_DISABLE_IMPERSONATE, null, null);
        }

        /// <summary>
        /// Get server process ID.
        /// </summary>
        public int ServerProcessId => GetAttributeInt(PipeAttributeType.Pipe, "ServerProcessId");

        /// <summary>
        /// Get client session ID.
        /// </summary>
        public int ServerSessionId => GetAttributeInt(PipeAttributeType.Pipe, "ServerSessionId");
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
        public NtNamedPipeFileClient WritePipe { get; }

        internal NtNamedPipeFilePair(NtNamedPipeFile read_pipe,
            NtNamedPipeFileClient write_pipe)
        {
            ReadPipe = read_pipe ?? throw new ArgumentNullException(nameof(read_pipe));
            WritePipe = write_pipe ?? throw new ArgumentNullException(nameof(write_pipe));
        }

        void IDisposable.Dispose()
        {
            ReadPipe?.Dispose();
            WritePipe?.Dispose();
        }
    }
}
