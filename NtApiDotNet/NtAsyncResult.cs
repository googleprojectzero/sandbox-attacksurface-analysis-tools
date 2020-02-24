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
    internal sealed class NtAsyncResult : IDisposable
    {
        private NtObject _object;
        private NtEvent _event;
        private SafeIoStatusBuffer _io_status;
        private IoStatus _result;

        internal NtAsyncResult(NtObject @object)
        {
            _object = @object;
            if (!_object.CanSynchronize)
            {
                _event = NtEvent.Create(null,
                    EventType.SynchronizationEvent, false);
            }
            _io_status = new SafeIoStatusBuffer();
            _result = null;
        }

        internal SafeKernelObjectHandle EventHandle
        {
            get { return _event.GetHandle(); }
        }

        internal NtStatus CompleteCall(NtStatus status)
        {
            if (status == NtStatus.STATUS_PENDING)
            {
                if (WaitForComplete())
                {
                    status = _io_status.Result.Status;
                }
            }
            else if (status.IsSuccess())
            {
                _result = _io_status.Result;
            }
            return status;
        }

        internal async Task<NtStatus> CompleteCallAsync(NtStatus status, CancellationToken token)
        {
            try
            {
                if (status == NtStatus.STATUS_PENDING)
                {
                    if (await WaitForCompleteAsync(token))
                    {
                        return _result.Status;
                    }
                }
                else if (status.IsSuccess())
                {
                    _result = _io_status.Result;
                }
                return status;
            }
            catch (TaskCanceledException)
            {
                // Cancel and then rethrow.
                Cancel();
                throw;
            }
        }

        /// <summary>
        /// Wait for the result to complete. This could be waiting on an event
        /// or the file handle.
        /// </summary>
        /// <returns>Returns true if the wait completed successfully.</returns>
        /// <remarks>If true is returned then status and information can be read out.</remarks>
        internal bool WaitForComplete()
        {
            if (_result != null)
            {
                return true;
            }

            NtStatus status;
            if (_event != null)
            {
                status = _event.Wait(NtWaitTimeout.Infinite).ToNtException();
            }
            else
            {
                status = _object.Wait(NtWaitTimeout.Infinite).ToNtException();
            }

            if (status == NtStatus.STATUS_SUCCESS)
            {
                _result = _io_status.Result;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Wait for the result to complete asynchronously. This could be waiting on an event
        /// or the file handle.
        /// </summary>
        /// <param name="token">Cancellation token.</param>
        /// <returns>Returns true if the wait completed successfully.</returns>
        /// <remarks>If true is returned then status and information can be read out.</remarks>
        internal async Task<bool> WaitForCompleteAsync(CancellationToken token)
        {
            if (_result != null)
            {
                return true;
            }

            bool success;

            using (NtWaitHandle wait_handle = _event?.DuplicateAsWaitHandle() ?? _object.DuplicateAsWaitHandle())
            {
                success = await wait_handle.WaitAsync(Timeout.Infinite, token);
            }

            if (success)
            {
                _result = _io_status.Result;
                return true;
            }

            return false;
        }

        private IoStatus GetIoStatus()
        {
            if (_result == null)
            {
                throw new NtException(NtStatus.STATUS_PENDING);
            }
            return _result;
        }

        /// <summary>
        /// Return the status information field.
        /// </summary>
        /// <exception cref="NtException">Thrown if not complete.</exception>
        internal long Information
        {
            get
            {
                return GetIoStatus().Information.ToInt64();
            }
        }

        /// <summary>
        /// Return the status information field. (32 bit)
        /// </summary>
        /// <exception cref="NtException">Thrown if not complete.</exception>
        internal int Information32
        {
            get
            {
                return GetIoStatus().Information.ToInt32();
            }
        }

        /// <summary>
        /// Get completion status code.
        /// </summary>
        /// <exception cref="NtException">Thrown if not complete.</exception>
        internal NtStatus Status
        {
            get
            {
                return GetIoStatus().Status;
            }
        }

        internal IoStatus Result
        {
            get
            {
                return GetIoStatus();
            }
        }

        /// <summary>
        /// Returns true if the call is pending.
        /// </summary>
        internal bool IsPending
        {
            get
            {
                return _result == null;
            }
        }

        internal SafeIoStatusBuffer IoStatusBuffer
        {
            get { return _io_status; }
        }

        /// <summary>
        /// Dispose object.
        /// </summary>
        public void Dispose()
        {
            if (_event != null)
            {
                _event.Close();
            }

            if (_io_status != null)
            {
                _io_status.Close();
            }
        }

        /// <summary>
        /// Reset the file result so it can be reused.
        /// </summary>
        internal void Reset()
        {
            _result = null;
            if (_event != null)
            {
                _event.Clear();
            }
        }

        /// <summary>
        /// Cancel the pending IO operation.
        /// </summary>
        internal void Cancel()
        {
            Cancel(true);
        }

        /// <summary>
        /// Cancel the pending IO operation.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        internal NtStatus Cancel(bool throw_on_error)
        {
            if (_object is NtFile)
            {
                IoStatus io_status = new IoStatus();
                return NtSystemCalls.NtCancelIoFileEx(_object.Handle,
                    _io_status, io_status).ToNtException(throw_on_error);
            }
            return NtStatus.STATUS_SUCCESS;
        }
    }
}
