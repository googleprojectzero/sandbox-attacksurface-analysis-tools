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

using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;

namespace NtApiDotNet
{
    /// <summary>
    /// Static utility methods.
    /// </summary>
    public static class NtObjectUtils
    {
        internal static byte[] StructToBytes<T>(T value)
        {
            int length = Marshal.SizeOf(typeof(T));
            byte[] ret = new byte[length];
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(value, buffer, false);
                Marshal.Copy(buffer, ret, 0, ret.Length);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return ret;
        }

        /// <summary>
        /// Convert the safe handle to an array of bytes.
        /// </summary>
        /// <returns>The data contained in the allocaiton.</returns>
        internal static byte[] SafeHandleToArray(SafeHandle handle, int length)
        {
            byte[] ret = new byte[length];
            Marshal.Copy(handle.DangerousGetHandle(), ret, 0, ret.Length);
            return ret;
        }

        internal static byte[] ReadAllBytes(this BinaryReader reader, int length)
        {
            byte[] ret = reader.ReadBytes(length);
            if (ret.Length != length)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        /// <summary>
        /// Convert an NtStatus to an exception if the status is an error
        /// </summary>
        /// <param name="status">The NtStatus</param>
        /// <returns>The original NtStatus if not an error</returns>
        /// <exception cref="NtException">Thrown if status is an error.</exception>
        public static NtStatus ToNtException(this NtStatus status)
        {
            return status.ToNtException(true);
        }

        /// <summary>
        /// Convert an NtStatus to an exception if the status is an error and throw_on_error is true.
        /// </summary>
        /// <param name="status">The NtStatus</param>
        /// <param name="throw_on_error">True to throw an exception onerror.</param>
        /// <returns>The original NtStatus if not thrown</returns>
        /// <exception cref="NtException">Thrown if status is an error and throw_on_error is true.</exception>
        public static NtStatus ToNtException(this NtStatus status, bool throw_on_error)
        {
            if (throw_on_error && !status.IsSuccess())
            {
                throw new NtException(status);
            }
            return status;
        }

        /// <summary>
        /// Checks if the NtStatus value is a success
        /// </summary>
        /// <param name="status">The NtStatus value</param>
        /// <returns>True if a success</returns>
        public static bool IsSuccess(this NtStatus status)
        {
            return (int)status >= 0;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string modulename);

        [Flags]
        enum FormatFlags
        {
            AllocateBuffer = 0x00000100,
            FromHModule = 0x00000800,
            FromSystem = 0x00001000,
            IgnoreInserts = 0x00000200
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int FormatMessage(
          FormatFlags dwFlags,
          IntPtr lpSource,
          uint dwMessageId,
          int dwLanguageId,
          out SafeLocalAllocHandle lpBuffer,
          int nSize,
          IntPtr Arguments
        );

        /// <summary>
        /// Convert an NTSTATUS to a message description.
        /// </summary>
        /// <param name="status">The status to convert.</param>
        /// <returns>The message description, or an empty string if not found.</returns>
        public static string GetNtStatusMessage(NtStatus status)
        {
            IntPtr module_handle = IntPtr.Zero;
            uint message_id = (uint)status;
            if ((message_id & 0xFFFF0000) == DosErrorStatusCode)
            {
                message_id &= 0xFFFF;
                module_handle = GetModuleHandle("kernel32.dll");
            }
            else
            {
                module_handle = GetModuleHandle("ntdll.dll");
            }

            if (FormatMessage(FormatFlags.AllocateBuffer | FormatFlags.FromHModule
                | FormatFlags.FromSystem | FormatFlags.IgnoreInserts,
                module_handle, message_id, 0, out SafeLocalAllocHandle buffer, 0, IntPtr.Zero) > 0)
            {
                using (buffer)
                {
                    return Marshal.PtrToStringUni(buffer.DangerousGetHandle()).Trim();
                }
            }
            return String.Empty;
        }

        /// <summary>
        /// Convert an integer to an NtStatus code.
        /// </summary>
        /// <param name="status">The integer status.</param>
        /// <returns>The converted code.</returns>
        public static NtStatus ConvertIntToNtStatus(int status)
        {
            return (NtStatus)(uint)status;
        }

        internal static bool GetBit(this int result, int bit)
        {
            return (result & (1 << bit)) != 0;
        }

        internal static bool GetBit(this long result, int bit)
        {
            return (result & (1 << bit)) != 0;
        }

        internal static bool GetBit(this IntPtr result, int bit)
        {
            return GetBit(result.ToInt64(), bit);
        }

        internal static int GetBits(this int result, int bit, int length)
        {
            int mask = (1 << length) - 1;
            return (result >> bit) & mask;
        }

        internal static long GetBits(this long result, int bit, int length)
        {
            long mask = (1L << length) - 1L;
            return (result >> bit) & mask;
        }

        internal static long GetBits(this IntPtr result, int bit, int length)
        {
            return GetBits(result.ToInt64(), bit, length);
        }

        internal static void CheckEnumType(Type t)
        {
            if (!t.IsEnum || t.GetEnumUnderlyingType() != typeof(uint))
            {
                throw new ArgumentException("Type must be an enumeration of unsigned int.");
            }
        }

        internal static string ToHexString(this byte[] ba, int offset, int length)
        {
            return BitConverter.ToString(ba, offset, length).Replace("-", string.Empty);
        }

        internal static string ToHexString(this byte[] ba, int offset)
        {
            return BitConverter.ToString(ba, offset).Replace("-", string.Empty);
        }

        internal static string ToHexString(this byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", string.Empty);
        }

        /// <summary>
        /// Convert an access rights type to a string.
        /// </summary>
        /// <param name="t">The enumeration type for the string conversion</param>
        /// <param name="access">The access mask to convert</param>
        /// <returns>The string version of the access</returns>
        internal static string AccessRightsToString(Type t, AccessMask access)
        {
            List<string> names = new List<string>();
            uint remaining = access.Access;

            // If the valid is explicitly defined return it.
            if (Enum.IsDefined(t, remaining))
            {
                return Enum.GetName(t, remaining);
            }

            for (int i = 0; i < 32; ++i)
            {
                uint mask = 1U << i;

                if (mask > remaining)
                {
                    break;
                }

                if (mask == (uint)GenericAccessRights.MaximumAllowed)
                {
                    continue;
                }

                if ((remaining & mask) == 0)
                {
                    continue;
                }

                if (!Enum.IsDefined(t, mask))
                {
                    continue;
                }

                names.Add(Enum.GetName(t, mask));

                remaining = remaining & ~mask;
            }

            if (remaining != 0)
            {
                names.Add($"0x{remaining:X}");
            }

            if (names.Count == 0)
            {
                names.Add("None");
            }

            return string.Join("|", names);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="access">The access rights</param>
        /// <returns>The string format of the access rights</returns>
        internal static string AccessRightsToString(Enum access)
        {
            return AccessRightsToString(access.GetType(), access);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="granted_access">The granted access mask.</param>
        /// <param name="generic_mapping">Generic mapping for object type.</param>
        /// <param name="enum_type">Enum type to convert to string.</param>
        /// <param name="map_to_generic">True to try and convert to generic rights where possible.</param>
        /// <returns>The string format of the access rights</returns>
        public static string GrantedAccessAsString(AccessMask granted_access, GenericMapping generic_mapping, Type enum_type, bool map_to_generic)
        {
            if (granted_access == 0)
            {
                return "None";
            }

            AccessMask mapped_access = generic_mapping.MapMask(granted_access);
            if (map_to_generic)
            {
                mapped_access = generic_mapping.UnmapMask(mapped_access);
            }
            else if (generic_mapping.HasAll(granted_access))
            {
                return "Full Access";
            }

            return NtObjectUtils.AccessRightsToString(enum_type, mapped_access);
        }

        /// <summary>
        /// Convert an IEnumerable to a Disposable List.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="list"></param>
        /// <returns></returns>
        public static DisposableList<T> ToDisposableList<T>(this IEnumerable<T> list) where T : IDisposable
        {
            return new DisposableList<T>(list);
        }

        /// <summary>
        /// Run a function on an NtResult and dispose the result afterwards.
        /// </summary>
        /// <typeparam name="T">The underlying result type.</typeparam>
        /// <typeparam name="S">The result of the function.</typeparam>
        /// <param name="result">The result.</param>
        /// <param name="func">The function to call.</param>
        /// <returns>The result of func.</returns>
        /// <remarks>If result is not a success then the function is not called.</remarks>
        public static S RunAndDispose<T, S>(this NtResult<T> result, Func<T, S> func) where T : NtObject
        {
            if (!result.IsSuccess)
            {
                return default(S);
            }
            using (result)
            {
                return func(result.Result);
            }
        }

        /// <summary>
        /// Run an action on an NtResult and dispose the result afterwards.
        /// </summary>
        /// <typeparam name="T">The underlying result type.</typeparam>
        /// <param name="result">The result.</param>
        /// <param name="action">The action to call.</param>
        /// <remarks>If result is not a success then the action is not called.</remarks>
        public static void RunAndDispose<T>(this NtResult<T> result, Action<T> action) where T : NtObject
        {
            if (!result.IsSuccess)
            {
                return;
            }

            using (result)
            {
                action(result.Result);
            }
        }

        /// <summary>
        /// Run a function on an NtResult and dispose the result afterwards.
        /// </summary>
        /// <typeparam name="T">The underlying result type.</typeparam>
        /// <typeparam name="S">The result of the function.</typeparam>
        /// <param name="result">The result.</param>
        /// <param name="func">The function to call.</param>
        /// <returns>The result of func.</returns>
        public static S RunAndDispose<T, S>(this T result, Func<T, S> func) where T : NtObject
        {
            using (result)
            {
                return func(result);
            }
        }

        /// <summary>
        /// Run an action on an NtResult and dispose the result afterwards.
        /// </summary>
        /// <typeparam name="T">The underlying result type.</typeparam>
        /// <param name="result">The result.</param>
        /// <param name="action">The action to call.</param>
        public static void RunAndDispose<T>(this T result, Action<T> action) where T : NtObject
        {
            using (result)
            {
                action(result);
            }
        }

        // A special "fake" status code to map DOS errors to NTSTATUS.
        private const uint DosErrorStatusCode = 0xF00D0000;

        internal static NtStatus MapDosErrorToStatus(int dos_error)
        {
            return (NtStatus)(DosErrorStatusCode | dos_error);
        }

        internal static NtStatus MapDosErrorToStatus()
        {
            return MapDosErrorToStatus(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Map a status to a DOS error code. Takes into account the fake
        /// status codes.
        /// </summary>
        /// <param name="status">The status code.</param>
        /// <returns>The mapped DOS error.</returns>
        public static int MapNtStatusToDosError(NtStatus status)
        {
            uint value = (uint)status;
            if ((value & 0xFFFF0000) == DosErrorStatusCode)
            {
                return (int)(value & 0xFFFF);
            }
            return NtRtl.RtlNtStatusToDosError(status);
        }

        /// <summary>
        /// Create an NT result object. If status is successful then call function otherwise use default value.
        /// </summary>
        /// <typeparam name="T">The result type.</typeparam>
        /// <param name="status">The associated status case.</param>
        /// <param name="throw_on_error">Throw an exception on error.</param>
        /// <param name="create_func">Function to call to create an instance of the result</param>
        /// <returns>The created result.</returns>
        internal static NtResult<T> CreateResult<T>(this NtStatus status, bool throw_on_error, Func<T> create_func)
        {
            return CreateResult(status, throw_on_error, s => create_func());
        }

        /// <summary>
        /// Create a successful NT result object.
        /// </summary>
        /// <typeparam name="T">The result type.</typeparam>
        /// <param name="result">The result value.</param>
        /// <returns>The created result.</returns>
        internal static NtResult<T> CreateResult<T>(this T result)
        {
            return new NtResult<T>(NtStatus.STATUS_SUCCESS, result);
        }

        /// <summary>
        /// Create an NT result object. If status is successful then call function otherwise use default value.
        /// </summary>
        /// <typeparam name="T">The result type.</typeparam>
        /// <param name="status">The associated status case.</param>
        /// <param name="throw_on_error">Throw an exception on error.</param>
        /// <param name="create_func">Function to call to create an instance of the result</param>
        /// <param name="error_func">Function to call on error.</param>
        /// <returns>The created result.</returns>
        internal static NtResult<T> CreateResult<T>(this NtStatus status, bool throw_on_error, Func<NtStatus, T> create_func, Action<NtStatus> error_func)
        {
            if (status.IsSuccess())
            {
                return new NtResult<T>(status, create_func(status));
            }

            error_func?.Invoke(status);
            if (throw_on_error)
            {
                throw new NtException(status);
            }

            return new NtResult<T>(status, default(T));
        }

        /// <summary>
        /// Create an NT result object. If status is successful then call function otherwise use default value.
        /// </summary>
        /// <typeparam name="T">The result type.</typeparam>
        /// <param name="status">The associated status case.</param>
        /// <param name="throw_on_error">Throw an exception on error.</param>
        /// <param name="create_func">Function to call to create an instance of the result</param>
        /// <returns>The created result.</returns>
        internal static NtResult<T> CreateResult<T>(this NtStatus status, bool throw_on_error, Func<NtStatus, T> create_func)
        {
            return CreateResult(status, throw_on_error, create_func, null);
        }

        internal static NtResult<T> CreateResultFromError<T>(this NtStatus status, bool throw_on_error)
        {
            if (throw_on_error)
            {
                throw new NtException(status);
            }

            return new NtResult<T>(status, default(T));
        }

        internal static NtResult<T> CreateResultFromDosError<T>(int error, bool throw_on_error)
        {
            NtStatus status = MapDosErrorToStatus(error);
            if (throw_on_error)
            {
                throw new NtException(status);
            }

            return new NtResult<T>(status, default(T));
        }

        internal static IEnumerable<T> SelectValidResults<T>(this IEnumerable<NtResult<T>> iterator)
        {
            return iterator.Where(r => r.IsSuccess).Select(r => r.Result);
        }

        internal static SafeKernelObjectHandle ToSafeKernelHandle(this SafeHandle handle)
        {
            if (handle is SafeKernelObjectHandle)
            {
                return (SafeKernelObjectHandle)handle;
            }
            return new SafeKernelObjectHandle(handle.DangerousGetHandle(), false);
        }

        internal static IEnumerable<T> ToCached<T>(this IEnumerable<T> enumerable)
        {
            return new CachedEnumerable<T>(enumerable);
        }

        internal static bool IsWindows7OrLess
        {
            get
            {
                return Environment.OSVersion.Version < new Version(6, 2);
            }
        }

        internal static bool IsWindows8OrLess
        {
            get
            {
                return Environment.OSVersion.Version < new Version(6, 3);
            }
        }

        internal static bool IsWindows81OrLess
        {
            get
            {
                return Environment.OSVersion.Version < new Version(6, 4);
            }
        }

        internal static string GetFileName(string full_path)
        {
            string name = full_path;
            if (name == @"\")
            {
                return string.Empty;
            }

            int index = name.LastIndexOf('\\');
            if (index >= 0)
            {
                return name.Substring(index + 1);
            }
            return name;
        }

        internal static SafeKernelObjectHandle GetHandle(this NtObject obj)
        {
            return obj?.Handle ?? SafeKernelObjectHandle.Null;
        }

        internal static UnicodeString ToUnicodeString(this string str)
        {
            return str != null ? new UnicodeString(str) : null;
        }

        internal static OptionalGuid ToOptional(this Guid? guid)
        {
            return guid.HasValue ? new OptionalGuid(guid.Value) : null;
        }

        internal static LargeInteger ToLargeInteger(this long? l)
        {
            return l.HasValue ? new LargeInteger(l.Value) : null;
        }

        internal static LargeInteger ToLargeInteger(this NtWaitTimeout timeout)
        {
            return ToLargeInteger(timeout?.Timeout);
        }
    }
}
