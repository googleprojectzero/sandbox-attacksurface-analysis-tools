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
using NtApiDotNet.Win32;
using System.Threading.Tasks;

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

        /// <summary>
        /// Get the severity of the NTSTATUS.
        /// </summary>
        /// <param name="status">The NtStatus value</param>
        /// <returns>The severity.</returns>
        public static NtStatusSeverity GetSeverity(this NtStatus status)
        {
            return (NtStatusSeverity)((uint)status >> 30);
        }

        /// <summary>
        /// Get the facility of the NTSTATUS.
        /// </summary>
        /// <param name="status">The NtStatus value</param>
        /// <returns>The facility.</returns>
        public static NtStatusFacility GetFacility(this NtStatus status)
        {
            return (NtStatusFacility)(((uint)status >> 16) & 0xFFF);
        }

        /// <summary>
        /// Get the status code of the NTSTATUS.
        /// </summary>
        /// <param name="status">The NtStatus value.</param>
        /// <returns>The static code.</returns>
        public static int GetStatusCode(this NtStatus status)
        {
            return (int)((uint)status & 0xFFFF);
        }

        /// <summary>
        /// Is an NTSTATUS a customer code.
        /// </summary>
        /// <param name="status">The NtStatus value</param>
        /// <returns>True if is a customer code.</returns>
        public static bool IsCustomerCode(this NtStatus status)
        {
            return (((uint)status >> 29) & 1) != 0;
        }

        /// <summary>
        /// Is an NTSTATUS reserved.
        /// </summary>
        /// <param name="status">The NtStatus value</param>
        /// <returns>True if reserved.</returns>
        public static bool IsReserved(this NtStatus status)
        {
            return (((uint)status >> 28) & 1) != 0;
        }

        /// <summary>
        /// Build a status from it's component parts.
        /// </summary>
        /// <param name="severity">The severity of the status code.</param>
        /// <param name="is_customer_code">Is this a customer code?</param>
        /// <param name="is_reserved">Is this a reserved code?</param>
        /// <param name="facility">The facility.</param>
        /// <param name="code">The status code.</param>
        /// <returns></returns>
        public static NtStatus BuildStatus(NtStatusSeverity severity, bool is_customer_code, 
            bool is_reserved, NtStatusFacility facility, int code)
        {
            uint status = (uint)code |
                ((uint)facility << 16) |
                (is_reserved ? (1U << 28) : 0U) |
                (is_customer_code ? (1U << 29) : 0U) |
                ((uint)severity << 30);
            return (NtStatus)status;
        }

        /// <summary>
        /// Convert an NTSTATUS to a message description.
        /// </summary>
        /// <param name="status">The status to convert.</param>
        /// <returns>The message description, or an empty string if not found.</returns>
        public static string GetNtStatusMessage(NtStatus status)
        {
            SafeLoadLibraryHandle module = SafeLoadLibraryHandle.Null;
            uint message_id = (uint)status;
            if (status.GetFacility() == NtStatusFacility.FACILITY_NTWIN32)
            {
                module = SafeLoadLibraryHandle.GetModuleHandleNoThrow("kernel32.dll");
                message_id = (uint)status.GetStatusCode();
            }
            else
            {
                module = SafeLoadLibraryHandle.GetModuleHandleNoThrow("ntdll.dll");
            }

            return Win32Utils.FormatMessage(module, message_id);
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

            return AccessRightsToString(enum_type, mapped_access);
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
        /// <param name="default_value">The default value to return if an error occurred.</param>
        /// <returns>The result of func.</returns>
        /// <remarks>If result is not a success then the function is not called.</remarks>
        public static S RunAndDispose<T, S>(this NtResult<T> result, Func<T, S> func, S default_value) where T : NtObject
        {
            using (result)
            {
                if (!result.IsSuccess)
                {
                    return default_value;
                }
                return func(result.Result);
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
        /// <remarks>If result is not a success then the function is not called.</remarks>
        public static S RunAndDispose<T, S>(this NtResult<T> result, Func<T, S> func) where T : NtObject
        {
            return RunAndDispose(result, func, default(S));
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

        /// <summary>
        /// Convert a handle to a known object type.
        /// </summary>
        /// <param name="handle">The handle.</param>
        /// <returns>The object type.</returns>
        public static NtObject FromHandle(SafeKernelObjectHandle handle)
        {
            return NtType.GetTypeByName(handle.NtTypeName, true).FromHandle(handle);
        }

        /// <summary>
        /// Convert a handle to a known object type.
        /// </summary>
        /// <param name="handle">The handle.</param>
        /// <param name="owns_handle">True to own the handle.</param>
        /// <returns>The object type.</returns>
        public static NtObject FromHandle(IntPtr handle, bool owns_handle)
        {
            return FromHandle(new SafeKernelObjectHandle(handle, owns_handle));
        }

        /// <summary>
        /// Convert a handle to a known object type.
        /// </summary>
        /// <param name="handle">The handle.</param>
        /// <param name="owns_handle">True to own the handle.</param>
        /// <returns>The object type.</returns>
        public static NtObject FromHandle(int handle, bool owns_handle)
        {
            return FromHandle(new IntPtr(handle), owns_handle);
        }

        internal static NtStatus MapDosErrorToStatus(this Win32Error dos_error)
        {
            return MapDosErrorToStatus((int)dos_error);
        }

        internal static void ToNtException(this Win32Error dos_error)
        {
            ToNtException(MapDosErrorToStatus((int)dos_error));
        }

        internal static NtStatus MapDosErrorToStatus(int dos_error)
        {
            return BuildStatus(NtStatusSeverity.STATUS_SEVERITY_WARNING, false, false, 
                NtStatusFacility.FACILITY_NTWIN32, dos_error);
        }

        internal static NtStatus MapDosErrorToStatus()
        {
            return MapDosErrorToStatus(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Map a status to a DOS error code. Takes into account NTWIN32
        /// status codes.
        /// </summary>
        /// <param name="status">The status code.</param>
        /// <returns>The mapped DOS error.</returns>
        public static int MapNtStatusToDosError(NtStatus status)
        {
            if (status.GetFacility() == NtStatusFacility.FACILITY_NTWIN32)
            {
                return status.GetStatusCode();
            }
            return NtRtl.RtlNtStatusToDosError(status);
        }

        /// <summary>
        /// Create an NT result object. If status is successful then call function otherwise use default value.
        /// </summary>
        /// <typeparam name="T">The result type.</typeparam>
        /// <param name="status">The associated status code.</param>
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
        /// <param name="status">The associated status code.</param>
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
        /// <param name="status">The associated status code.</param>
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

        internal static NtResult<T> CreateResultFromDosError<T>(this Win32Error error, bool throw_on_error)
        {
            NtStatus status = MapDosErrorToStatus(error);
            if (throw_on_error)
            {
                throw new NtException(status);
            }

            return new NtResult<T>(status, default(T));
        }

        internal static NtResult<T> CreateResultFromDosError<T>(int error, bool throw_on_error)
        {
            return CreateResultFromDosError<T>((Win32Error)error, throw_on_error);
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
            return timeout?.Timeout;
        }

        internal static int GetLength(this SafeBuffer buffer)
        {
            return (int)buffer.ByteLength;
        }

        internal static OptionalInt32 GetOptionalInt32(this SafeBuffer buffer)
        {
            if (buffer == null || buffer.IsInvalid)
            {
                return null;
            }
            return new OptionalInt32(buffer.GetLength());
        }

        internal static OptionalLength GetOptionalLength(this SafeBuffer buffer)
        {
            if (buffer == null || buffer.IsInvalid)
            {
                return null;
            }
            return new OptionalLength(buffer.GetLength());
        }

        internal static async Task<T> UnwrapNtResultAsync<T>(this Task<NtResult<T>> task)
        {
            var result = await task;
            return result.Result;
        }

        internal static async Task<NtStatus> UnwrapNtStatusAsync<T>(this Task<NtResult<T>> task)
        {
            var result = await task;
            return result.Status;
        }

        internal static async Task<NtResult<S>> MapAsync<T, S>(this Task<NtResult<T>> task, Func<T, S> map)
        {
            var result = await task;
            return result.Map(map);
        }
    }
}
