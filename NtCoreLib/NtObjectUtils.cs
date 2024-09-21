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

using NtCoreLib.Kernel.Interop;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Utilities.Reflection;
using NtCoreLib.Win32;
using NtCoreLib.Win32.Loader;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NtCoreLib;

/// <summary>
/// Static utility methods.
/// </summary>
public static class NtObjectUtils
{
    internal static byte[] ReadAllBytes(this BinaryReader reader, int length)
    {
        byte[] ret = reader.ReadBytes(length);
        if (ret.Length != length)
        {
            throw new EndOfStreamException();
        }
        return ret;
    }

    internal static string ReadNulTerminated(this BinaryReader reader)
    {
        StringBuilder builder = new();

        while (true)
        {
            char c = reader.ReadChar();
            if (c == 0)
            {
                break;
            }
            builder.Append(c);
        }
        return builder.ToString();
    }

    internal static void WriteNulTerminated(this BinaryWriter writer, string str)
    {
        writer.Write(Encoding.Unicode.GetBytes(str + "\0"));
    }

    internal static byte[] ReadToEnd(this BinaryReader reader)
    {
        return reader.ReadBytes((int)reader.RemainingLength());
    }

    internal static long RemainingLength(this Stream stm)
    {
        return stm.Length - stm.Position;
    }

    internal static long RemainingLength(this BinaryReader reader)
    {
        return reader.BaseStream.RemainingLength();
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
    /// Checks if the NtStatus value is an error.
    /// </summary>
    /// <param name="status">The NtStatus value</param>
    /// <returns>True if an error.</returns>
    public static bool IsError(this NtStatus status)
    {
        return status.GetSeverity() == NtStatusSeverity.STATUS_SEVERITY_ERROR;
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
        if (!IsWindows)
            return string.Empty;

        SafeLoadLibraryHandle module;
        uint message_id = (uint)status;
        NtStatusFacility facility = status.GetFacility();
        if (facility == NtStatusFacility.FACILITY_NTWIN32 ||
            facility == NtStatusFacility.FACILITY_VISUALCPP)
        {
            module = SafeLoadLibraryHandle.GetModuleHandleNoThrow("kernel32.dll");
            message_id = (uint)status.GetStatusCode();
        }
        else
        {
            module = SafeLoadLibraryHandle.GetModuleHandleNoThrow("ntdll.dll");
        }

        return module?.FormatMessage(message_id) ?? string.Empty;
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

    internal static bool GetBit(this ushort result, int bit)
    {
        return GetBit((int)result, bit);
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

    internal static string ToHexString(this byte[] ba)
    {
        return BitConverter.ToString(ba).Replace("-", string.Empty);
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
        return RunAndDispose(result, func, default);
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

    /// <summary>
    /// Map a DOS error to an NT status code.
    /// </summary>
    /// <param name="dos_error">The DOS error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus MapDosErrorToStatus(this Win32Error dos_error)
    {
        return MapDosErrorToStatus((int)dos_error);
    }

    internal static NtStatus MapDosErrorToStatus(int dos_error)
    {
        if (dos_error == 0)
        {
            return NtStatus.STATUS_SUCCESS;
        }
        else if (dos_error < 0 || dos_error > 0xFFFF)
        {
            return (NtStatus)dos_error;
        }
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
    public static Win32Error MapNtStatusToDosError(this NtStatus status)
    {
        if (status.GetFacility() == NtStatusFacility.FACILITY_NTWIN32)
        {
            return (Win32Error)status.GetStatusCode();
        }

        if (!IsWindows)
            return (Win32Error)(-1);

        return (Win32Error)NtRtl.RtlNtStatusToDosErrorNoTeb(status);
    }

    /// <summary>
    /// Get the last NT status code in this thread set for Win32 last error.
    /// </summary>
    /// <returns>The last NT status code.</returns>
    public static NtStatus GetLastNtStatus()
    {
        return NtRtl.RtlGetLastNtStatus();
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

        return new NtResult<T>(status, default);
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

        return new NtResult<T>(status, default);
    }

    internal static IEnumerable<T> SelectValidResults<T>(this IEnumerable<NtResult<T>> iterator)
    {
        return iterator.Where(r => r.IsSuccess).Select(r => r.Result);
    }

    internal static bool IsWindows7OrLess => NtSystemInfo.OSVersion.Version < new Version(6, 2);

    internal static bool IsWindows8OrLess => NtSystemInfo.OSVersion.Version < new Version(6, 3);

    internal static bool IsWindows81OrLess => NtSystemInfo.OSVersion.Version < new Version(6, 4);

    internal static SupportedVersion SupportedVersion => _supported_version.Value;

    private static readonly Lazy<string> _assembly_version = new(() =>
    {
        Assembly asm = Assembly.GetCallingAssembly();
        return asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion;
    });

    private static readonly Lazy<SupportedVersion> _supported_version = new(() =>
    {
        if (IsWindows7OrLess)
            return SupportedVersion.Windows7;
        if (IsWindows8OrLess)
            return SupportedVersion.Windows8;
        if (IsWindows81OrLess)
            return SupportedVersion.Windows81;
        Version ver = NtSystemInfo.OSVersion.Version;
        if (ver.Major != 10)
        {
            return SupportedVersion.Unknown;
        }

        if (ver.Build <= 10240)
        {
            return SupportedVersion.Windows10;
        }
        else if (ver.Build <= 10586)
        {
            return SupportedVersion.Windows10_TH2;
        }
        else if (ver.Build <= 14393)
        {
            return SupportedVersion.Windows10_RS1;
        }
        else if (ver.Build <= 15063)
        {
            return SupportedVersion.Windows10_RS2;
        }
        else if (ver.Build <= 16299)
        {
            return SupportedVersion.Windows10_RS3;
        }
        else if (ver.Build <= 17134)
        {
            return SupportedVersion.Windows10_RS4;
        }
        else if (ver.Build <= 17763)
        {
            return SupportedVersion.Windows10_RS5;
        }
        else if (ver.Build <= 18362)
        {
            return SupportedVersion.Windows10_19H1;
        }
        else if (ver.Build <= 18363)
        {
            return SupportedVersion.Windows10_19H2;
        }
        else if (ver.Build <= 19041)
        {
            return SupportedVersion.Windows10_20H1;
        }
        else if (ver.Build <= 19042)
        {
            return SupportedVersion.Windows10_20H2;
        }
        else if (ver.Build <= 19043)
        {
            return SupportedVersion.Windows10_21H1;
        }
        else if (ver.Build <= 19044)
        {
            return SupportedVersion.Windows10_21H2;
        }
        else if (ver.Build <= 19045)
        {
            return SupportedVersion.Windows10_22H2;
        }
        else if (ver.Build <= 22000)
        {
            return SupportedVersion.Windows11;
        }
        else if (ver.Build <= 22621)
        {
            return SupportedVersion.Windows11_22H2;
        }
        else
        {
            return SupportedVersion.Windows_Latest;
        }
    });

    internal static string GetVersion()
    {
        return _assembly_version.Value;
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

    internal static Version UnpackVersion(ulong version)
    {
        ushort[] parts = new ushort[4];
        ulong[] original = new ulong[] { version };

        Buffer.BlockCopy(original, 0, parts, 0, sizeof(ulong));

        return new Version(parts[3], parts[2], parts[1], parts[0]);
    }

    internal static ulong PackVersion(Version version)
    {
        ushort[] parts = new ushort[4] { (ushort)version.Revision, (ushort)version.Build, (ushort)version.Minor, (ushort)version.Major };
        ulong[] original = new ulong[1];

        Buffer.BlockCopy(parts, 0, original, 0, sizeof(ulong));

        return original[0];
    }

    internal static bool HasFlagSet<T>(this T value, T bit) where T : Enum
    {
        return (((IConvertible)value).ToInt64(null) & ((IConvertible)bit).ToInt64(null)) != 0;
    }

    internal static bool HasFlagAllSet<T>(this T value, T bit) where T : Enum
    {
        return value.HasFlag(bit);
    }

    internal static bool EqualByteArray(byte[] a, byte[] b)
    {
        if (a == b)
            return true;
        if (a == null || b == null)
            return false;
        if (a.Length != b.Length)
            return false;
        for (int i = 0; i < a.Length; ++i)
        {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

    internal static bool EqualByteArray(byte[] a, byte[] b, int max_length)
    {
        if (a == b)
            return true;
        if (a == null || b == null)
            return false;
        if (a.Length < max_length || b.Length < max_length)
            return false;
        for (int i = 0; i < max_length; ++i)
        {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

    internal static int GetHashCodeByteArray(byte[] a)
    {
        if (a == null || a.Length == 0)
            return 0;
        return a.Aggregate((v, c) => (byte)(v ^ c));
    }

    internal static T[] Slice<T>(this T[] arr, int offset, int count)
    {
        return new ArraySegment<T>(arr, offset, count).ToArray();
    }

    internal static LargeIntegerStruct ToLargeIntegerStruct(this DateTime time)
    {
        if (time == DateTime.MinValue)
            return new LargeIntegerStruct();
        return new LargeIntegerStruct() { QuadPart = time.ToFileTime() };
    }

    internal static string[] ParseMultiString(byte[] data)
    {
        return Encoding.Unicode.GetString(data).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
    }

    internal static bool IsWindows => Environment.OSVersion.Platform == PlatformID.Win32NT;

    internal static bool IsEmpty<T>(this IEnumerable<T> e)
    {
        if (e == null)
            return true;
        return !e.Any();
    }

    internal static byte[] CloneBytes(this byte[] ba)
    {
        return (byte[])ba?.Clone();
    }
}
