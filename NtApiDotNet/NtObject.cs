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
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Generic access rights.
    /// </summary>
    [Flags]
    public enum GenericAccessRights : uint
    {
        None = 0,
        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000,
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        MaximumAllowed = 0x02000000,
        AccessSystemSecurity = 0x01000000
    };

    /// <summary>
    /// Options for duplicating objects.
    /// </summary>
    [Flags]
    public enum DuplicateObjectOptions
    {
        None = 0,
        /// <summary>
        /// Close the original handle.
        /// </summary>
        CloseSource = 1,
        /// <summary>
        /// Duplicate with the same access.
        /// </summary>
        SameAccess = 2,
        /// <summary>
        /// Duplicate with the same handle attributes.
        /// </summary>
        SameAttributes = 4,
    }

    /// <summary>
    /// Information class for NtQueryObject
    /// </summary>
    /// <see cref="NtSystemCalls.NtQueryObject(SafeHandle, ObjectInformationClass, IntPtr, int, out int)"/>
    public enum ObjectInformationClass
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectAllInformation,
        ObjectDataInformation
    }

    /// <summary>
    /// Structure to return Object Name
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class ObjectNameInformation
    {
        public UnicodeStringOut Name;
    }

    /// <summary>
    /// Structure to return Object basic information
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectBasicInformation
    {
        public int Attributes;
        public uint DesiredAccess;
        public int HandleCount;
        public int ReferenceCount;
        public int PagedPoolUsage;
        public int NonPagedPoolUsage;
        public int Reserved0;
        public int Reserved1;
        public int Reserved2;
        public int NameInformationLength;
        public int TypeInformationLength;
        public int SecurityDescriptorLength;
        public LargeIntegerStruct CreationTime;
    }

    /// <summary>
    /// Type of kernel pool used for object allocation
    /// </summary>
    public enum PoolType
    {
        NonPagedPool,
        PagedPool,
        NonPagedPoolMustSucceed,
        DontUseThisType,
        NonPagedPoolCacheAligned,
        PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtClose(IntPtr handle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDuplicateObject(
          SafeHandle SourceProcessHandle,
          SafeHandle SourceHandle,
          SafeHandle TargetProcessHandle,
          out SafeKernelObjectHandle TargetHandle,
          GenericAccessRights DesiredAccess,
          AttributeFlags HandleAttributes,
          DuplicateObjectOptions Options
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryObject(
		    SafeHandle ObjectHandle,
            ObjectInformationClass ObjectInformationClass,
		    IntPtr ObjectInformation,
            int ObjectInformationLength,
		    out int ReturnLength
		);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySecurityObject(
            SafeHandle Handle,
            SecurityInformation SecurityInformation,
            [Out] byte[] SecurityDescriptor,
            int SecurityDescriptorLength,
            out int ReturnLength
            );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetSecurityObject(
            SafeHandle Handle,
            SecurityInformation SecurityInformation,
            [In] byte[] SecurityDescriptor
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMakeTemporaryObject(SafeKernelObjectHandle Handle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMakePermanentObject(SafeKernelObjectHandle Handle);
    }
#pragma warning restore 1591

    /// <summary>
    /// Base class for all NtObject types we handle
    /// </summary>
    public abstract class NtObject : IDisposable
    {
        /// <summary>
        /// Base constructor
        /// </summary>
        /// <param name="handle">Handle to the object</param>
        protected NtObject(SafeKernelObjectHandle handle)
        {
            Handle = handle;
            try
            {
                CanSynchronize = IsAccessGrantedRaw<GenericAccessRights>(GenericAccessRights.Synchronize);
            }
            catch (NtException)
            {
                // Shouldn't fail but just in case.
            }
        }

        private static SafeStructureInOutBuffer<T> QueryObject<T>(SafeKernelObjectHandle handle, ObjectInformationClass object_info) where T : new()
        {
            SafeStructureInOutBuffer<T> ret = null;
            NtStatus status = NtStatus.STATUS_BUFFER_TOO_SMALL;
            try
            {
                int return_length;
                status = NtSystemCalls.NtQueryObject(handle, object_info, IntPtr.Zero, 0, out return_length);
                if ((status != NtStatus.STATUS_BUFFER_TOO_SMALL) && (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH))
                    status.ToNtException();
                if (return_length == 0)
                    ret = new SafeStructureInOutBuffer<T>();
                else
                    ret = new SafeStructureInOutBuffer<T>(return_length, false);
                status = NtSystemCalls.NtQueryObject(handle, object_info, ret.DangerousGetHandle(), ret.Length, out return_length);
                status.ToNtException();
            }
            finally
            {
                if (ret != null && !status.IsSuccess())
                {
                    ret.Close();
                    ret = null;
                }
            }
            return ret;
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="options">Duplicate handle options</param>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <returns>The new duplicated handle.</returns>
        public SafeKernelObjectHandle DuplicateHandle(NtProcess dest_process, uint access_rights, DuplicateObjectOptions options)
        {
            SafeKernelObjectHandle new_handle;

            NtSystemCalls.NtDuplicateObject(NtProcess.Current.Handle, Handle,
              dest_process.Handle, out new_handle, (GenericAccessRights)access_rights, AttributeFlags.None, 
              options).ToNtException();

            return new_handle;
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle with the same access rights.
        /// </summary>
        /// <returns>The new duplicated handle.</returns>
        public SafeKernelObjectHandle DuplicateHandle()
        {
            return DuplicateHandle(NtProcess.Current, 0, DuplicateObjectOptions.SameAccess);
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <returns>The new duplicated handle.</returns>
        public SafeKernelObjectHandle DuplicateHandle(uint access_rights)
        {
            return DuplicateHandle(NtProcess.Current, access_rights, DuplicateObjectOptions.None);
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <returns>The new duplicated handle.</returns>
        public SafeKernelObjectHandle DuplicateHandle(GenericAccessRights access_rights)
        {
            return DuplicateHandle((uint)access_rights);
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="source_process">The source process for the handle</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="handle">The handle in the source process to duplicate</param>
        /// <param name="options">Duplicate handle options</param>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <returns>The new duplicated handle.</returns>
        public static SafeKernelObjectHandle DuplicateHandle(NtProcess source_process, SafeHandle handle, NtProcess dest_process, GenericAccessRights access_rights, DuplicateObjectOptions options)
        {
            SafeKernelObjectHandle new_handle;

            NtSystemCalls.NtDuplicateObject(source_process.Handle, handle,
              dest_process.Handle, out new_handle,
              GenericAccessRights.None, AttributeFlags.None, 
              DuplicateObjectOptions.SameAccess).ToNtException();

            return new_handle;
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="source_process">The source process for the handle</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="handle">The handle in the source process to duplicate</param>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <returns>The new duplicated handle.</returns>
        public static SafeKernelObjectHandle DuplicateHandle(NtProcess source_process, SafeHandle handle, NtProcess dest_process, GenericAccessRights access_rights)
        {
            return DuplicateHandle(source_process, handle, dest_process, access_rights, DuplicateObjectOptions.None);
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="source_process">The source process for the handle</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="handle">The handle in the source process to duplicate</param>
        /// <returns>The new duplicated handle.</returns>
        public static SafeKernelObjectHandle DuplicateHandle(NtProcess source_process, SafeHandle handle, NtProcess dest_process)
        {
            return DuplicateHandle(source_process, handle, dest_process, GenericAccessRights.None, DuplicateObjectOptions.SameAccess);
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="handle">The handle in the source process to duplicate</param>
        /// <returns>The new duplicated handle.</returns>
        public static SafeKernelObjectHandle DuplicateHandle(SafeHandle handle)
        {
            return DuplicateHandle(NtProcess.Current, handle, NtProcess.Current);
        }

        private static string GetName(SafeKernelObjectHandle handle)
        {
            try
            {
                // TODO: Might need to do this async for file objects, they have a habit of sticking.
                using (var name = QueryObject<ObjectNameInformation>(handle, ObjectInformationClass.ObjectNameInformation))
                {
                    return name.Result.Name.ToString();
                }
            }
            catch
            {
                return String.Empty;
            }
        }

        /// <summary>
        /// Duplicate the object handle as a WaitHandle.
        /// </summary>
        /// <returns>The wait handle.</returns>
        public NtWaitHandle DuplicateAsWaitHandle()
        {
            return new NtWaitHandle(this);
        }

        /// <summary>
        /// Get full path to the object
        /// </summary>
        public virtual string FullPath
        {
            get
            {
                return GetName(Handle);
            }
        }

        private ObjectBasicInformation? _basic_info;

        /// <summary>
        /// Get the basic information for the object.
        /// </summary>
        /// <returns>The basic information</returns>
        private ObjectBasicInformation QueryBasicInformation()
        {
            if (!_basic_info.HasValue)
            {
                try
                {
                    using (var basic_info = QueryObject<ObjectBasicInformation>(Handle, ObjectInformationClass.ObjectBasicInformation))
                    {
                        _basic_info = basic_info.Result;
                    }
                }
                catch
                {
                    _basic_info = new ObjectBasicInformation();
                }
            }
            return _basic_info.Value;
        }

        /// <summary>
        /// Get the granted access as an unsigned integer
        /// </summary>
        public uint GrantedAccessRaw
        {
            get
            {
                return QueryBasicInformation().DesiredAccess;
            }
        }

        /// <summary>
        /// Get the granted access as an object
        /// </summary>
        public virtual object GrantedAccessObject
        {
            get
            {
                return GrantedAccessRaw;
            }
        }

        /// <summary>
        /// Check if access is granted to a set of rights
        /// </summary>
        /// <typeparam name="T">The type of enumeration for the access rights</typeparam>
        /// <param name="access">The access rights to check</param>
        /// <returns>True if all the access rights are granted</returns>
        public bool IsAccessGrantedRaw<T>(T access) where T : IConvertible
        {
            uint granted = GrantedAccessRaw;
            uint required = access.ToUInt32(null);
            return (granted & required) == required;
        }

        /// <summary>
        /// Get security descriptor as a byte array
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public byte[] GetSecurityDescriptorBytes(SecurityInformation security_information)
        {
            int return_length;
            NtStatus status = NtSystemCalls.NtQuerySecurityObject(Handle, security_information, null, 0, out return_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                status.ToNtException();
            byte[] buffer = new byte[return_length];
            NtSystemCalls.NtQuerySecurityObject(Handle, security_information, buffer, buffer.Length, out return_length).ToNtException();
            return buffer;
        }

        /// <summary>
        /// Get security descriptor as a byte array
        /// </summary>
        /// <returns>Returns an array of bytes for the security descriptor</returns>
        public byte[] GetSecurityDescriptorBytes()
        {
            return GetSecurityDescriptorBytes(SecurityInformation.AllBasic);
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_desc">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        public void SetSecurityDescriptor(byte[] security_desc, SecurityInformation security_information)
        {
            NtSystemCalls.NtSetSecurityObject(Handle, security_information, security_desc).ToNtException();
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_desc">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_desc, SecurityInformation security_information)
        {
            SetSecurityDescriptor(security_desc.ToByteArray(), security_information);
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
        {
            return new SecurityDescriptor(GetSecurityDescriptorBytes(security_information));
        }

        /// <summary>
        /// Get the security descriptor, with Dacl, Owner, Group and Label
        /// </summary>
        public SecurityDescriptor SecurityDescriptor
        {
            get
            {
                return GetSecurityDescriptor(SecurityInformation.AllBasic);
            }
        }

        /// <summary>
        /// Get the security descriptor as an SDDL string
        /// </summary>
        /// <returns>The security descriptor as an SDDL string</returns>
        public string GetSddl()
        {
            return SecurityDescriptor.ToSddl();
        }

        /// <summary>
        /// Get the security descriptor as an SDDL string
        /// </summary>
        /// <returns>The security descriptor as an SDDL string</returns>
        public string Sddl
        {
            get { return GetSddl(); }
        }

        /// <summary>
        /// The low-level handle to the object.
        /// </summary>
        public SafeKernelObjectHandle Handle { get; private set; }

        /// <summary>
        /// Make the object a temporary object
        /// </summary>
        public void MakeTemporary()
        {
            NtSystemCalls.NtMakeTemporaryObject(Handle).ToNtException();
        }

        /// <summary>
        /// Make the object a permanent object
        /// </summary>
        public void MakePermanent()
        {
           NtSystemCalls.NtMakePermanentObject(Handle).ToNtException();
        }

        /// <summary>
        /// Wait on the object to become signalled
        /// </summary>
        /// <param name="alertable">True to make the wait alertable</param>
        /// <param name="timeout">The time out</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait(bool alertable, NtWaitTimeout timeout)
        {
            return NtWait.Wait(this, alertable, timeout);
        }

        /// <summary>
        /// Wait on the object to become signalled
        /// </summary>
        /// <param name="timeout">The time out</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait(NtWaitTimeout timeout)
        {
            return Wait(false, timeout);
        }

        /// <summary>
        /// Wait on the object to become signalled
        /// </summary>
        /// <param name="alertable">True to make the wait alertable</param>
        /// <param name="timeout_sec">The time out in seconds</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait(bool alertable, int timeout_sec)
        {
            return Wait(alertable, NtWaitTimeout.FromSeconds(timeout_sec));
        }

        /// <summary>
        /// Wait on the object to become signalled
        /// </summary>
        /// <param name="timeout_sec">The time out in seconds</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait(int timeout_sec)
        {
            return Wait(false, timeout_sec);
        }

        /// <summary>
        /// Wait on the object to become signalled for an infinite time.
        /// </summary>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait()
        {
            return Wait(false, NtWaitTimeout.Infinite);
        }

        /// <summary>
        /// Indicates whether a specific type of kernel object can be opened.
        /// </summary>
        /// <param name="typename">The kernel typename to check.</param>
        /// <returns>True if this type of object can be opened.</returns>
        /// <see cref="OpenWithType(string, string, NtObject, GenericAccessRights)"/>
        public static bool CanOpenType(string typename)
        {
            switch (typename.ToLower())
            {
                case "device":
                case "file":
                case "event":
                case "directory":
                case "symboliclink":
                case "mutant":
                case "semaphore":
                case "section":
                case "job":
                case "key":
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Open an NT object with a specified type.
        /// </summary>
        /// <param name="typename">The name of the type to open (e.g. Event). If null the method will try and lookup the appropriate type.</param>
        /// <param name="path">The path to the object to open.</param>
        /// <param name="root">A root directory to open from.</param>
        /// <param name="access">Generic access rights to the object.</param>
        /// <returns>The opened object.</returns>
        /// <exception cref="NtException">Thrown if an error occurred opening the object.</exception>
        /// <exception cref="ArgumentException">Thrown if type of resource couldn't be found.</exception>
        public static NtObject OpenWithType(string typename, string path, NtObject root, GenericAccessRights access)
        {
            if (typename == null)
            {
                typename = NtDirectory.GetDirectoryEntryType(path, root);
                if (typename == null)
                {
                    throw new ArgumentException(String.Format("Can't find type for path {0}", path));
                }
            }

            switch (typename.ToLower())
            {
                case "device":
                    return NtFile.Open(path, root, (FileAccessRights)access, FileShareMode.None, FileOpenOptions.None);
                case "file":
                    return NtFile.Open(path, root, (FileAccessRights)access, FileShareMode.Read | FileShareMode.Write | FileShareMode.Delete, FileOpenOptions.None);
                case "event":
                    return NtEvent.Open(path, root, (EventAccessRights)access);
                case "directory":
                    return NtDirectory.Open(path, root, (DirectoryAccessRights)access);
                case "symboliclink":
                    return NtSymbolicLink.Open(path, root, (SymbolicLinkAccessRights)access);
                case "mutant":
                    return NtMutant.Open(path, root, (MutantAccessRights)access);
                case "semaphore":
                    return NtSemaphore.Open(path, root, (SemaphoreAccessRights)access);
                case "section":
                    return NtSection.Open(path, root, (SectionAccessRights)access);
                case "job":
                    return NtJob.Open(path, root, (JobAccessRights)access);
                case "key":
                    return NtKey.Open(path, root, (KeyAccessRights)access);
                default:
                    throw new ArgumentException(String.Format("Can't open type {0}", typename));
            }
        }

        /// <summary>
        /// Get the NT type name for this object.
        /// </summary>
        /// <returns>The NT type name.</returns>
        public string NtTypeName
        {
            get
            {
                using (SafeStructureInOutBuffer<ObjectTypeInformation> type_info = new SafeStructureInOutBuffer<ObjectTypeInformation>(1024, true))
                {
                    int return_length;
                    NtSystemCalls.NtQueryObject(Handle,
                        ObjectInformationClass.ObjectTypeInformation, type_info.DangerousGetHandle(), type_info.Length, out return_length).ToNtException();
                    return type_info.Result.Name.ToString();
                }
            }
        }

        /// <summary>
        /// Get the NtType for this object.
        /// </summary>
        /// <returns>The NtType for the type name</returns>
        public NtType NtType
        {
            get
            {
                return NtType.GetTypeByName(NtTypeName);
            }
        }

        /// <summary>
        /// Convert an access rights type to a string.
        /// </summary>
        /// <param name="t">The enumeration type for the string conversion</param>
        /// <param name="access">The access mask to convert</param>
        /// <returns>The string version of the access</returns>
        public static string AccessRightsToString(Type t, uint access)
        {
            List<string> names = new List<string>();
            uint remaining = access;

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
                names.Add(String.Format("0x{0:X}", remaining));
            }

            if (names.Count == 0)
            {
                names.Add("None");
            }

            return string.Join("|", names);
        }

        private static void CheckEnumType(Type t)
        {            
            if (!t.IsEnum || t.GetEnumUnderlyingType() != typeof(uint))
            {
                throw new ArgumentException("Type must be an enumeration of unsigned int.");
            }
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <typeparam name="T">The enum type for the access rights</typeparam>
        /// <param name="access">The access rights</param>
        /// <returns>The string format of the access rights</returns>
        public static string AccessRightsToString<T>(T access) where T : struct, IConvertible
        {
            CheckEnumType(typeof(T));
            return AccessRightsToString(typeof(T), access.ToUInt32(null));
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <typeparam name="T">The enum type for the access rights</typeparam>
        /// <param name="access">The access rights</param>
        /// <param name="typeinfo">NtType to map generic access masks to specific access masks</param>
        /// <returns>The string format of the access rights</returns>
        public static string AccessRightsToString<T>(T access, NtType typeinfo) where T : struct, IConvertible
        {
            CheckEnumType(typeof(T));
            uint mapped_access = typeinfo.MapGenericRights(access.ToUInt32(null));
            if ((mapped_access & typeinfo.GenericMapping.GenericAll) == typeinfo.GenericMapping.GenericAll)
            {
                return "Full Access";
            }
            return AccessRightsToString(typeof(T), mapped_access);
        }

        /// <summary>
        /// Get the name of the object
        /// </summary>
        public string Name
        {
            get
            {
                string name = FullPath;
                if (name == @"\")
                {
                    return String.Empty;
                }

                int index = name.LastIndexOf('\\');
                if (index >= 0)
                {
                    return name.Substring(index + 1);
                }
                return name;
            }
        }

        /// <summary>
        /// Convert to a string
        /// </summary>
        /// <returns>The string form of the object</returns>
        public override string ToString()
        {
            return Name;
        }


        /// <summary>
        /// Indicates if the handle can be used for synchronization.
        /// </summary>
        public bool CanSynchronize { get; private set; }

        /// <summary>
        /// Get object creation time.
        /// </summary>
        public DateTime CreationTime
        {
            get
            {
                return DateTime.FromFileTime(QueryBasicInformation().CreationTime.QuadPart);
            }
        }

        #region IDisposable Support
        private bool disposedValue = false;

        /// <summary>
        /// Virtual Dispose method.
        /// </summary>
        /// <param name="disposing">True if disposing, false if finalizing</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                Handle.Close();
                disposedValue = true;
            }
        }
        
        /// <summary>
        /// Finalizer
        /// </summary>
        ~NtObject()
        {            
            Dispose(false);
        }

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            Dispose(true);         
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Close handle
        /// </summary>
        public void Close()
        {
            Dispose();
        }
        #endregion
    }

    /// <summary>
    /// A derived class to add some useful functions such as Duplicate
    /// </summary>
    /// <typeparam name="O">The derived type to use as return values</typeparam>
    /// <typeparam name="A">An enum which represents the access mask values for the type</typeparam>
    public abstract class NtObjectWithDuplicate<O, A> : NtObject where O : NtObject where A : struct, IConvertible
    {
        internal NtObjectWithDuplicate(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        private static O Create(params object[] ps)
        {
            return (O)Activator.CreateInstance(typeof(O), BindingFlags.NonPublic | BindingFlags.Instance, null, ps, null);
        }

        /// <summary>
        /// Duplicate the object with specific access rights
        /// </summary>
        /// <param name="access">The access rights for the new handle</param>
        /// <returns>The duplicated object</returns>
        public O Duplicate(A access)
        {
            IConvertible a = access;
            return Duplicate(a.ToUInt32(null));            
        }

        /// <summary>
        /// Duplicate the object with specific access rights
        /// </summary>
        /// <param name="access">The access rights for the new handle</param>
        /// <returns>The duplicated object</returns>
        public O Duplicate(uint access)
        {
            IConvertible a = access;

            return Create(DuplicateHandle(access));
        }

        /// <summary>
        /// Duplicate the object with same access rights
        /// </summary>
        /// <returns>The duplicated object</returns>
        public O Duplicate()
        {
            return Create(DuplicateHandle());
        }

        /// <summary>
        /// Get granted access for handle.
        /// </summary>
        /// <returns>Granted access</returns>
        public A GrantedAccess
        {
            get
            {
                if (!typeof(A).IsEnum)
                    throw new ArgumentException("Type of access must be an enum");
                return (A)Enum.ToObject(typeof(A), GrantedAccessRaw);
            }
        }

        /// <summary>
        /// Get granted access as an object
        /// </summary>
        /// <returns>The granted access</returns>
        public override object GrantedAccessObject
        {
            get
            {
                return GrantedAccess;
            }
        }

        /// <summary>
        /// Check if a specific set of access rights is granted
        /// </summary>
        /// <param name="access">The access rights to check</param>
        /// <returns>True if all access rights are granted</returns>
        public bool IsAccessGranted(A access)
        {
            uint access_raw = access.ToUInt32(null);
            return (GrantedAccessRaw & access_raw) == access_raw;
        }

        /// <summary>
        /// Get the granted access as a string
        /// </summary>
        /// <returns>The string form of the granted access</returns>
        public string GetGrantedAccessString()
        {
            NtType type = NtType.GetTypeByName(NtTypeName);

            return AccessRightsToString(GrantedAccess, type);
        }

        /// <summary>
        /// Create a new instance from a kernel handle
        /// </summary>
        /// <param name="handle">The kernel handle</param>
        /// <returns>The new typed instance</returns>
        public static O FromHandle(SafeKernelObjectHandle handle)
        {
            return Create(handle);
        }

        /// <summary>
        /// Duplicate an instance from a process
        /// </summary>
        /// <param name="process">The process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <returns>The duplicated handle</returns>
        public static O DuplicateFrom(NtProcess process, IntPtr handle, A access)
        {
            return FromHandle(NtObject.DuplicateHandle(process, new SafeKernelObjectHandle(handle, false), NtProcess.Current, (GenericAccessRights)access.ToUInt32(null)));
        }

        /// <summary>
        /// Duplicate an instance from a process
        /// </summary>
        /// <param name="pid">The process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <returns>The duplicated handle</returns>
        public static O DuplicateFrom(int pid, IntPtr handle, A access)
        {
            using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.DupHandle))
            {
                return DuplicateFrom(process, handle, access);
            }
        }

        /// <summary>
        /// Duplicate an instance from a process with same access rights.
        /// </summary>
        /// <param name="process">The process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <returns>The duplicated handle</returns>
        public static O DuplicateFrom(NtProcess process, IntPtr handle)
        {
            return FromHandle(NtObject.DuplicateHandle(process, new SafeKernelObjectHandle(handle, false), NtProcess.Current));
        }

        /// <summary>
        /// Duplicate an instance from a process with same access rights
        /// </summary>
        /// <param name="pid">The process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <returns>The duplicated handle</returns>
        public static O DuplicateFrom(int pid, IntPtr handle)
        {
            using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.DupHandle))
            {
                return DuplicateFrom(process, handle);
            }
        }
    }

    /// <summary>
    /// A generic wrapper for any object, used if we don't know the type ahead of time.
    /// </summary>
    public class NtGeneric : NtObjectWithDuplicate<NtGeneric, GenericAccessRights>
    {
        internal NtGeneric(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Convert the generic object to the best typed object.
        /// </summary>
        /// <returns>The typed object. Can be NtGeneric if no better type is known.</returns>
        public NtObject ToTypedObject()
        {
            switch (NtTypeName)
            {
                case "device":
                    return new NtFile(DuplicateHandle());
                case "file":
                    return new NtFile(DuplicateHandle());
                case "event":
                    return new NtEvent(DuplicateHandle());
                case "directory":
                    return new NtDirectory(DuplicateHandle());
                case "symboliclink":
                    return new NtSymbolicLink(DuplicateHandle());
                case "mutant":
                    return new NtMutant(DuplicateHandle());
                case "semaphore":
                    return new NtSemaphore(DuplicateHandle());
                case "section":
                    return new NtSection(DuplicateHandle());
                case "job":
                    return new NtJob(DuplicateHandle());
                case "key":
                    return new NtKey(DuplicateHandle());
                case "token":
                    return new NtToken(DuplicateHandle());
                default:
                    return Duplicate();
            }
        }
    }
}
