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
        Access0 = 0x00000001,
        Access1 = 0x00000002,
        Access2 = 0x00000004,
        Access3 = 0x00000008,
        Access4 = 0x00000010,
        Access5 = 0x00000020,
        Access6 = 0x00000040,
        Access7 = 0x00000080,
        Access8 = 0x00000100,
        Access9 = 0x00000200,
        Access10 = 0x00000400,
        Access11 = 0x00000800,
        Access12 = 0x00001000,
        Access13 = 0x00002000,
        Access14 = 0x00004000,
        Access15 = 0x00008000,
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        AccessSystemSecurity = 0x01000000,
        MaximumAllowed = 0x02000000,
        GenericAll = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite = 0x40000000,
        GenericRead = 0x80000000,
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
    /// <see cref="NtSystemCalls.NtQueryObject(SafeHandle, ObjectInformationClass, SafeBuffer, int, out int)"/>
    public enum ObjectInformationClass
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectAllInformation,
        ObjectHandleInformation
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

    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectHandleInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool Inherit;
        [MarshalAs(UnmanagedType.U1)]
        public bool ProtectFromClose;
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
          AccessMask DesiredAccess,
          AttributeFlags HandleAttributes,
          DuplicateObjectOptions Options
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryObject(
		    SafeHandle ObjectHandle,
            ObjectInformationClass ObjectInformationClass,
		    SafeBuffer ObjectInformation,
            int ObjectInformationLength,
		    out int ReturnLength
		);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationObject(
            SafeHandle ObjectHandle,
            ObjectInformationClass ObjectInformationClass,
            SafeBuffer ObjectInformation,
            int ObjectInformationLength
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
        private string _type_name;
        private ObjectBasicInformation _basic_information;

        /// <summary>
        /// Get the basic information for the object.
        /// </summary>
        /// <returns>The basic information</returns>
        private static ObjectBasicInformation QueryBasicInformation(SafeKernelObjectHandle handle)
        {

            try
            {
                using (var basic_info = QueryObject<ObjectBasicInformation>(handle, ObjectInformationClass.ObjectBasicInformation))
                {
                    return basic_info.Result;
                }
            }
            catch
            {
                return new ObjectBasicInformation();
            }
        }

        /// <summary>
        /// Base constructor
        /// </summary>
        /// <param name="handle">Handle to the object</param>
        protected NtObject(SafeKernelObjectHandle handle)
        {
            SetHandle(handle, true);
        }

        internal void SetHandle(SafeKernelObjectHandle handle, bool query_basic_info)
        {
            Handle = handle;
            if (query_basic_info)
            {
                try
                {
                    // Query basic information which shouldn't change.
                    _basic_information = QueryBasicInformation(handle);
                    CanSynchronize = IsAccessMaskGranted(GenericAccessRights.Synchronize);
                }
                catch (NtException)
                {
                    // Shouldn't fail here but just in case.
                }
            }
        }

        private static SafeStructureInOutBuffer<T> QueryObject<T>(SafeKernelObjectHandle handle, ObjectInformationClass object_info) where T : new()
        {
            SafeStructureInOutBuffer<T> ret = null;
            NtStatus status = NtStatus.STATUS_BUFFER_TOO_SMALL;
            try
            {
                int return_length;
                status = NtSystemCalls.NtQueryObject(handle, object_info, SafeHGlobalBuffer.Null, 0, out return_length);
                if ((status != NtStatus.STATUS_BUFFER_TOO_SMALL) && (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH))
                    status.ToNtException();
                if (return_length == 0)
                    ret = new SafeStructureInOutBuffer<T>();
                else
                    ret = new SafeStructureInOutBuffer<T>(return_length, false);
                status = NtSystemCalls.NtQueryObject(handle, object_info, ret, ret.Length, out return_length);
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
        /// <param name="flags">Attribute flags for new handle</param>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <param name="src_process">The source process to duplicate from</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="options">Duplicate handle options</param>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        internal static NtResult<SafeKernelObjectHandle> DuplicateHandle(
            NtProcess src_process, SafeKernelObjectHandle src_handle,
            NtProcess dest_process, AccessMask access_rights,
            AttributeFlags flags, DuplicateObjectOptions options,
            bool throw_on_error)
        {
            SafeKernelObjectHandle new_handle;
            return NtSystemCalls.NtDuplicateObject(src_process.Handle, src_handle,
              dest_process.Handle, out new_handle, access_rights, flags,
              options).CreateResult(throw_on_error, () => new_handle);
        }

        /// <summary>
        /// Duplicate the internal handle to a new handle.
        /// </summary>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="options">Duplicate handle options</param>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <returns>The duplicated handle.</returns>
        internal static SafeKernelObjectHandle DuplicateHandle(
            SafeKernelObjectHandle src_handle,
            NtProcess dest_process, AccessMask access_rights,
            DuplicateObjectOptions options)
        {
            return DuplicateHandle(NtProcess.Current, src_handle, dest_process,
                access_rights, AttributeFlags.None, options, true).Result;
        }

        /// <summary>
        /// Duplicate a handle from the current process to a new handle with the same access rights.
        /// </summary>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <returns>The duplicated handle.</returns>
        internal static SafeKernelObjectHandle DuplicateHandle(
            SafeKernelObjectHandle src_handle,
            NtProcess dest_process)
        {
            return DuplicateHandle(src_handle, dest_process, 0, DuplicateObjectOptions.SameAccess);
        }

        /// <summary>
        /// Duplicate a handle from and to the current process to a new handle with the same access rights.
        /// </summary>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <returns>The duplicated handle.</returns>
        internal static SafeKernelObjectHandle DuplicateHandle(
            SafeKernelObjectHandle src_handle)
        {
            return DuplicateHandle(src_handle, NtProcess.Current);
        }

        /// <summary>
        /// Duplicate a handle from and to the current process to a new handle with new access rights.
        /// </summary>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <param name="access_rights">The access for the new handle.</param>
        /// <returns>The duplicated handle.</returns>
        internal static SafeKernelObjectHandle DuplicateHandle(SafeKernelObjectHandle src_handle, AccessMask access_rights)
        {
            return DuplicateHandle(src_handle, NtProcess.Current, access_rights, DuplicateObjectOptions.None);
        }

        /// <summary>
        /// Duplicate object.
        /// </summary>
        /// <param name="access_rights">Access rights to duplicate with.</param>
        /// <param name="flags">Attribute flags.</param>
        /// <param name="options">Duplicate options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The duplicated object.</returns>
        public abstract NtResult<NtObject> DuplicateObject(AccessMask access_rights, AttributeFlags flags, DuplicateObjectOptions options, bool throw_on_error);

        /// <summary>
        /// Duplicate object with specific access rights.
        /// </summary>
        /// <param name="access_rights">Access rights to duplicate with.</param>
        /// <returns>The duplicated object.</returns>
        public NtObject DuplicateObject(AccessMask access_rights)
        {
            return DuplicateObject(access_rights, AttributeFlags.None, DuplicateObjectOptions.None, true).Result;
        }

        /// <summary>
        /// Duplicate object with sane access rights.
        /// </summary>
        /// <returns>The duplicated object.</returns>
        public NtObject DuplicateObject()
        {
            return DuplicateObject(0, AttributeFlags.None, DuplicateObjectOptions.SameAccess, true).Result;
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

        /// <summary>
        /// Get the granted access as an unsigned integer
        /// </summary>
        public AccessMask GrantedAccessMask
        {
            get
            {
                return _basic_information.DesiredAccess;
            }
        }

        /// <summary>
        /// Check if access is granted to a set of rights
        /// </summary>
        /// <param name="access">The access rights to check</param>
        /// <returns>True if all the access rights are granted</returns>
        public bool IsAccessMaskGranted(AccessMask access)
        {
            return GrantedAccessMask.IsAllAccessGranted(access);
        }

        /// <summary>
        /// Get security descriptor as a byte array
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public byte[] GetSecurityDescriptorBytes(SecurityInformation security_information)
        {
            return GetSecurityDescriptorBytes(security_information, true).Result;
        }


        /// <summary>
        /// Get security descriptor as a byte array
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <return>The NT status result and security descriptor.</return>
        public NtResult<byte[]> GetSecurityDescriptorBytes(SecurityInformation security_information, bool throw_on_error)
        {
            // Just do a check here, no point checking if ReadControl not available.
            if (!IsAccessMaskGranted(GenericAccessRights.ReadControl))
            {
                return NtStatus.STATUS_ACCESS_DENIED.CreateResultFromError<byte[]>(throw_on_error);
            }

            int return_length;
            NtStatus status = NtSystemCalls.NtQuerySecurityObject(Handle, security_information, null, 0, out return_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                return status.CreateResult(throw_on_error, () => new byte[0]);
            }
            byte[] buffer = new byte[return_length];
            return NtSystemCalls.NtQuerySecurityObject(Handle, security_information, buffer,
                buffer.Length, out return_length).CreateResult(throw_on_error, () => buffer);
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
            SetSecurityDescriptor(security_desc, security_information, true);
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_desc">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <return>The NT status result.</return>
        public NtStatus SetSecurityDescriptor(byte[] security_desc, SecurityInformation security_information, bool throw_on_error)
        {
            return NtSystemCalls.NtSetSecurityObject(Handle, security_information, security_desc).ToNtException(throw_on_error);
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
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor</returns>
        public NtResult<SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return GetSecurityDescriptorBytes(security_information, throw_on_error).Map(sd => new SecurityDescriptor(sd));
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
        public static bool CanOpenType(string typename)
        {
            NtType type = NtType.GetTypeByName(typename, false);
            if (type == null)
            {
                return false;
            }
            return type.CanOpen;
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
        public static NtObject OpenWithType(string typename, string path, NtObject root, AccessMask access)
        {
            if (typename == null)
            {
                typename = NtDirectory.GetDirectoryEntryType(path, root);
                if (typename == null)
                {
                    throw new ArgumentException(String.Format("Can't find type for path {0}", path));
                }
            }

            NtType type = NtType.GetTypeByName(typename, false);
            if (type != null && type.CanOpen)
            {
                return type.Open(path, root, access);
            }
            else
            {
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
                if (_type_name == null)
                {
                    using (var type_info = new SafeStructureInOutBuffer<ObjectTypeInformation>(1024, true))
                    {
                        int return_length;
                        NtSystemCalls.NtQueryObject(Handle,
                            ObjectInformationClass.ObjectTypeInformation, type_info, type_info.Length, out return_length).ToNtException();
                        _type_name = type_info.Result.Name.ToString();
                    }
                }
                return _type_name;
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
                return NtType.GetTypeByName(NtTypeName, true);
            }
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="map_to_generic">True to try and convert to generic rights where possible.</param>
        /// <returns>The string format of the access rights</returns>
        public string GrantedAccessAsString(bool map_to_generic)
        {
            return NtType.AccessMaskToString(GrantedAccessMask, map_to_generic);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <returns>The string format of the access rights</returns>
        public string GrantedAccessAsString()
        {
            return GrantedAccessAsString(false);
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
                return DateTime.FromFileTime(_basic_information.CreationTime.QuadPart);
            }
        }
        
        /// <summary>
        /// Get or set whether the handle is inheritable.
        /// </summary>
        public bool Inherit
        {
            get
            {
                return Handle.Inherit;
            }

            set
            {
                Handle.Inherit = value;
            }
        }

        /// <summary>
        /// Get or set whether the handle is protected from closing.
        /// </summary>
        public bool ProtectFromClose
        {
            get
            {
                return Handle.ProtectFromClose;
            }

            set
            {
                Handle.ProtectFromClose = value;
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
            if (!typeof(A).IsEnum)
                throw new ArgumentException("Type of access must be an enum");
        }

        private static O Create(params object[] ps)
        {
            return (O)Activator.CreateInstance(typeof(O), BindingFlags.NonPublic | BindingFlags.Instance, null, ps, null);
        }

        private static GenericAccessRights ToGenericAccess(IConvertible conv)
        {
            return (GenericAccessRights)conv.ToUInt32(null);
        }

        /// <summary>
        /// Duplicate object.
        /// </summary>
        /// <param name="access_rights">Access rights to duplicate with.</param>
        /// <param name="flags">Attribute flags.</param>
        /// <param name="options">Duplicate options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The duplicated object.</returns>
        public sealed override NtResult<NtObject> DuplicateObject(AccessMask access_rights, AttributeFlags flags, DuplicateObjectOptions options, bool throw_on_error)
        {
            return Duplicate(access_rights.ToSpecificAccess<A>(), flags, options, throw_on_error).Cast<NtObject>();
        }

        /// <summary>
        /// Duplicate object.
        /// </summary>
        /// <param name="access_rights">Access rights to duplicate with.</param>
        /// <param name="flags">Attribute flags.</param>
        /// <param name="options">Duplicate options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The duplicated object.</returns>
        public NtResult<O> Duplicate(A access_rights, AttributeFlags flags, DuplicateObjectOptions options, bool throw_on_error)
        {
            return DuplicateHandle(NtProcess.Current, Handle, NtProcess.Current, ToGenericAccess(access_rights), flags, options, throw_on_error).Map(h => ShallowClone(h, true));
        }

        /// <summary>
        /// Duplicate the object with specific access rights
        /// </summary>
        /// <param name="access">The access rights for the new handle</param>
        /// <returns>The duplicated object</returns>
        public O Duplicate(A access)
        {
            return Duplicate(access, AttributeFlags.None, DuplicateObjectOptions.None, true).Result;
        }

        /// <summary>
        /// Duplicate the object with same access rights
        /// </summary>
        /// <returns>The duplicated object</returns>
        public O Duplicate()
        {
            return Duplicate(default(A), AttributeFlags.None, DuplicateObjectOptions.SameAccess, true).Result;
        }

        private O ShallowClone(SafeKernelObjectHandle handle, bool query_basic_info)
        {
            O ret = (O)MemberwiseClone();
            ret.SetHandle(handle, query_basic_info);
            return ret;
        }

        // Get a shallow clone where the handle isn't owned.
        internal O ShallowClone()
        {
            return ShallowClone(new SafeKernelObjectHandle(Handle.DangerousGetHandle(), false), false);
        }

        private A UIntToAccess(GenericAccessRights access)
        {
            return (A)Enum.ToObject(typeof(A), (uint)access);
        }

        /// <summary>
        /// Get granted access for handle.
        /// </summary>
        /// <returns>Granted access</returns>
        public A GrantedAccess
        {
            get
            {
                return GrantedAccessMask.ToSpecificAccess<A>();
            }
        }

        /// <summary>
        /// Get the maximum permission access for this object based on a token
        /// and it's security descriptor.
        /// </summary>
        /// <param name="token">The token to check against.</param>
        /// <returns>Returns 0 if can't read the security descriptor.</returns>
        public A GetMaximumAccess(NtToken token)
        {
            if (!IsAccessMaskGranted(GenericAccessRights.ReadControl))
            {
                return default(A);
            }

            return NtSecurity.GetMaximumAccess(SecurityDescriptor,
                                    token, NtType.GenericMapping).ToSpecificAccess<A>();
        }

        /// <summary>
        /// Get the maximum permission access for this object based on the current token
        /// and its security descriptor.
        /// </summary>
        /// <returns>Returns 0 if can't read the security descriptor.</returns>
        public A GetMaximumAccess()
        {
            using (NtToken token = NtToken.OpenProcessToken())
            {
                return GetMaximumAccess(token);
            }
        }

        /// <summary>
        /// Check if a specific set of access rights is granted
        /// </summary>
        /// <param name="access">The access rights to check</param>
        /// <returns>True if all access rights are granted</returns>
        public bool IsAccessGranted(A access)
        {
            return IsAccessMaskGranted(ToGenericAccess(access));
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
        /// <param name="options">The options for duplication.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<O> DuplicateFrom(NtProcess process, IntPtr handle, 
            A access, DuplicateObjectOptions options, bool throw_on_error)
        {
            return NtObject.DuplicateHandle(process, new SafeKernelObjectHandle(handle, false), 
                NtProcess.Current, ToGenericAccess(access), AttributeFlags.None,
                options, throw_on_error).Map(h => FromHandle(h));
        }

        /// <summary>
        /// Duplicate an instance from a process
        /// </summary>
        /// <param name="pid">The process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<O> DuplicateFrom(int pid, IntPtr handle,
            A access, DuplicateObjectOptions options, bool throw_on_error)
        {
            using (var process = NtProcess.Open(pid, ProcessAccessRights.DupHandle, throw_on_error))
            {
                if (!process.IsSuccess)
                {
                    return new NtResult<O>(process.Status, default(O));
                }

                return DuplicateFrom(process.Result, handle, access, options, throw_on_error);
            }
        }

        /// <summary>
        /// Duplicate an instance from a process with a specified access rights.
        /// </summary>
        /// <param name="process">The process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate.</param>
        /// <returns>The duplicated handle</returns>
        public static O DuplicateFrom(NtProcess process, IntPtr handle, A access)
        {
            return DuplicateFrom(process, handle, access, 
                DuplicateObjectOptions.None, true).Result;
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
            return DuplicateFrom(pid, handle, access,
                DuplicateObjectOptions.None, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from a process with same access rights.
        /// </summary>
        /// <param name="process">The process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <returns>The duplicated object.</returns>
        public static O DuplicateFrom(NtProcess process, IntPtr handle)
        {
            return DuplicateFrom(process, handle, default(A), DuplicateObjectOptions.SameAccess, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from a process with same access rights
        /// </summary>
        /// <param name="pid">The process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <returns>The duplicated handle</returns>
        public static O DuplicateFrom(int pid, IntPtr handle)
        {
            return DuplicateFrom(pid, handle, default(A), DuplicateObjectOptions.SameAccess, true).Result;
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
            return NtType.FromHandle(DuplicateHandle(Handle));
        }
    }

    /// <summary>
    /// A structure to return the result of an NT system call with status.
    /// This allows a function to return both a status code and a result
    /// without having to resort to out parameters.
    /// </summary>
    /// <typeparam name="T">The result type.</typeparam>
    public struct NtResult<T> : IDisposable
    {
        private T _result;

        /// <summary>
        /// The NT status code.
        /// </summary>
        public NtStatus Status { get; private set; }
        /// <summary>
        /// The result of the NT call.
        /// </summary>
        public T Result
        {
            get
            {
                System.Diagnostics.Debug.Assert(Status.IsSuccess());
                return _result;
            }
        }
        /// <summary>
        /// Get the result object or throw an exception if status code is an error.
        /// </summary>
        /// <returns>The result NT result.</returns>
        /// <exception cref="NtException">Thrown if status code is an error.</exception>
        public T GetResultOrThrow()
        {
            Status.ToNtException();
            return Result;
        }
        /// <summary>
        /// Is the result successful.
        /// </summary>
        public bool IsSuccess
        {
            get
            {
                return Status.IsSuccess();
            }
        }

        /// <summary>
        /// Map result to a different type.
        /// </summary>
        /// <typeparam name="S">The different type to map to.</typeparam>
        /// <param name="map_func">A function to map the result.</param>
        /// <returns>The mapped result.</returns>
        public NtResult<S> Map<S>(Func<T, S> map_func)
        {
            if (IsSuccess)
            {
                return new NtResult<S>(Status, map_func(Result));
            }
            return new NtResult<S>(Status, default(S));
        }

        /// <summary>
        /// Cast result to a different type.
        /// </summary>
        /// <typeparam name="S">The different type to cast to.</typeparam>
        /// <returns>The mapped result.</returns>
        public NtResult<S> Cast<S>()
        {
            return Map<S>(d => (S)(object)d);
        }

        /// <summary>
        /// Dispose result.
        /// </summary>
        public void Dispose()
        {
            using (_result as IDisposable) { }
        }

        internal NtResult(NtStatus status, T result)
        {
            Status = status;
            _result = result;
        }
    }
}
