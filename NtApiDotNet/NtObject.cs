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
using System.Linq;

namespace NtApiDotNet
{
    /// <summary>
    /// Base class for all NtObject types we handle
    /// </summary>
    public abstract class NtObject : IDisposable
    {
        #region Private Members
        private ObjectBasicInformation _basic_information;

        /// <summary>
        /// Get the basic information for the object.
        /// </summary>
        /// <returns>The basic information</returns>
        private static ObjectBasicInformation QueryBasicInformation(SafeKernelObjectHandle handle)
        {
            var basic_info = QueryObjectFixed<ObjectBasicInformation>(handle, 
                ObjectInformationClass.ObjectBasicInformation, false);
            if (basic_info.IsSuccess)
                return basic_info.Result;
            return new ObjectBasicInformation();
        }

        private static NtResult<T> QueryObjectFixed<T>(SafeKernelObjectHandle handle,
            ObjectInformationClass object_info, bool throw_on_error) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                return NtSystemCalls.NtQueryObject(handle, object_info, buffer, 
                    buffer.Length, out int return_length).CreateResult(throw_on_error, () => buffer.Result);
            }
        }

        private static NtResult<SafeStructureInOutBuffer<T>> QueryObject<T>(SafeKernelObjectHandle handle,
            ObjectInformationClass object_info, bool throw_on_error) where T : new()
        {
            SafeStructureInOutBuffer<T> ret = null;
            NtStatus status = NtStatus.STATUS_BUFFER_TOO_SMALL;
            try
            {
                status = NtSystemCalls.NtQueryObject(handle, object_info, SafeHGlobalBuffer.Null, 0, out int return_length);
                if ((status != NtStatus.STATUS_BUFFER_TOO_SMALL) && (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH))
                    return status.CreateResultFromError<SafeStructureInOutBuffer<T>>(throw_on_error);

                if (return_length == 0)
                    ret = new SafeStructureInOutBuffer<T>();
                else
                    ret = new SafeStructureInOutBuffer<T>(return_length, false);
                status = NtSystemCalls.NtQueryObject(handle, object_info, ret, ret.Length, out return_length);
                return status.CreateResult(throw_on_error, () => ret);
            }
            finally
            {
                if (ret != null && !status.IsSuccess())
                {
                    ret.Close();
                    ret = null;
                }
            }
        }

        private static string GetName(SafeKernelObjectHandle handle)
        {
            // TODO: Might need to do this async for file objects, they have a habit of sticking.
            using (var name = QueryObject<ObjectNameInformation>(handle, ObjectInformationClass.ObjectNameInformation, false))
            {
                if (name.IsSuccess)
                    return name.Result.Result.Name.ToString();
            }
            return string.Empty;
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Base constructor
        /// </summary>
        /// <param name="handle">Handle to the object</param>
        protected NtObject(SafeKernelObjectHandle handle)
        {
            SetHandle(handle, true);
        }
        #endregion

        #region Internal Members

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
            return DuplicateHandle(src_process, src_handle.DangerousGetHandle(),
                dest_process, access_rights, flags, options,
                throw_on_error).Map(h => new SafeKernelObjectHandle(h, true));
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
        /// Duplicate a handle from and to the current process to a new handle with the same access rights.
        /// </summary>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The duplicated handle.</returns>
        internal static NtResult<SafeKernelObjectHandle> DuplicateHandle(
            SafeKernelObjectHandle src_handle, bool throw_on_error)
        {
            return DuplicateHandle(NtProcess.Current, src_handle, NtProcess.Current, 0, 0,
                DuplicateObjectOptions.SameAccess | DuplicateObjectOptions.SameAttributes, throw_on_error);
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

        #endregion

        #region Static Methods


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
        /// <param name="attributes">Attributes to open the object.</param>
        /// <param name="security_quality_of_service">Security quality of service.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened object.</returns>
        /// <exception cref="NtException">Thrown if an error occurred opening the object.</exception>
        public static NtResult<NtObject> OpenWithType(string typename, string path, NtObject root,
            AttributeFlags attributes, AccessMask access, SecurityQualityOfService security_quality_of_service, bool throw_on_error)
        {
            using (var obj_attr = new ObjectAttributes(path, attributes, root, security_quality_of_service, null))
            {
                if (typename == null)
                {
                    typename = NtDirectory.GetDirectoryEntryType(path, root);
                }

                // Brute force the open.
                if (typename == null)
                {
                    foreach (var nttype in NtType.GetTypes().Where(t => t.CanOpen))
                    {
                        var result = nttype.Open(obj_attr, access, false);
                        if (result.IsSuccess)
                        {
                            return result;
                        }
                    }

                    return NtStatus.STATUS_OBJECT_TYPE_MISMATCH.CreateResultFromError<NtObject>(true);
                }

                NtType type = NtType.GetTypeByName(typename, false);
                if (type != null && type.CanOpen)
                {
                    return type.Open(obj_attr, access, throw_on_error);
                }
                else
                {
                    return NtStatus.STATUS_OBJECT_TYPE_MISMATCH.CreateResultFromError<NtObject>(true);
                }
            }
        }

        /// <summary>
        /// Open an NT object with a specified type.
        /// </summary>
        /// <param name="typename">The name of the type to open (e.g. Event). If null the method will try and lookup the appropriate type.</param>
        /// <param name="path">The path to the object to open.</param>
        /// <param name="root">A root directory to open from.</param>
        /// <param name="access">Generic access rights to the object.</param>
        /// <param name="attributes">Attributes to open the object.</param>
        /// <param name="security_quality_of_service">Security quality of service.</param>
        /// <returns>The opened object.</returns>
        /// <exception cref="NtException">Thrown if an error occurred opening the object.</exception>
        public static NtObject OpenWithType(string typename, string path, NtObject root,
            AttributeFlags attributes, AccessMask access, SecurityQualityOfService security_quality_of_service)
        {
            return OpenWithType(typename, path, root, attributes, access, security_quality_of_service, true).Result;
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
            return OpenWithType(typename, path, root, AttributeFlags.CaseInsensitive, access, null, true).Result;
        }

        /// <summary>
        /// Close a handle in another process.
        /// </summary>
        /// <param name="handle">The source handle to close.</param>
        /// <param name="process">The source process containing the handle to close.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus CloseHandle(
            NtProcess process, IntPtr handle,
            bool throw_on_error)
        {
            return NtSystemCalls.NtDuplicateObject(process.Handle, handle,
                IntPtr.Zero, IntPtr.Zero, 0, 0,
                 DuplicateObjectOptions.CloseSource).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Close a handle in another process.
        /// </summary>
        /// <param name="handle">The source handle to close.</param>
        /// <param name="process">The source process containing the handle to close.</param>
        public static void CloseHandle(
            NtProcess process, IntPtr handle)
        {
            CloseHandle(process, handle, true);
        }

        /// <summary>
        /// Close a handle in another process by PID.
        /// </summary>
        /// <param name="handle">The source handle to close.</param>
        /// <param name="pid">The source process ID containing the handle to close.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus CloseHandle(
            int pid, IntPtr handle,
            bool throw_on_error)
        {
            using (var proc = NtProcess.Open(pid, ProcessAccessRights.DupHandle, throw_on_error))
            {
                if (!proc.IsSuccess)
                {
                    return proc.Status;
                }

                return CloseHandle(proc.Result, handle, throw_on_error);
            }
        }

        /// <summary>
        /// Close a handle in another process by PID.
        /// </summary>
        /// <param name="handle">The source handle to close.</param>
        /// <param name="pid">The source process ID containing the handle to close.</param>
        public static void CloseHandle(
            int pid, IntPtr handle)
        {
            CloseHandle(pid, handle, true);
        }


        /// <summary>
        /// Close a handle.
        /// </summary>
        /// <param name="handle">The handle to close.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>This ensures the handle can't be 0 before calling NtClose.</remarks>
        public static NtStatus CloseHandle(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                return NtStatus.STATUS_INVALID_HANDLE;
            return NtSystemCalls.NtClose(handle);
        }

        /// <summary>
        /// Duplicate a handle to a new handle, potentially in a different process.
        /// </summary>
        /// <param name="flags">Attribute flags for new handle</param>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <param name="src_process">The source process to duplicate from</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="options">Duplicate handle options</param>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<IntPtr> DuplicateHandle(
            NtProcess src_process, IntPtr src_handle,
            NtProcess dest_process, AccessMask access_rights,
            AttributeFlags flags, DuplicateObjectOptions options,
            bool throw_on_error)
        {
            return NtSystemCalls.NtDuplicateObject(src_process.Handle, src_handle,
                dest_process.Handle, out IntPtr external_handle, access_rights, flags,
                options).CreateResult(throw_on_error, () => external_handle);
        }

        /// <summary>
        /// Duplicate a handle to a new handle, potentially in a different process.
        /// </summary>
        /// <param name="flags">Attribute flags for new handle</param>
        /// <param name="src_handle">The source handle to duplicate</param>
        /// <param name="src_process">The source process to duplicate from</param>
        /// <param name="dest_process">The desination process for the handle</param>
        /// <param name="options">Duplicate handle options</param>
        /// <param name="access_rights">The access rights for the new handle</param>
        /// <returns>The NT status code and object result.</returns>
        public static IntPtr DuplicateHandle(
            NtProcess src_process, IntPtr src_handle,
            NtProcess dest_process, AccessMask access_rights,
            AttributeFlags flags, DuplicateObjectOptions options)
        {
            return DuplicateHandle(src_process, src_handle,
                dest_process, access_rights, flags,
                options, true).Result;
        }

        #endregion

        #region Public Methods
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
        /// Duplicate object.
        /// </summary>
        /// <param name="access_rights">Access rights to duplicate with.</param>
        /// <param name="flags">Attribute flags.</param>
        /// <param name="options">Duplicate options</param>
        /// <returns>The duplicated object.</returns>
        public NtObject DuplicateObject(AccessMask access_rights, AttributeFlags flags, DuplicateObjectOptions options)
        {
            return DuplicateObject(access_rights, flags, options, true).Result;
        }

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
        /// Duplicate object with same access rights.
        /// </summary>
        /// <returns>The duplicated object.</returns>
        public NtObject DuplicateObject()
        {
            return DuplicateObject(0, AttributeFlags.None, DuplicateObjectOptions.SameAccess, true).Result;
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
            using (var buffer = NtSecurity.GetSecurityDescriptor(Handle, security_information, throw_on_error))
            {
                return buffer.Map(b => b.ToArray());
            }
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
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <return>The NT status result.</return>
        public NtStatus SetSecurityDescriptor(byte[] security_desc, SecurityInformation security_information, bool throw_on_error)
        {
            using (var buffer = security_desc.ToBuffer())
            {
                return NtSecurity.SetSecurityDescriptor(Handle, buffer, security_information, throw_on_error);
            }
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
        public void SetSecurityDescriptor(SecurityDescriptor security_desc, SecurityInformation security_information)
        {
            SetSecurityDescriptor(security_desc, security_information, true);
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_desc">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetSecurityDescriptor(SecurityDescriptor security_desc, SecurityInformation security_information, bool throw_on_error)
        {
            using (var buffer = security_desc.ToSafeBuffer(true))
            {
                return NtSecurity.SetSecurityDescriptor(Handle, buffer, security_information, throw_on_error);
            }
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
        {
            return GetSecurityDescriptor(security_information, true).Result;
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor</returns>
        public NtResult<SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            using (var buffer = NtSecurity.GetSecurityDescriptor(Handle, security_information, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<SecurityDescriptor>();

                return SecurityDescriptor.Parse(buffer.Result, NtType, IsContainer, throw_on_error);
            }
        }

        /// <summary>
        /// Get the security descriptor as an SDDL string
        /// </summary>
        /// <returns>The security descriptor as an SDDL string</returns>
        public string GetSddl() => SecurityDescriptor.ToSddl();

        /// <summary>
        /// Make the object a temporary object
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus MakeTemporary(bool throw_on_error) => NtSystemCalls.NtMakeTemporaryObject(Handle).ToNtException(throw_on_error);

        /// <summary>
        /// Make the object a temporary object
        /// </summary>
        public void MakeTemporary() => MakeTemporary(true);

        /// <summary>
        /// Make the object a permanent object
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus MakePermanent(bool throw_on_error) => NtSystemCalls.NtMakePermanentObject(Handle).ToNtException(throw_on_error);

        /// <summary>
        /// Make the object a permanent object
        /// </summary>
        public void MakePermanent() => MakePermanent(true);

        /// <summary>
        /// Wait on the object to become signaled
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
        /// Wait on the object to become signaled
        /// </summary>
        /// <param name="timeout">The time out</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait(NtWaitTimeout timeout)
        {
            return Wait(false, timeout);
        }

        /// <summary>
        /// Wait on the object to become signaled
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
        /// Wait on the object to become signaled
        /// </summary>
        /// <param name="timeout_sec">The time out in seconds</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait(int timeout_sec)
        {
            return Wait(false, timeout_sec);
        }

        /// <summary>
        /// Wait on the object to become signaled for an infinite time.
        /// </summary>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtStatus Wait()
        {
            return Wait(false, NtWaitTimeout.Infinite);
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
        /// Check if this object is exactly the same as another using NtCompareObject.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if this is the same object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <remarks>This is only supported on Windows 10 and above. For one which works on everything use SameObject.</remarks>
        public bool CompareObject(NtObject obj)
        {
            NtStatus status = NtSystemCalls.NtCompareObjects(Handle, obj.Handle);
            if (status == NtStatus.STATUS_NOT_SAME_OBJECT)
            {
                return false;
            }
            status.ToNtException();
            return true;
        }

        /// <summary>
        /// Check if this object is exactly the same as another.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if this is the same object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <remarks>This function can be slow to run and unreliable. Use CompareObject is Windows 10 or above.</remarks>
        public bool SameObject(NtObject obj)
        {
            if (NtObjectUtils.SupportedVersion >= SupportedVersion.Windows10)
            {
                return CompareObject(obj);
            }
            else
            {
                NtSystemInfo.ResolveObjectAddress(this, obj);
                return Address == obj.Address;
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

        #endregion

        #region Public Properties

        /// <summary>
        /// Get full path to the object
        /// </summary>
        public virtual string FullPath => GetName(Handle);

        /// <summary>
        /// Get the granted access as an unsigned integer
        /// </summary>
        public AccessMask GrantedAccessMask => _basic_information.DesiredAccess;

        /// <summary>
        /// Get the security descriptor, with Dacl, Owner, Group and Label
        /// </summary>
        public SecurityDescriptor SecurityDescriptor => GetSecurityDescriptor(SecurityInformation.AllBasic);

        /// <summary>
        /// Get the security descriptor as an SDDL string
        /// </summary>
        /// <returns>The security descriptor as an SDDL string</returns>
        public string Sddl => GetSddl();

        /// <summary>
        /// The low-level handle to the object.
        /// </summary>
        public SafeKernelObjectHandle Handle { get; private set; }

        /// <summary>
        /// Get the NT type name for this object.
        /// </summary>
        /// <returns>The NT type name.</returns>
        public string NtTypeName => Handle.NtTypeName;

        /// <summary>
        /// Get the NtType for this object.
        /// </summary>
        /// <returns>The NtType for the type name</returns>
        public NtType NtType => NtType.GetTypeByName(NtTypeName, true);

        /// <summary>
        /// Get the name of the object
        /// </summary>
        public string Name => NtObjectUtils.GetFileName(FullPath);

        /// <summary>
        /// Indicates if the handle can be used for synchronization.
        /// </summary>
        public bool CanSynchronize { get; private set; }

        /// <summary>
        /// Get object creation time.
        /// </summary>
        public DateTime CreationTime => DateTime.FromFileTime(_basic_information.CreationTime.QuadPart);

        /// <summary>
        /// Get the attribute flags for the object.
        /// </summary>
        public AttributeFlags AttributesFlags => _basic_information.Attributes;

        /// <summary>
        /// Get number of handles for this object.
        /// </summary>
        public int HandleReferenceCount => QueryBasicInformation(Handle).HandleCount;

        /// <summary>
        /// Get reference count for this object.
        /// </summary>
        public int PointerReferenceCount => QueryBasicInformation(Handle).ReferenceCount;

        /// <summary>
        /// Get or set whether the handle is inheritable.
        /// </summary>
        public bool Inherit
        {
            get => Handle.Inherit;
            set => Handle.Inherit = value;
        }

        /// <summary>
        /// Get or set whether the handle is protected from closing.
        /// </summary>
        public bool ProtectFromClose
        {
            get => Handle.ProtectFromClose;
            set => Handle.ProtectFromClose = value;
        }

        /// <summary>
        /// Get the object's address is kernel memory.
        /// </summary>
        /// <remarks>As getting the address is expensive you need to pass the object to NtSystemInfo::ResolveObjectAddress to intialize.</remarks>
        public ulong Address { get; internal set; }

        /// <summary>
        /// Returns whether this object is a container.
        /// </summary>
        public virtual bool IsContainer => false;

        /// <summary>
        /// Returns whether this object is closed.
        /// </summary>
        public bool IsClosed => Handle.IsClosed;

        #endregion

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
                if (!Handle.PseudoHandle)
                {
                    Handle.Close();
                }
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
}
