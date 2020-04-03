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
using System.Reflection;

namespace NtApiDotNet
{
    /// <summary>
    /// A derived class to add some useful functions such as Duplicate
    /// </summary>
    /// <typeparam name="O">The derived type to use as return values</typeparam>
    /// <typeparam name="A">An enum which represents the access mask values for the type</typeparam>
    public abstract class NtObjectWithDuplicate<O, A> : NtObject where O : NtObject where A : Enum
    {
        internal abstract class NtTypeFactoryImplBase : NtTypeFactory
        {
            protected NtTypeFactoryImplBase(Type container_access_rights_type, bool can_open, MandatoryLabelPolicy default_policy) 
                : base(typeof(A), container_access_rights_type, typeof(O), can_open, default_policy)
            {
            }

            protected NtTypeFactoryImplBase(Type container_access_rights_type, bool can_open)
                : this(container_access_rights_type, can_open, MandatoryLabelPolicy.NoWriteUp)
            {
            }

            protected NtTypeFactoryImplBase(bool can_open, MandatoryLabelPolicy default_policy)
                : this(typeof(A), can_open, default_policy)
            {
            }

            protected NtTypeFactoryImplBase(bool can_open)
                : this(can_open, MandatoryLabelPolicy.NoWriteUp)
            {
            }

            protected NtTypeFactoryImplBase()
                :  this(false)
            {
            }

            protected virtual NtResult<O> OpenInternal(ObjectAttributes obj_attributes, A desired_access, bool throw_on_error)
            {
                return NtStatus.STATUS_NOT_IMPLEMENTED.CreateResultFromError<O>(throw_on_error);
            }

            public sealed override NtResult<NtObject> Open(ObjectAttributes obj_attributes, AccessMask desired_access, bool throw_on_error)
            {
                return OpenInternal(obj_attributes, desired_access.ToSpecificAccess<A>(), throw_on_error).Cast<NtObject>();
            }

            public sealed override NtObject FromHandle(SafeKernelObjectHandle handle)
            {
                return NtObjectWithDuplicate<O, A>.FromHandle(handle);
            }
        }

        internal NtObjectWithDuplicate(SafeKernelObjectHandle handle) : base(handle)
        {
            System.Diagnostics.Debug.Assert(typeof(A).IsEnum);
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
        /// Reopen object with different access rights.
        /// </summary>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="attributes">Additional attributes for open.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The reopened object.</returns>
        public virtual NtResult<O> ReOpen(A desired_access, AttributeFlags attributes, bool throw_on_error)
        {
            if (!NtType.CanOpen)
            {
                return NtStatus.STATUS_OBJECT_PATH_NOT_FOUND.CreateResultFromError<O>(throw_on_error);
            }

            using (var obj_attr = new ObjectAttributes(string.Empty, attributes, this))
            {
                return NtType.Open(obj_attr, ToGenericAccess(desired_access), throw_on_error).Cast<O>();
            }
        }

        /// <summary>
        /// Reopen object with different access rights.
        /// </summary>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The reopened object.</returns>
        public NtResult<O> ReOpen(A desired_access, bool throw_on_error)
        {
            return ReOpen(desired_access, AttributeFlags.CaseInsensitive, throw_on_error);
        }

        /// <summary>
        /// Reopen object with different access rights.
        /// </summary>
        /// <param name="desired_access">The desired access.</param>
        /// <returns>The reopened object.</returns>
        public O ReOpen(A desired_access)
        {
            return ReOpen(desired_access, true).Result;
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
        /// Duplicate object.
        /// </summary>
        /// <param name="access_rights">Access rights to duplicate with.</param>
        /// <param name="flags">Attribute flags.</param>
        /// <param name="options">Duplicate options</param>
        /// <returns>The duplicated object.</returns>
        public O Duplicate(A access_rights, AttributeFlags flags, DuplicateObjectOptions options)
        {
            return Duplicate(access_rights, flags, options, true).Result;
        }

        /// <summary>
        /// Duplicate the object with specific access rights
        /// </summary>
        /// <param name="access">The access rights for the new handle</param>
        /// <returns>The duplicated object</returns>
        public O Duplicate(A access)
        {
            return Duplicate(access, true).Result;
        }

        /// <summary>
        /// Duplicate the object with specific access rights
        /// </summary>
        /// <param name="access">The access rights for the new handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The duplicated object</returns>
        public NtResult<O> Duplicate(A access, bool throw_on_error)
        {
            return Duplicate(access, AttributeFlags.None, DuplicateObjectOptions.SameAttributes, throw_on_error);
        }

        /// <summary>
        /// Duplicate the object with same access rights
        /// </summary>
        /// <returns>The duplicated object</returns>
        public O Duplicate()
        {
            return Duplicate(true).Result;
        }

        /// <summary>
        /// Duplicate the object with same access rights
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The duplicated object</returns>
        public NtResult<O> Duplicate(bool throw_on_error)
        {
            return Duplicate(default, AttributeFlags.None, DuplicateObjectOptions.SameAccess, throw_on_error);
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

        /// <summary>
        /// Get granted access for handle.
        /// </summary>
        /// <returns>Granted access</returns>
        public A GrantedAccess => GrantedAccessMask.ToSpecificAccess<A>();

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
                return default;
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
        /// Create a new instance from a kernel handle
        /// </summary>
        /// <param name="handle">The kernel handle</param>
        /// <param name="owns_handle">True to own the handle.</param>
        /// <returns>The new typed instance</returns>
        public static O FromHandle(IntPtr handle, bool owns_handle)
        {
            return FromHandle(new SafeKernelObjectHandle(handle, owns_handle));
        }

        /// <summary>
        /// Create a new instance from a kernel handle.
        /// </summary>
        /// <param name="handle">The kernel handle</param>
        /// <remarks>The call doesn't own the handle. The returned object can't be used to close the handle.</remarks>
        /// <returns>The new typed instance</returns>
        public static O FromHandle(IntPtr handle)
        {
            return FromHandle(handle, false);
        }

        /// <summary>
        /// Duplicate an instance from a process
        /// </summary>
        /// <param name="process">The process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="attributes">The attribute flags for the new object.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<O> DuplicateFrom(NtProcess process, IntPtr handle,
            A access, AttributeFlags attributes, DuplicateObjectOptions options, bool throw_on_error)
        {
            return NtObject.DuplicateHandle(process, new SafeKernelObjectHandle(handle, false),
                NtProcess.Current, ToGenericAccess(access), AttributeFlags.None,
                options, throw_on_error).Map(h => FromHandle(h));
        }

        /// <summary>
        /// Duplicate an instance from a process
        /// </summary>
        /// <param name="process">The process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="attributes">The attribute flags for the new object.</param>
        /// <returns>The NT status code and object result.</returns>
        public static O DuplicateFrom(NtProcess process, IntPtr handle,
            A access, AttributeFlags attributes, DuplicateObjectOptions options)
        {
            return DuplicateFrom(process, handle, access, attributes, options, true).Result;
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
                    return new NtResult<O>(process.Status, default);
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
            return DuplicateFrom(process, handle, default, DuplicateObjectOptions.SameAccess, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from a process with same access rights
        /// </summary>
        /// <param name="pid">The process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <returns>The duplicated handle</returns>
        public static O DuplicateFrom(int pid, IntPtr handle)
        {
            return DuplicateFrom(pid, handle, default, DuplicateObjectOptions.SameAccess, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process
        /// </summary>
        /// <param name="process">The destination process (with DupHandle access)</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public NtResult<IntPtr> DuplicateTo(NtProcess process,
            A access, DuplicateObjectOptions options, bool throw_on_error)
        {
            return DuplicateTo(process, Handle,
                access, options, throw_on_error);
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process
        /// </summary>
        /// <param name="process">The destination process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<IntPtr> DuplicateTo(NtProcess process, SafeKernelObjectHandle handle,
            A access, DuplicateObjectOptions options, bool throw_on_error)
        {
            return DuplicateHandle(NtProcess.Current, handle.DangerousGetHandle(),
                process, ToGenericAccess(access), AttributeFlags.None,
                options, throw_on_error);
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process
        /// </summary>
        /// <param name="pid">The destination process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<IntPtr> DuplicateTo(int pid, SafeKernelObjectHandle handle,
            A access, DuplicateObjectOptions options, bool throw_on_error)
        {
            using (var process = NtProcess.Open(pid, ProcessAccessRights.DupHandle, throw_on_error))
            {
                if (!process.IsSuccess)
                {
                    return new NtResult<IntPtr>(process.Status, IntPtr.Zero);
                }

                return DuplicateTo(process.Result, handle, access, options, throw_on_error);
            }
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process with a specified access rights.
        /// </summary>
        /// <param name="process">The destination process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate.</param>
        /// <returns>The duplicated handle</returns>
        public static IntPtr DuplicateTo(NtProcess process, SafeKernelObjectHandle handle, A access)
        {
            return DuplicateTo(process, handle, access,
                DuplicateObjectOptions.None, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process
        /// </summary>
        /// <param name="pid">The destination process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <returns>The duplicated handle</returns>
        public static IntPtr DuplicateTo(int pid, SafeKernelObjectHandle handle, A access)
        {
            return DuplicateTo(pid, handle, access,
                DuplicateObjectOptions.None, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process with same access rights.
        /// </summary>
        /// <param name="process">The destination process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <returns>The duplicated object.</returns>
        public static IntPtr DuplicateTo(NtProcess process, SafeKernelObjectHandle handle)
        {
            return DuplicateTo(process, handle, default, DuplicateObjectOptions.SameAccess, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process with same access rights.
        /// </summary>
        /// <param name="process">The destination process (with DupHandle access)</param>
        /// <returns>The duplicated object.</returns>
        public IntPtr DuplicateTo(NtProcess process)
        {
            return DuplicateTo(process, Handle);
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process with same access rights
        /// </summary>
        /// <param name="pid">The destination process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <returns>The duplicated handle</returns>
        public static IntPtr DuplicateTo(int pid, SafeKernelObjectHandle handle)
        {
            return DuplicateTo(pid, handle, default, DuplicateObjectOptions.SameAccess, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from current process to an other process with same access rights
        /// </summary>
        /// <param name="pid">The destination process ID</param>
        /// <returns>The duplicated handle</returns>
        public IntPtr DuplicateTo(int pid)
        {
            return DuplicateTo(pid, Handle);
        }

        /// <summary>
        /// Duplicate an instance from a process to an other process
        /// </summary>
        /// <param name="src_process">The source process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="dst_process">The destination process (with DupHandle access)</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<IntPtr> DuplicateTo(NtProcess src_process, IntPtr handle, NtProcess dst_process,
            A access, DuplicateObjectOptions options, bool throw_on_error)
        {
            return DuplicateHandle(src_process, handle,
                dst_process, ToGenericAccess(access), AttributeFlags.None,
                options, throw_on_error);
        }

        /// <summary>
        /// Duplicate an instance from a process to an other process
        /// </summary>
        /// <param name="src_pid">The source process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="dst_pid">The destination process ID</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <param name="options">The options for duplication.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<IntPtr> DuplicateTo(int src_pid, IntPtr handle, int dst_pid,
            A access, DuplicateObjectOptions options, bool throw_on_error)
        {
            using (var src_process = NtProcess.Open(src_pid, ProcessAccessRights.DupHandle, throw_on_error))
            {
                if (!src_process.IsSuccess)
                {
                    return new NtResult<IntPtr>(src_process.Status, IntPtr.Zero);
                }

                using (var dst_process = NtProcess.Open(dst_pid, ProcessAccessRights.DupHandle, throw_on_error))
                {
                    if (!dst_process.IsSuccess)
                    {
                        return new NtResult<IntPtr>(dst_process.Status, IntPtr.Zero);
                    }

                    return DuplicateTo(src_process.Result, handle, dst_process.Result, access, options, throw_on_error);
                }
            }
        }

        /// <summary>
        /// Duplicate an instance from a process to an other process with a specified access rights.
        /// </summary>
        /// <param name="src_process">The source process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="dst_process">The destination process (with DupHandle access)</param>
        /// <param name="access">The access rights to duplicate.</param>
        /// <returns>The duplicated handle</returns>
        public static IntPtr DuplicateTo(NtProcess src_process, IntPtr handle, NtProcess dst_process, A access)
        {
            return DuplicateTo(src_process, handle, dst_process, access,
                DuplicateObjectOptions.None, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from a process to an other process
        /// </summary>
        /// <param name="src_pid">The source process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="dst_pid">The destination process ID</param>
        /// <param name="access">The access rights to duplicate with</param>
        /// <returns>The duplicated handle</returns>
        public static IntPtr DuplicateTo(int src_pid, IntPtr handle, int dst_pid, A access)
        {
            return DuplicateTo(src_pid, handle, dst_pid, access,
                DuplicateObjectOptions.None, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from a process to an other process with same access rights.
        /// </summary>
        /// <param name="src_process">The source process (with DupHandle access)</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="dst_process">The destination process (with DupHandle access)</param>
        /// <returns>The duplicated object.</returns>
        public static IntPtr DuplicateTo(NtProcess src_process, IntPtr handle, NtProcess dst_process)
        {
            return DuplicateTo(src_process, handle, dst_process, default, DuplicateObjectOptions.SameAccess, true).Result;
        }

        /// <summary>
        /// Duplicate an instance from a process to an other process with same access rights
        /// </summary>
        /// <param name="src_pid">The source process ID</param>
        /// <param name="handle">The handle value to duplicate</param>
        /// <param name="dst_pid">The destination process ID</param>
        /// <returns>The duplicated handle</returns>
        public static IntPtr DuplicateTo(int src_pid, IntPtr handle, int dst_pid)
        {
            return DuplicateTo(src_pid, handle, dst_pid, default, DuplicateObjectOptions.SameAccess, true).Result;
        }
    }
}
