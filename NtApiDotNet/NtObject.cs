using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
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
    };

    [Flags]
    public enum DuplicateObjectOptions
    {
        None = 0,
        CloseSource = 1,
        SameAccess = 2,
        SameAttributes = 4,
    }

    public enum ObjectInformationClass
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectAllInformation,
        ObjectDataInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public class ObjectNameInformation
    {
        public UnicodeStringOut Name;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    public struct GenericMapping
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;

        public uint MapMask(uint mask)
        {
            NtRtl.RtlMapGenericMask(ref mask, ref this);
            return mask;
        }

        public override string ToString()
        {
            return String.Format("R:{0:X08} W:{1:X08} E:{2:X08} A:{3:X08}",
                GenericRead, GenericWrite, GenericExecute, GenericAll);
        }
    }

    

    [Flags]
    public enum SecurityInformation : uint
    {
        Owner = 1,
        Group = 2,
        Dacl = 4,
        Sacl = 8,
        Label = 0x10,
        Attribute = 0x20,
        Scope = 0x40,
        ProcessTrustLabel = 0x80,
        Backup = 0x10000,
        ProtectedDacl = 0x80000000,
        ProtectedSacl = 0x40000000,
        UnprotectedDacl = 0x20000000,
        UnprotectedSacl = 0x1000000,
        AllBasic = Dacl | Owner | Group | Label,
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

    /// <summary>
    /// Base class for all NtObject types we handle
    /// </summary>
    public abstract class NtObject : IDisposable
    {
        protected NtObject(SafeKernelObjectHandle handle)
        {
            SetHandle(handle);          
        }

        internal void SetHandle(SafeKernelObjectHandle handle)
        {
            Handle = handle;
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
                    StatusToNtException(status);
                if (return_length == 0)
                    ret = new SafeStructureInOutBuffer<T>();
                else
                    ret = new SafeStructureInOutBuffer<T>(return_length, false);
                status = NtSystemCalls.NtQueryObject(handle, object_info, ret.DangerousGetHandle(), ret.Length, out return_length);
                StatusToNtException(status);
            }
            finally
            {
                if (ret != null && !IsSuccess(status))
                {
                    ret.Close();
                    ret = null;
                }
            }
            return ret;
        }

        public static bool IsSuccess(int status)
        {
            return status >= 0;
        }

        public static bool IsSuccess(NtStatus status)
        {
            return IsSuccess((int)status);
        }

        public static void StatusToNtException(int status)
        {
            StatusToNtException((NtStatus)status);            
        }

        public static void StatusToNtException(NtStatus status)
        {
            if (!IsSuccess(status))
            {
                throw new NtException(status);
            }
        }

        public SafeKernelObjectHandle DuplicateHandle(NtProcess dest_process, uint access, DuplicateObjectOptions options)
        {
            SafeKernelObjectHandle new_handle;

            StatusToNtException(NtSystemCalls.NtDuplicateObject(NtProcess.Current.Handle, Handle,
              dest_process.Handle, out new_handle, (GenericAccessRights)access, AttributeFlags.None, 
              options));

            return new_handle;
        }

        public SafeKernelObjectHandle DuplicateHandle()
        {
            return DuplicateHandle(NtProcess.Current, 0, DuplicateObjectOptions.SameAccess);
        }

        public SafeKernelObjectHandle DuplicateHandle(uint access)
        {
            return DuplicateHandle(NtProcess.Current, access, DuplicateObjectOptions.None);
        }

        public SafeKernelObjectHandle DuplicateHandle(GenericAccessRights access)
        {
            return DuplicateHandle((uint)access);
        }

        public static SafeKernelObjectHandle DuplicateHandle(NtProcess source_process, SafeHandle handle, NtProcess dest_process, GenericAccessRights access_rights, DuplicateObjectOptions options)
        {
            SafeKernelObjectHandle new_handle;

            StatusToNtException(NtSystemCalls.NtDuplicateObject(source_process.Handle, handle,
              dest_process.Handle, out new_handle,
              GenericAccessRights.None, AttributeFlags.None, 
              DuplicateObjectOptions.SameAccess));            

            return new_handle;
        }

        public static SafeKernelObjectHandle DuplicateHandle(NtProcess source_process, SafeHandle handle, NtProcess dest_process, GenericAccessRights access_rights)
        {
            return DuplicateHandle(source_process, handle, dest_process, access_rights, DuplicateObjectOptions.None);
        }

        public static SafeKernelObjectHandle DuplicateHandle(NtProcess source_process, SafeHandle handle, NtProcess dest_process)
        {
            return DuplicateHandle(source_process, handle, dest_process, GenericAccessRights.None, DuplicateObjectOptions.SameAccess);
        }

        public static SafeKernelObjectHandle DuplicateHandle(SafeHandle handle)
        {
            return DuplicateHandle(NtProcess.Current, handle, NtProcess.Current);
        }

        public static SafeFileHandle DuplicateAsFile(SafeHandle handle)
        {
            using (SafeKernelObjectHandle dup_handle = DuplicateHandle(NtProcess.Current, handle, NtProcess.Current))
            {
                SafeFileHandle ret = new SafeFileHandle(dup_handle.DangerousGetHandle(), true);
                dup_handle.SetHandleAsInvalid();
                return ret;
            }
        }

        public static SafeRegistryHandle DuplicateAsRegistry(SafeHandle handle)
        {
            using (SafeKernelObjectHandle dup_handle = DuplicateHandle(NtProcess.Current, handle, NtProcess.Current))
            {
                SafeRegistryHandle ret = new SafeRegistryHandle(dup_handle.DangerousGetHandle(), true);
                dup_handle.SetHandleAsInvalid();
                return ret;
            }            
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

        public virtual string GetName()
        {
            return GetName(Handle);           
        }

        protected static uint GetGrantedAccessInternal(SafeKernelObjectHandle handle)
        {
            try
            {
                using (var basic_info = QueryObject<ObjectBasicInformation>(handle, ObjectInformationClass.ObjectBasicInformation))
                {
                    return basic_info.Result.DesiredAccess;
                }
            }
            catch
            {
                return 0;
            }
        }

        public uint GetGrantedAccessRaw()
        {
            return GetGrantedAccessInternal(Handle);
        }
        public static byte[] GetRawSecurityDescriptor(SafeKernelObjectHandle handle, SecurityInformation security_information)
        {
            int return_length;
            NtStatus status = NtSystemCalls.NtQuerySecurityObject(handle, security_information, null, 0, out return_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                StatusToNtException(status);
            byte[] buffer = new byte[return_length];
            StatusToNtException(NtSystemCalls.NtQuerySecurityObject(handle, security_information, buffer, buffer.Length, out return_length));
            return buffer;
        }

        public byte[] GetRawSecurityDescriptor(SecurityInformation security_information)
        {
            return GetRawSecurityDescriptor(Handle, security_information);         
        }

        public byte[] GetRawSecurityDescriptor()
        {
            return GetRawSecurityDescriptor(SecurityInformation.AllBasic);
        }

        public void SetSecurityDescriptor(byte[] security_desc, SecurityInformation security_information)
        {
            StatusToNtException(NtSystemCalls.NtSetSecurityObject(Handle, security_information, security_desc));            
        }

        public void SetSecurityDescriptor(SecurityDescriptor security_desc, SecurityInformation security_information)
        {
            SetSecurityDescriptor(security_desc.ToByteArray(), security_information);
        }

        public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
        {
            return new SecurityDescriptor(GetRawSecurityDescriptor(security_information));
        }

        public SecurityDescriptor GetSecurityDescriptor()
        {
            return GetSecurityDescriptor(SecurityInformation.AllBasic);
        }

        public string GetSddl()
        {
            return GetSecurityDescriptor().ToSddl();
        }

        public SafeKernelObjectHandle Handle { get; private set; }

        public void MakeTemporary()
        {
            StatusToNtException(NtSystemCalls.NtMakeTemporaryObject(Handle));
        }

        public void MakePermanent()
        {
            StatusToNtException(NtSystemCalls.NtMakePermanentObject(Handle));
        }

        public static NtObject OpenWithType(string typename, string path, NtObject root, GenericAccessRights access)
        {
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
                default:
                    throw new ArgumentException(String.Format("Can't open type {0}", typename));
            }
        }

        public string GetTypeName()
        {
            using (SafeStructureInOutBuffer<ObjectTypeInformation> type_info = new SafeStructureInOutBuffer<ObjectTypeInformation>(1024, true))
            {
                int return_length;
                StatusToNtException(NtSystemCalls.NtQueryObject(Handle, 
                    ObjectInformationClass.ObjectTypeInformation, type_info.DangerousGetHandle(), type_info.Length, out return_length));
                return type_info.Result.Name.ToString();
            }
        }

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

        public static string AccessRightsToString<T>(T access) where T : struct, IConvertible
        {
            CheckEnumType(typeof(T));
            return AccessRightsToString(typeof(T), access.ToUInt32(null));
        }

        public static string AccessRightsToString<T>(T access, ObjectTypeInfo typeinfo) where T : struct, IConvertible
        {
            CheckEnumType(typeof(T));
            uint mapped_access = typeinfo.MapGenericRights(access.ToUInt32(null));
            if ((mapped_access & typeinfo.GenericMapping.GenericAll) == typeinfo.GenericMapping.GenericAll)
            {
                return "Full Access";
            }
            return AccessRightsToString(typeof(T), mapped_access);
        }

        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                Handle.Close();
                disposedValue = true;
            }
        }
        
        ~NtObject()
        {            
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);         
            GC.SuppressFinalize(this);
        }

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
        public NtObjectWithDuplicate(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        private static O Create(params object[] ps)
        {
            return (O)Activator.CreateInstance(typeof(O), BindingFlags.NonPublic | BindingFlags.Instance, null, ps, null);
        }

        public O Duplicate(A access)
        {
            IConvertible a = access;
            return Duplicate(a.ToUInt32(null));            
        }

        public O Duplicate(uint access)
        {
            IConvertible a = access;

            return Create(DuplicateHandle(access));
        }

        public O Duplicate()
        {
            return Create(DuplicateHandle());
        }

        public A GetGrantedAccess() 
        {
            return GetGrantedAccess(Handle);
        }

        public static A GetGrantedAccess(SafeKernelObjectHandle handle) 
        {
            if (!typeof(A).IsEnum)
                throw new ArgumentException("Type of access must be an enum");
            return (A)Enum.ToObject(typeof(A), GetGrantedAccessInternal(handle));
        }

        public bool IsAccessGranted(A access)
        {
            uint access_raw = access.ToUInt32(null);
            return (GetGrantedAccessInternal(Handle) & access_raw) == access_raw;
        }

        public string GetGrantedAccessString()
        {
            ObjectTypeInfo type = ObjectTypeInfo.GetTypeByName(GetTypeName());

            return AccessRightsToString(GetGrantedAccess(), type);
        }

        public static O FromHandle(SafeKernelObjectHandle handle)
        {
            return Create(handle);
        }

        public static O DuplicateFrom(NtProcess process, IntPtr handle, A access)
        {
            return FromHandle(NtObject.DuplicateHandle(process, new SafeKernelObjectHandle(handle, false), NtProcess.Current, (GenericAccessRights)access.ToUInt32(null)));
        }

        public static O DuplicateFrom(int pid, IntPtr handle, A access)
        {
            using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.DupHandle))
            {
                return DuplicateFrom(process, handle, access);
            }
        }

        public static O DuplicateFrom(NtProcess process, IntPtr handle)
        {
            return FromHandle(NtObject.DuplicateHandle(process, new SafeKernelObjectHandle(handle, false), NtProcess.Current));
        }

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

        public T Cast<T>() where T : NtObject
        {
            return null;
        }
    }
}
