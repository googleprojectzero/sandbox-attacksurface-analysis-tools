//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtApiDotNet;
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SandboxPowerShellApi
{
    public class GenericObjectSecurity : ObjectSecurity<int>
    {
        public GenericObjectSecurity() : base(false, ResourceType.KernelObject)
        {
        }

        public GenericObjectSecurity(NtObject obj, AccessControlSections include_sections) : base(false, ResourceType.KernelObject, obj.Handle, include_sections)
        {
        }

        internal void PersistHandle(SafeHandle handle)
        {
            base.Persist(handle);
        }
    }

    public class GenericObjectSecurity2 : GenericObjectSecurity<DirectoryAccessRights>
    {
        public GenericObjectSecurity2() : base(false, ResourceType.KernelObject)
        {
        }

        public GenericObjectSecurity2(NtObject obj, AccessControlSections include_sections) : base(false, ResourceType.KernelObject, obj.Handle, include_sections)
        {
        }

        internal void PersistHandle(SafeHandle handle)
        {
            base.Persist(handle);
        }
    }

    public class GenericAuditRule<T> : AuditRule where T : struct, IConvertible
    {
        public T Rights
        {
            get
            {
                return (T)((object)Convert.ToUInt32(base.AccessMask));
            }
        }

        public GenericAuditRule(IdentityReference identity, T rights, AuditFlags flags) : this(identity, rights, InheritanceFlags.None, PropagationFlags.None, flags)
        {
        }

        public GenericAuditRule(IdentityReference identity, T rights, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
            : this(identity, (int)rights.ToUInt32(null), false, inheritanceFlags, propagationFlags, flags)
        {
        }

        public GenericAuditRule(string identity, T rights, AuditFlags flags)
            : this(new NTAccount(identity), rights, InheritanceFlags.None, PropagationFlags.None, flags)
        {
        }

        public GenericAuditRule(string identity, T rights, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
            : this(new NTAccount(identity), (int)rights.ToUInt32(null), false, inheritanceFlags, propagationFlags, flags)
        {
        }

        internal GenericAuditRule(IdentityReference identity, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
            : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, flags)
        {
        }
    }

    public class GenericAccessRule<T> : AccessRule where T : struct, IConvertible
    {
        public T Rights
        {
            get
            {
                return (T)((object)Convert.ToUInt32(base.AccessMask));
            }
        }

        public GenericAccessRule(IdentityReference identity, T rights, AccessControlType type)
            : this(identity, (int)rights.ToUInt32(null), false, InheritanceFlags.None, PropagationFlags.None, type)
        {
        }

        public GenericAccessRule(string identity, T rights, AccessControlType type)
            : this(new NTAccount(identity), (int)rights.ToUInt32(null), false, InheritanceFlags.None, PropagationFlags.None, type)
        {
        }

        public GenericAccessRule(IdentityReference identity, T rights, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
            : this(identity, (int)rights.ToUInt32(null), false, inheritanceFlags, propagationFlags, type)
        {
        }

        public GenericAccessRule(string identity, T rights, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
            : this(new NTAccount(identity), (int)rights.ToUInt32(null), false, inheritanceFlags, propagationFlags, type)
        {
        }

        internal GenericAccessRule(IdentityReference identity, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
            : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, type)
        {
        }
    }

    public class GenericObjectSecurity<T> : NativeObjectSecurity where T : struct, IConvertible
    {
        public override Type AccessRightType
        {
            get
            {
                return typeof(T);
            }
        }

        public override Type AccessRuleType
        {
            get
            {
                return typeof(GenericAccessRule<T>);
            }
        }

        public override Type AuditRuleType
        {
            get
            {
                return typeof(AuditRule<T>);
            }
        }

        protected GenericObjectSecurity(bool isContainer, ResourceType resourceType) : base(isContainer, resourceType, null, null)
        {
        }

        protected GenericObjectSecurity(bool isContainer, ResourceType resourceType, string name, AccessControlSections includeSections) : base(isContainer, resourceType, name, includeSections, null, null)
        {
        }

        protected GenericObjectSecurity(bool isContainer, ResourceType resourceType, string name, AccessControlSections includeSections, NativeObjectSecurity.ExceptionFromErrorCode exceptionFromErrorCode, object exceptionContext) : base(isContainer, resourceType, name, includeSections, exceptionFromErrorCode, exceptionContext)
        {
        }

        protected GenericObjectSecurity(bool isContainer, ResourceType resourceType, SafeHandle safeHandle, AccessControlSections includeSections) : base(isContainer, resourceType, safeHandle, includeSections, null, null)
        {
        }

        protected GenericObjectSecurity(bool isContainer, ResourceType resourceType, SafeHandle safeHandle, AccessControlSections includeSections, NativeObjectSecurity.ExceptionFromErrorCode exceptionFromErrorCode, object exceptionContext) : base(isContainer, resourceType, safeHandle, includeSections, exceptionFromErrorCode, exceptionContext)
        {
        }

        public override AccessRule AccessRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
        {
            return new GenericAccessRule<T>(identityReference, accessMask, isInherited, inheritanceFlags, propagationFlags, type);
        }

        public override AuditRule AuditRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
        {
            return new GenericAuditRule<T>(identityReference, accessMask, isInherited, inheritanceFlags, propagationFlags, flags);
        }

        private AccessControlSections GetAccessControlSectionsFromChanges()
        {
            AccessControlSections accessControlSections = AccessControlSections.None;
            if (base.AccessRulesModified)
            {
                accessControlSections = AccessControlSections.Access;
            }
            if (base.AuditRulesModified)
            {
                accessControlSections |= AccessControlSections.Audit;
            }
            if (base.OwnerModified)
            {
                accessControlSections |= AccessControlSections.Owner;
            }
            if (base.GroupModified)
            {
                accessControlSections |= AccessControlSections.Group;
            }
            return accessControlSections;
        }

        protected internal void Persist(SafeHandle handle)
        {
            base.WriteLock();
            try
            {
                AccessControlSections accessControlSectionsFromChanges = this.GetAccessControlSectionsFromChanges();
                base.Persist(handle, accessControlSectionsFromChanges);
                base.OwnerModified = (base.GroupModified = (base.AuditRulesModified = (base.AccessRulesModified = false)));
            }
            finally
            {
                base.WriteUnlock();
            }
        }

        public virtual void AddAccessRule(GenericAccessRule<T> rule)
        {
            base.AddAccessRule(rule);
        }

        public virtual void SetAccessRule(GenericAccessRule<T> rule)
        {
            base.SetAccessRule(rule);
        }

        public virtual void ResetAccessRule(GenericAccessRule<T> rule)
        {
            base.ResetAccessRule(rule);
        }

        public virtual bool RemoveAccessRule(GenericAccessRule<T> rule)
        {
            return base.RemoveAccessRule(rule);
        }

        public virtual void RemoveAccessRuleAll(GenericAccessRule<T> rule)
        {
            base.RemoveAccessRuleAll(rule);
        }

        public virtual void RemoveAccessRuleSpecific(GenericAccessRule<T> rule)
        {
            base.RemoveAccessRuleSpecific(rule);
        }

        public virtual void AddAuditRule(GenericAuditRule<T> rule)
        {
            base.AddAuditRule(rule);
        }

        public virtual void SetAuditRule(GenericAuditRule<T> rule)
        {
            base.SetAuditRule(rule);
        }

        public virtual bool RemoveAuditRule(GenericAuditRule<T> rule)
        {
            return base.RemoveAuditRule(rule);
        }

        public virtual void RemoveAuditRuleAll(GenericAuditRule<T> rule)
        {
            base.RemoveAuditRuleAll(rule);
        }

        public virtual void RemoveAuditRuleSpecific(GenericAuditRule<T> rule)
        {
            base.RemoveAuditRuleSpecific(rule);
        }
    }
}
