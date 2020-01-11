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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet
{
    /// <summary>
    /// Flags for a boundary descriptor
    /// </summary>
    [Flags]
    public enum BoundaryDescriptorFlags
    {
        /// <summary>
        /// None
        /// </summary>
        None = 0,

        /// <summary>
        /// Automatically add the AppContainer package SID to the boundary
        /// </summary>
        AddPackageSid = 1,
    }

    /// <summary>
    /// Class which represents a private namespace boundary descriptor
    /// </summary>
    public sealed class BoundaryDescriptor : IDisposable
    {
        #region Private Members
        private IntPtr _boundary_descriptor;

        private void AddIntegrityLevel(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {
                NtRtl.RtlAddIntegrityLabelToBoundaryDescriptor(ref _boundary_descriptor, sid_buffer).ToNtException();
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">The name of the boundary</param>
        /// <param name="flags">Additional flags for the boundary</param>
        public BoundaryDescriptor(string name, BoundaryDescriptorFlags flags)
        {
            _boundary_descriptor = NtRtl.RtlCreateBoundaryDescriptor(new UnicodeString(name), flags);
            if (_boundary_descriptor == IntPtr.Zero)
            {
                throw new NtException(NtStatus.STATUS_MEMORY_NOT_ALLOCATED);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">The name of the boundary</param>
        public BoundaryDescriptor(string name)
            : this(name, BoundaryDescriptorFlags.None)
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add a SID to the boundary descriptor.
        /// </summary>
        /// <remarks>This SID is used in an access check when creating or deleting private namespaces.</remarks>
        /// <param name="sid">The SID to add.</param>
        public void AddSid(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {
                NtRtl.RtlAddSIDToBoundaryDescriptor(ref _boundary_descriptor, sid_buffer).ToNtException();
            }
        }

        /// <summary>
        /// Add an integrity level to the boundary descriptor.
        /// </summary>
        /// <remarks>This integrity level is used in an access check when creating or deleting private namespaces.</remarks>
        /// <param name="integrity_level">The integrity level to add.</param>
        public void AddIntegrityLevel(TokenIntegrityLevel integrity_level)
        {
            AddIntegrityLevel(NtSecurity.GetIntegritySid(integrity_level));
        }

        /// <summary>
        /// Add a list of SIDs to the boundary descriptor. 
        /// </summary>
        /// <param name="sids">The SIDs to add. This can include normal and integrity level SIDs</param>
        public void AddSids(IEnumerable<Sid> sids)
        {
            foreach (Sid sid in sids)
            {
                if (NtSecurity.IsIntegritySid(sid))
                {
                    AddIntegrityLevel(sid);
                }
                else
                {
                    AddSid(sid);
                }
            }
        }

        /// <summary>
        /// Add a list of SIDs to the boundary descriptor. 
        /// </summary>
        /// <param name="sid">The first SID to add</param>
        /// <param name="sids">Additional SIDs</param>
        public void AddSids(Sid sid, params Sid[] sids)
        {
            AddSids(new Sid[] { sid }.Concat(sids));
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The handle to the boundary descriptor. 
        /// </summary>
        public IntPtr Handle => _boundary_descriptor;
        #endregion

        #region Static Methods
        /// <summary>
        /// Create a boundary descriptor from a string representation.
        /// </summary>
        /// <param name="descriptor">A boundary descriptor string of the form [SID[:SID...]@]NAME where SID is an SDDL format SID.</param>
        /// <returns>The new boundary descriptor.</returns>
        public static BoundaryDescriptor CreateFromString(string descriptor)
        {
            string[] parts = descriptor.Split(new char[] { '@' }, 2);
            string obj_name = parts.Length > 1 ? parts[1] : parts[0];

            BoundaryDescriptor boundary = new BoundaryDescriptor(obj_name);

            if (parts.Length > 1)
            {
                boundary.AddSids(parts[0].Split(':').Select(s => new Sid(s)));
            }

            return boundary;
        }
        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                NtRtl.RtlDeleteBoundaryDescriptor(_boundary_descriptor);
                disposedValue = true;
            }
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~BoundaryDescriptor()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
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
        #endregion
    }
}
