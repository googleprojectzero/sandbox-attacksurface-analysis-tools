//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Utilities.ASN1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authenticode
{
    /// <summary>
    /// Class to represent a single authenticode certificate entry.
    /// </summary>
    public sealed class AuthenticodeCertificate
    {
        private const string SPC_INDIRECT_DATA_OBJID = "1.3.6.1.4.1.311.2.1.4";
        private const string SPC_PE_IMAGE_DATAOBJ = "1.3.6.1.4.1.311.2.1.15";
        private static Guid SPCSERIALIZED_OBJECT = new Guid("d586b5a6-a1b4-6624-ae05-a217da8e60d6");
        private const string SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID = "1.3.6.1.4.1.311.2.3.1";
        private const string SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID = "1.3.6.1.4.1.311.2.3.2";

        /// <summary>
        /// The list of certificates in the entry.
        /// </summary>
        public IReadOnlyList<X509Certificate2> Certificates { get; }

        /// <summary>
        /// Whethe the entry contains page hashes.
        /// </summary>
        public bool ContainsPageHash { get; }

        private AuthenticodeCertificate(IEnumerable<X509Certificate2> certs, bool contains_page_hash)
        {
            Certificates = certs.ToList().AsReadOnly();
            ContainsPageHash = contains_page_hash;
        }

        private static bool CheckForPageHash(DERValue root)
        {
            if (!root.CheckSequence() || !root.HasChildren())
                return false;
            root = root.Children[0];
            if (!root.CheckSequence() || !root.HasChildren())
                return false;
            if (root.Children.Length < 2 || root.ReadChildObjID() != SPC_PE_IMAGE_DATAOBJ || !root.Children[1].CheckSequence())
                return false;
            root = root.Children[1];
            if (root.Children.Length < 2 || !root.Children[0].CheckPrimitive(UniversalTag.BIT_STRING) || !root.Children[1].CheckContext(0))
                return false;
            root = root.Children[1];
            if (root.Children.Length < 1 || !root.Children[0].CheckContext(1))
                return false;
            root = root.Children[0];
            if (root.Children.Length < 2 || !root.Children[0].CheckPrimitive(UniversalTag.OCTET_STRING) 
                || !root.Children[1].CheckPrimitive(UniversalTag.OCTET_STRING))
                return false;
            if (root.Children[0].Data.Length != 16)
                return false;
            if (new Guid(root.Children[0].Data) != SPCSERIALIZED_OBJECT)
                return false;

            DERValue[] values = DERParser.ParseData(root.Children[1].Data, 0);
            if (values.Length < 1)
                return false;
            var objid = values[0].GetChild(0)?.GetChild(0);
            if (!objid?.CheckPrimitive(UniversalTag.OBJECT_IDENTIFIER) ?? false)
                return false;

            string objid_value = objid.Value.ReadObjID();
            return objid_value == SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID 
                || objid_value == SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID;
        }

        internal static NtResult<AuthenticodeCertificate> Parse(byte[] data, bool throw_on_error)
        {
            try
            {
                var cms = new SignedCms();
                cms.Decode(data);
                if (cms.ContentInfo.ContentType.Value != SPC_INDIRECT_DATA_OBJID)
                    return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<AuthenticodeCertificate>(throw_on_error);
                var values = DERParser.ParseData(cms.ContentInfo.Content, 0);
                if (values.Length < 1)
                    return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<AuthenticodeCertificate>(throw_on_error);
                return new AuthenticodeCertificate(cms.Certificates.Cast<X509Certificate2>(), CheckForPageHash(values[0])).CreateResult();
            }
            catch (EndOfStreamException)
            {
                return NtStatus.STATUS_END_OF_FILE.CreateResultFromError<AuthenticodeCertificate>(throw_on_error);
            }
            catch (CryptographicException)
            {
                return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<AuthenticodeCertificate>(throw_on_error);
            }
            catch (InvalidDataException)
            {
                return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<AuthenticodeCertificate>(throw_on_error);
            }
        }
    }
}
