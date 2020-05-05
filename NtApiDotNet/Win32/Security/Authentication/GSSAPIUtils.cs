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
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// A class which represents an GSS-API Token.
    /// </summary>
    internal static class GSSAPIUtils
    {
        #region Internal Static Methods
        internal static bool TryParse(byte[] data, out byte[] token, out string oid)
        {
            token = null;
            oid = string.Empty;
            try
            {
                BinaryReader reader = new BinaryReader(new MemoryStream(data));

                byte start = reader.ReadByte();
                if (start != 0x60)
                    return false;
                int length = DERUtils.ReadLength(reader);
                byte[] inner_token = reader.ReadAllBytes(length);
                reader = new BinaryReader(new MemoryStream(inner_token));
                if (reader.ReadByte() != 0x06)
                    return false;
                int oid_length = DERUtils.ReadLength(reader);
                oid = DERUtils.ReadObjID(reader.ReadAllBytes(oid_length));
                token = reader.ReadAllBytes((int)reader.RemainingLength());
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }
        #endregion
    }
}
