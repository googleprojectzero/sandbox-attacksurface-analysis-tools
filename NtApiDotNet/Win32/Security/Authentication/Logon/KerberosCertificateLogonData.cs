//  Copyright 2022 Google LLC. All Rights Reserved.
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

using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Base class for CSP data.
    /// </summary>
    public abstract class KerberosCertificateLogonData
    {
        internal abstract byte[] GetData();
        internal abstract int GetLogonType();

        internal byte[] ToArray()
        {
            byte[] data = GetData();
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(data.Length);
            writer.Write(GetLogonType());
            writer.Write(data);
            return stm.ToArray();
        }
    }
}
