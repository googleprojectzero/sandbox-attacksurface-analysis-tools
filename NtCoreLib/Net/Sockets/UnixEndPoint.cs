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
///////////////////////////////////////////////////
// Based on the version in the CANAPE.Core project,
// relicensed by the author.
///////////////////////////////////////////////////

using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NtApiDotNet.Net.Sockets
{
    /// <summary>
    /// Endpoint implementation for a AF_UNIX socket.
    /// </summary>
    [Serializable]
    public class UnixEndPoint : EndPoint
    {
        private const int UNIX_PATH_MAX = 108;
        private byte[] _path_bytes;

        private string GetPath()
        {
            if (_path_bytes.Length == 0 || _path_bytes[0] == '\0')
            {
                return string.Empty;
            }
            return Encoding.UTF8.GetString(_path_bytes).TrimEnd('\0');
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        public UnixEndPoint()
        {
            _path_bytes = new byte[0];
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="path">The path to the unix socket.</param>
        public UnixEndPoint(string path)
        {
            Path = path;
        }

        /// <summary>
        /// Get or set the path.
        /// </summary>
        public string Path
        {
            get => GetPath();
            set
            {
                byte[] path_bytes = Encoding.UTF8.GetBytes(value + "\0");
                if (path_bytes.Length > UNIX_PATH_MAX)
                {
                    throw new ArgumentException("Path can't be longer than 108 bytes including terminator");
                }
                _path_bytes = path_bytes;
            }
        }

        /// <summary>
        /// Address family.
        /// </summary>
        public override AddressFamily AddressFamily => AddressFamily.Unix;

        /// <summary>
        /// Serialize the socket address.
        /// </summary>
        /// <returns>The serialized address.</returns>
        public override SocketAddress Serialize()
        {
            // At least on Windows you need to allocate the entire address otherwise bad things happen.
            var addr = new SocketAddress(AddressFamily.Unix, 110);
            // The first two bytes should already be filled out.
            for (int i = 0; i < _path_bytes.Length; ++i)
            {
                addr[i + 2] = _path_bytes[i];
            }
            return addr;
        }

        /// <summary>
        /// Create a endpoint from a socket address.
        /// </summary>
        /// <param name="socketAddress">The socket address.</param>
        /// <returns>The created endpoint.</returns>
        public override EndPoint Create(SocketAddress socketAddress)
        {
            var ep = new UnixEndPoint
            {
                _path_bytes = new byte[socketAddress.Size - 2]
            };
            var family = (AddressFamily)(socketAddress[0] | (socketAddress[1] << 8));
            if (family != AddressFamily.Unix)
            {
                throw new ArgumentException("Family in socket address isn't AF_UNIX");
            }

            for (int i = 0; i < socketAddress.Size - 2; ++i)
            {
                ep._path_bytes[i] = socketAddress[i + 2];
            }
            return ep;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The endpoint as a string.</returns>
        public override string ToString()
        {
            return Path;
        }

        /// <summary>
        /// Overridden equals method.
        /// </summary>
        /// <param name="obj">The object to compare.</param>
        /// <returns>True if the objects are equal.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is UnixEndPoint))
            {
                return false;
            }

            UnixEndPoint ep = (UnixEndPoint)obj;
            if (ep._path_bytes.Length != _path_bytes.Length)
            {
                return false;
            }

            for (int i = 0; i < _path_bytes.Length; ++i)
            {
                if (_path_bytes[i] != ep._path_bytes[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Get endpoint hash code.
        /// </summary>
        /// <returns>The hashcode.</returns>
        public override int GetHashCode()
        {
            return _path_bytes.Aggregate(0, (a, b) => a ^ b);
        }
    }
}
