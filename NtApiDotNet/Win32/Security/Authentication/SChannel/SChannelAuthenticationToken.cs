using NtApiDotNet.Utilities.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Authentication.SChannel
{
    /// <summary>
    /// Authentication token for SChannel and CredSSP.
    /// </summary>
    /// <remarks>This is a simple parser for the TLS record format.</remarks>
    public class SChannelAuthenticationToken : AuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// TLS record type.
        /// </summary>
        public TlsRecordType RecordType { get; }
        
        /// <summary>
        /// Major version of protocol.
        /// </summary>
        public int MajorVersion { get; }

        /// <summary>
        /// Minor version of protocol.
        /// </summary>
        public int MinorVersion { get; }

        /// <summary>
        /// The record data.
        /// </summary>
        public byte[] RecordData { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns>The token as a formatted string.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"SChannel: {RecordType}");
            builder.AppendLine($"Version: {MajorVersion}.{MinorVersion}");
            builder.AppendLine("Record Data:");
            HexDumpBuilder hex_builder = new HexDumpBuilder(true, true, true, false, 0);
            hex_builder.Append(RecordData);
            hex_builder.Complete();
            builder.AppendLine(hex_builder.ToString());
            return builder.ToString();
        }
        #endregion

        #region Constructors

        internal SChannelAuthenticationToken(byte[] data, TlsRecordType record_type, 
            int major_version, int minor_version, byte[] record_data) : base(data)
        {
            RecordType = record_type;
            MajorVersion = major_version;
            MinorVersion = minor_version;
            RecordData = record_data;
        }

        #endregion

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an SChannel authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The SChannel authentication token.</param>
        /// <param name="client">True if this is a token from a client.</param>
        /// <param name="token_count">The token count number.</param>
        /// <returns>True if parsed successfully.</returns>
        internal static bool TryParse(byte[] data, int token_count, bool client, out SChannelAuthenticationToken token)
        {
            token = null;
            if (data.Length < 5)
                return false;

            int length = (data[3] << 8) | data[4];
            if (data.Length != (length + 5))
                return false;
            byte[] record_data = new byte[length];
            Buffer.BlockCopy(data, 5, record_data, 0, record_data.Length);
            token = new SChannelAuthenticationToken(data, (TlsRecordType)data[0],
                data[1], data[2], record_data);
            return true;
        }
        #endregion
    }
}
