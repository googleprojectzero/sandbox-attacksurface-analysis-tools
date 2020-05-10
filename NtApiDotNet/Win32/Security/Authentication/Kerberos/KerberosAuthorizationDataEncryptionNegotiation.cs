using NtApiDotNet.Utilities.ASN1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent AD_ETYPE_NEGOTIATION type.
    /// </summary>
    public class KerberosAuthorizationDataEncryptionNegotiation : KerberosAuthorizationData
    {
        /// <summary>
        /// List of supported encryption types.
        /// </summary>
        public IEnumerable<KerberosEncryptionType> EncryptionList { get; }

        private protected KerberosAuthorizationDataEncryptionNegotiation(byte[] data, IEnumerable<KerberosEncryptionType> enc_list) 
            : base(KerberosAuthorizationDataType.AD_ETYPE_NEGOTIATION, data)
        {
            EncryptionList = enc_list;
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine(string.Join(", ", EncryptionList));
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataEncryptionNegotiation entry)
        {
            entry = null;
            DERValue[] values = DERParser.ParseData(data, 0);
            if (!values.CheckValueSequence())
                return false;
            List<KerberosEncryptionType> enc_types = new List<KerberosEncryptionType>();
            try
            {
                foreach (var next in values[0].Children)
                {
                    if (!next.CheckPrimitive(UniversalTag.INTEGER))
                        return false;
                    enc_types.Add((KerberosEncryptionType)next.ReadInteger());
                }
            }
            catch (InvalidDataException)
            {
                return false;
            }

            entry = new KerberosAuthorizationDataEncryptionNegotiation(data, enc_types.AsReadOnly());
            return true;
        }
    }
}
