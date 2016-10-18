using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNetTests
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                using (NtKey key = NtKey.GetCurrentUserKey().Open("Console"))
                {
                    Console.WriteLine(key.GetName());

                    //using (NtToken token = NtToken.OpenProcessToken(true))
                    //{
                    //    SecurityDescriptor sd = new SecurityDescriptor();
                    //    sd.Sacl = new Acl();
                    //    sd.Sacl.NullAcl = false;
                    //    sd.Sacl.Add(new Ace(AceType.MandatoryLabel, AceFlags.None, 1, Sid.GetIntegritySid(TokenIntegrityLevel.Low)));
                    //    SecurityDescriptor sd2 = new SecurityDescriptor("S:(ML;;NW;;;LW)");
                    //    //Console.WriteLine(sd);
                    //    //token.SetIntegrityLevel(TokenIntegrityLevel.Low);
                    //    //SecurityDescriptor sd = new SecurityDescriptor(token);
                    //    using (NtKey key2 = NtKey.Create(new ObjectAttributes("ABC", AttributeFlags.CaseInsensitive, key, null, sd), KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile))
                    //    {
                    //        key2.Delete();
                    //    }
                    //}

                    //foreach (NtKeyValue s in key.QueryValues())
                    //{
                    //    Console.WriteLine("{0} - {1} - {2}", s.Name, s.Type, s.ToObject());
                    //}
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
