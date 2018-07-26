using NtApiDotNet.Ndr;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class to represent an RPC endpoint.
    /// </summary>
    public class RpcEndpoint
    {
        /// <summary>
        /// The interface ID of the endpoint.
        /// </summary>
        public Guid InterfaceId { get; }
        /// <summary>
        /// The interface version.
        /// </summary>
        public Version InterfaceVersion { get; }
        /// <summary>
        /// The object UUID.
        /// </summary>
        public Guid ObjectUuid { get; }
        /// <summary>
        /// Optional annotation.
        /// </summary>
        public string Annotation { get; }
        /// <summary>
        /// RPC binding string.
        /// </summary>
        public string BindingString { get; }
        /// <summary>
        /// Endpoint protocol sequence.
        /// </summary>
        public string Protseq { get; }
        /// <summary>
        /// Endpoint network address.
        /// </summary>
        public string NetworkAddr { get; }
        /// <summary>
        /// Endpoint name.
        /// </summary>
        public string Endpoint { get; }
        /// <summary>
        /// Endpoint network options.
        /// </summary>
        public string NetworkOptions { get; }

        internal RpcEndpoint(RPC_IF_ID if_id, UUID uuid, SafeRpcStringHandle annotation, SafeRpcBindingHandle binding)
        {
            InterfaceId = if_id.Uuid;
            InterfaceVersion = new Version(if_id.VersMajor, if_id.VersMinor);
            ObjectUuid = uuid.Uuid;
            Annotation = annotation.ToString();
            BindingString = binding.ToString();
            var cracked = new CrackedBindingString(BindingString);
            Protseq = cracked.Protseq;
            NetworkAddr = cracked.NetworkAddr;
            Endpoint = cracked.Endpoint;
            NetworkOptions = cracked.NetworkOptions;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>String form of the object.</returns>
        public override string ToString()
        {
            return $"[{InterfaceId}, {InterfaceVersion}] {BindingString}";
        }
    }

    /// <summary>
    /// Static class to access information from the RPC mapper.
    /// </summary>
    public static class RpcEndpointMapper
    {
        private static IEnumerable<RpcEndpoint> QueryEndpoints(SafeRpcBindingHandle search_binding)
        {
            using (search_binding)
            {
                int status = NdrNativeUtils.RpcMgmtEpEltInqBegin(search_binding, RpcEndpointInquiryFlag.All,
                    null, RpcEndPointVersionOption.All, null, out SafeRpcInquiryHandle inquiry);
                if (status != 0)
                {
                    throw new SafeWin32Exception(status);
                }

                using (inquiry)
                {
                    while (true)
                    {
                        RPC_IF_ID if_id = new RPC_IF_ID();
                        UUID uuid = new UUID();
                        status = NdrNativeUtils.RpcMgmtEpEltInqNext(inquiry, if_id, out SafeRpcBindingHandle binding, uuid, out SafeRpcStringHandle annotation);
                        if (status != 0)
                        {
                            if (status == 1772)
                            {
                                break;
                            }
                            throw new SafeWin32Exception(status);
                        }
                        try
                        {
                            yield return new RpcEndpoint(if_id, uuid, annotation, binding);
                        }
                        finally
                        {
                            binding.Dispose();
                            annotation.Dispose();
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Query all endpoints registered on the local system.
        /// </summary>
        /// <returns>List of endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryAllEndpoints()
        {
            return QueryEndpoints(SafeRpcBindingHandle.Null);
        }
    }
}
