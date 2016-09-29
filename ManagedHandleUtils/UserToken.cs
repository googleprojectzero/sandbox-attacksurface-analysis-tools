using NtApiDotNet;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace HandleUtils
{
    public sealed class UserToken : IDisposable
    {
        NtApiDotNet.NtToken _token;

        public UserGroup GetUser()
        {
            try
            {
                return _token.GetUser();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public TokenType GetTokenType()
        {
            try
            {
                return _token.GetTokenType();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public SecurityImpersonationLevel GetImpersonationLevel()
        {
            try
            {
                return _token.GetImpersonationLevel();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public TokenIntegrityLevel GetTokenIntegrityLevel()
        {
            try
            {
                return _token.GetIntegrityLevel();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public void SetTokenIntegrityLevel(TokenIntegrityLevel token_il)
        {
            try
            {
                _token.SetIntegrityLevel(token_il);
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public long GetAuthenticationId()
        {
            try
            {
                return _token.GetAuthenticationId().ToInt64();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public long GetTokenId()
        {
            try
            {
                return _token.GetId().ToInt64();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public long GetModifiedId()
        {
            try
            {
                return _token.GetModifiedId().ToInt64();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public int GetSessionId()
        {
            try
            {
                return _token.GetSessionId();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public void SetSessionId(int session_id)
        {
            try
            {
                using (NtToken token = _token.Duplicate(NtApiDotNet.TokenAccessRights.AdjustSessionId))
                {
                    token.SetSessionId(session_id);
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public string GetSourceName()
        {
            try
            {
                return _token.GetSource().SourceName;
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public long GetSourceId()
        {
            try
            {
                return _token.GetSource().SourceIdentifier.ToInt64();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public long GetTokenOriginId()
        {
            try
            {
                return _token.GetOrigin().ToInt64();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserToken GetLinkedToken()
        {
            try
            {
                NtApiDotNet.NtToken token = _token.GetLinkedToken();
                if (token.Handle.IsInvalid)
                {
                    return new UserToken(token);
                }
                else
                {
                    return null;
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserGroup[] GetGroups()
        {
            try
            {
                return _token.GetGroups();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public TokenPrivilege[] GetPrivileges()
        {
            try
            {
                return _token.GetPrivileges();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserGroup GetDefaultOwner()
        {
            try
            {
                return new UserGroup(_token.GetOwner(), NtApiDotNet.GroupAttributes.None);
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserGroup GetPrimaryGroup()
        {
            try
            {
                return new UserGroup(_token.GetPrimaryGroup(), NtApiDotNet.GroupAttributes.None);
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public RawAcl GetDefaultDacl()
        {
            try
            {
                NtApiDotNet.Acl acl = _token.GetDefaultDalc();
                if (acl.NullAcl)
                {
                    return null;
                }
                return new RawAcl(acl.ToByteArray(), 0);
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public void SetNullDefaultDacl()
        {
            try
            {
                using (var token = _token.Duplicate(NtApiDotNet.TokenAccessRights.WriteDac))
                {
                    token.SetDefaultDacl(new NtApiDotNet.Acl() { NullAcl = true });
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public bool IsUIAccess()
        {
            try
            {
                return _token.IsUiAccess();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public bool IsSandboxInert()
        {
            try
            {
                return _token.IsSandboxInert();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public bool IsVirtualizationAllowed()
        {
            try
            {
                return _token.IsVirtualizationAllowed();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public bool IsVirtualizationEnabled()
        {
            try
            {
                if (IsVirtualizationAllowed())
                {
                    return _token.IsVirtualizationEnabled();
                }
                else
                {
                    return false;
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public TokenElevationType GetElevationType()
        {
            try
            {
                return (TokenElevationType)_token.GetElevationType();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public bool IsElevated()
        {
            try
            {
                return _token.IsElevated();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public bool IsRestricted()
        {
            try
            {
                return _token.IsRestricted();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserGroup[] GetRestrictedSids()
        {
            try
            {
                return _token.GetRestrictedSids();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public bool IsAppContainer()
        {
            try
            {
                return _token.IsAppContainer();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserGroup GetPackageSid()
        {
            if (IsAppContainer())
            {
                return new UserGroup(_token.GetAppContainerSid(), NtApiDotNet.GroupAttributes.None);
            }
            else
            {
                return null;
            }            
        }

        public int GetAppContainerNumber()
        {
            try
            {
                return _token.GetAppContainerNumber();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserGroup[] GetCapabilities()
        {
            if (IsAppContainer())
            {
                try
                {
                    return _token.GetCapabilities();
                }
                catch (NtApiDotNet.NtException ex)
                {
                    throw ex.AsWin32Exception();
                }
            }
            return new UserGroup[0];
        }

        public UserToken DuplicateToken(TokenType type, SecurityImpersonationLevel implevel)
        {
            try
            {
                using (NtToken token = _token.Duplicate(NtApiDotNet.TokenAccessRights.Duplicate))
                {
                    return new UserToken(token.DuplicateToken(type, implevel));
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserToken DuplicateToken(TokenType type, SecurityImpersonationLevel implevel, TokenIntegrityLevel token_il)
        {
            UserToken ret = DuplicateToken(type, implevel);
            ret.SetTokenIntegrityLevel(token_il);
            return ret;
        }

        public UserToken DuplicateHandle()
        {
            try
            {
                return new UserToken(_token.Duplicate());
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserToken DuplicateHandle(uint access_rights)
        {
            try
            {
                return new UserToken(_token.Duplicate(access_rights));
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserToken MakeLuaToken()
        {
            try
            {
                return new UserToken(_token.Filter(NtApiDotNet.FilterTokenFlags.LuaToken, 
                    new NtApiDotNet.Sid[0], new NtApiDotNet.TokenPrivilegeValue[0], new NtApiDotNet.Sid[0]));
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public UserToken CreateRestrictedToken(UserGroup[] disable_sids, TokenPrivilege[] disable_privs, UserGroup[] restricted_sids, FilterTokenFlags flags)
        {
            try
            {
                using (NtToken token = _token.Duplicate(NtApiDotNet.TokenAccessRights.GenericRead | NtApiDotNet.TokenAccessRights.GenericExecute))
                {
                    return new UserToken(token.Filter(flags, disable_sids.Select(g => g.Sid),
                        disable_privs.Select(p => p.Luid), restricted_sids.Select(g => g.Sid)));
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public TokenMandatoryPolicy GetIntegrityLevelPolicy()
        {
            try
            {
                return _token.GetMandatoryPolicy();
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public ImpersonateProcess Impersonate()
        {
            try
            {
                NtApiDotNet.TokenAccessRights access_rights = NtApiDotNet.TokenAccessRights.GenericRead | NtApiDotNet.TokenAccessRights.GenericExecute;
                return new ImpersonateProcess(_token.DuplicateHandle((NtApiDotNet.GenericAccessRights)access_rights));
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public void EnablePrivilege(TokenPrivilege priv, bool enable)
        {
            try
            {
                using (NtApiDotNet.NtToken token = _token.Duplicate(NtApiDotNet.TokenAccessRights.AdjustPrivileges))
                {
                    token.SetPrivilege(new NtApiDotNet.TokenPrivilege(priv.Luid,
                        enable ? NtApiDotNet.PrivilegeAttributes.Enabled : NtApiDotNet.PrivilegeAttributes.Disabled));
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public void EnableGroup(UserGroup group, bool enable)
        {
            try
            {
                using (NtApiDotNet.NtToken token = _token.Duplicate(NtApiDotNet.TokenAccessRights.AdjustGroups))
                {
                    token.SetGroup(group.Sid, enable ? NtApiDotNet.GroupAttributes.Enabled : NtApiDotNet.GroupAttributes.None);
                }
            }
            catch (NtApiDotNet.NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        public SafeHandle Handle
        {
            get
            {
                return _token.Handle;
            }            
        }

        public NtToken Token
        {
            get { return _token; }
        }

        public void Close()
        {
            _token.Close();
        }

        public void Dispose()
        {
            Close();
        }

        public UserToken(NtApiDotNet.NtToken token)
        {
            _token = token;
        }

        public UserToken(NativeHandle handle)
        {
            using (handle)
            {
                _token = NtApiDotNet.NtToken.FromHandle(handle.GetNtApiHandle());
            }
        }
    }
}
