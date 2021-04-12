#include <Windows.h>
#include <array>
#include <iostream>
#include <vector>
#include <synchapi.h>
#include "Prototypes.h"
#include <winnt.h>


using AquireOrRelease = NTSTATUS(NTAPI*)();

typedef std::pair <PLIST_ENTRY, int> Pair;

struct Info
{
	PLIST_ENTRY pListHead = nullptr, pListMod = nullptr;
	PEB_LDR_DATA* pLdr = nullptr;
	UNICODE_STRING* pModName = nullptr;
	PLDR_MODULE pLdrMod = NULL;
	uintptr_t PebAddr = NULL;
	AquireOrRelease PebLock;
	AquireOrRelease ReleasePebLock;
	char tModName[MAX_PATH];
	
} UnlinkData;

uintptr_t GetPEB()
{

	uintptr_t  PebAddr;

	__asm __volatile
	{
		push esi

		xor esi, esi

		mov esi, fs : [0x30]

		mov PebAddr, esi

		pop esi
	}

	return (PebAddr > 0) ? PebAddr : NULL;
}

enum : int
{

	InLoadOrderModuleList = 36, InMemoryOrderModuleList = 28, InInitializationOrderModuleList = 20
};


void ClearListEntries(int EntryOffset, const char* ModName)
{
	UnlinkData.PebLock();

	while (UnlinkData.pListMod->Flink != UnlinkData.pListHead)
	{
		UnlinkData.pListMod = UnlinkData.pListMod->Flink;
		UnlinkData.pModName = (UNICODE_STRING*)(((DWORD)(UnlinkData.pListMod)) + EntryOffset);

		WORD DllNameLength = (UnlinkData.pModName->Length) / 2; 

		int n = DllNameLength + 1;

			while (n--)
			{
				if (n != DllNameLength)
				{
					UnlinkData.tModName[n] = (CHAR)(*((UnlinkData.pModName->Buffer) +(n)));
					continue;

				}

				UnlinkData.tModName[n] = (char)'\000';

			}

			if (strstr(UnlinkData.tModName, ModName))
			{
				if (EntryOffset == InLoadOrderModuleList)
				{
					UnlinkData.pLdrMod = (PLDR_MODULE)(((DWORD)(UnlinkData.pListMod)));

					UnlinkData.pLdrMod->HashTableEntry.Blink->Flink = UnlinkData.pLdrMod->HashTableEntry.Flink;
					UnlinkData.pLdrMod->HashTableEntry.Flink->Blink = UnlinkData.pLdrMod->HashTableEntry.Blink;
				}

				UnlinkData.pListMod->Blink->Flink = UnlinkData.pListMod->Flink;
				UnlinkData.pListMod->Flink->Blink = UnlinkData.pListMod->Blink;
			}


	}

	UnlinkData.ReleasePebLock();
}



void UnlinkModule(const char* TargetModName)
{

	UnlinkData.PebLock = (AquireOrRelease)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAcquirePebLock"));
	UnlinkData.ReleasePebLock = (AquireOrRelease)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlReleasePebLock"));


	UnlinkData.PebAddr = GetPEB();

	UnlinkData.pLdr = (PEB_LDR_DATA*)(DWORD*)*(DWORD*)(UnlinkData.PebAddr + 12);

	std::vector <Pair> pairs;

	pairs.push_back(std::make_pair(&(UnlinkData.pLdr->InLoadOrderModuleList), InLoadOrderModuleList));
	pairs.push_back(std::make_pair(&(UnlinkData.pLdr->InMemoryOrderModuleList), InMemoryOrderModuleList));
	pairs.push_back(std::make_pair(&(UnlinkData.pLdr->InInitializationOrderModuleList), InInitializationOrderModuleList));

	for (std::vector<std::pair<PLIST_ENTRY, int>>::const_iterator iterator = pairs.begin(); iterator != pairs.end(); ++iterator)
	{
		UnlinkData.pListHead = UnlinkData.pListMod = iterator->first;
		ClearListEntries(iterator->second, TargetModName);
	}
}

 
DWORD WINAPI TestThread(HMODULE hModule)
{

	Sleep(3000);

	UnlinkModule("my attemp at a bhop.dll");

	Sleep(4525223);
	return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:

		CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)TestThread, &hModule, NULL, nullptr);
		DisableThreadLibraryCalls(hModule);
		break;
	case DLL_PROCESS_DETACH:

		break;
	}

	return TRUE;
}



