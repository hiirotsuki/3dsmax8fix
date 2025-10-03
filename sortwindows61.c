/* SPDX-License-Identifier: GPL-2.0-or-later */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

#ifdef _DEBUG
HANDLE hConsole;

#define TRACE(...) do { \
	char buffer[1024]; \
	wsprintfA(buffer, __VA_ARGS__); \
	WriteConsoleA(hConsole, buffer, lstrlenA(buffer), NULL, NULL); \
} while(0)
#else
#define TRACE(...)
#endif

wchar_t *xstrrchrW(const wchar_t *s, wchar_t c)
{
	const wchar_t *last = NULL;

	while (*s)
	{
		if (*s == c)
			last = s;
		s++;
	}

	if (c == L'\0')
		return (wchar_t *)s;

	return (wchar_t *)last;
}

void *hookIAT(HMODULE hModule, const char *dllName, const char *funcName, void *hookFunction)
{
	if (!hModule || !dllName || !funcName || !hookFunction)
		return NULL;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir.Size == 0 || importDir.VirtualAddress == 0)
		return NULL;

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir.VirtualAddress);
	while (importDesc->Name)
	{
		const char *importDllName = (const char*)((BYTE*)hModule + importDesc->Name);
		if (!lstrcmpiA(importDllName, dllName))
		{
			PIMAGE_THUNK_DATA thunk	 = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
			PIMAGE_THUNK_DATA origThunk = NULL;

			if (importDesc->OriginalFirstThunk)
				origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
			else
				origThunk = thunk;

			for (; origThunk->u1.AddressOfData; ++thunk, ++origThunk)
			{
				// Skip ordinal imports
				if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					continue;

				PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);
				if (!import || !import->Name)
					continue;

				if (!lstrcmpiA((const char *)import->Name, funcName))
				{
					void *originalAddress = (void *)thunk->u1.Function;

					DWORD oldProtect;
					if (VirtualProtect(&thunk->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProtect))
					{
						thunk->u1.Function = (uintptr_t)hookFunction;
						TRACE("replacing function\n");
						VirtualProtect(&thunk->u1.Function, sizeof(void *), oldProtect, &oldProtect);
						return originalAddress;
					}
				}
			}
		}

		++importDesc;
	}
	TRACE("function not found!\n");
	return NULL;
}

typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

LoadLibraryExW_t pLoadLibraryExW = NULL;

/* The magic! */
HMODULE LoadLibraryExW_hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	/* If the Plan9 network provider is attempted to be loaded, return NULL to indicate that it does not exist */
	if(!lstrcmpiW(xstrrchrW(lpLibFileName, L'\\') + 1, L"P9NP.DLL"))
	{
		TRACE("returning NULL on P9NP.DLL\n");
		return NULL;
	}

#ifdef _DEBUG
	WriteConsoleW(hConsole, xstrrchrW(lpLibFileName, L'\\') + 1, lstrlenW(xstrrchrW(lpLibFileName, L'\\') + 1), NULL, NULL);
	TRACE("\n");
#endif
	return pLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

static HMODULE real = NULL;
static void *pSortGetHandle = NULL;
static void *pSortCloseHandle = NULL;

BOOL WINAPI DllMainCRTStartup(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	wchar_t sysPath[MAX_PATH] = {0};

	if(dwReason == DLL_PROCESS_ATTACH)
	{
#ifdef _DEBUG
		AllocConsole();
		hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
#endif

		GetSystemDirectoryW(sysPath, sizeof(sysPath));
		lstrcatW(sysPath, L"\\sortwindows61.dll");

		real = LoadLibraryW(sysPath);
		if(!real)
			return FALSE;

		pSortGetHandle = GetProcAddress(real, "SortGetHandle");
		pSortCloseHandle = GetProcAddress(real, "SortCloseHandle");

		pLoadLibraryExW = hookIAT(GetModuleHandleW(L"mpr.dll"), "api-ms-win-core-libraryloader-l1-2-0.dll", "LoadLibraryExW", LoadLibraryExW_hook);
	}
	else if(dwReason == DLL_PROCESS_DETACH)
	{
		if(real)
			FreeLibrary(real);
	}
	return TRUE;
}

/* the declarations of these things are unknown, so asm jumps are needed... :-( */
__attribute__((naked)) __declspec(dllexport) void SortGetHandle(void)
{
	__asm__ __volatile__ (
		"jmp *%0\n"
		:
		: "r" (pSortGetHandle)
	);
}

__attribute__((naked)) __declspec(dllexport) void SortCloseHandle(void)
{
	__asm__ __volatile__ (
		"jmp *%0\n"
		:
		: "r" (pSortCloseHandle)
	);
}
