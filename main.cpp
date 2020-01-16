#ifndef UNICODE
#define UNICODE
#endif

#include <Windows.h>
#include <stdio.h>

#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <unordered_map>
#include <list>  

#include "wingetopt.h"

#pragma comment(lib, "ntdll")

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemExtendedHandleInformation 64


typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
   HANDLE SourceProcessHandle,
   HANDLE SourceHandle,
   HANDLE TargetProcessHandle,
   PHANDLE TargetHandle,
   ACCESS_MASK DesiredAccess,
   ULONG Attributes,
   ULONG Options
   );


typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
   size_t Object;
   size_t UniqueProcessId;
   size_t HandleValue;
   int GrantedAccess;
   short CreatorBackTraceIndex;
   short ObjectTypeIndex;
   int HandleAttributes;
   int Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
   ULONG_PTR HandleCount;
   ULONG_PTR reserved;
   SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;


typedef enum _POOL_TYPE
{
   NonPagedPool,
   PagedPool,
   NonPagedPoolMustSucceed,
   DontUseThisType,
   NonPagedPoolCacheAligned,
   PagedPoolCacheAligned,
   NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
   UNICODE_STRING Name;
   ULONG TotalNumberOfObjects;
   ULONG TotalNumberOfHandles;
   ULONG TotalPagedPoolUsage;
   ULONG TotalNonPagedPoolUsage;
   ULONG TotalNamePoolUsage;
   ULONG TotalHandleTableUsage;
   ULONG HighWaterNumberOfObjects;
   ULONG HighWaterNumberOfHandles;
   ULONG HighWaterPagedPoolUsage;
   ULONG HighWaterNonPagedPoolUsage;
   ULONG HighWaterNamePoolUsage;
   ULONG HighWaterHandleTableUsage;
   ULONG InvalidAttributes;
   GENERIC_MAPPING GenericMapping;
   ULONG ValidAccess;
   BOOLEAN SecurityRequired;
   BOOLEAN MaintainHandleCount;
   USHORT MaintainTypeList;
   POOL_TYPE PoolType;
   ULONG PagedPoolUsage;
   ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;


void PrintHelp()
{
   printf("Usage: enum_proc_openers params\n");
   printf("\tParams:\n");
   printf("\t-o [pid] opener pid\n");
   printf("\t-t [pid] target pid\n");
   printf("\t-h print this\n");
}
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
std::string GetLastErrorAsString();

int main(int argc, char** argv)
{
   PSYSTEM_HANDLE_INFORMATION_EX handleInfo;
   ULONG handleInfoSize = 0x1000;
   std::unordered_map<size_t, std::list<size_t>> PidsHandles;

   _NtDuplicateObject NtDuplicateObject =
      (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");


   ULONG uOpenerPid = 0;
   ULONG uTargetPid = 0;

   char cur_arg;
   while ((cur_arg = getopt(argc, argv, (char*)"o:t:h")) != -1)
   {
      switch (cur_arg)
      {
      case 'o':
         uOpenerPid = atoi(optarg);
         break;
      case 't':
         uTargetPid = atoi(optarg);
         break;
      case 'h':
         PrintHelp();
         return 0;
      case '?':
      default:
         PrintHelp();
         break;
      };
   };


   // Enable debug privilege
   HANDLE hMainToken;

   if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hMainToken))
   {
      if (GetLastError() == ERROR_NO_TOKEN)
      {
         if (!ImpersonateSelf(SecurityImpersonation))
         {
            printf("ImpersonateSelf failed\n");
            return 1;
         }

         if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hMainToken))
         {
            printf("OpenThreadToken failed\n");
            return 1;
         }
      }
      else
      {
         printf("OpenThreadToken failed\n");
         return 1;
      }
   }

   if (!SetPrivilege(hMainToken, SE_DEBUG_NAME, true))
   {
      printf("SetPrivilege failed\n");
      CloseHandle(hMainToken);
      return 1;
   };

   POBJECT_TYPE_INFORMATION ObjectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
   if (!ObjectTypeInfo)
   {
      printf("Allocation failed\n");
      return 1;
   }

   // Handle enumeration
   handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(handleInfoSize);

   if (!handleInfo)
   {
      printf("Allocation failed\n");
      return 1;
   }

   while (NtQuerySystemInformation(
      (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
      handleInfo,
      handleInfoSize,
      NULL
   ) == STATUS_INFO_LENGTH_MISMATCH)
   {
      handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(handleInfo, handleInfoSize *= 2);

      if (!handleInfo)
      {
         printf("Reallocation failed\n");
         return 1;
      }
   }

   for (ULONG i = 0; i < handleInfo->HandleCount; i++)
   {
      if (PidsHandles.find(handleInfo->Handles[i].UniqueProcessId) == PidsHandles.end())
      {
         PidsHandles.insert({ handleInfo->Handles[i].UniqueProcessId, std::list<size_t>() });
      }

      PidsHandles.at(handleInfo->Handles[i].UniqueProcessId).push_back(handleInfo->Handles[i].HandleValue);
   }

   free(handleInfo);

   // Process enumeration (Code from msdn)
   HANDLE hProcessSnap;
   PROCESSENTRY32 pe32;
   DWORD dwPriorityClass;

   hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if (hProcessSnap == INVALID_HANDLE_VALUE)
   {
      printf("CreateToolhelp32Snapshot failed\n");
      return 1;
   }

   pe32.dwSize = sizeof(PROCESSENTRY32);

   if (!Process32First(hProcessSnap, &pe32))
   {
      printf("Process32First failed\n");
      CloseHandle(hProcessSnap);
      return 1;
   }

   do
   {
      if (uOpenerPid && pe32.th32ProcessID != uOpenerPid)
      {
         continue;
      }

      if (PidsHandles.find(pe32.th32ProcessID) == PidsHandles.end())
      {
         continue;
      }

      HANDLE hCurProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pe32.th32ProcessID);

      if (!hCurProcess)
      {
         continue;
      }


      for (size_t hCurHandle : PidsHandles.at(pe32.th32ProcessID))
      {
         HANDLE hCurDuplicate = 0;

         if (!NT_SUCCESS(NtDuplicateObject(
            hCurProcess,
            (HANDLE)hCurHandle,
            GetCurrentProcess(),
            &hCurDuplicate,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            0
         )))
         {
            continue;
         }

         if (!NT_SUCCESS(NtQueryObject(
            hCurDuplicate,
            (OBJECT_INFORMATION_CLASS)ObjectTypeInformation,
            ObjectTypeInfo,
            0x1000,
            NULL
         )))
         {
            printf("[%d][0x%llx] Can't query object\n", pe32.th32ProcessID, hCurHandle);
            CloseHandle(hCurDuplicate);
            continue;
         }

         if (wcscmp(L"Process", ObjectTypeInfo->Name.Buffer))
         {
            CloseHandle(hCurDuplicate);
            continue;
         }

         char szTargetPath[MAX_PATH];

         if (!GetModuleFileNameExA(hCurDuplicate, 0, szTargetPath, MAX_PATH))
         {
            CloseHandle(hCurDuplicate);
            continue;
         }

         // Get handles target pid
         PROCESS_BASIC_INFORMATION pbi;
         ZeroMemory(&pbi, sizeof(pbi));

         if (NT_SUCCESS(NtQueryInformationProcess(hCurDuplicate, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL)))
         {
            if (pbi.UniqueProcessId == uTargetPid || !uTargetPid)
            {
               printf("[Pid: %d][Handle: 0x%x]\t%S\topened\t%s [Pid: %d]\n",
                  pe32.th32ProcessID,
                  hCurHandle,
                  pe32.szExeFile,
                  szTargetPath,
                  (DWORD)pbi.UniqueProcessId);
            }
         }
         else
         {
            printf("[Pid: %d][Handle: 0x%x]\t%S\topened\t%s [Pid: Unknown]\n",
               pe32.th32ProcessID,
               hCurHandle,
               pe32.szExeFile,
               szTargetPath);
         }

         CloseHandle(hCurDuplicate);
      }

      CloseHandle(hCurProcess);

   } while (Process32Next(hProcessSnap, &pe32));

   free(ObjectTypeInfo);

   return 0;
}


BOOL SetPrivilege(
   HANDLE hToken,          // token handle
   LPCTSTR Privilege,      // Privilege to enable/disable
   BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
   TOKEN_PRIVILEGES tp;
   LUID luid;
   TOKEN_PRIVILEGES tpPrevious;
   DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

   if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

   // 
   // first pass.  get current privilege setting
   // 
   tp.PrivilegeCount = 1;
   tp.Privileges[0].Luid = luid;
   tp.Privileges[0].Attributes = 0;

   AdjustTokenPrivileges(
      hToken,
      FALSE,
      &tp,
      sizeof(TOKEN_PRIVILEGES),
      &tpPrevious,
      &cbPrevious
   );

   if (GetLastError() != ERROR_SUCCESS) return FALSE;

   // 
   // second pass.  set privilege based on previous setting
   // 
   tpPrevious.PrivilegeCount = 1;
   tpPrevious.Privileges[0].Luid = luid;

   if (bEnablePrivilege)
   {
      tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
   }
   else
   {
      tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
         tpPrevious.Privileges[0].Attributes);
   }

   AdjustTokenPrivileges(
      hToken,
      FALSE,
      &tpPrevious,
      cbPrevious,
      NULL,
      NULL
   );

   if (GetLastError() != ERROR_SUCCESS) return FALSE;

   return TRUE;
};