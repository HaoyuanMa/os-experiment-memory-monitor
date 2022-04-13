#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<Windows.h>
#include<Psapi.h>
#include<sysinfoapi.h>
#include<TlHelp32.h>

char BK[50] = "                        ";

void PrintMenu()
{
	printf("%s* * * * * * * * * * * * * * * * * * * * * * * * *\n", BK);
	printf("%s*                  Memory Monitor               *\n", BK);
	printf("%s*                                               *\n", BK);
	printf("%s*  a.Show Performance Information               *\n", BK);
	printf("%s*  b.Show Memory Status                         *\n", BK);
	printf("%s*  c.Show System Information                    *\n", BK);		
	printf("%s*  d.Query All Process Control Information      *\n", BK);
	printf("%s*  e.Query Single Process Control Information   *\n", BK);
	printf("%s*                                               *\n", BK);
	printf("%s* * * * * * * * * * * * * * * * * * * * * * * * *\n", BK);
	printf("\n\n\nPlease choose function.\n( q to quit. )\n");
}

void a()
{
	struct _PERFORMANCE_INFORMATION
		pi;
	GetPerformanceInfo(&pi, sizeof(pi));
	printf("\n\n");
	printf("%sCommit Total:                  | %u\n", BK, pi.CommitTotal);
	printf("%sCommit Limit:                  | %u\n", BK, pi.CommitLimit);
	printf("%sCommit Peak:                   | %u\n", BK, pi.CommitPeak);
	printf("%sPhysical Total:                | %u\n", BK, pi.PhysicalTotal);
	printf("%sPhysical Available:            | %u\n", BK, pi.PhysicalAvailable);
	printf("%sSystem Cache:                  | %u\n", BK, pi.SystemCache);
	printf("%sKernel Total:                  | %u\n", BK, pi.KernelTotal);
	printf("%sKernel Paged:                  | %u\n", BK, pi.KernelPaged);
	printf("%sKernel Nonpaged:               | %u\n", BK, pi.KernelNonpaged);
	printf("%sPage Size                      | %.2f KB\n", BK, pi.PageSize / 1024.0);
	printf("%sHandle Count:                  | %u\n", BK, pi.HandleCount);
	printf("%sProcess Count:                 | %u\n", BK, pi.ProcessCount);
	printf("%sThread Count:                  | %u\n", BK, pi.ThreadCount);
	printf("\n\n");
}

void b()
{
	struct _MEMORYSTATUSEX mi;
	mi.dwLength = sizeof(mi);
	GlobalMemoryStatusEx(&mi);
	printf("\n\n");
	printf("%sMemory Load:                    | %.2f%%\n", BK, (float)mi.dwMemoryLoad);
	printf("%sTotle Memory:                   | %.2f GB\n", BK, mi.ullTotalPhys / 1024.0 / 1024.0 / 1024.0);
	printf("%sAvail Memory:                   | %.2f GB\n", BK, mi.ullAvailPhys / 1024.0 / 1024.0 / 1024.0);
	printf("%sTotal PageFile:                 | %.2f GB\n", BK, mi.ullTotalPageFile / 1024.0 / 1024.0 / 1024.0);
	printf("%sAvail PageFile                  | %.2f GB\n", BK, mi.ullAvailPageFile / 1024.0 / 1024.0 / 1024.0);
	printf("%sTotal Virtual:                  | %.2f GB\n", BK, mi.ullTotalVirtual / 1024.0 / 1024.0 / 1024.0);
	printf("%sAvail Virtual:                  | %.2f GB\n", BK, mi.ullAvailVirtual / 1024.0 / 1024.0 / 1024.0);
	printf("\n\n");
}

void c()
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	printf("\n\n");
	printf("%sPage Size:                      | %d KB\n", BK, (int)si.dwPageSize / 1024);
	printf("%sMinimumApplicationAddress:      | 0x%0.8x \n", BK, si.lpMinimumApplicationAddress);
	printf("%sMaximumApplicationAddress:      | 0x%0.8x \n", BK, si.lpMaximumApplicationAddress);
	printf("%sNumberOfProcessors:             | %d\n", BK, si.dwNumberOfProcessors);
	printf("%sProcessor Type                  | %d\n", BK, si.dwProcessorType);
	printf("%sAllocation Granularity:         | %d KB\n", BK, (int)si.dwAllocationGranularity / 1024);
	printf("%sProcessor Level:                | %d\n", BK, si.wProcessorLevel);
	printf("\n\n");
}

void d(int pid)
{
	printf("\n\n");

	SYSTEM_INFO si;
	GetSystemInfo(&si);

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);
	HANDLE hps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	int find = Process32First(hps, &pe);

	while (find)
	{
		if (pid == -1 || pe.th32ProcessID == pid)
		{
			//SetLastError(0);
			
			HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
			
			//printf("error: %d\n", GetLastError());

			PROCESS_MEMORY_COUNTERS pmc;
			GetProcessMemoryInfo(hp, &pmc, sizeof(pmc));
		
			if (pid == -1)
			{
				wprintf(L"%12d                        %ls", pe.th32ProcessID, pe.szExeFile);
				for (int i = 1; i <= (70 - (int)wcslen(pe.szExeFile)); i++)
					printf(" ");
				printf("%.2fKB\n", pmc.WorkingSetSize / 1024.0);
			}
			else
			{
				printf("%sProcess Id:                     | %d\n", BK, pe.th32ProcessID);
				wprintf(L"                        Process Name:                   | %ls\n", pe.szExeFile);
				printf("%sWorkingSet Size:                | %.2fKB\n", BK, pmc.WorkingSetSize / 1024.0);
			}

			MEMORY_BASIC_INFORMATION mbi;
			LPCVOID pb = (LPVOID)si.lpMinimumApplicationAddress;

			if(pid != -1)
				printf("%sMemory Information:\n", BK);
			while (pid!=-1 && pb < si.lpMaximumApplicationAddress)
			{
				
				VirtualQueryEx(hp, pb, &mbi, sizeof(mbi));
				LPCVOID ped = (PBYTE)pb + mbi.RegionSize;
				
				printf("%s0x%8x - 0x%8x (%.2f MB)    state: ", BK, pb, ped, mbi.RegionSize / 1024.0 / 1024.0);
				
				switch (mbi.State)
				{
				case MEM_COMMIT:
					printf("COMMIT  ");
					break;
				case MEM_FREE:
					printf("FREE    ");
					break;
				case MEM_RESERVE:
					printf("RESERVE ");
					break;
				}
				printf("   type: ");
				switch (mbi.Type)
				{
				case MEM_IMAGE:
					printf("IMAGE ");
					break;
				case MEM_MAPPED:
					printf("MAPPED ");
					break;
				case MEM_PRIVATE:
					printf("PRIVATE ");
					break;
				}
				printf("\n");
				pb = ped;	
			}
			//printf("\n");
			CloseHandle(hp);
		}
		find = Process32Next(hps, &pe);
	}
	printf("\n\n");
	CloseHandle(hps);
}

int main()
{
	while (1)
	{
		PrintMenu();
		char ch = getchar();
		getchar();
		switch (ch)
		{
		case 'a': a(); break;
		case 'b': b(); break;
		case 'c': c(); break;
		case 'd':
		{
			printf("   Process Id%sProcess Name", BK);
			for (int i = 1; i < 55; i++)
				printf(" ");
			printf("WorkingSet Size\n");
			d(-1);
			break;
		}
		case 'e':
		{
			int id;
			printf("Please input the id of process.\n");
			scanf("%d", &id);
			getchar();
			d(id);
			break;
		}
		case 'q': return 0;
		default: break;
		}
	}
}

