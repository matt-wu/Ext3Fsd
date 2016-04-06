#include <Ext2Srv.h>
#include <tlhelp32.h>


BOOL Ext2EnablePrivilege(LPCTSTR lpszPrivilegeName)
{
    TOKEN_PRIVILEGES tp = {0};
    HANDLE           token;
    LUID             luid;
    BOOL             rc;

    rc = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES |
                          TOKEN_QUERY | TOKEN_READ, &token);
    if(!rc)
        goto errorout;

    rc = LookupPrivilegeValue(NULL, lpszPrivilegeName, &luid);
    if(!rc)
        goto errorout;

    /* initialize token privilege */
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    rc = AdjustTokenPrivileges(token, FALSE, &tp, NULL, NULL, NULL);
    CloseHandle(token);

errorout:

    return rc;
}

VOID
Ext2DrvNotify(TCHAR drive, int add)
{
    DEV_BROADCAST_VOLUME    dbv;
    DWORD target = BSM_APPLICATIONS;
    unsigned long drv = 0;

    if (drive >= 'A' && drive <= 'Z')
        drv = drive - 'A';
    else if(drive >= 'a' && drive <= 'z')
        drv = drive - 'a';
    else
        return;

    dbv.dbcv_size       = sizeof( dbv );
    dbv.dbcv_devicetype = DBT_DEVTYP_VOLUME;
    dbv.dbcv_reserved   = 0;
    dbv.dbcv_unitmask   = (1 << drv);
    dbv.dbcv_flags      = DBTF_NET;
    BroadcastSystemMessage(BSF_IGNORECURRENTTASK | BSF_FORCEIFHUNG |
                           BSF_NOHANG | BSF_NOTIMEOUTIFNOTHUNG,
                           &target, WM_DEVICECHANGE, add ?
                           DBT_DEVICEARRIVAL : DBT_DEVICEREMOVECOMPLETE,
                           (LPARAM)(DEV_BROADCAST_HDR *)&dbv );
}


DWORD Ext2QueryMgr(TCHAR *Auth, DWORD *pids, DWORD as)
{
    DWORD  total = 0;
    HANDLE p = NULL;
    PROCESSENTRY32 r = {0};

    p = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == p)
        return 0;

    r.dwSize=sizeof(PROCESSENTRY32);
    if (!Process32First(p, &r)) {
        goto errorout;
    }

    do {
        TCHAR *n = _tcsrchr(&r.szExeFile[0], _T('\\'));
        if (!n)
            n = &r.szExeFile[0];
        if (_tcsicmp(n, Auth) == 0) {
            pids[total++] = r.th32ProcessID;
            if (total >= as)
                break;
        }
        
    } while(Process32Next(p, &r));

errorout:

    CloseHandle(p);

    return total;
}

TCHAR * Ext2BuildAssdCMD(TCHAR *task)
{
    TCHAR  cmd[258]= {0}, *p, *refresh = NULL;
    int    len = 0;

    if (GetModuleFileName(NULL, cmd, 510)) {
    } else { 
        _tcscpy(cmd, GetCommandLine());
        p = _tcsstr(cmd, _T("/"));
        if (p)
            *p = 0;
    }

    len = (int)_tcslen(cmd) + 40;
    refresh = new TCHAR[len];
    if (!refresh)
        goto errorout;
    memset(refresh, 0, sizeof(TCHAR)*len);
    _tcscpy_s(refresh, len - 1, cmd);
    _tcscat_s(refresh, len, _T(" "));
    _tcscat_s(refresh, len, task);

errorout:
    return refresh;
}

int Ext2CreateToken(DWORD pid, DWORD *sid, HANDLE *token)
{
    HANDLE  token_user = NULL;
    int     rc = -1;

    rc = ProcessIdToSessionId(pid, sid);
    if (!rc) {
        rc = -1 * GetLastError();
        goto errorout;
    }

    if (!token)
        goto errorout;

    rc = WTSQueryUserToken(*sid, &token_user);
    if (!rc) {
        rc = -1 * GetLastError();
        goto errorout;
    }

    rc = DuplicateTokenEx(token_user, MAXIMUM_ALLOWED, NULL,
                          SecurityIdentification, TokenPrimary,
                          token);
    if (!rc) {
        rc = -1 * GetLastError();
        goto errorout;
    }

errorout:

    if (token_user && token_user != INVALID_HANDLE_VALUE)
        CloseHandle(token_user);

    return rc;
}

int Ext2StartUserTask(TCHAR *task, DWORD sid, HANDLE token)
{
    LPTSTR  cmd = NULL;
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    int     rc = -1;

    cmd = Ext2BuildAssdCMD(task);
    if (!cmd) {
        rc = -1;
        goto errorout;
    }

    si.cb = sizeof( STARTUPINFO );
    // si.lpDesktop = _T("winsta0\\default");
    rc = CreateProcessAsUser(token, NULL, cmd, NULL, NULL,
                             FALSE, NORMAL_PRIORITY_CLASS |
                             CREATE_NO_WINDOW, NULL, NULL,
                             &si, &pi );
    if (!rc) {
        rc = -1 * GetLastError();
        goto errorout;
    }

    /* wait until process exits or timeouts */
    rc = WaitForSingleObject(pi.hProcess, 30000);
    if (rc == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, -1);
        ErrLog("Ext2DoAssdNotify: %S timeout, to be terminated.\n", task);
    }
    if (!GetExitCodeProcess(pi.hProcess, (LPDWORD)&rc)) {
        rc = -2;
    }

    if (pi.hProcess != INVALID_HANDLE_VALUE) { 
        CloseHandle(pi.hProcess); 
    } 
    if (pi.hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(pi.hThread); 
    }

errorout:

    if (cmd)
        delete []cmd;

    return rc;
}

INT Ext2NotifyUser(TCHAR *task, ULONG mgr)
{
    DWORD   pid[10] = {0}, num, sid = 0;
    HANDLE  token = 0;
    INT     rc = -1;

    num = Ext2QueryMgr(_T("Ext2Mgr.exe"), pid, 10);
    if (mgr)
        pid[num++] = mgr;

    while (num > 0 && pid[num - 1]) {

        rc = Ext2CreateToken(pid[--num], &sid, &token);
        if (rc != 1) {
            continue;
        }

        rc = Ext2StartUserTask(task, sid, token);
        if (token && token != INVALID_HANDLE_VALUE) {
            CloseHandle(token);
            token = NULL;
        }
        if (rc) {
            break;
        }
    }

    return rc;
}


BOOL Ext2AssignDrvLetter(TCHAR *dev, TCHAR drv)
{
	TCHAR	dos[8];

	_stprintf_s(dos, 8, _T("%C:"), drv);
	if (!DefineDosDevice(DDD_RAW_TARGET_PATH, dos, dev)) {
        ErrLog("mount: failed to assigned drive letter %C:.\n", drv);
        return 0;
	}

    Ext2DrvNotify(drv, TRUE);

	return TRUE;
}

BOOL Ext2RemoveDrvLetter(TCHAR drive)
{
	TCHAR	dosDev[MAX_PATH];

    /* remove drive letter */
	_stprintf_s(dosDev, MAX_PATH, _T("%C:"), drive);
	DefineDosDevice(DDD_REMOVE_DEFINITION,
                    dosDev, NULL);
    Ext2DrvNotify(drive, FALSE);

	return TRUE;
}
