use obfstr::obfstr;
use once_cell::sync::Lazy;
use winapi::shared::ntdef::{HANDLE, NTSTATUS};
use winapi::um::winnt::PSECURITY_QUALITY_OF_SERVICE;

pub static NTDLL_DLL: Lazy<String> = Lazy::new(|| obfstr!("ntdll.dll").to_string());

pub static NTIMTH: Lazy<String> = Lazy::new(|| obfstr!("NtImpersonateThread").to_string());

pub type NtImpersonateThreadFn = unsafe extern "system" fn(
    server_thread_handle: HANDLE,
    client_thread_handle: HANDLE,
    security_qos: PSECURITY_QUALITY_OF_SERVICE,
) -> NTSTATUS;
