use obfstr::obfstr;
use once_cell::sync::Lazy;
use winapi::shared::ntdef::{HANDLE, NTSTATUS};
use winapi::um::winnt::PSECURITY_QUALITY_OF_SERVICE;

pub static NTDLL_DLL: Lazy<String> = Lazy::new(|| obfstr!("ntdll.dll").to_string());

pub static NTIMPERSONATETHREAD: Lazy<String> = Lazy::new(|| obfstr!("NtImpersonateThread").to_string());

pub type  NtImpersonateThreadFn = unsafe extern "system" fn(
    ServerThreadHandle: HANDLE,
    ClientThreadHandle: HANDLE,
    SecurityQos: PSECURITY_QUALITY_OF_SERVICE,
) -> NTSTATUS;