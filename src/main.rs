

use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use chardet::detect;
use chardet::charset2encoding;
use encoding_rs::{Encoding, UTF_8};
use std::env;

fn add_padding(base64_str: &str) -> String {
    let padding = base64_str.len() % 4;
    match padding {
        2 => format!("{}==", base64_str),
        3 => format!("{}=", base64_str),
        _ => base64_str.to_string(),
    }
}

fn is_base64(input: &str) -> bool {
    let base64_pattern = Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap();
    base64_pattern.is_match(input)
}
fn contains_script_commands(text: &str) -> Vec<String> {
    let powershell_commands = [
        "Get-Command", "Get-Help", "Get-Service", "Start-Service", "Stop-Service", "Restart-Service",
        "Set-Service", "Get-Process", "Start-Process", "Stop-Process", "Get-ChildItem", "Get-Item",
        "Set-Item", "Remove-Item", "Copy-Item", "Move-Item", "Rename-Item", "New-Item", "Test-Path",
        "Resolve-Path", "Get-Content", "Set-Content", "Add-Content", "Clear-Content", "Select-String",
        "Out-File", "Out-Host", "Out-GridView", "Write-Output", "Write-Error", "Write-Host",
        "Write-Warning", "Write-Verbose", "New-Object", "Invoke-Command", "Invoke-Expression",
        "Import-Module", "Export-ModuleMember", "Get-Module", "Remove-Module", "Get-Variable",
        "Set-Variable", "Remove-Variable", "Clear-Variable", "Get-Alias", "Set-Alias", "New-Alias",
        "Export-Alias", "Import-Alias", "Get-Event", "Register-ObjectEvent", "Unregister-Event",
        "Wait-Event", "Get-EventSubscriber", "Get-History", "Add-History", "Clear-History",
        "Invoke-History", "New-PSDrive", "Get-PSDrive", "Remove-PSDrive", "Get-Location",
        "Set-Location", "Push-Location", "Pop-Location", "Get-Date", "Set-Date", "Get-Random",
        "Start-Sleep", "Measure-Object", "Sort-Object", "Select-Object", "Group-Object",
        "Format-Table", "Format-List", "Format-Wide", "ConvertTo-Json", "ConvertFrom-Json",
        "ConvertTo-Xml", "ConvertFrom-Csv", "Export-Csv", "Import-Csv", "Compare-Object",
        "ForEach-Object", "Where-Object", "Switch", "If", "Else", "For", "While", "Do", "Try",
        "Catch", "Finally", "Throw",
    ];
    let bash_commands_with_args = [
        "cd", "cp", "mv", "rm", "mkdir", "rmdir", "scp", "rsync", "chmod", "chown", "wget", "curl",
        "find", "grep", "sed", "awk", "export", "alias", "unalias", "env", "ip", "iptables",
    ];
    let bash_commands_no_args = [
        "ls", "pwd", "cat", "more", "less", "head", "tail", "ps", "top", "htop", "df", "du", "tar",
        "zip", "unzip", "nano", "vim", "vi", "ssh", "ping", "traceroute", "whoami", "uname", "date",
        "time", "who", "users", "info", "which", "whereis", "updatedb", "stat", "uptime", "free",
    ];
    let windows_commands = [
        "dir", "cls", "copy", "del", "move", "type", "rename", "attrib", "net", "netstat", "ping",
        "tracert", "ipconfig", "tasklist", "taskkill", "systeminfo", "whoami", "reg", "schtasks",
        "shutdown", "sc", "diskpart", "format", "chkdsk", "sfc", "find", "findstr", "set", "setx",
        "echo", "pause", "color", "title", "tree", "call", "start", "ver", "wmic",
    ];

    let pattern_with_args = format!(r"(?i)\b({})(\s+|$)", bash_commands_with_args.join("|"));
    let pattern_no_args = format!(r"(?i)\b({})\b", bash_commands_no_args.join("|"));
    let powershell_pattern = format!(r"(?i)\b({})\b", powershell_commands.join("|"));
    let windows_pattern = format!(r"(?i)\b({})\b", windows_commands.join("|"));
    let combined_pattern = format!(
        "{}|{}|{}|{}",
        pattern_with_args, pattern_no_args, powershell_pattern, windows_pattern
    );

    let re = Regex::new(&combined_pattern).unwrap();
    let mut detected_commands = Vec::new();
    for mat in re.find_iter(text) {
        detected_commands.push(mat.as_str().trim().to_string());
    } 
    detected_commands
}

fn decode_with_encoding(bytes: &[u8], encoding: &str) -> Option<String> {
    match encoding {
        "UTF-8" => String::from_utf8(bytes.to_vec()).ok(),
        "UTF-16LE" => {
            let utf16: Vec<u16> = bytes.chunks(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
            String::from_utf16(&utf16).ok()
        }
        "UTF-16BE" => {
            let utf16: Vec<u16> = bytes.chunks(2).map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])).collect();
            String::from_utf16(&utf16).ok()
        }
        _ => {
            let encoding = Encoding::for_label(encoding.as_bytes()).unwrap_or(UTF_8);
            let (decoded, _, _) = encoding.decode(bytes);
            decoded.into_owned().into()
        }
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: <program> <base64_string>");
        std::process::exit(1);
    }
    let input = &args[1];
    let padded_input = add_padding(input);

    if !is_base64(&padded_input) {
        println!("not base64");
        std::process::exit(0);
    }

    let decoded_bytes = match general_purpose::STANDARD.decode(&padded_input) {
        Ok(bytes) => bytes,
        Err(_) => {
            println!("not base64");
            std::process::exit(0);
        }
    };
    let detected_normal = detect(&decoded_bytes);
    let normal_encoding = charset2encoding(&detected_normal.0);
    let normal_assurance_percentage = (detected_normal.1 * 100.0).round();

    let xored_bytes: Vec<u8> = decoded_bytes.iter().map(|b| b ^ 0xFF).collect();
    let detected_xored = detect(&xored_bytes);
    let xored_encoding = charset2encoding(&detected_xored.0);
    let xored_assurance_percentage = (detected_xored.1 * 100.0).round();

    let (final_bytes, final_encoding, final_assurance, was_xored) = if normal_assurance_percentage >= xored_assurance_percentage {
        (&decoded_bytes, normal_encoding, normal_assurance_percentage, false)
    } else {
        (&xored_bytes, xored_encoding, xored_assurance_percentage, true)
    };

    if let Some(decoded_text) = decode_with_encoding(final_bytes, final_encoding) {
        let detected_commands = contains_script_commands(&decoded_text);
        if !detected_commands.is_empty() {
            println!("error: script commands found");
            println!("Was XORed: {}", was_xored);
            println!("Detected encoding: {}", final_encoding);
            println!("Assurance: {}%", final_assurance);
            println!("Detected script commands: {:?}", detected_commands);
            std::process::exit(1);
        }
        println!("no script commands found");
        println!("Was XORed: {}", was_xored);
        println!("Detected encoding: {}", final_encoding);
        println!("Assurance: {}%", final_assurance);
    } else {
        println!("error: unsupported encoding");
        println!("Was XORed: {}", was_xored);
        println!("Detected encoding: {}", final_encoding);
        println!("Assurance: {}%", final_assurance);
        std::process::exit(1);
    }
}
