use std::env;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Constants for checking encryption (from check.c)
const MAGIC_NUMBER_1_CHECK: u32 = 0x1301D80;
const MAGIC_NUMBER_2_CHECK: u32 = 0x1301D90;

/// Constants for decryption (from decrypt.c)
const BLOCK_SIZE: usize = 8;
const MAGIC_1_DECRYPT: u32 = 0x31353839;
const MAGIC_2_DECRYPT: u32 = 0x32333838;

/// Configuration for CLI options.
struct Config {
    in_place: bool,
    output_dir: Option<String>,
    input_files: Vec<String>,
}

/// Print usage and description.
fn print_usage(program: &str) {
    println!("Netease Minecraft Bedrock edition save Decrypter");
    println!();
    println!("Usage:");
    println!("  {} -i <input_file1> [<input_file2> ...]", program);
    println!("      Decrypt files in place (the original file will be overwritten).");
    println!();
    println!(
        "  {} -o <output_folder> <input_file1> [<input_file2> ...]",
        program
    );
    println!("      Decrypt files and write the output to the specified folder (keeping the original file unchanged).");
}

/// Parses CLI arguments. Accepts either:
/// - in-place mode: `-i <input_file1> [<input_file2> ...]`
/// - output folder mode: `-o <output_folder> <input_file1> [<input_file2> ...]`
fn parse_cli_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Err("Not enough arguments.".to_string());
    }
    match args[1].as_str() {
        "-i" if args.len() < 3 => {
            print_usage(&args[0]);
            Err("Not enough arguments for in-place decryption.".to_string())
        }
        "-i" => {
            let input_files = args[2..].to_vec();
            Ok(Config {
                in_place: true,
                output_dir: None,
                input_files,
            })
        }
        "-o" if args.len() < 4 => {
            print_usage(&args[0]);
            Err("Not enough arguments for output folder mode.".to_string())
        }
        "-o" => {
            let output_dir = args[2].clone();
            let input_files = args[3..].to_vec();
            Ok(Config {
                in_place: false,
                output_dir: Some(output_dir),
                input_files,
            })
        }
        "-h" | "--help" => {
            print_usage(&args[0]);
            Err("Help displayed.".to_string())
        }
        _ => {
            print_usage(&args[0]);
            Err("Invalid option provided.".to_string())
        }
    }
}

/// Checks whether the file data is considered "encrypted" by reading its first 8 bytes.
/// Returns true if either the first 4 bytes match MAGIC_NUMBER_1_CHECK or the next 4 bytes match MAGIC_NUMBER_2_CHECK.
fn check_magic_numbers(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let magic1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let magic2 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    magic1 == MAGIC_NUMBER_1_CHECK || magic2 == MAGIC_NUMBER_2_CHECK
}

/// Decrypts the input data in blocks of 8 bytes.
/// Each block’s first 4 bytes are XOR’d with MAGIC_1_DECRYPT and the next 4 with MAGIC_2_DECRYPT.
/// Returns the decrypted data starting at offset 4 (mimicking the original C behavior).
fn decrypt(input: &[u8]) -> Vec<u8> {
    let size = input.len();
    let padding = if size % BLOCK_SIZE != 0 {
        BLOCK_SIZE - (size % BLOCK_SIZE)
    } else {
        0
    };
    let total_size = size + padding;

    // Create a working buffer with the necessary padding.
    let mut buffer = Vec::with_capacity(total_size);
    buffer.extend_from_slice(input);
    buffer.resize(total_size, 0);

    // Process each 8-byte block.
    for block_start in (0..total_size).step_by(BLOCK_SIZE) {
        if block_start + BLOCK_SIZE <= total_size {
            // Decrypt the first 4 bytes.
            let mut first_bytes = [0u8; 4];
            first_bytes.copy_from_slice(&buffer[block_start..block_start + 4]);
            let decrypted_first = u32::from_le_bytes(first_bytes) ^ MAGIC_1_DECRYPT;
            buffer[block_start..block_start + 4].copy_from_slice(&decrypted_first.to_le_bytes());

            // Decrypt the next 4 bytes.
            let mut second_bytes = [0u8; 4];
            second_bytes.copy_from_slice(&buffer[block_start + 4..block_start + 8]);
            let decrypted_second = u32::from_le_bytes(second_bytes) ^ MAGIC_2_DECRYPT;
            buffer[block_start + 4..block_start + 8]
                .copy_from_slice(&decrypted_second.to_le_bytes());
        }
    }
    // Return decrypted data starting at offset 4.
    if size > 4 {
        buffer[4..size].to_vec()
    } else {
        Vec::new()
    }
}

/// Processes a single file: reads the file, checks for encryption, decrypts it if necessary,
/// and writes the result to either the same file (in-place) or to the specified output folder.
fn process_file(input_path: &str, config: &Config) -> io::Result<()> {
    let input_data = fs::read(input_path)?;
    let path = Path::new(input_path);
    let filename = match path.file_name() {
        Some(name) => name,
        None => {
            eprintln!("Could not determine file name for {}", input_path);
            return Ok(());
        }
    };

    if !check_magic_numbers(&input_data) {
        println!("File '{}' is already decrypted. Skipping.", input_path);
        return Ok(());
    }
    println!("Decrypting file '{}'.", input_path);
    let decrypted_data = decrypt(&input_data);

    let output_path = if config.in_place {
        // In-place decryption: write the decrypted data back to the original file.
        PathBuf::from(input_path)
    } else {
        // Output folder mode: construct output file path using the specified directory and the original file name.
        let mut op = PathBuf::from(config.output_dir.as_ref().unwrap());
        op.push(filename);
        op
    };

    fs::write(output_path, &decrypted_data)?;
    println!("Decryption complete for '{}'.", input_path);
    Ok(())
}

fn main() -> io::Result<()> {
    let config = match parse_cli_args() {
        Ok(cfg) => cfg,
        Err(err) => {
            if err != "Help displayed." {
                eprintln!("{}", err);
            }
            std::process::exit(1);
        }
    };

    // In output folder mode, ensure the output directory exists.
    if !config.in_place {
        if let Some(ref dir) = config.output_dir {
            fs::create_dir_all(dir)?;
        }
    }

    // Process each input file.
    for input_file in &config.input_files {
        if let Err(e) = process_file(input_file, &config) {
            eprintln!("Error processing {}: {}", input_file, e);
        }
    }
    Ok(())
}
