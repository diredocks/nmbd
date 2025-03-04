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

/// CLI configuration structure.
struct Config {
    output_dir: String,
    input_files: Vec<String>,
}

/// Parses the CLI arguments.
/// Expected usage: `program -o <output_folder> <input_file1> [<input_file2> ...]`
fn parse_cli_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        return Err(format!(
            "Usage: {} -o <output_folder> <input_file1> [<input_file2> ...]",
            args[0]
        ));
    }
    if args[1] != "-o" {
        return Err(format!(
            "Usage: {} -o <output_folder> <input_file1> [<input_file2> ...]",
            args[0]
        ));
    }
    let output_dir = args[2].clone();
    let input_files = args[3..].to_vec();
    Ok(Config {
        output_dir,
        input_files,
    })
}

/// Checks whether the file data is considered "encrypted" by reading its first 8 bytes.
/// Returns true if either the first 4 bytes match MAGIC_NUMBER_1_CHECK
/// or the next 4 bytes match MAGIC_NUMBER_2_CHECK.
fn check_magic_numbers(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let magic1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let magic2 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    magic1 == MAGIC_NUMBER_1_CHECK || magic2 == MAGIC_NUMBER_2_CHECK
}

/// Decrypts the input data in blocks of 8 bytes.
/// Each block\u2019s first 4 bytes are XOR\u2019d with MAGIC_1_DECRYPT and the next 4 bytes with MAGIC_2_DECRYPT.
/// Returns the decrypted data (starting at offset 4, as in the original C code).
fn decrypt(input: &[u8]) -> Vec<u8> {
    let size = input.len();
    let padding = if size % BLOCK_SIZE != 0 {
        BLOCK_SIZE - (size % BLOCK_SIZE)
    } else {
        0
    };
    let total_size = size + padding;

    // Create a working buffer with necessary padding.
    let mut buffer = Vec::with_capacity(total_size);
    buffer.extend_from_slice(input);
    buffer.resize(total_size, 0);

    // Process each block.
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
    // As in the original C program, skip the first 4 bytes in the final output.
    if size > 4 {
        buffer[4..size].to_vec()
    } else {
        Vec::new()
    }
}

/// Reads a file, checks if it is encrypted, and if so decrypts it.
/// The output is written into the specified output folder using the same file name.
/// If the file is not encrypted, a message is printed and the file is skipped.
fn process_file(input_path: &str, output_dir: &str) -> io::Result<()> {
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

    // Decrypt the input data.
    let decrypted_data = decrypt(&input_data);

    // Build the output file path.
    let mut output_path = PathBuf::from(output_dir);
    output_path.push(filename);

    // Write the decrypted data to the output file.
    fs::write(output_path, &decrypted_data)?;
    println!("Decryption complete for '{}'.", input_path);
    Ok(())
}

fn main() -> io::Result<()> {
    // Parse CLI arguments.
    let config = match parse_cli_args() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    // Ensure the output directory exists (create if it doesn't).
    fs::create_dir_all(&config.output_dir)?;

    // Process each input file.
    for input_file in &config.input_files {
        if let Err(e) = process_file(input_file, &config.output_dir) {
            eprintln!("Error processing {}: {}", input_file, e);
        }
    }

    Ok(())
}
