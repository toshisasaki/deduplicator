use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use serde_json::json;
use openssl::sha::Sha1;
use clap::{Arg, Command, ArgAction};
use walkdir::WalkDir;
use rayon::prelude::*;

/// Struct for holding duplicate file information
#[derive(Serialize, Deserialize, Debug)]
struct DuplicateFiles {
    hash: String,
    paths: Vec<String>,
}

/// Process a file to compute its SHA-1 hash
fn process_file(path: PathBuf) -> Option<(String, String)> {
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(_) => return None,
    };

    let mut reader = BufReader::with_capacity(256 * 1024 * 1024, file); // 256MB buffer
    let mut hasher = Sha1::new();

    let mut buffer = vec![0; 256 * 1024 * 1024]; // 256MB buffer
    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break, // EOF reached
            Ok(bytes) => bytes,
            Err(_) => return None,
        };

        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finish();
    let hash_hex = hex::encode(hash);

    Some((hash_hex, path.to_string_lossy().to_string()))
}

/// Find duplicates in the specified directory
fn find_duplicates(input_dir: &str) -> io::Result<Vec<DuplicateFiles>> {
    // Collect file paths from directory traversal
    let entries: Vec<_> = WalkDir::new(input_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let path = entry.path().to_path_buf();
            match fs::metadata(&path) {
                Ok(metadata) if metadata.len() > 0 => Some(path),
                _ => None,
            }
        })
        .collect();

    // Process files in parallel
    let results: Vec<_> = entries
        .par_iter()
        .filter_map(|path| process_file(path.clone()))
        .collect();

    // Organize results by hash
    let mut hash_map: HashMap<String, Vec<String>> = HashMap::new();
    for (hash, path) in results {
        hash_map.entry(hash).or_insert_with(Vec::new).push(path);
    }

    // Collect duplicate files
    let duplicates: Vec<DuplicateFiles> = hash_map
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(hash, paths)| DuplicateFiles { hash, paths })
        .collect();

    Ok(duplicates)
}

/// Delete duplicate files, keeping only one
fn delete_duplicates(duplicates: &[DuplicateFiles]) -> io::Result<()> {
    for duplicate in duplicates {
        for path in &duplicate.paths[1..] {
            fs::remove_file(path)?;
            println!("Deleted: {}", path);
        }
    }
    Ok(())
}

/// Move duplicate files to a specified directory, keeping only one
fn move_duplicates(duplicates: &[DuplicateFiles], move_dir: &str) -> io::Result<()> {
    for duplicate in duplicates {
        fs::create_dir_all(move_dir)?;

        for path in &duplicate.paths[1..] {
            let file_name = Path::new(path).file_name().unwrap();
            let target_path = Path::new(move_dir).join(file_name);

            fs::rename(path, &target_path)?;
            println!("Moved: {} -> {}", path, target_path.display());
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let matches = Command::new("File Duplicates Finder")
        .version("1.0")
        .author("Anderson Toshiyuki Sasaki <11450334+toshisasaki@users.noreply.github.com>")
        .about("Finds and manages duplicate files in a directory based on their SHA-1 hash")
        .arg(Arg::new("input_dir")
            .short('i')
            .long("input")
            .value_name("INPUT_DIR")
            .help("The path to the input directory")
            .required(true)
            .action(ArgAction::Set))
        .arg(Arg::new("output_file")
            .short('o')
            .long("output")
            .value_name("OUTPUT_FILE")
            .help("The path to the output JSON file")
            .required(true)
            .action(ArgAction::Set))
        .arg(Arg::new("action")
            .short('a')
            .long("action")
            .value_name("ACTION")
            .help("The action to perform: 'list', 'delete', or 'move'")
            .required(true)
            .action(ArgAction::Set))
        .arg(Arg::new("move_dir")
            .short('m')
            .long("move-dir")
            .value_name("MOVE_DIR")
            .help("The directory where duplicates should be moved (required for 'move' action)")
            .action(ArgAction::Set))
        .get_matches();

    let input_dir = matches.get_one::<String>("input_dir").unwrap();
    let output_file = matches.get_one::<String>("output_file").unwrap();
    let action = matches.get_one::<String>("action").unwrap();
    let move_dir = matches.get_one::<String>("move_dir");

    let duplicates = find_duplicates(input_dir)?;

    match action.as_str() {
        "list" => {
            let json_output = serde_json::to_string_pretty(&json!(duplicates))?;
            println!("{}", json_output);
        }
        "delete" => {
            delete_duplicates(&duplicates)?;
        }
        "move" => {
            if let Some(dir) = move_dir {
                move_duplicates(&duplicates, dir)?;
            } else {
                eprintln!("Error: --move-dir must be specified for 'move' action");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Unsupported action: {}", action);
            std::process::exit(1);
        }
    }

    let mut file = File::create(output_file)?;
    let json_output = serde_json::to_string_pretty(&json!(duplicates))?;
    file.write_all(json_output.as_bytes())?;

    Ok(())
}

