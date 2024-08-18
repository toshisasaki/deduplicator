use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use serde_json::json;
use openssl::sha::Sha1;
use walkdir::WalkDir;
use tokio::task;
use futures::stream::{self, StreamExt};
use clap::{Arg, Command, ArgAction};
use num_cpus;

#[derive(Serialize, Deserialize, Debug)]
struct DuplicateFiles {
    hash: String,
    paths: Vec<String>,
}

async fn process_file(path: PathBuf) -> Option<(String, String)> {
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(_) => return None,
    };

    let mut contents = Vec::new();
    if file.read_to_end(&mut contents).is_err() || contents.is_empty() {
        return None;
    }

    let mut hasher = Sha1::new();
    hasher.update(&contents);
    let hash = hasher.finish();
    let hash_hex = hex::encode(hash);

    Some((hash_hex, path.to_string_lossy().to_string()))
}

async fn find_duplicates(input_dir: &str) -> io::Result<Vec<DuplicateFiles>> {
    let mut file_futures = Vec::new();

    for entry in WalkDir::new(input_dir)
        .follow_links(true)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.metadata().map(|m| m.is_file()).unwrap_or(false))
    {
        let path = entry.path().to_path_buf();
        file_futures.push(task::spawn(process_file(path)));
    }

    let num_cpus = num_cpus::get();
    println!("Detected {} CPUs", num_cpus);

    let results = stream::iter(file_futures)
        .buffer_unordered(num_cpus * 2) // Adjust buffer size based on CPU count
        .filter_map(|x| async { x.ok().flatten() })
        .collect::<Vec<(String, String)>>()
        .await;

    let mut hash_map: HashMap<String, Vec<String>> = HashMap::new();

    for (hash, path) in results {
        hash_map.entry(hash).or_insert_with(Vec::new).push(path);
    }

    let duplicates: Vec<DuplicateFiles> = hash_map
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(hash, paths)| DuplicateFiles { hash, paths })
        .collect();

    Ok(duplicates)
}

fn delete_duplicates(duplicates: &[DuplicateFiles]) -> io::Result<()> {
    for duplicate in duplicates {
        // Keep the first file and delete the rest
        for path in &duplicate.paths[1..] {
            fs::remove_file(path)?;
            println!("Deleted: {}", path);
        }
    }
    Ok(())
}

fn move_duplicates(duplicates: &[DuplicateFiles], move_dir: &str) -> io::Result<()> {
    for duplicate in duplicates {
        // Ensure the target directory exists
        fs::create_dir_all(move_dir)?;

        // Keep the first file and move the rest
        for path in &duplicate.paths[1..] {
            let file_name = Path::new(path).file_name().unwrap();
            let target_path = Path::new(move_dir).join(file_name);

            fs::rename(path, &target_path)?;
            println!("Moved: {} -> {}", path, target_path.display());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
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

    let duplicates = find_duplicates(input_dir).await?;

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

