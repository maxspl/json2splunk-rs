use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use env_logger;
use log::info;

mod utils;
mod splunk_utils;
mod json2splunk;

use crate::utils::file_matcher::{FileMatcher, FileTuple};
use json2splunk::Json2Splunk;
use num_cpus;

/// Command line arguments for the json2splunk_rust application.
#[derive(Parser, Debug)]
#[command(name = "json2splunk_rust", about = "Ingest JSON/CSV logs into Splunk via HEC.")]
struct Cli {
    /// Increase output verbosity (DEBUG, INFO, WARNING, ERROR)
    #[arg(short = 'v', long = "verbosity", default_value = "INFO")]
    verbosity: String,

    /// Directory to index. Required unless --file is provided.
    #[arg(long = "input", required_unless_present = "file")]
    input: Option<PathBuf>,

    /// Single file to process. When set, --indexer_patterns is not required.
    #[arg(long = "file")]
    file: Option<PathBuf>,

    /// Optional : Specifies the file input type (json|jsonl|csv). Default is None.
    #[arg(long = "input_type")]
    input_type: Option<String>,

    /// Splunk index name.
    /// Required unless --normalize_test_dir is provided.
    #[arg(
        long = "index",
        required_unless_present = "normalize_test_dir"
    )]
    index: Option<String>,

    /// Specifies the number of CPUs to use for processing. Defaults to the number of available CPUs.
    #[arg(long = "nb_cpu", default_value_t = num_cpus::get())]
    nb_cpu: usize,

    /// Enables test mode where no data is sent to Splunk. Useful to debug matched files.
    #[arg(long = "test")]
    test: bool,

    /// Specifies the path to the Splunk configuration file.
    #[arg(long = "config_spl", default_value = "splunk_configuration.yml")]
    config_spl: PathBuf,

    /// Specifies the path to the file patterns configuration. Not required when --file is used.
    #[arg(long = "indexer_patterns", default_value = "indexer_patterns.yml")]
    indexer_patterns: PathBuf,

    /// Specifies a list of extensions to prefilter the input directory. Defaults is None.
    #[arg(long = "ext")]
    ext: Option<String>,

    /// Directory where VRL scripts are located. Default to current dir.
    #[arg(long = "vrl_dir", value_name = "DIR")]
    vrl_dir: Option<PathBuf>,

    /// Debug/Test option to write normalized JSONL files to a directory
    /// instead of sending events to Splunk (VRL normalize test mode).
    #[arg(long, value_name = "DIR")]
    normalize_test_dir: Option<PathBuf>,

   /// Deprecated: UID metadata is enabled by default. This flag is kept for compatibility.
    #[arg(long = "uid", hide = true)]
    uid: bool,

    /// Disable automatic UID metadata on ingested events.
    #[arg(long = "no-uid", conflicts_with = "uid")]
    no_uid: bool,

    /// Force ingestion even when the file already has a completed ingestion_metadata event in Splunk.
    /// By default, json2splunk-rs skips already ingested files.
    #[arg(long = "force_reingest", conflicts_with = "overwrite_ingested")]
    force_reingest: bool,

    /// Delete existing events for already ingested sourcefiles, then ingest them again.
    /// This requires the Splunk delete capability.
    #[arg(long = "overwrite_ingested", conflicts_with = "force_reingest")]
    overwrite_ingested: bool,

    // --- Options only used with --file ---

    /// Sourcetype to assign when using --file. Defaults to the file stem.
    #[arg(long = "sourcetype", requires = "file")]
    sourcetype: Option<String>,

    /// Host value to assign when using --file. Defaults to "Unknown".
    #[arg(long = "host", requires = "file")]
    host: Option<String>,

    /// Artifact name when using --file. Defaults to the file stem.
    #[arg(long = "artifact", requires = "file")]
    artifact: Option<String>,

    /// JSON path(s) to the timestamp field when using --file (repeatable: --timestamp_path a --timestamp_path b).
    #[arg(long = "timestamp_path", requires = "file")]
    timestamp_path: Vec<String>,

    /// Timestamp format (strftime) when using --file.
    #[arg(long = "timestamp_format", requires = "file")]
    timestamp_format: Option<String>,

    /// JSON path to the host field when using --file.
    #[arg(long = "host_path", requires = "file")]
    host_path: Option<String>,

    /// VRL normalize script(s) when using --file (repeatable: --normalize s1 --normalize s2).
    #[arg(long = "normalize", requires = "file")]
    normalize: Vec<String>,

    /// File encoding when using --file (e.g. utf-8, latin-1).
    #[arg(long = "encoding", requires = "file")]
    encoding: Option<String>,

    /// Source value to assign when using --file. Defaults to the file stem.
    #[arg(long = "source", requires = "file")]
    source: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(cli.verbosity.as_str())
    ).init();

    let start = Instant::now();
    info!("Using {} CPUs", cli.nb_cpu);

    let tuples: Vec<FileTuple> = if let Some(ref file_path) = cli.file {
        if !file_path.exists() {
            eprintln!("Error: file not found: {:?}", file_path);
            std::process::exit(1);
        }
        let stem = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let sourcetype = cli.sourcetype.clone().unwrap_or_else(|| stem.clone());
        let host = cli.host.clone().unwrap_or_else(|| "Unknown".to_string());
        let artifact = cli.artifact.clone().unwrap_or_else(|| stem.clone());
        let timestamp_format = cli.timestamp_format.clone().unwrap_or_default();
        info!("Single file mode: {:?}", file_path);
        vec![FileTuple {
            file_path: file_path.clone(),
            sourcetype,
            host,
            timestamp_path: cli.timestamp_path.clone(),
            timestamp_format,
            host_path: cli.host_path.clone(),
            source: cli.source.clone().unwrap_or_else(|| stem.clone()),
            artifact,
            normalize: cli.normalize.clone(),
            encoding: cli.encoding.clone(),
        }]
    } else {
        let input_dir = cli.input.as_ref().unwrap();
        let mut fm = FileMatcher::new(cli.indexer_patterns.clone(), cli.test, cli.ext.clone());
        fm.create_dataframe(input_dir);
        fm.print_statistics();
        info!("Input identification completed in {:?}", start.elapsed());
        fm.list_of_tuples
    };

    let mut j2s = Json2Splunk::new(cli.normalize_test_dir.clone());
    j2s.set_add_uid(cli.uid || !cli.no_uid);
    j2s.set_vrl_dir(cli.vrl_dir.clone());

    let normalize_mode = cli.normalize_test_dir.is_some();
    let index_str = cli.index.as_deref().unwrap_or("");

    if !normalize_mode && index_str.is_empty() {
        eprintln!("Error: --index is required unless --normalize_test_dir is used.");
        std::process::exit(1);
    }

    if cli.input_type.is_some() {
        j2s.input_type = cli.input_type.clone();
    }

    if j2s.configure(index_str, cli.nb_cpu, cli.test, &cli.config_spl) {
        if cli.overwrite_ingested {
            if j2s.overwrite_ingest(&tuples).is_none() {
                eprintln!(
                    "Error: could not overwrite already ingested events in Splunk, \
                    aborting before continuing re-ingestion. \
                    Check that the Splunk user can run the delete command."
                );
                std::process::exit(1);
            }
        } else {
            let tuples = if cli.force_reingest {
                info!("force_reingest: disabled already-ingested filtering, all candidate files will be ingested.");
                tuples
            } else {
                match j2s.filter_ingested(tuples) {
                    Some(t) => t,
                    None => {
                        eprintln!(
                            "Error: could not retrieve ingestion state from Splunk, \
                            aborting instead of risking duplicates. \
                            Rerun with --force_reingest to force ingestion."
                        );
                        std::process::exit(1);
                    }
                }
            };

            if tuples.is_empty() {
                info!("No file left to ingest after already-ingested filtering.");
            } else {
                j2s.ingest(&tuples);
            }
        }
    }

    info!("Finished in {:?}", start.elapsed());
}
