use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use env_logger;
use log::info;

mod utils;
mod splunk_utils;
mod json2splunk;

use crate::utils::file_matcher::FileMatcher;
use json2splunk::Json2Splunk;
use num_cpus;

/// Command line arguments for the json2splunk_rust application.
#[derive(Parser, Debug)]
#[command(name = "json2splunk_rust", about = "Ingest JSON/CSV logs into Splunk via HEC.")]
struct Cli {
    /// Increase output verbosity (DEBUG, INFO, WARNING, ERROR)
    #[arg(short = 'v', long = "verbosity", default_value = "INFO")]
    verbosity: String,

    /// Directory to index (required)
    #[arg(long = "input", required = true)]
    input: PathBuf,

    /// Optional : Specifies the file type input. Defaults is None.
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

    /// Specifies the path to the file patterns configuration
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
}

fn main() {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(cli.verbosity.as_str())
    ).init();

    let start = Instant::now();
    info!("Using {} CPUs", cli.nb_cpu);

    let mut fm = FileMatcher::new(cli.indexer_patterns.clone(), cli.test, cli.ext.clone());
    fm.create_dataframe(&cli.input);
    fm.print_statistics();

    let id_time = Instant::now();
    info!("Input identification completed in {:?}", id_time.duration_since(start));

    let mut j2s = Json2Splunk::new(cli.normalize_test_dir.clone());
    j2s.set_vrl_dir(cli.vrl_dir.clone());

    let normalize_mode = cli.normalize_test_dir.is_some();
    let index_str = cli.index.as_deref().unwrap_or("");

    if !normalize_mode && index_str.is_empty() {
        eprintln!("Error: --index is required unless --normalize_test_dir is used.");
        std::process::exit(1);
    }

    if !cli.input_type.is_none() {
        j2s.input_type = cli.input_type.clone();
    }

    if j2s.configure(index_str, cli.nb_cpu, cli.test, &cli.config_spl) {
        j2s.ingest(&fm.list_of_tuples);
    }

    info!("Finished in {:?}", start.elapsed());
}
