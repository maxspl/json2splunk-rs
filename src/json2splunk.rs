use std::fs::File;
use std::io::{BufRead, BufReader, Write, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use log::{debug, error, info, warn};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::splunk_utils::{
    splunk_helper::SplunkHelper,
    http_event_collector::HttpEventCollector
};

use crate::utils::{
    file_matcher::FileTuple,
    utils::{LossyUtf8Reader, extract_host_from_record, extract_timestamp_from_record, normalize_host, hash_path, is_valid_hec_time},
    vrl::{VrlChain, compile_vrl_chain, apply_vrl_chain_to_record}
};

use std::sync::Arc;
use std::thread;
use crossbeam_channel as chan;
use reqwest::blocking::Client; 
use std::io::Read;


// Structure of the Splunk configuration YAML
#[derive(Debug, Deserialize)]
struct SplunkSection {
    host: String,
    user: String,
    password: String,
    mport: u16,
    ssl: bool,
}

#[derive(Debug, Deserialize)]
struct SplunkConfig {
    splunk: SplunkSection,
}

//Use to build HEC payloads
#[derive(Clone)]
struct EventContext {
    source: String,
    sourcetype: String,
    host_base: String,
    host_path: Option<String>,
    timestamp_paths: Vec<String>,
    timestamp_format: String,
    artifact: String,
    sourcefile: String,
}

/// Main struct
pub struct Json2Splunk {
    hec_template: Option<HttpEventCollector>,
    pub nb_cpu: usize,
    pub test_mode: bool,
    pub index: String,
    pub vrl_dir: Option<PathBuf>,
    pub normalize_test_dir: Option<PathBuf>,
    pub input_type: Option<String>,
    client: Client, 
}

enum ParseMode {
    Json,
    Raw,
}

enum NormalizeWriter {
    Abort,
    Disabled,
    Enabled(BufWriter<File>),
}

impl Json2Splunk {
    pub fn new(normalize_test_dir: Option<PathBuf>) -> Self {
            let client = Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .danger_accept_invalid_certs(true)
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .pool_max_idle_per_host(32)
                .build()
                .expect("Failed to create global HTTP client");

            Json2Splunk {
                hec_template: None,
                nb_cpu: 1,
                test_mode: false,
                index: String::new(),
                normalize_test_dir,
                vrl_dir: None,
                input_type: None,
                client, 
            }
        }

    pub fn set_vrl_dir(&mut self, dir: Option<PathBuf>) {
        self.vrl_dir = dir;
    }

    fn init_hec(hec_template_opt: Option<&HttpEventCollector>, is_normalize: bool, file_kind_label: &str,) -> Option<Option<HttpEventCollector>> {
        if is_normalize {
            return Some(None);
        }

        match hec_template_opt {
            Some(h) => Some(Some(h.clone())),
            None => {
                error!(
                    "HEC template is required for {} processing in Splunk mode.",
                    file_kind_label
                );
                None
            }
        }
    }
    fn run_parallel_line_pipeline(&self, 
        file_kind_label: &str,
        default_output_name: &str,
        hec_template_opt: Option<&HttpEventCollector>,
        file_tuples: &FileTuple,
        normalize_dir: Option<&PathBuf>,
        mode: ParseMode,
    ) {
        // 1. Resolve the input file path and check if we are in normalize-test mode
        let path = file_tuples.file_path.clone();
        let is_normalize = normalize_dir.is_some();
    
        // 2. Initialize the HEC template (only required if we actually send to Splunk)
        //    - If normalize mode is enabled, this is skipped internally
        //    - If HEC is required but missing, we abort processing
        let hec_template = match Self::init_hec(hec_template_opt, is_normalize, file_kind_label) {
            Some(h) => h,
            None => return,
        };
    
        // 3. Initialize the normalize writer (only used when normalize-test is enabled)
        //    This function:
        //      - Creates <input>.<hash>.normalized.jsonl
        //      - Updates normalize_mapping.json
        //      - Returns a NormalizeWriter enum describing what to do
        let writer_state = Self::init_normalize_writer(
            normalize_dir,
            &path,
            default_output_name,
            file_kind_label,
            &file_tuples.source,
        );
    
        // 4. Build the shared event context (metadata: source, sourcetype, host, etc.)
        let ctx = Arc::new(Self::build_event_context(file_tuples, &path));
        
        // Create an atomic counter to count the number of events sent for this file.
        let event_count = Arc::new(AtomicU64::new(0));

        // 5. Compile the VRL normalization chain for this file type
        let vrl_chain: Arc<VrlChain> =
            Arc::new(compile_vrl_chain(self.vrl_dir.as_deref(), &file_tuples.normalize));
    
        // 6. Open the input file for reading
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open {} file {:?}: {}", file_kind_label, path, e);
                return;
            }
        };
    
        // 7. Create channel for normalized-line writing (used only in normalize-test mode)
        let (write_tx, write_rx) = chan::bounded::<Vec<u8>>(10_000);
        let mut writer_handle = None;
    
        // 8. Decide how to handle normalized output based on NormalizeWriter
        match writer_state {
            // 8.1 Fatal error during writer initialization → abort this file
            NormalizeWriter::Abort => {
                drop(write_rx);
                return;
            }
    
            // 8.2 Normalize-test disabled → drop receiver so worker threads won’t block
            NormalizeWriter::Disabled => {
                drop(write_rx);
            }
    
            // 8.3 Normalize-test enabled → spawn writer thread
            NormalizeWriter::Enabled(mut w) => {
                writer_handle = Some(thread::spawn(move || {
                    // This thread receives serialized JSON records and writes them
                    // to <input>.<hash>.normalized.jsonl
                    for bytes in write_rx {
                        if w.write_all(&bytes).is_err() || w.write_all(b"\n").is_err() {
                            warn!("Failed to write to output file, stopping writer thread");
                            break;
                        }
                    }
                    let _ = w.flush();
                }));
            }
        }
    
        // 9. Create channel between the reader thread and worker threads
        let (tx, rx) = chan::bounded::<(usize, String)>(10_000);
    
        // 10. Determine how many worker threads to use: max available, minimum 1
        let nb_workers = self.nb_cpu.max(1);

        // Check if encoding is set in indexer patterns
        let is_utf8 = if let Some(enc) = &file_tuples.encoding {
            if enc.eq_ignore_ascii_case("utf-8") || enc.eq_ignore_ascii_case("utf8") {
                info!("{} encoding '{}' detected for {:?}, using fast UTF-8 reader.", file_kind_label, enc, path);
                true
            } else {
                warn!("Encoding '{}' for {:?} not supported (only UTF-8). Falling back to lossy reader.", enc, path);
                false
            }
        } else {
            // No encoding hint → assume non-UTF8 and be safe
            warn!("No encoding metadata for {:?}, falling back to lossy reader.", path);
            false
        };


        // 11. Spawn the reader thread (single producer)
        let path_for_reader = path.clone();
        let reader_handle = thread::spawn(move || {
            let mut reader = BufReader::new(file);
            let mut buf = Vec::<u8>::new();
            let mut lineno = 0usize;
    
            loop {
                buf.clear();
    
                // 11.1 Read one line from the input file
                let res = reader.read_until(b'\n', &mut buf);
                match res {
                    Ok(0) => break, // EOF
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error reading {:?}: {}", path_for_reader, e);
                        break;
                    }
                };
    
                lineno += 1;
    
                // 11.2 Convert raw bytes to trimmed string
                let raw = if is_utf8 {
                    // Fast path: avoid lossy and avoid a second allocation
                    match std::str::from_utf8(&buf) {
                        Ok(s) => s.trim().to_string(),
                        Err(_) => {
                            // fallback to lossy if needed
                            String::from_utf8_lossy(&buf).trim().to_string()
                        }
                    }
                } else {
                    // Non-UTF8 declared encoding → decode lossy immediately
                    String::from_utf8_lossy(&buf).trim().to_string()
                };
    
                // Skip empty lines
                if raw.is_empty() {
                    continue;
                }
    
                // 11.3 Send line number + content to worker pool
                if tx.send((lineno, raw)).is_err() {
                    break;
                }
            }
    
            debug!("Reader thread finished for {:?}", path_for_reader);
        });
    
        // 12. Spawn worker threads (parallel consumers)
        let mut worker_handles = Vec::with_capacity(nb_workers);
    
        for _ in 0..nb_workers {
            let rx = rx.clone();
            let ctx = Arc::clone(&ctx);
            let vrl_chain = Arc::clone(&vrl_chain);
            let event_count = Arc::clone(&event_count);

            // 12.1 Only clone write channel if writer thread exists
            let write_tx = if writer_handle.is_some() {
                Some(write_tx.clone())
            } else {
                None
            };
    
            // 12.2 Each worker gets its own cloned HEC client
            let mut hec_client = hec_template.clone();
            let path_for_worker = path.clone();
    
            // 12.3 Copy parsing mode to avoid sharing reference
            let mode_for_worker = match mode {
                ParseMode::Json => ParseMode::Json,
                ParseMode::Raw => ParseMode::Raw,
            };
    
            worker_handles.push(thread::spawn(move || {
                let mut local_count = 0usize;
    
                for (lineno, raw) in rx.iter() {
    
                    // 13. Parse input line depending on file mode
                    let mut record = match mode_for_worker {
    
                        // 13.1 JSON mode → parse as JSON object
                        ParseMode::Json => {
                            match serde_json::from_str::<Value>(&raw) {
                                Ok(value) => value,
                                Err(e) => {
                                    warn!(
                                        "Invalid JSON at line {} in {:?}: {}. Skipping.",
                                        lineno, path_for_worker, e
                                    );
                                    continue;
                                }
                            }
                        }
    
                        // 13.2 RAW mode → wrap raw content into { "message": "..." }
                        ParseMode::Raw => {
                            let trimmed = raw.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            json!({ "message": trimmed })
                        }
                    };
    
                    // 14. Apply VRL normalization chain (if configured)
                    if !vrl_chain.is_empty() {
                        match apply_vrl_chain_to_record(record, &vrl_chain) {
                            Some(norm) => record = norm,
                            None => continue, // Record dropped by VRL
                        }
                    }
    
                    // 15. If normalize-test mode → send normalized JSON to writer thread
                    if let Some(ref tx) = write_tx {
                        if let Ok(bytes) = serde_json::to_vec(&record) {
                            let _ = tx.send(bytes);
                        }
                    }
    
                    // 16. If Splunk HEC is enabled → build payload and batch-send
                    if let Some(ref mut hec) = hec_client {
                        let payload = Json2Splunk::build_payload(record, &ctx);
                        hec.batch_event(payload);
                            // Increment the total event counter whenever an event is sent
                            event_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
    
                // 17. Final flush for events still buffered
                if let Some(mut hec) = hec_client {
                    hec.flush_batch();
                }
            }));
        }
    
        // 18. Drop the main write sender so writer thread terminates once workers finish
        drop(write_tx);
    
        // 19. Wait for reader thread to finish
        let _ = reader_handle.join();
    
        // 20. Wait for all worker threads to finish
        for h in worker_handles {
            let _ = h.join();
        }
    
        // 21. Wait for writer thread to finish (if it exists)
        if let Some(h) = writer_handle {
            let _ = h.join();
        }
    
        // 22. Log completion
        info!("Finished {} file {:?}", file_kind_label, path);

        // If Splunk HEC is configured, send a summary event with the expected count.
        if let Some(ref hec_template) = hec_template {
            let total = event_count.load(Ordering::Relaxed);
            let summary_record = json!({
                "expected_event_count": total,
                "event_type": "ingestion_metadata",
            });
            let payload = Json2Splunk::build_payload(summary_record, &ctx);
            let mut hec = hec_template.clone();
            hec.batch_event(payload);
            hec.flush_batch();
        }
    }
    

    fn run_parallel_csv_pipeline(
        &self,
        hec_template_opt: Option<&HttpEventCollector>,
        file_tuples: &FileTuple,
        normalize_dir: Option<&PathBuf>,
    ) {
        // 1. Resolve input CSV path and check if we are in normalize-test mode
        let path = file_tuples.file_path.clone();
        let is_normalize = normalize_dir.is_some();
    
        // 2. Initialize HEC template (if needed)
        //    - If normalize-test is enabled, HEC may be skipped internally
        //    - If HEC is required but not available, abort this file
        let hec_template = match Self::init_hec(hec_template_opt, is_normalize, "CSV") {
            Some(h) => h,
            None => return,
        };
    
        // 3. Initialize normalize writer (only meaningful in normalize-test mode)
        //    This may:
        //      - Create <input>.<hash>.normalized.jsonl
        //      - Update normalize_mapping.json
        //      - Return a NormalizeWriter enum describing the outcome
        let writer_state = Self::init_normalize_writer(
            normalize_dir,
            &path,
            "output.csv",
            "CSV",
            &file_tuples.source,
        );
        
        // 4. Build shared event context (host/source/sourcetype/artifact...)
        let ctx = Arc::new(Self::build_event_context(file_tuples, &path));
    
        // Create an atomic counter to count the number of events sent for this file.
        let event_count = Arc::new(AtomicU64::new(0));

        // 5. Compile VRL normalization chain for this CSV file (if any)
        let vrl_chain: Arc<VrlChain> =
            Arc::new(compile_vrl_chain(self.vrl_dir.as_deref(), &file_tuples.normalize));
    
        // 6. Open CSV input file
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open CSV file {:?}: {}", path, e);
                return;
            }
        };
    
        // 7. Wrap file in a BufReader → LossyUtf8Reader → CSV reader
        //    - LossyUtf8Reader handles invalid UTF-8 gracefully
        //    - CSV reader is configured to:
        //        * Treat first row as headers
        //        * Allow variable-length rows (flexible)
        let buf_reader = BufReader::new(file);
        let reader: Box<dyn Read + Send> = if let Some(enc) = &file_tuples.encoding {
            if enc.eq_ignore_ascii_case("utf-8") || enc.eq_ignore_ascii_case("utf8") {
                info!("CSV encoding '{}' detected for {:?}, using fast UTF-8 reader.", enc, path);
                Box::new(buf_reader)
            } else {
                warn!("Encoding '{}' for {:?} not supported (only UTF-8). Falling back to lossy reader.", enc, path);
                Box::new(LossyUtf8Reader::new(buf_reader))
            }
        } else {
            Box::new(LossyUtf8Reader::new(buf_reader))
        };

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(reader);

        // 8. Read CSV headers into a separate structure for mapping to JSON keys
        let headers = match rdr.headers() {
            Ok(h) => h.clone(),
            Err(e) => {
                error!("Failed to read CSV headers from {:?}: {}", path, e);
                return;
            }
        };
    
        // 9. Create channel for normalized JSONL writing (used in normalize-test mode)
        let (write_tx, write_rx) = chan::bounded::<Vec<u8>>(10_000);
        let mut writer_handle = None;
        
        // 10. Handle normalize writer behavior based on NormalizeWriter state
        match writer_state {
            // 10.1 Irrecoverable error during writer setup → abort processing
            NormalizeWriter::Abort => {
                drop(write_rx);
                return;
            }
            // 10.2 Normalize-test disabled → drop receiver so no writer thread is used
            NormalizeWriter::Disabled => {
                // No normalize-test output; drop receiver so workers won't block on send
                drop(write_rx);
            }
            // 10.3 Normalize-test enabled → spawn writer thread to consume write_rx
            NormalizeWriter::Enabled(mut w) => {
                writer_handle = Some(thread::spawn(move || {
                    let mut lines: u64 = 0;

                    // This thread writes each serialized JSON line to the normalized output file
                    for bytes in write_rx {
                        lines += 1;
                        if w.write_all(&bytes).is_err() || w.write_all(b"\n").is_err() {
                            break;
                        }
                    }
                    let _ = w.flush();
                }));
            }
        }
        
        // 11. Create channel from CSV reader → worker threads
        //     - Each message is a raw CSV record (StringRecord)
        let (tx, rx) = chan::bounded::<csv::StringRecord>(10_000);
    
        // 12. Decide number of worker threads
        let nb_workers = self.nb_cpu.max(1);
    
        // 13. Spawn reader thread that:
        //      - Iterates over CSV records
        //      - Sends raw CSV records to worker threads via tx
        let path_for_reader = path.clone();
        let reader_handle = thread::spawn(move || {
            let mut rows: usize = 0;

            // Explicit iterator so we can time the "next" call
            let mut iter = rdr.records();
            let path_for_reader2 = path_for_reader.clone();

            loop {
                let result_opt = iter.next();

                let result = match result_opt {
                    Some(res) => res,
                    None => break, // EOF
                };

                let record = match result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            "CSV row {} in {:?} could not be parsed: {}. Skipping.",
                            rows + 1,
                            path_for_reader2,
                            e
                        );
                        continue;
                    }
                };

                rows += 1;

                if tx.send(record).is_err() {
                    break;
                }
            }
        });

    
        // 14. Spawn worker threads to process records in parallel
        let mut worker_handles = Vec::with_capacity(nb_workers);
    
        for worker_id in 0..nb_workers {
            let rx = rx.clone();
            let ctx = Arc::clone(&ctx);
            let vrl_chain = Arc::clone(&vrl_chain);
            let headers = headers.clone(); // each worker gets its own copy of headers
            let event_count = Arc::clone(&event_count);

            // 14.1 Only create a write channel handle if writer thread exists
            let write_tx = if writer_handle.is_some() {
                Some(write_tx.clone())
            } else {
                None
            };
    
            // 14.2 Each worker gets its own HEC client clone (if HEC is enabled)
            let mut hec_client = hec_template.clone();
    
            worker_handles.push(thread::spawn(move || {

                let mut local_count = 0usize;
    
                // 15. Consume CSV records from the channel
                for record in rx.iter() {

                    // 15.0 Build JSON object from headers + record in the worker
                    let mut map = Map::new();
                    let mut all_empty = true;
                    for (h, v) in headers.iter().zip(record.iter()) {
                        let s = v.to_string();
                        if !s.is_empty() {
                            all_empty = false;
                        }
                        map.insert(h.to_string(), Value::String(s));
                    }

                    // Skip rows where all fields are empty
                    if all_empty {
                        continue;
                    }

                    let mut record_val = Value::Object(map);
    
                    // 15.1 Apply VRL normalization chain (if not empty)
                    if !vrl_chain.is_empty() {
                        let res = apply_vrl_chain_to_record(record_val, &vrl_chain);

                        match res {
                            Some(norm) => record_val = norm,
                            None => continue, // record dropped by VRL logic
                        }
                    }
    
                    // 15.2 If normalize-test mode: forward normalized JSON to writer thread
                    if let Some(ref tx) = write_tx {
                        if let Ok(bytes) = serde_json::to_vec(&record_val) {
                            let _ = tx.send(bytes);
                        }
                    }
    
                    // 15.3 If Splunk HEC is configured: send record as a batched event
                    if let Some(ref mut hec) = hec_client {
                        let payload = Json2Splunk::build_payload(record_val, &ctx);
                        hec.batch_event(payload);
                        local_count += 1;
                        // Increment the overall event counter
                        event_count.fetch_add(1, Ordering::Relaxed);
                        // 15.4 Periodically flush batches (every 1000 events)
                        if local_count % 1000 == 0 {
                            hec.flush_batch();
                        }
                    }
                }
    
                // 16. Final flush of any remaining batched events
                if let Some(mut hec) = hec_client {
                    hec.flush_batch();
                }
            }));
        }
    
        // 17. Drop the main write sender so that, once workers finish,
        //     the writer thread sees channel closure and exits cleanly
        drop(write_tx); 
    
        // 18. Wait for CSV reader thread to finish
        let _ = reader_handle.join();
    
        // 19. Wait for all worker threads to finish
        for h in worker_handles {
            let _ = h.join();
        }
    
        // 20. Wait for writer thread to finish (if normalize-test writer was spawned)
        if let Some(h) = writer_handle {
            let _ = h.join();
        }
    
        info!("Finished CSV file {:?}", path);

        // Emit a summary event with the expected number of events for this CSV file
        if let Some(ref hec_template) = hec_template {
            let total = event_count.load(Ordering::Relaxed);
            let summary_record = json!({
                "expected_event_count": total,
                "event_type": "ingestion_metadata",
            });
            let payload = Json2Splunk::build_payload(summary_record, &ctx);
            let mut hec = hec_template.clone();
            hec.batch_event(payload);
            hec.flush_batch();
        }
    }


    fn init_normalize_writer(
        normalize_dir: Option<&PathBuf>,
        path: &Path,
        default_input_name: &str,
        file_kind_label: &str,
        source: &str,
    ) -> NormalizeWriter {
        // Only use with normalize-test to write output jsonl
        // Write <input_name>.<hash>.normalized.jsonl
        // Write normalize_mapping.json

        if let Some(out_dir) = normalize_dir {
            debug!(
                "Normalize-test: Processing {} file {:?} (source: {})",
                file_kind_label, path, source
            );

            if std::fs::create_dir_all(out_dir).is_err() {
                error!(
                    "Failed to create normalize-test directory {}",
                    out_dir.display()
                );
                return NormalizeWriter::Abort;
            }

            let hash = hash_path(path);
            let hash_hex = format!("{:016x}", hash);

            let input_name = path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new(default_input_name));

            let input_stem = std::path::Path::new(input_name)
                .file_stem()
                .unwrap_or(input_name)
                .to_string_lossy();

            let out_file_name = format!("{input_stem}.{hash_hex}.normalized.jsonl");
            let out_path = out_dir.join(out_file_name);

            let out_file = match File::create(&out_path) {
                Ok(f) => f,
                Err(e) => {
                    error!(
                        "normalize-test: cannot create {:?}: {}",
                        out_path, e
                    );
                    return NormalizeWriter::Abort;
                }
            };

            info!("normalize-test {} output → {}", file_kind_label, out_path.display());

            let mapping_path = out_dir.join("normalize_mapping.json");

            let mut mappings: Map<String, Value> = if mapping_path.exists() {
                match File::open(&mapping_path) {
                    Ok(f) => {
                        match serde_json::from_reader::<_, Value>(BufReader::new(f)) {
                            Ok(Value::Object(m)) => m,
                            Ok(_) => {
                                warn!(
                                    "normalize-test: mapping file {} is not an object, resetting.",
                                    mapping_path.display()
                                );
                                Map::new()
                            }
                            Err(e) => {
                                warn!(
                                    "normalize-test: could not parse mapping file {}: {}. Resetting.",
                                    mapping_path.display(),
                                    e
                                );
                                Map::new()
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "normalize-test: could not open mapping file {}: {}. Resetting.",
                            mapping_path.display(),
                            e
                        );
                        Map::new()
                    }
                }
            } else {
                Map::new()
            };

            let input_key = path.to_string_lossy().to_string();
            let output_val = Value::String(out_path.to_string_lossy().into_owned());
            mappings.insert(input_key, output_val);

            match File::create(&mapping_path) {
                Ok(f) => {
                    if let Err(e) =
                        serde_json::to_writer(BufWriter::new(f), &Value::Object(mappings))
                    {
                        warn!(
                            "normalize-test: failed to write mapping file {}: {}",
                            mapping_path.display(),
                            e
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "normalize-test: cannot create mapping file {}: {}",
                        mapping_path.display(),
                        e
                    );
                }
            }

            NormalizeWriter::Enabled(BufWriter::new(out_file))
        } else {
            debug!(
                "Processing {} file {:?} (source: {})",
                file_kind_label, path, source
            );
            NormalizeWriter::Disabled
        }
    }



    fn build_event_context(file_tuples: &FileTuple, path: &Path) -> EventContext {
        EventContext {
            source: file_tuples.source.clone(),
            sourcetype: file_tuples.sourcetype.clone(),
            host_base: file_tuples.host.clone(),
            host_path: file_tuples.host_path.clone(),
            timestamp_paths: file_tuples.timestamp_path.clone(),
            timestamp_format: file_tuples.timestamp_format.clone(),
            artifact: file_tuples.artifact.clone(),
            sourcefile: path.to_string_lossy().to_string(),
        }
    }

    pub fn configure(&mut self, index: &str, nb_cpu: usize, testing: bool, config_spl: &Path,) -> bool {
            self.index = index.to_string();
            self.nb_cpu = nb_cpu.max(1);
            self.test_mode = testing;

            if self.normalize_test_dir.is_some() {
                if self.test_mode {
                    warn!("Both test mode and normalize_test_dir are set; normalize_test_dir mode implies no data will be sent to Splunk.");
                }
                info!("normalize_test_dir={:?} set; skipping Splunk configuration.", self.normalize_test_dir);
                return true;
            }

            if self.test_mode {
                warn!("Testing mode enabled. NO data will be sent to Splunk.");
            }

            let file = match File::open(config_spl) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to open Splunk configuration file {:?}: {}", config_spl, e);
                    return false;
                }
            };

            let cfg: SplunkConfig = match serde_yaml::from_reader(file) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to parse Splunk configuration YAML: {}", e);
                    return false;
                }
            };

            let spl = &cfg.splunk;
            info!("Splunk config: host={}, mport={}, ssl={}", spl.host, spl.mport, spl.ssl);

            let helper = SplunkHelper::new(&spl.host, &spl.user, &spl.password, spl.mport, spl.ssl);

            if !helper.test_connection() {
                error!("Unable to connect to Splunk management API.");
                return false;
            }

            if !helper.create_index(index) {
                error!("Failed to create or verify index {}", index);
                return false;
            }

            let token = match helper.ensure_hec_token(index) {
                Some(t) => t,
                None => {
                    error!("Failed to obtain HEC token for index {}", index);
                    return false;
                }
            };

            let mut hec = HttpEventCollector::new(&token, &spl.host, "json", self.client.clone());
            hec.index = Some(index.to_string());

            info!("HEC Instance Ready: server_uri={}", hec.server_uri());
            self.hec_template = Some(hec);
            info!("Splunk configuration successful.");
            true
        }

    fn build_payload(record: Value, ctx: &EventContext) -> Value {
        let mut host = normalize_host(&ctx.host_base);

        if let Some(ref host_path_str) = ctx.host_path {
            if let Some(h2) = extract_host_from_record(&record, host_path_str) {
                host = normalize_host(&h2);
            }
        }

        let mut payload = json!({
            "event": record,
            "source": ctx.source,
            "sourcetype": ctx.sourcetype,
            "host": host,
            "fields": {
                "sourcefile": ctx.sourcefile,
                "artifact": ctx.artifact,
            }
        });

        if !ctx.timestamp_paths.is_empty() {
            let fmt_opt = if ctx.timestamp_format.is_empty() {
                None
            } else {
                Some(ctx.timestamp_format.as_str())
            };

            if let Some(ts) = extract_timestamp_from_record(
                payload.get("event").unwrap(),
                &ctx.timestamp_paths,
                fmt_opt,
            ) {
                if is_valid_hec_time(ts) {
                    payload["time"] = json!(ts);
                } else {
                    debug!(
                        "Dropping unreasonable event time={} for sourcefile={} (host_base={})",
                        ts,
                        ctx.sourcefile,
                        ctx.host_base
                    );
                    // No `time` → Splunk will use ingest time
                }
            }
        }


        payload
    }

    pub fn ingest(&mut self, tuples: &[FileTuple]) {
        // Main function of Json2Splunk
        // Takes in input tuples generated by FileMatcher (file_path, sourcetype, timestamp_path...)
        
        let normalize_dir = self.normalize_test_dir.clone();

        if normalize_dir.is_some() {
            info!(
                "Normalize test mode: writing normalized JSON to {:?}, no data to Splunk.",
                normalize_dir.as_ref().unwrap()
            );
            if tuples.is_empty() {
                info!("No files to process.");
                return;
            }
        } else if self.test_mode {
            info!("Test mode enabled: ingest() will not send data.");
            return;
        }

        let hec_template = if normalize_dir.is_none() {
            match self.hec_template.clone() {
                Some(h) => Some(h),
                None => {
                    error!("HEC template not configured; call configure() first.");
                    return;
                }
            }
        } else {
            None
        };

        if tuples.is_empty() {
            info!("No files to ingest.");
            return;
        }

        // Process each file
        for file_tuples in tuples {
            debug!(
                "Starting ingestion of file {:?} for source {}",
                file_tuples.file_path, file_tuples.source
            );
            self.process_file(hec_template.as_ref(), file_tuples, normalize_dir.as_ref(),
            );
        }
    }

    fn process_file(&self, hec_template: Option<&HttpEventCollector>, file_tuples: &FileTuple,normalize_dir: Option<&PathBuf>,) {
        let file = &file_tuples.file_path;

        let mut ext = file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if !self.input_type.is_none(){
            ext = self.input_type.clone().unwrap();
        }
        // Dispatch processing based on file type: csv, jsonl or raw (eg. access logs)
        match ext.as_str() {
            "json" | "jsonl" => self.run_parallel_line_pipeline("JSON/JSONL", "output.jsonl", hec_template, file_tuples, normalize_dir, ParseMode::Json,),
            "csv" => self.run_parallel_csv_pipeline(hec_template, file_tuples, normalize_dir),
            _ => self.run_parallel_line_pipeline("RAW", "output.raw", hec_template, file_tuples, normalize_dir,ParseMode::Raw,)
        }
    }

}
