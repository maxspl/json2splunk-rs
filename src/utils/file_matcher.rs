use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use log::{error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use walkdir::WalkDir;

/// Base on the YAML fields:
///   - sourcetype: optional, default to source name
///   - timestamp_path: list of JSON paths
///   - timestamp_format: strftime format
///   - host_path: JSON path
///   - host_rex: regex to extract host from file path
///   - artifact: optional, default to source name
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileCriteria {
    pub name_rex: Option<String>,
    pub path_suffix: Option<String>,
    pub path_rex: Option<String>,
    pub sourcetype: Option<String>,
    pub timestamp_path: Option<Vec<String>>,
    pub timestamp_format: Option<String>,
    pub host_path: Option<String>,
    pub host_rex: Option<String>,
    pub artifact: Option<String>,
    pub normalize: Option<Vec<String>>,
    pub encoding: Option<String>,

    /// Precompiled regexes 
    #[serde(skip)]
    #[serde(default)]
    pub name_re: Option<Regex>,

    #[serde(skip)]
    #[serde(default)]
    pub path_re: Option<Regex>,

    #[serde(skip)]
    #[serde(default)]
    pub host_re: Option<Regex>,
}

/// Matched files metadata
/// (file_path, sourcetype, host, timestamp_path, timestamp_format, host_path, source, artifact, normalize)
#[derive(Debug, Clone)]
pub struct FileTuple {
    pub file_path: PathBuf,
    pub sourcetype: String,
    pub host: String,
    pub timestamp_path: Vec<String>,
    pub timestamp_format: String,
    pub host_path: Option<String>,
    pub source: String,
    pub artifact: String,
    pub normalize: Vec<String>,
    pub encoding: Option<String>,
}

/// Patterns are stored in an IndexMap to preserve YAML order.
/// "IndexMap is a hash table where the iteration order of the key–value pairs is independent of the hash values of the keys."
/// The first pattern in the YAML that matches is treated as the primary match.
#[derive(Debug, Clone)]
pub struct FileMatcher {
    /// Patterns loaded from YAML, keyed by source name (evtx, ntfs_info, orc_csv, …)
    /// Order is the same as in indexer_patterns.yml.
    pub patterns: IndexMap<String, FileCriteria>,
    pub raw_patterns: YamlValue,

    pub test_mode: bool,
    pub ext_filter: Option<Vec<String>>,

    pub matched_files: Vec<PathBuf>,
    /// Unmatched files are fully stored only in test_mode, otherwise only the count is tracked to displays stats
    pub unmatched_files: Vec<PathBuf>,
    pub unmatched_count: usize,
    pub multi_match_count: usize,

    /// How many files matched each pattern (primary match), in YAML order.
    pub pattern_match_count: IndexMap<String, usize>,

    /// Final list of tuples used by Json2Splunk
    pub list_of_tuples: Vec<FileTuple>,
}

impl FileMatcher {
    pub fn new(pattern_file: PathBuf, test_mode: bool, ext_filter: Option<String>) -> Self {
        if !pattern_file.exists() {
            error!(
                "Pattern file not found: {:?}. Please check the --pattern-file path.",
                pattern_file
            );
            std::process::exit(1);
        }

        // Open indexer pattenr file
        let file = match fs::File::open(&pattern_file) {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "Failed to open pattern file {:?}: {}",
                    pattern_file, e
                );
                std::process::exit(1);
            }
        };

        // Parse its yml content
        let raw_yaml: YamlValue = match serde_yaml::from_reader(file) {
            Ok(yaml) => yaml,
            Err(e) => {
                error!(
                    "Invalid YAML in pattern file {:?}: {}",
                    pattern_file, e
                );
                std::process::exit(1);
            }
        };

        // Convert YAML to IndexMap to preserve order from indexer_patterns.yml
        // Important to keep original order 
        // Select where the patterns live:
        // - root is the patterns map
        // - patterns are under top-level "splunk"
        let patterns_node: YamlValue = match &raw_yaml {
            YamlValue::Mapping(m) => {
                // If "splunk" exists and is a mapping, use it
                if let Some(v) = m.get(YamlValue::String("splunk".to_string())) {
                    match v {
                        YamlValue::Mapping(_) => v.clone(),
                        _ => raw_yaml.clone(), // "splunk" exists but isn't a mapping -> fallback
                    }
                } else {
                    raw_yaml.clone()
                }
            }
            _ => raw_yaml.clone(),
        };

        // Deserialize the selected node into IndexMap<String, FileCriteria>
        let mut patterns_map: IndexMap<String, FileCriteria> =
            match serde_yaml::from_value(patterns_node.clone()) {
                Ok(map) => map,
                Err(e) => {
                    error!(
                        "Invalid YAML structure in pattern file {:?}: {}",
                        pattern_file, e
                    );
                    std::process::exit(1);
                }
            };

        // Precompile regexes once to avoid Regex::new
        for (name, crit) in patterns_map.iter_mut() {
            if let Some(ref s) = crit.name_rex {
                match Regex::new(s) {
                    Ok(re) => crit.name_re = Some(re),
                    Err(e) => {
                        error!(
                            "Invalid name_rex regex '{}' for pattern '{}': {}",
                            s, name, e
                        );
                    }
                }
            }

            if let Some(ref s) = crit.path_rex {
                match Regex::new(s) {
                    Ok(re) => crit.path_re = Some(re),
                    Err(e) => {
                        error!(
                            "Invalid path_rex regex '{}' for pattern '{}': {}",
                            s, name, e
                        );
                    }
                }
            }

            if let Some(ref s) = crit.host_rex {
                match Regex::new(s) {
                    Ok(re) => crit.host_re = Some(re),
                    Err(e) => {
                        error!(
                            "Invalid host_rex regex '{}' for pattern '{}': {}",
                            s, name, e
                        );
                    }
                }
            }
        }

        // Transform ext arg from string like ".csv, .jsonl" to Vec<String>
        let ext_list = ext_filter.map(|s| {
            s.split(',')
                .map(|e| e.trim().trim_start_matches('.').to_lowercase())
                .collect::<Vec<_>>()
        });

        // Init pattern match counters to 0, in the same order as patterns_map
        let mut pattern_match_count = IndexMap::new();
        for key in patterns_map.keys() {
            pattern_match_count.insert(key.clone(), 0);
        }

        FileMatcher {
            patterns: patterns_map,
            raw_patterns: raw_yaml,
            test_mode,
            ext_filter: ext_list,
            matched_files: vec![],
            unmatched_files: vec![],
            unmatched_count: 0,
            multi_match_count: 0,
            pattern_match_count,
            list_of_tuples: vec![],
        }
    }

    /// Determines if a file extension is allowed via --ext filter
    fn ext_allowed(&self, path: &Path) -> bool {
        if let Some(exts) = &self.ext_filter {
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                return exts.contains(&ext.to_lowercase());
            }
            return false;
        }
        true
    }

    /// Apply the matching criteria from indexer_patterns.yml
    ///
    /// AND logic:
    ///   - if name_rex is present, file *name* must match
    ///   - if path_suffix is present, parent dir path must end with it
    ///   - if path_rex is present, parent dir path must match it
    ///
    /// Iteration over self.patterns is in YAML order (IndexMap),
    /// so the first pattern that matches is the highest priority.
    fn match_file(&self, path: &Path) -> Vec<String> {
        let mut matches = vec![];

        // File name only, for name_rex (e.g. "\.jsonl$")
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        // Parent directory path as a string, for path_suffix / path_rex
        let dir_path: Cow<'_, str> = path
            .parent()
            .map(|p| p.to_string_lossy())
            .unwrap_or_else(|| Cow::Borrowed(""));

        for (source, criteria) in &self.patterns {
            let mut ok = true;

            // 1) If name_re is defined, the *file name* must match it
            if let Some(re) = &criteria.name_re {
                if !re.is_match(file_name) {
                    ok = false;
                }
            }

            // 2) If path_suffix is defined, the *directory path* must end with it
            if let Some(suffix) = &criteria.path_suffix {
                if !dir_path.ends_with(suffix) {
                    ok = false;
                }
            }

            // 3) If path_re is defined, the *directory path* must match it
            if let Some(re) = &criteria.path_re {
                if !re.is_match(&dir_path) {
                    ok = false;
                }
            }

            if ok {
                matches.push(source.clone());
            }
        }

        matches
    }

    /// Scans the directory recursively for files matching ext + patterns
    ///
    /// Builds:
    ///   - matched_files / unmatched_count / multi_match_count
    ///   - pattern_match_count (per primary match)
    ///   - list_of_tuples: Vec<FileTuple> (like Python's DataFrame rows)
    pub fn create_dataframe(&mut self, input_dir: &Path) {
        for entry in WalkDir::new(input_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if !self.ext_allowed(path) {
                    continue;
                }

                let matches = self.match_file(path);

                if matches.is_empty() {
                    self.unmatched_count += 1;
                    if self.test_mode {
                        self.unmatched_files.push(path.to_path_buf());
                    }
                    continue;
                }

                if matches.len() > 1 {
                    self.multi_match_count += 1;
                    warn!("MULTI-MATCH: {:?} => {:?}", path, matches);
                }

                // Primary pattern = first match in YAML order
                let primary_source = matches[0].clone();
                let criteria = match self.patterns.get(&primary_source) {
                    Some(c) => c,
                    None => {
                        // Should not happen, but be defensive.
                        warn!(
                            "Pattern '{}' not found in patterns map for file {:?}",
                            primary_source, path
                        );
                        continue;
                    }
                };

                // sourcetype: default to source name
                let sourcetype = criteria
                    .sourcetype
                    .clone()
                    .unwrap_or_else(|| primary_source.clone());

                // timestamp_path: default empty vec
                let timestamp_path = criteria
                    .timestamp_path
                    .clone()
                    .unwrap_or_else(|| Vec::new());

                // timestamp_format: default empty string
                let timestamp_format = criteria
                    .timestamp_format
                    .clone()
                    .unwrap_or_else(|| String::new());

                // artifact: default to source name
                let artifact = criteria
                    .artifact
                    .clone()
                    .unwrap_or_else(|| primary_source.clone());

                let normalize = criteria
                    .normalize
                    .clone()
                    .unwrap_or_else(|| Vec::new());

                let encoding = criteria.encoding.clone();

                // Host logic (per Python):
                //   - start with "Unknown"
                //   - if host_rex is set, extract from file path
                //   - if host_path is set, we only set host_path (host will be extracted from JSON later)
                let mut host = "Unknown".to_string();
                let host_path = criteria.host_path.clone();
                if let Some(re) = &criteria.host_re {
                    if let Some(caps) = re.captures(&path.to_string_lossy()) {
                        if let Some(m) = caps.get(1) {
                            host = m.as_str().to_string();
                        }
                    }
                }

                // Normalize host: lower, split by . and take the first
                let host_norm = {
                    let lower = host.to_lowercase();
                    match lower.split('.').next() {
                        Some(first) if !first.is_empty() => first.to_string(),
                        _ => lower,
                    }
                };

                let tuple = FileTuple {
                    file_path: path.to_path_buf(),
                    sourcetype,
                    host: host_norm,
                    timestamp_path,
                    timestamp_format,
                    host_path,
                    source: primary_source.clone(),
                    artifact,
                    normalize,
                    encoding,
                };

                self.matched_files.push(path.to_path_buf());
                self.list_of_tuples.push(tuple);

                // Update primary pattern match count in YAML order
                if let Some(counter) = self.pattern_match_count.get_mut(&primary_source) {
                    *counter += 1;
                }
            }
        }
    }

    pub fn print_statistics(&self) {
        info!("========== FILE MATCHER REPORT ==========");
        info!("Matched files: {}", self.matched_files.len());
        info!("Unmatched files: {}", self.unmatched_count);
        info!("Files with multiple matches: {}", self.multi_match_count);

        // Per-pattern counts, in the same order as indexer_patterns.yml
        for (key, _) in &self.patterns {
            let count = self.pattern_match_count.get(key).cloned().unwrap_or(0);
            info!(
                "Number of files that matched pattern '{}': {}",
                key, count
            );
        }

        if self.test_mode {
            info!("Test mode: writing test_files_to_index.json");

            let mut json_vec = vec![];

            for t in &self.list_of_tuples {
                json_vec.push(serde_json::json!({
                    "file_path": t.file_path.to_string_lossy(),
                    "file_name": t.file_path.file_name().unwrap().to_string_lossy(),
                    "source": t.source,
                    "sourcetype": t.sourcetype,
                    "host": t.host,
                    "timestamp_path": t.timestamp_path,
                    "timestamp_format": t.timestamp_format,
                    "host_path": t.host_path,
                    "artifact": t.artifact,
                }));
            }

            fs::write(
                "test_files_to_index.json",
                serde_json::to_string_pretty(&json_vec).unwrap(),
            )
            .unwrap();
        }
    }
}
