# json2splunk-rs

`json2splunk-rs` is a rework of [json2splunk](https://github.com/maxspl/json2splunk) :
- faster
- supports [VRL normalization](https://vector.dev/docs/reference/vrl/)
- much harder to debug

This tool allows to ingest `jsonl` and `csv` into Splunk using HEC. 


## Features

- **CSV files**: Supports also csv files.
- **Multiprocessing Support**: Utilizes multiple CPUs to process events concurrently.
- **Flexible File Matching**: Configurable file matching rules based on file name/path patterns and path suffixes, allowing selective processing of files.
- **Splunk Integration**: Automates the creation of Splunk indices and HEC tokens, ensuring that data is ingested smoothly and efficiently into Splunk.
- **Test Mode**: Allows running the script in a test configuration where no data is actually sent to Splunk, useful for debugging and validation.
- **Vector Remap Language (VRL)**: In-memory fields transformation (to Elastic Common Schema for example) before sending events to Splunk

## Setup

1. **Get latest released binary**:

2. **Configure Splunk Settings**:
   Update `splunk_configuration.yml` with your Splunk instance details:
   ```yaml
   splunk:
     host: {splunk_FQDN_or_IP}
     user: {splunk_user}
     password: {splunk_password}
     port: {splunk_port} # Default is 8000
     mport: {splunk_mport} # Default is 8089
     ssl: {splunk_enable_ssl} # Default is False
   ```

3. **Set File Matching Rules** - Optional if using `--file` arg:

   Edit `indexer_patterns.yml` to define the patterns for the files you want to ingest:
   ```yaml
   <source_name>:
     name_rex:         # regex matching the file name (optional if path_suffix or path_rex is set). Regex applied on FILE PATH (including filename)
     path_suffix:      # suffix path to files to index (optional if name_rex or path_rex is set). Matches ending path.
                       # Example: "path_suffix: evtx" will match files under .../evtx/ (respecting ext filter if used)
     path_rex:         # regex matching the file parent directory (optional if name_rex or path_suffix is set).
                       # Regex applied on FILE DIRECTORY (without filename)
     sourcetype:       # Splunk sourcetype (optional). If not specified, defaults to <source_name>
     normalize:        # list of VRL scripts to apply for normalization (optional).
                       # Each entry is a file name or path to a .vrl script, resolved relative to --vrl_dir (or as absolute paths).
                       # Example:
                       #   normalize:
                       #     - "evtx_common.vrl"
                       #     - "evtx_4688.vrl"
     timestamp_path:   # list of JSON key paths (first existing key in the event is used) containing the event timestamp.
                       # Populates Splunk _time field.
                       # Applied AFTER VRL normalization.
                       # Example:
                       #   timestamp_path:
                       #     - "Event.System.TimeCreated.#attributes.SystemTime"
                       #     - "@timestamp"
     timestamp_format: # format of the timestamp extracted. Example: "%Y-%m-%dT%H:%M:%S.%fZ" (optional)
                       # Applied AFTER VRL normalization.
     host_path:        # path to the JSON key containing the event host. Populates Splunk host field.
                       # Applied AFTER VRL normalization.
                       # Example: "Event.System.Computer" (optional)
     host_rex:         # regex to extract the hostname from the filename or the file path. Populates Splunk host field. (optional)
     artifact:         # source_name alternative (optional) – can be useful to define a global name like "EVTX" where
                       # source_name is very specific like "windows:evtx:powershell". If not specified, defaults to <source_name>.
     encoding:         # encoding of the input file (optional). Currently "utf8" is recognized for fast path;
                       # other values fall back to a lossy UTF-8 reader.
                       # Example: "utf-8"
   ```


## Usage

Run the script with the required parameters. Example usage:
  
```bash
json2splunk-rs --input /path/to/logs --index my_index
json2splunk-rs --input /path/to/logs --index my_index --config_spl /opt/json2splunk/splunk_configuration.yml --indexer_patterns /opt/json2splunk/indexer_patterns.yml
json2splunk-rs --input /path/to/logs --index my_index --nb_cpu 4
json2splunk-rs --input /path/to/logs --index my_index --ext ".csv,.jsonl"
json2splunk-rs --input /path/to/logs --index my_index --vrl_dir /opt/json2splunk/vrl
json2splunk-rs --input /path/to/logs --normalize-test-dir ./normalized_output
json2splunk-rs --input /path/to/logs --index my_index --force_reingest
json2splunk-rs --input /path/to/logs --index my_index --overwrite_ingested
json2splunk-rs --file ./Security.jsonl --index my_index --config_spl /opt/json2splunk/splunk_configuration.yml --source windows:evtx --sourcetype _json --artifact EVTX --timestamp_path "Event.System.TimeCreated.#attributes.SystemTime"
```

### Parameters

- `--input`: Mandatory. Directory containing the log files to process.
- `--file`: Process a single file. When used, `--indexer_patterns` is not required. 
- `--index`: Mandatory unless --normalize-test-dir is used. The name of the Splunk index to use.
- `--nb_cpu`: Optional. Specifies the number of CPUs to use for processing. Defaults to the number of available CPUs.
- `--test`: Optional. Enables test mode where no data is sent to Splunk. Useful for debugging.
- `--config_spl`: Optional. Specifies the path to the Splunk configuration file. Defaults to `splunk_configuration.yml`.
- `--indexer_patterns`: Optional. Specifies the path to the file patterns configuration. Defaults to `indexer_patterns.yml`.
- `--ext`: Optional. Specifies a list of extensions to prefilter the input directory. Defaults is None.
- `--vrl_dir`: Optional. Directory where VRL scripts referenced in indexer_patterns.yml are located. Defaults to the current directory.
- `--normalize-test-dir`: Optional. Writes normalized (post-VRL) JSONL files to a directory instead of sending them to Splunk. Useful for testing transformations.
- `--verbosity`: Optional. Controls log verbosity (DEBUG, INFO, WARNING, ERROR). Defaults to INFO.
- `--no-uid`: Disable automatic `uid` metadata generation on real ingested events.
- `--force_reingest`: Disable the filter that detect already ingested files and ingest all matched files. This can create duplicates.
- `--overwrite_ingested`: Delete existing events with the same indexed `sourcefile` value, then ingest the file again. This requires the Splunk user to be allowed to run the `delete` command. Conflicts with `--force_reingest`.
 
### Single-file parameters

These are used only with `--file`:

- `--source`: Optional. Splunk source value. Defaults to the filename without extension.
- `--sourcetype`: Optional. Splunk sourcetype. Defaults to the filename without extension.
- `--host`: Optional. Host value. Defaults to `Unknown`.
- `--artifact`: Optional. Artifact metadata field. Defaults to the filename without extension.
- `--timestamp_path`: Optional. JSON path used to extract event time. Defaults to an empty list.
- `--timestamp_format`: Optional. Timestamp format used with `--timestamp_path`. Defaults to an empty string.
- `--host_path`: Optional. JSON path used to extract the host from each event after normalization. Defaults to `None`.
- `--normalize`: Optional. VRL script path. Defaults to an empty list.
- `--encoding`: Optional. File encoding hint. Defaults to `None`.


## UID behavior

By default, every event sent to Splunk receives a generated UUID in HEC `fields.uid`:

```json
{
  "fields": {
    "uid": "550e8400-e29b-41d4-a716-446655440000",
    "sourcefile": "/case/evtx/Security.jsonl",
    "artifact": "EVTX"
  }
}
```

This is intended for timeline flagging and event correlation after ingestion.

Use `--no-uid` only if you explicitly do not want this metadata field.

The generated `uid` is Splunk HEC metadata, not a field inserted inside the original event JSON object.

## Already ingested files

By default, `json2splunk-rs` avoids duplicate ingestion. Before sending data to Splunk, it tries to find already ingested files:

```spl
| tstats count where index="<index>" source="json2splunk:ingestion_metadata" by sourcefile
```

Any matched input file whose absolute path is already present in the indexed `sourcefile` field is skipped.

To bypass this protection and ingest everything anyway:

```bash
json2splunk-rs --input /path/to/logs --index my_index --force_reingest
```

To replace existing events for already ingested files:

```bash
json2splunk-rs --input /path/to/logs --index my_index --overwrite_ingested
```

`--overwrite_ingested` runs a delete search for each already ingested source file before processing it again:

```spl
search index="<index>" sourcefile="/absolute/path/to/file.jsonl" | delete
```

## Ingestion metadata events

After each processed input file, `json2splunk-rs` sends one additional metadata event to Splunk. It uses a dedicated source:

```text
source=json2splunk:ingestion_metadata
sourcetype=_json
```

Example event body:

```json
{
  "source=json2splunk": "ingestion_metadata",
  "sourcetype": "_json",
  "event_type": "ingestion_metadata",
  "expected_event_count": 1234,
  "original_source": "evtx",
  "original_sourcetype": "_json",
  "original_sourcefile": "/case/evtx/Security.jsonl"
}
```

`expected_event_count` is the number of real events queued for Splunk HEC for that input file. It does not include the metadata event itself.

### VRL Support

You can dynamically transform vents using VRL files.
VRL scripts are referenced in indexer_patterns.yml under the normalize section and loaded from the directory specified by --vrl_dir.

The order of processing is:

0. **Raw event ingestion**   
   The file is read, parsed (JSON or CSV), and converted into a structured event.

1. **VRL normalization (optional)**   
   All VRL scripts listed in the matching rule (`normalize:`) are applied in order.  
   These scripts can add, remove, rename, or enrich fields.

Example of `transform.vrl`:
  ```vrl
  .tenant = "acme"
  if exists(.timestamp) {
    ._time = .timestamp
  }
  ```

2. **Post-normalization metadata extraction**  
   The following rule-based extractions occur **after VRL has finished**:
- `timestamp_path` (first matching key is used)
- `timestamp_format`
- `host_path`

3. **Source / sourcetype / artifact assignment**  
   Values from the matching rule are applied to prepare metadata for Splunk ingestion.

4. **Output stage**
  - If `--normalize-test-dir` option is provided:   
    The normalized and enriched output is written as jsonl files (no ingestion occurs).
  - Otherwise:  
    Events are batched and sent to Splunk via HEC.

### Test Mode

Test mode is designed to validate the setup without pushing data to Splunk. It simulates the entire process, from file scanning to data preparation, without making any actual data transmissions to Splunk. 

This mode also generates a dataframe (named test_files_to_index.json) containing matched files and patterns, which can be reviewed to ensure correct file handling before live deployment.

For example, the dataframe can be used to review the patterns matched by each file: 

```json
[
  {
    "file_path": "input_sample/prefetch/SRV-DA09DKL--prefetch-AA4646DB4646A841_2000000016FC0_D000000018CE8_4_TABBY.EXE-D326E1BD.pf_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "file_name": "SRV-DA09DKL--prefetch-AA4646DB4646A841_2000000016FC0_D000000018CE8_4_TABBY.EXE-D326E1BD.pf_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "source": [
      "prefetch",
      "all"
    ],
    "sourcetype": "_json",
    "timestamp_path": "",
    "timestamp_format": "",
    "host": "SRV-DA09DKL",
    "host_path": null
  },
  {
    "file_path": "input_sample/evtx/SRV-DA09DKL--evtx-AA4646DB4646A841_10000000014B3_E0000000249F8_4_Microsoft-Windows-StorageSettings%4Diagnostic.evtx_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "file_name": "SRV-DA09DKL--evtx-AA4646DB4646A841_10000000014B3_E0000000249F8_4_Microsoft-Windows-StorageSettings%4Diagnostic.evtx_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "source": [
      "evtx",
      "all"
    ],
    "sourcetype": "_json",
    "timestamp_path": [
      "Event.System.TimeCreated.#attributes.SystemTime"
    ],
    "timestamp_format": "%Y-%m-%dT%H:%M:%S.%fZ",
    "host": "Unknown", // Normal as host_path is extracted after the dataframe creation
    "host_path": "Event.System.Computer"
  }
]
``` 

# Example 

### Directory Structure Example

Let's ingest these files:

```
/input_sample
├── output
│   ├── app
│   │   ├── error
│   │   │   └── app_error.jsonl
│   │   ├── info
│   │   │   └── app_info.jsonl
│   │   └── debug
│   │       └── app_debug.jsonl
├── prefech
│   ├── HOST-A--prefetch1.jsonl
│   ├── HOST-A--prefetch2.jsonl
│   └── HOST-A--prefetch3.jsonl
└── evtx
    ├── event1.jsonl
    ├── event2.jsonl
    └── event3.jsonl
```

### Patterns Configuration (`indexer_patterns.yml`)

This YAML file is crucial for specifying which files `json2splunk-rs` should process. You can define multiple criteria based on file name (or file path) regex patterns and path suffixes:
Each entry specifies a unique pattern to match certain files with specific processing rules for Splunk ingestion.

**Warning:** Fields required: sourcetype, one of: name_rex, path_suffix
**Warning:** If a file matches several artifacts, the first one is selected.

```yaml
windows:evtx:powershell:
    name_rex: Windows_PowerShell.*\.jsonl$
    path_suffix: evtx
    host_path: "Event.System.Computer" # Extract the host from the event
    timestamp_path:  # Extract the timestamp from the event
      - "Event.System.TimeCreated.#attributes.SystemTime"
      - "Event.Timestamp"
    timestamp_format: "%Y-%m-%dT%H:%M:%S.%fZ" # Specify the timestamp format
    artifact: EVTX
evtx:
    name_rex: \.jsonl$
    path_suffix: evtx
    sourcetype: _json
    normalize:
      - normalize/windows/evtx.vrl
    host_path: ".host.name" # Extract the host AFTER VRL normalization from the event
    timestamp_path: # Extract the timestamp from the event AFTER VRL normalization
        - "timestamp"
    timestamp_format: "%Y-%m-%dT%H:%M:%SZ" # Timestamp after VRL normalization
prefetch:
    name_rex: \.jsonl$
    path_rex: ".*prefetch"
    sourcetype: _json
    host_rex: (^[\w-]+)-- # Extract host from file path
    normalize:
      - normalize/windows/prefetch.vrl
    timestamp_path: # Extract the host AFTER VRL normalization from the event
      - "timestamp" # Extract the timestamp from the event AFTER VRL normalization
    timestamp_format: "%Y-%m-%dT%H:%M:%SZ" # Timestamp after VRL normalization
reg:
    name_rex: --hives_hk
    host_rex: ([\w\.-]+)--
    sourcetype: _json
    normalize:
      - normalize/windows/hives.vrl                   
    timestamp_path:
      - "timestamp" 
    timestamp_format: "%Y-%m-%dT%H:%M:%SZ"
application:
    path_suffix: output/app
    sourcetype: _json
    host_rex: (^[\w-]+)--
```

## Dry run before Splunk ingestion

```bash
json2splunk-rs --indexer_patterns patterns.yml --input input_sample/ --normalize-test-dir ./normalized_output
```
=> Inspect output files in ./normalized_output directory.

### Index files in Splunk
```bash
json2splunk-rs --indexer_patterns patterns.yml --config_spl splunk_configuration.yml --input input_sample/ --index my_index
```