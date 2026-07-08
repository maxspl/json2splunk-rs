use std::collections::{HashMap, HashSet};
use std::time::Duration;

use log::{error, info, warn};
use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;

pub struct SplunkHelper {
    surl: String,
    suser: String,
    spass: String,
    client: Client,
}

impl SplunkHelper {
    pub fn new(host: &str, user: &str, pass: &str, port: u16, ssl: bool) -> Self {
        let protocol = "https";
        let surl = format!("{protocol}://{host}:{port}");

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(!ssl)
            .build()
            .expect("Failed to build reqwest client");

        SplunkHelper { surl, suser: user.to_string(), spass: pass.to_string(), client }
    }

    fn request(
        &self,
        method: reqwest::Method,
        uri: &str,
        form: Option<&HashMap<&str, &str>>,
    ) -> Option<Response> {
        let url = format!("{}/{}", self.surl, uri.trim_start_matches('/'));

        let mut req = self
            .client
            .request(method, &url)
            .basic_auth(&self.suser, Some(&self.spass));

        if let Some(f) = form {
            req = req.form(f);
        }

        match req.send() {
            Ok(resp) => {
                if resp.status() == StatusCode::UNAUTHORIZED {
                    error!("Splunk authentication failed (401) for {}", url);
                    None
                } else {
                    Some(resp)
                }
            }
            Err(e) => {
                error!("Request error on {}: {}", url, e);
                None
            }
        }
    }

    pub fn test_connection(&self) -> bool {
        info!("Testing Splunk connection…");
        if let Some(resp) = self.request(reqwest::Method::GET, "/services/data/inputs/http", None) {
            if resp.status().is_success() {
                info!("Splunk server reachable.");
                return true;
            }
        }
        error!("Cannot reach Splunk management interface.");
        false
    }

    pub fn create_index(&self, index: &str) -> bool {
        let uri = format!("/services/data/indexes/{}", index);

        if let Some(resp) = self.request(reqwest::Method::GET, &uri, None) {
            if resp.status().is_success() {
                info!("Index {} already exists.", index);
                return true;
            }
        }

        let mut form = HashMap::new();
        form.insert("name", index);

        if let Some(resp) =
            self.request(reqwest::Method::POST, "/services/data/indexes", Some(&form))
        {
            if resp.status().is_success() {
                info!("Index {} created successfully.", index);
                return true;
            }
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            error!("Failed to create index {} ({}): {}", index, status, body);
        }

        false
    }

    fn extract_token(body: &str) -> Option<String> {
        let start_tag = r#"<s:key name="token">"#;
        let start = body.find(start_tag)? + start_tag.len();
        let end = body[start..].find("</s:key>")? + start;
        Some(body[start..end].trim().to_string())
    }

    fn extract_indexes(body: &str) -> Vec<String> {
        let mut out = vec![];

        let key_tag = r#"<s:key name="indexes">"#;
        let start = match body.find(key_tag) {
            Some(s) => s + key_tag.len(),
            None => return out,
        };
        let end = match body[start..].find("</s:key>") {
            Some(e) => e + start,
            None => return out,
        };
        let section = &body[start..end];

        let mut rest = section;
        let item_start = "<s:item>";
        let item_end = "</s:item>";
        while let Some(pos) = rest.find(item_start) {
            let after = &rest[pos + item_start.len()..];
            if let Some(endpos) = after.find(item_end) {
                out.push(after[..endpos].trim().to_string());
                rest = &after[endpos + item_end.len()..];
            } else {
                break;
            }
        }

        out
    }

    fn get_existing_token(&self, name: &str) -> Option<String> {
        let uri = format!("/services/data/inputs/http/{}", name);
        let resp = self.request(reqwest::Method::GET, &uri, None)?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();

        if !status.is_success() {
            info!(
                "No existing HEC input '{}' (status {}). Will probably need to create it.",
                name, status
            );
            return None;
        }

        let token = Self::extract_token(&body)?;
        info!(
            "Found existing HEC input '{}' (token begins with {}).",
            name,
            &token[..8.min(token.len())]
        );
        Some(token)
    }

    fn create_new_token(&self, name: &str) -> Option<String> {
        info!("Creating new HEC input '{}'…", name);

        let mut form = HashMap::new();
        form.insert("name", name);

        let resp = self.request(
            reqwest::Method::POST,
            "/services/data/inputs/http",
            Some(&form),
        )?;

        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            error!("Failed to create input {} ({}): {}", name, status, body);
            return None;
        }

        let token = Self::extract_token(&body)?;
        info!(
            "HEC input '{}' created successfully (token begins with {}).",
            name,
            &token[..8.min(token.len())]
        ); 
        Some(token)
    }

    pub fn register_index_to_token(&self, token_name: &str, index: &str) -> bool {
        let uri = format!("/services/data/inputs/http/{}", token_name);

        let resp = match self.request(reqwest::Method::GET, &uri, None) {
            Some(r) => r,
            None => {
                error!(
                    "Failed to GET HEC input '{}' when trying to register index '{}'",
                    token_name, index
                ); 
                return false;
            }
        };

        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            error!(
                "HEC input '{}' GET failed with status {} while registering index '{}'",
                token_name, status, index
            ); 
            return false;
        }

        let mut indexes = Self::extract_indexes(&body);
        if indexes.contains(&index.to_string()) {
            info!(
                "Index '{}' already associated to HEC input '{}', nothing to do.",
                index, token_name
            ); 
            return true;
        }
        indexes.push(index.to_string());

        let joined = indexes.join(",");
        info!(
            "Registering index '{}' to HEC input '{}' (indexes now: {}).",
            index, token_name, joined
        ); 

        let mut form = HashMap::new();
        form.insert("indexes", joined.as_str());
        form.insert("index", indexes[0].as_str()); 

        let resp = match self.request(reqwest::Method::POST, &uri, Some(&form)) {
            Some(r) => r,
            None => {
                error!(
                    "Failed to POST updated indexes for HEC input '{}' (index '{}')",
                    token_name, index
                ); 
                return false;
            }
        };

        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if status.is_success() {
            info!(
                "Index '{}' successfully associated to HEC input '{}'.",
                index, token_name
            ); 
            true
        } else {
            error!(
                "Unable to associate index '{}' to HEC input '{}' (status {}): {}",
                index, token_name, status, body
            ); 
            false
        }
    }

    pub fn ensure_hec_token(&self, index: &str) -> Option<String> {
        let name = "json2splunk-rs";

        // 1) Try existing input
        if let Some(token) = self.get_existing_token(name) {
            info!(
                "Using existing HEC input '{}' for index '{}'.",
                name, index
            ); 
            if !self.register_index_to_token(name, index) {
                error!(
                    "Failed to associate index {} with HEC input {}",
                    index, name
                );
                return None;
            }
            return Some(token);
        }

        info!(
            "No existing HEC input '{}' found, will create it for index '{}'.",
            name, index
        ); 

        // 2) Create new input
        let token = self.create_new_token(name)?;
        if !self.register_index_to_token(name, index) {
            error!(
                "Failed to associate index {} with new HEC input {}",
                index, name
            );
            return None;
        }

        Some(token)
    }

    fn escape_spl_string(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }


    /// Returns sourcefile values whose ingestion completed in the given index,
    /// based on per-file ingestion_metadata events emitted by json2splunk-rs.
    ///
    /// The lookup uses tstats against indexed metadata, grouped by the indexed
    /// HEC field sourcefile. 
    ///
    /// A file interrupted mid-ingestion has no metadata event and is therefore not
    /// reported as ingested. Returns `None` if the search could not be run or read.
    pub fn list_completed_sourcefiles_tstats(&self, index: &str) -> Option<HashSet<String>> {
        let safe_index = Self::escape_spl_string(index);
        let spl = format!(
            "| tstats count where index=\"{}\" source=\"json2splunk:ingestion_metadata\" by sourcefile",
            safe_index
        );

        let mut form = HashMap::new();
        form.insert("search", spl.as_str());
        form.insert("exec_mode", "oneshot");
        form.insert("output_mode", "json");
        form.insert("count", "0");
        form.insert("earliest_time", "0");
        form.insert("latest_time", "now");

        let url = format!("{}/services/search/jobs", self.surl);
        let resp = match self
            .client
            .request(reqwest::Method::POST, &url)
            .basic_auth(&self.suser, Some(&self.spass))
            // A oneshot tstats search can still take time on very large indexes.
            .timeout(Duration::from_secs(120))
            .form(&form)
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                error!("Oneshot tstats request error on {}: {}", url, e);
                return None;
            }
        };

        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            error!("Oneshot tstats failed (status {}): {}", status, body);
            return None;
        }

        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to parse oneshot tstats response: {}", e);
                return None;
            }
        };

        let mut out = HashSet::new();
        if let Some(results) = parsed.get("results").and_then(|r| r.as_array()) {
            for r in results {
                if let Some(sf) = r.get("sourcefile").and_then(|v| v.as_str()) {
                    out.insert(sf.to_string());
                }
            }
        }

        info!(
            "Splunk tstats reports {} file(s) already fully ingested in index '{}'.",
            out.len(),
            index
        );

        Some(out)
    }

    /// Deletes all events for one indexed sourcefile from the target index.
    ///
    /// This uses Splunk's `delete` search command, so the configured user must
    /// have the relevant capability. Events are hidden from future searches, not
    /// physically removed from buckets.
    pub fn delete_sourcefile_events(&self, index: &str, sourcefile: &str) -> bool {
        let safe_index = Self::escape_spl_string(index);
        let safe_sourcefile = Self::escape_spl_string(sourcefile);
        let spl = format!(
            r#"search index="{}" sourcefile="{}" | delete"#,
            safe_index,
            safe_sourcefile
        );

        let mut form = HashMap::new();
        form.insert("search", spl.as_str());
        form.insert("exec_mode", "blocking");
        form.insert("output_mode", "json");
        form.insert("earliest_time", "0");
        form.insert("latest_time", "now");

        let url = format!("{}/services/search/jobs", self.surl);
        let resp = match self
            .client
            .request(reqwest::Method::POST, &url)
            .basic_auth(&self.suser, Some(&self.spass))
            // Deleting events for a large file can take longer than normal API calls.
            .timeout(Duration::from_secs(600))
            .form(&form)
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                error!("Delete search request error on {}: {}", url, e);
                return false;
            }
        };

        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            error!(
                "Delete search failed for sourcefile={} (status {}): {}",
                sourcefile,
                status,
                body
            );
            return false;
        }

        info!(
            "Delete search completed for sourcefile={} in index '{}'.",
            sourcefile,
            index
        );
        true
    }

}
