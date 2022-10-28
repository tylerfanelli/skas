use std::io::Read;

use anyhow::Result;
use curl::easy::{Easy, List};
use kbs_types::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct TeeConfig {
    pub workload_id: String,
    pub cpus: u8,
    pub ram_mib: usize,
    pub tee: kbs_types::Tee,
    pub tee_data: String,
    pub attestation_url: String,
}

/// Taken from libkrun: src/vmm/src/linux/tee/amdsev.rs
pub struct CurlAgent {
    easy: Easy,
    session_id: Option<String>,
}

impl Default for CurlAgent {
    fn default() -> Self {
        Self {
            easy: Easy::new(),
            session_id: None,
        }
    }
}

impl CurlAgent {
    fn post(&mut self, url: &str, mut data: &[u8]) -> Result<Vec<u8>, curl::Error> {
        let mut rsp = Vec::new();

        let mut headers = List::new();
        headers.append("Accept: application/json")?;
        headers.append("Content-Type: application/json; charset=utf-8")?;

        if let Some(session_id) = &self.session_id {
            headers.append(&format!("Cookie: session_id={}", session_id))?;
        }

        self.easy.post(true)?;
        self.easy.post_field_size(data.len() as u64)?;
        self.easy.url(url)?;
        self.easy.http_headers(headers)?;

        let mut transfer = self.easy.transfer();

        transfer.read_function(|buf| Ok(data.read(buf).unwrap_or(0)))?;
        transfer.write_function(|data| {
            rsp.extend_from_slice(data);
            Ok(data.len())
        })?;

        transfer
            .header_function(|header| {
                if let Some(session_id) = extract_session_id(header) {
                    self.session_id = Some(session_id);
                }

                true
            })
            .unwrap();

        transfer.perform()?;
        drop(transfer);

        Ok(rsp)
    }
}

fn extract_session_id(header: &[u8]) -> Option<String> {
    let header = match std::str::from_utf8(header) {
        Ok(h) => h,
        Err(_) => return None,
    };

    if !header.contains("session_id") {
        return None;
    }

    let parts: Vec<&str> = header.split(';').collect();
    for p in parts {
        let elems: Vec<&str> = p.split('=').collect();
        if elems.len() == 2 && elems[0].contains("session_id") {
            return Some(elems[1].to_string());
        }
    }

    None
}

pub fn register_workload(
    curl: &mut CurlAgent,
    config: &TeeConfig,
    launch_measurement: String,
    passphrase: String,
) -> Result<()> {
    let register = Register {
        workload_id: config.workload_id.clone(),
        launch_measurement,
        tee_config: serde_json::json!(config).to_string(),
        passphrase,
    };

    let url = format!("{}/kbs/v0/register_workload", config.attestation_url);
    let data = serde_json::json!(register).to_string();
    let bytes = data.as_bytes();

    let _response = curl.post(&url, bytes).unwrap();

    Ok(())
}

pub fn request_challenge(curl: &mut CurlAgent, config: &TeeConfig) -> Result<Challenge> {
    let url = format!("{}/kbs/v0/register_workload", config.attestation_url);

    let snp_req = SnpRequest {
        workload_id: config.workload_id.clone(),
    };

    let req = Request {
        version: "0.0.0".to_string(),
        tee: config.tee.clone(),
        extra_params: serde_json::to_string(&snp_req).unwrap(),
    };

    let data = serde_json::json!(req).to_string();
    let bytes = data.as_bytes();

    let url = format!("{}/kbs/v0/auth", config.attestation_url);

    let response = curl.post(&url, bytes).unwrap();

    let challenge: Challenge = serde_json::from_slice(&response).unwrap();

    Ok(challenge)
}

#[test]
#[ignore]
fn registration_test() {
    let config = TeeConfig {
        workload_id: "id".to_string(),
        cpus: 1,
        ram_mib: 1,
        tee: Tee::Snp,
        tee_data: "".to_string(),
        attestation_url: "http://127.0.0.1:8000".to_string(),
    };

    let mut curl = CurlAgent::default();

    let measurement = "MEASUREMENT".to_string();
    let passphrase = "mysecretpassphrase".to_string();

    register_workload(&mut curl, &config, measurement, passphrase).unwrap();
}

#[test]
fn request_challenge_test() {
    let mut curl = CurlAgent::default();
    let config = TeeConfig {
        workload_id: "id2".to_string(),
        cpus: 2,
        ram_mib: 1,
        tee: Tee::Snp,
        tee_data: "".to_string(),
        attestation_url: "http://127.0.0.1:8000".to_string(),
    };

    let measurement = "MEASUREMENT2".to_string();
    let passphrase = "mysecretpassphrase2".to_string();

    register_workload(&mut curl, &config, measurement, passphrase).unwrap();

    let _challenge = request_challenge(&mut curl, &config).unwrap();
}
