use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use std::env;

#[derive(Deserialize, Debug)]
struct VTResponse {
    data: Option<VTData>,
}
#[derive(Deserialize, Debug)]
struct VTData {
    attributes: VTAtributes,
}
#[derive(Deserialize, Debug)]
struct VTAtributes {
    last_analysis_stats: AnalisisStats,
}
#[derive(Deserialize, Debug)]
struct AnalisisStats {
    harmless: u32,
    malicious: u32,
    suspicious: u32,
    undetected: u32,
}

pub fn config() -> Result<String, Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let api_key = env::var("VT_API_KEY")?;
    Ok(api_key)
}

const BASE_URL: &str = "https://virustotal.com/api/v3";

/// Checks a file has on VirusTotal API
/// 
/// The functions sends the provided hash to VT and parses the analysis stats returned by the API
/// 
/// It returnes a formated String containing the number of engines that classified the file as malicious, suspicious, harmless, or undetected
/// 
/// # Arguments 
/// * `api_key` - VirusTOtal API key used for autentification
/// * `hash` - Hash of a file
/// 
/// # Errors
/// 
/// Returns an error if:
///    * The api key couldn't be transformed into a valid http header
///    * The http request to VT could not be sent
///    * VT returns a non-succesfull HTTP status
///    * The response from VT cannot bet parsed into expected response structure
/// 
/// 
pub async fn check_hash_vt(
    api_key: &str,
    hash: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let mut url = String::from(BASE_URL);
    url.push_str("/files/");
    url.push_str(hash);
    let mut header = HeaderMap::new();
    let api_header = HeaderValue::from_str(api_key).map_err(|e| format!("Invalid VT api key header: {}",e))?;
    header.insert("x-apikey", api_header);

    let response = client.get(&url).headers(header).send().await.map_err(|e| format!("Could not sent request to VT {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "Could not read response body".to_string());
        return Err(format!("VirusTotal Error {} : {}", status, body).into());
    }

    let vt_response: VTResponse = response.json().await.map_err(|e| format!("Failed to parse VT response : {e}"))?;

    match vt_response.data {
        Some(data) => {
            let stats = data.attributes.last_analysis_stats;
            Ok(format!(
                "VirusTotal result:\nMalicious: {}\nSuspicious: {}\nHarmless: {}\n  Undetected: {}",
                stats.malicious, stats.suspicious, stats.harmless, stats.undetected
            ))
        }
        None => Ok("Hash not found on VirusTotal".to_string()),
    }
}
