use reqwest::{header::{HeaderMap, HeaderValue}};
use serde::Deserialize;
use std::env;

#[derive(Deserialize, Debug)]
struct VTResponse {
    data: Option<VTData>,
}
#[derive(Deserialize, Debug)]
struct VTData {
    attributes : VTAtributes,
}
#[derive(Deserialize, Debug)]
struct VTAtributes{
    last_analysis_stats : AnalisisStats,
}
#[derive(Deserialize, Debug)]
struct AnalisisStats{
    harmless:   u32,
    malicious:  u32,
    suspicious: u32,
    undetected: u32,
}

pub fn config() -> Result<String, Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let api_key = env::var("VT_API_KEY")?;
    Ok(api_key)

}

const BASE_URL: &str = "https://virustotal.com/api/v3";

pub async fn check_hash_vt(api_key : &str, hash : &str) ->Result<String, Box<dyn std::error::Error>>{
    let client = reqwest::Client::new();
    let mut url = String::from(BASE_URL);
    url.push_str("/files/");
    url.push_str(hash);
    let mut header = HeaderMap::new();
    header.insert("x-apikey",HeaderValue::from_str(api_key)?);
    
    let response = client.get(&url).headers(header).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await?;
        return Err(format!("VirusTotal Error {} : {}",status, body).into());
    }

    let vt_response : VTResponse = response.json().await?;

    match vt_response.data {
        Some(data) =>{
            let stats = data.attributes.last_analysis_stats;
            Ok(format!("VirusTotal result:\nMalicious: {}\nSuspicious: {}\nHarmless: {}\n  Undetected: {}",stats.malicious,
                stats.suspicious,
                stats.harmless,
                stats.undetected))
        }
        None => Ok("Hash not found on VirusTotal".to_string()),
    }
    

}

