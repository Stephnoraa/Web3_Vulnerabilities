// Secure Rust implementation with Actix Web
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use url::Url;
use std::collections::HashSet;

#[derive(Deserialize)]
struct FetchParams {
    url: String,
}

#[derive(Serialize)]
struct MetadataResponse {
    status: String,
    metadata: serde_json::Value,
}

// Function to validate URLs
fn is_url_allowed(url_str: &str) -> Result<Url, String> {
    // Parse the URL
    let url = Url::parse(url_str).map_err(|_| "Invalid URL format".to_string())?;
    
    // Only allow HTTPS
    if url.scheme() != "https" {
        return Err("Only HTTPS URLs are allowed".to_string());
    }
    
    // Check against allowlist of domains
    let allowed_domains: HashSet<&str> = [
        "example.com",
        "opensea.io",
        "ipfs.io",
        "arweave.net",
        "metadata.solana.com",
    ].iter().cloned().collect();
    
    let host = url.host_str().ok_or("No host in URL".to_string())?;
    
    if !allowed_domains.contains(host) {
        return Err(format!("Domain not in allowlist: {}", host));
    }
    
    Ok(url)
}

async fn fetch_metadata(params: web::Query<FetchParams>) -> impl Responder {
    // Validate the URL first
    let validated_url = match is_url_allowed(&params.url) {
        Ok(url) => url,
        Err(error) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("URL validation failed: {}", error)
            }));
        }
    };
    
    let client = Client::new();
    
    // Use the validated URL
    match client.get(validated_url.as_str()).send().await {
        Ok(response) => {
            match response.json::<serde_json::Value>().await {
                Ok(metadata) => {
                    let response = MetadataResponse {
                        status: "success".to_string(),
                        metadata,
                    };
                    HttpResponse::Ok().json(response)
                },
                Err(_) => {
                    HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "Failed to parse metadata"
                    }))
                }
            }
        },
        Err(_) => {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Failed to fetch from URL"
            }))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/api/fetch-metadata", web::get().to(fetch_metadata))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
