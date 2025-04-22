// Vulnerable Rust implementation with Actix Web
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize, Serialize};
use reqwest::Client;

#[derive(Deserialize)]
struct FetchParams {
    url: String,
}

#[derive(Serialize)]
struct MetadataResponse {
    status: String,
    metadata: serde_json::Value,
}

// VULNERABLE: No URL validation is performed
async fn fetch_metadata(params: web::Query<FetchParams>) -> impl Responder {
    let client = Client::new();
    
    // VULNERABLE: The URL is used directly without validation
    match client.get(&params.url).send().await {
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
