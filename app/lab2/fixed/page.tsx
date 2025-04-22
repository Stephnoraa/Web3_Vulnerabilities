"use client"

import { useState } from "react"
import Link from "next/link"
import { ArrowLeft, CheckCircle, ExternalLink, RefreshCw, ShieldCheck } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Navbar } from "@/components/navbar"

export default function FixedSSRFPage() {
  const [url, setUrl] = useState("https://example.com/nft/metadata.json")
  const [result, setResult] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const fetchMetadata = async () => {
    setLoading(true)
    setError("")
    setResult("")

    try {
      // This is just a frontend simulation - in a real app, this would call the Rust backend
      const response = await fetch(`/api/lab2/fixed/fetch?url=${encodeURIComponent(url)}`)

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || "Failed to fetch metadata")
      }

      const data = await response.json()

      // Simulate the Rust backend response
      if (url.startsWith("http://localhost") || url.startsWith("file://") || url.startsWith("http://192.168.")) {
        throw new Error("URL validation failed: Only https URLs to allowed domains are permitted")
      }

      setResult(
        JSON.stringify(
          {
            status: "success",
            metadata: {
              name: "Example NFT",
              description: "This is a simulated response from the secure Rust backend",
              image: "https://example.com/nft/image.png",
              attributes: [
                { trait_type: "Rarity", value: "Legendary" },
                { trait_type: "Power", value: 95 },
              ],
            },
            backend_info: {
              language: "Rust",
              framework: "Actix Web",
              version: "4.3.1",
              security: "URL validation enabled",
            },
          },
          null,
          2,
        ),
      )
    } catch (err) {
      setError(err.message || "An error occurred")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <div className="container px-4 py-8 md:py-12 max-w-5xl mx-auto">
          <div className="flex items-center mb-8">
            <Link href="/lab2">
              <Button variant="ghost" className="gap-2">
                <ArrowLeft className="h-4 w-4" />
                <span>Back to Lab 2</span>
              </Button>
            </Link>
            <div className="ml-auto flex items-center gap-2">
              <Link href="https://github.com/Stephnoraa/Web3_Vulnerabilities" target="_blank" rel="noopener noreferrer">
                <Button variant="outline" size="sm" className="gap-2">
                  <ExternalLink className="h-4 w-4" />
                  <span>View on GitHub</span>
                </Button>
              </Link>
            </div>
          </div>

          <Card className="border-2 border-green-500/50 mb-8">
            <CardHeader className="bg-green-50 dark:bg-green-950/20">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-green-500" />
                <CardTitle>Secure NFT Metadata Fetcher (Rust)</CardTitle>
              </div>
              <CardDescription>This service implements proper URL validation to prevent SSRF attacks.</CardDescription>
            </CardHeader>
            <CardContent className="pt-6">
              <div className="space-y-4">
                <div>
                  <h3 className="text-sm font-medium mb-2">Secure Rust Code:</h3>
                  <div className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto text-xs font-mono">
                    <pre>{`// Secure Rust implementation with Actix Web
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
}`}</pre>
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-medium mb-2">Enter NFT Metadata URL:</h3>
                  <div className="flex gap-2">
                    <Input
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://example.com/nft/metadata.json"
                      className="flex-1"
                    />
                    <Button onClick={fetchMetadata} disabled={loading} className="gap-2">
                      {loading && <RefreshCw className="h-4 w-4 animate-spin" />}
                      Fetch Metadata
                    </Button>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Try with: <code>http://localhost:8080/internal/keys</code> or <code>file:///etc/passwd</code> (will
                    be blocked)
                  </p>
                </div>

                {error && (
                  <div className="bg-red-50 border border-red-200 text-red-700 p-3 rounded-md text-sm dark:bg-red-950/30 dark:border-red-900 dark:text-red-400">
                    {error}
                  </div>
                )}

                {result && (
                  <div>
                    <h3 className="text-sm font-medium mb-2">Result:</h3>
                    <div className="bg-gray-50 border border-gray-200 p-4 rounded-md overflow-x-auto text-xs font-mono dark:bg-gray-900 dark:border-gray-800">
                      <pre>{result}</pre>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
            <CardFooter className="bg-green-50 dark:bg-green-950/20 flex flex-col items-start">
              <p className="text-sm text-green-700 dark:text-green-400">
                <strong>Security Measures:</strong> This Rust implementation prevents SSRF by:
              </p>
              <ul className="list-disc pl-5 text-sm text-green-700 dark:text-green-400 mt-1">
                <li>Validating URL format using Rust's url crate</li>
                <li>Enforcing HTTPS-only connections</li>
                <li>Implementing a domain allowlist</li>
                <li>Properly handling errors and providing clear validation messages</li>
              </ul>
            </CardFooter>
          </Card>

          <div className="rounded-md border p-4 bg-gray-50 dark:bg-gray-800">
            <h2 className="text-lg font-semibold mb-2">Security Improvements</h2>
            <p className="text-sm text-gray-700 dark:text-gray-300 mb-4">
              The secure implementation leverages Rust's strong type system and security-focused libraries to prevent
              SSRF attacks:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-white dark:bg-gray-900 p-4 rounded-md border">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <h3 className="font-medium">URL Parsing & Validation</h3>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Uses Rust's url crate to properly parse and validate URLs, ensuring they conform to expected formats
                  and preventing malformed URL attacks.
                </p>
              </div>
              <div className="bg-white dark:bg-gray-900 p-4 rounded-md border">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <h3 className="font-medium">Protocol Enforcement</h3>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Restricts URLs to HTTPS only, preventing attacks using alternative protocols like file://, gopher://,
                  or http:// to internal services.
                </p>
              </div>
              <div className="bg-white dark:bg-gray-900 p-4 rounded-md border">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <h3 className="font-medium">Domain Allowlisting</h3>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Implements a strict allowlist of trusted domains, ensuring requests can only be made to pre-approved
                  external services.
                </p>
              </div>
              <div className="bg-white dark:bg-gray-900 p-4 rounded-md border">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <h3 className="font-medium">Error Handling</h3>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Uses Rust's robust error handling to provide clear validation errors without exposing sensitive
                  information that could aid attackers.
                </p>
              </div>
            </div>
            <div className="mt-4">
              <Link href="/lab2/vulnerable">
                <Button variant="outline" className="gap-2">
                  Compare with Vulnerable Version
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
