"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { AlertTriangle, ArrowLeft, ExternalLink, RefreshCw, ShieldAlert } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function VulnerableSSRFPage() {
  const [url, setUrl] = useState("https://example.com/nft/metadata.json")
  const [result, setResult] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [logs, setLogs] = useState<string[]>([])
  const [activeTab, setActiveTab] = useState("example")

  useEffect(() => {
    // Initialize with some example data
    if (activeTab === "example") {
      setUrl("https://example.com/nft/metadata.json")
    } else if (activeTab === "internal") {
      setUrl("http://localhost:8080/admin/users")
    } else if (activeTab === "file") {
      setUrl("file:///etc/passwd")
    } else if (activeTab === "aws") {
      setUrl("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    }
  }, [activeTab])

  const addLog = (message: string) => {
    const timestamp = new Date().toISOString().replace("T", " ").substring(0, 19)
    setLogs((prev) => [...prev, `[${timestamp}] ${message}`])
  }

  const fetchMetadata = async () => {
    setLoading(true)
    setError("")
    setResult("")
    addLog(`Fetching metadata from: ${url}`)

    try {
      // Simulate different responses based on the URL to demonstrate the SSRF vulnerability
      setTimeout(() => {
        if (url.includes("example.com")) {
          // Normal NFT metadata
          const exampleData = {
            name: "Solana Monkey #1234",
            description: "A unique Solana Monkey Business NFT",
            image: "https://example.com/nft/image.png",
            attributes: [
              { trait_type: "Background", value: "Blue" },
              { trait_type: "Fur", value: "Brown" },
              { trait_type: "Eyes", value: "Crazy" },
              { trait_type: "Mouth", value: "Grin" },
            ],
            collection: {
              name: "Solana Monkey Business",
              family: "SMB",
            },
          }
          setResult(JSON.stringify(exampleData, null, 2))
          addLog("Successfully fetched NFT metadata")
        } else if (url.includes("localhost") || url.includes("127.0.0.1")) {
          // Simulating access to internal admin panel - SSRF vulnerability!
          const internalData = {
            users: [
              { id: 1, username: "admin", role: "administrator", apiKey: "admin_master_key_9a8b7c6d5e" },
              { id: 2, username: "jordan", role: "user", apiKey: "user_key_jordan_1q2w3e4r5t" },
              { id: 3, username: "taylor", role: "user", apiKey: "user_key_taylor_6y7u8i9o0p" },
              { id: 4, username: "morgan", role: "developer", apiKey: "dev_key_morgan_a1s2d3f4g5h" },
            ],
            system: {
              version: "1.0.3",
              environment: "production",
              database: {
                host: "internal-db.example.com",
                username: "db_admin",
                password: "super_secret_db_password_123!",
              },
              walletSeed:
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            },
          }
          setResult(JSON.stringify(internalData, null, 2))
          addLog("WARNING: Accessed internal admin panel via SSRF!")
        } else if (url.includes("file:")) {
          // Simulating access to local files - SSRF vulnerability!
          const fileData = {
            file_contents: `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System:/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
nftuser:x:1000:1000:NFT Service,,,:/home/nftuser:/bin/bash`,
            path: url.replace("file://", ""),
            accessed_at: new Date().toISOString(),
          }
          setResult(JSON.stringify(fileData, null, 2))
          addLog("CRITICAL: Accessed local file system via SSRF!")
        } else if (url.includes("169.254.169.254")) {
          // Simulating access to AWS metadata service - SSRF vulnerability!
          const awsData = {
            Code: "Success",
            LastUpdated: "2023-04-02T18:50:40Z",
            Type: "AWS-HMAC",
            AccessKeyId: "ASIA5IAXJ7KSTP7EXAMPLE",
            SecretAccessKey: "wnJ76xMUEoLEtZMgd12rGNd6KVkxEPwEXAMPLEKEY",
            Token:
              "IQoJb3JpZ2luX2VjEIz//////////wEaCXVzLWVhc3QtMSJHMEUCIQDnD0Sf2EIuMlGwuLTjJ5KE/IlJiWpLOLsaASXaUyuJ3AIgNmqQGj0gxZZJXYIGj0QdgDaLKr5WVlKp/LoHYXD6JW4qtAMIHBAAGgw1OTk4MjMzNTk5NzMiDGSdBiAj1qdJJXB0QCqRA7FfDcUUdOCYyQYLRfFgLnfQnNXmxEdYFB3N/qLvHEJxlnP2XEY4LuQtwLJL5Z8RVT6AUCzBxZp36LDNQebUi6CBqjm+Exampletoken",
            Expiration: "2023-04-03T01:04:26Z",
          }
          setResult(JSON.stringify(awsData, null, 2))
          addLog("CRITICAL: Accessed AWS metadata service via SSRF!")
        } else {
          setError("Failed to fetch metadata: Invalid URL or resource not found")
          addLog(`Error: Failed to fetch from ${url}`)
        }
        setLoading(false)
      }, 1000)
    } catch (err) {
      setError("An error occurred while fetching metadata")
      addLog(`Error: ${err.message}`)
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-red-50 to-orange-50 dark:from-slate-900 dark:to-slate-800">
      <header className="sticky top-0 z-10 border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80">
        <div className="container flex h-16 items-center px-4 sm:px-6 lg:px-8">
          <Link
            href="/lab2"
            className="flex items-center gap-2 text-sm text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-50"
          >
            <ArrowLeft className="h-4 w-4" />
            <span>Back to Lab 2</span>
          </Link>
          <div className="ml-auto flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-full bg-red-100 px-3 py-1 text-xs text-red-700 dark:bg-red-900/30 dark:text-red-400">
              <ShieldAlert className="h-3.5 w-3.5" />
              <span>Vulnerable Version</span>
            </div>
            <Link href="https://github.com/Stephnoraa/Web3_Vulnerabilities" target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="sm" className="gap-2 text-xs">
                <ExternalLink className="h-3.5 w-3.5" />
                <span>View on GitHub</span>
              </Button>
            </Link>
          </div>
        </div>
      </header>
      <main className="container px-4 py-8 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-8 rounded-lg bg-white/70 p-4 backdrop-blur-sm dark:bg-slate-800/70">
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">
              Lab 2: SSRF Vulnerability in NFT Metadata Fetcher (Rust)
            </h1>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
              This lab demonstrates a Server-Side Request Forgery (SSRF) vulnerability in a Rust-based NFT metadata
              fetcher service. Try entering different URLs to see how the service can be exploited to access internal
              resources.
            </p>
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <Card className="border-2 border-red-500/50">
                <CardHeader className="bg-red-50 dark:bg-red-950/20 pb-3">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                    <CardTitle className="text-base">Vulnerable NFT Metadata Fetcher</CardTitle>
                  </div>
                  <CardDescription className="text-xs">
                    This Rust service fetches NFT metadata from a user-provided URL without proper validation.
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-4">
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-xs font-medium mb-2">Vulnerable Rust Code:</h3>
                      <div className="bg-slate-900 text-slate-100 p-3 rounded-md overflow-x-auto text-xs font-mono">
                        <pre>{`// Vulnerable Rust implementation with Actix Web
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
}`}</pre>
                      </div>
                    </div>

                    <div>
                      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                        <TabsList className="mb-4 h-8 w-full">
                          <TabsTrigger value="example" className="text-xs flex-1">
                            Normal NFT
                          </TabsTrigger>
                          <TabsTrigger value="internal" className="text-xs flex-1">
                            Internal Server
                          </TabsTrigger>
                          <TabsTrigger value="file" className="text-xs flex-1">
                            Local File
                          </TabsTrigger>
                          <TabsTrigger value="aws" className="text-xs flex-1">
                            AWS Metadata
                          </TabsTrigger>
                        </TabsList>
                      </Tabs>

                      <div className="flex gap-2 mb-2">
                        <Input
                          value={url}
                          onChange={(e) => setUrl(e.target.value)}
                          placeholder="https://example.com/nft/metadata.json"
                          className="flex-1 text-xs"
                        />
                        <Button onClick={fetchMetadata} disabled={loading} size="sm" className="gap-2">
                          {loading && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                          Fetch
                        </Button>
                      </div>
                    </div>

                    {error && (
                      <div className="bg-red-50 border border-red-200 text-red-700 p-3 rounded-md text-xs dark:bg-red-950/30 dark:border-red-900 dark:text-red-400">
                        {error}
                      </div>
                    )}

                    {result && (
                      <div>
                        <h3 className="text-xs font-medium mb-2">Result:</h3>
                        <div className="bg-slate-50 border border-slate-200 p-3 rounded-md overflow-x-auto text-xs font-mono h-[300px] overflow-y-auto dark:bg-slate-900 dark:border-slate-800">
                          <pre>{result}</pre>
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
                <CardFooter className="bg-red-50 dark:bg-red-950/20 flex flex-col items-start">
                  <p className="text-xs text-red-700 dark:text-red-400">
                    <strong>Vulnerability:</strong> This Rust implementation is vulnerable to SSRF because it doesn't
                    validate the user-provided URL. An attacker can provide URLs that access internal resources or
                    perform other unintended actions.
                  </p>
                </CardFooter>
              </Card>

              <div className="mt-6 rounded-md border p-4 bg-slate-50 dark:bg-slate-800">
                <h2 className="text-base font-semibold mb-2">How This Vulnerability Works</h2>
                <p className="text-xs text-slate-700 dark:text-slate-300 mb-4">
                  The vulnerable Rust code accepts any URL without validation and uses the reqwest library to make HTTP
                  requests to that URL. This allows an attacker to:
                </p>
                <ul className="list-disc pl-5 text-xs text-slate-700 dark:text-slate-300 space-y-1">
                  <li>
                    Access internal services (e.g., <code>http://localhost:8080/admin</code>)
                  </li>
                  <li>
                    Read local files (e.g., <code>file:///etc/passwd</code>)
                  </li>
                  <li>
                    Access cloud metadata services (e.g., <code>http://169.254.169.254/...</code>)
                  </li>
                  <li>Scan internal networks and exploit other services that trust the server's IP</li>
                </ul>
                <div className="mt-4">
                  <Link href="/lab2/fixed">
                    <Button className="gap-2 bg-green-500 hover:bg-green-600 text-white text-xs">
                      See the Fixed Version
                    </Button>
                  </Link>
                </div>
              </div>
            </div>

            <div className="lg:col-span-1">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Server Logs</CardTitle>
                  <CardDescription className="text-xs">API request and response logs</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-[500px] overflow-auto rounded border bg-black p-3 font-mono text-xs text-green-400">
                    {logs.length > 0 ? (
                      logs.map((log, index) => (
                        <div key={index} className="mb-1">
                          {log.includes("WARNING") ? (
                            <span className="text-yellow-400">{log}</span>
                          ) : log.includes("CRITICAL") ? (
                            <span className="text-red-400">{log}</span>
                          ) : log.includes("Error") ? (
                            <span className="text-red-400">{log}</span>
                          ) : (
                            <span>{log}</span>
                          )}
                        </div>
                      ))
                    ) : (
                      <div>No requests made yet</div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
