import Link from "next/link"
import Image from "next/image"
import { ArrowLeft, Calendar, Clock, ExternalLink, FileCode, User } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Navbar } from "@/components/navbar"

export default function SSRFInRustPage() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <div className="container px-4 py-8 md:py-12 max-w-4xl mx-auto">
          <div className="flex items-center mb-8">
            <Link href="/blog">
              <Button variant="ghost" className="gap-2">
                <ArrowLeft className="h-4 w-4" />
                <span>Back to Blog</span>
              </Button>
            </Link>
          </div>

          <article className="prose prose-gray dark:prose-invert max-w-none">
            <h1 className="text-3xl font-bold tracking-tight mb-4">SSRF Vulnerabilities in Rust Web3 Applications</h1>

            <div className="flex items-center gap-4 text-sm text-gray-500 mb-8">
              <div className="flex items-center gap-1">
                <Calendar className="h-4 w-4" />
                <span>April 15, 2025</span>
              </div>
              <div className="flex items-center gap-1">
                <Clock className="h-4 w-4" />
                <span>8 min read</span>
              </div>
              <div className="flex items-center gap-1">
                <User className="h-4 w-4" />
                <span>By Security Research Team</span>
              </div>
            </div>

            <div className="relative w-full h-64 mb-8 rounded-lg overflow-hidden">
              <Image
                src="/placeholder.svg?height=400&width=800"
                alt="SSRF Vulnerability Diagram"
                fill
                className="object-cover"
              />
            </div>

            <h2>Introduction</h2>
            <p>
              Server-Side Request Forgery (SSRF) vulnerabilities remain a significant threat in Web3 applications, even
              when built with memory-safe languages like Rust. While Rust provides strong memory safety guarantees, it
              doesn't automatically protect against logical vulnerabilities like SSRF. This article explores how SSRF
              vulnerabilities can impact Rust-based Web3 applications and provides practical mitigation strategies.
            </p>

            <h2>Understanding SSRF in Web3 Context</h2>
            <p>
              In Web3 applications, SSRF vulnerabilities are particularly concerning because they can potentially
              expose:
            </p>
            <ul>
              <li>Private blockchain nodes and their administrative interfaces</li>
              <li>Wallet private keys and seed phrases stored on the server</li>
              <li>Internal APIs that manage token allowlists or other security controls</li>
              <li>Metadata services that might contain sensitive information about NFTs or tokens</li>
            </ul>

            <p>
              A common pattern in Web3 applications is fetching metadata from user-provided URLs, such as when
              displaying NFT information. If this functionality doesn't properly validate input URLs, it can lead to
              SSRF vulnerabilities.
            </p>

            <h2>Case Study: NFT Metadata Fetcher Vulnerability</h2>
            <p>
              In January 2025, a major NFT marketplace built with Rust suffered a security incident due to an SSRF
              vulnerability in their metadata fetching service. The vulnerability allowed attackers to access internal
              services, including a Redis instance containing session tokens and temporary private keys used for
              transaction signing.
            </p>

            <p>The vulnerable code looked similar to this:</p>

            <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto text-xs font-mono">
              {`// Vulnerable Rust code
async fn fetch_metadata(url: String) -> Result<JsonValue, Error> {
    let client = Client::new();
    let response = client.get(&url).send().await?;
    let json = response.json().await?;
    Ok(json)
}`}
            </pre>

            <p>
              This code accepts any URL without validation, allowing attackers to specify URLs pointing to internal
              services or using file:// protocol to read local files.
            </p>

            <h2>Exploiting SSRF in Rust Applications</h2>
            <p>Despite Rust's safety features, SSRF vulnerabilities can be exploited in several ways:</p>

            <h3>1. Accessing Internal Services</h3>
            <p>Attackers can target internal services that are not meant to be publicly accessible:</p>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto text-xs font-mono">
              {`http://localhost:6379 // Access Redis
http://localhost:8545 // Access Ethereum node RPC
http://internal-api.local/admin // Access internal admin APIs`}
            </pre>

            <h3>2. Reading Local Files</h3>
            <p>The file:// protocol can be used to read local files on the server:</p>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto text-xs font-mono">
              {`file:///etc/passwd
file:///home/user/.env
file:///app/config/secrets.json`}
            </pre>

            <h3>3. Port Scanning and Service Discovery</h3>
            <p>SSRF can be used to scan internal networks and discover services:</p>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto text-xs font-mono">
              {`http://192.168.1.1:22 // SSH
http://192.168.1.1:3306 // MySQL
http://10.0.0.1:9200 // Elasticsearch`}
            </pre>

            <h2>Secure Implementation in Rust</h2>
            <p>Here's how to implement a secure URL fetcher in Rust:</p>

            <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto text-xs font-mono">
              {`use url::Url;
use std::collections::HashSet;

fn is_url_allowed(url_str: &str) -> Result<Url, String> {
    // Parse the URL
    let url = Url::parse(url_str).map_err(|_| "Invalid URL format".to_string())?;
    
    // Only allow HTTPS
    if url.scheme() != "https" {
        return Err("Only HTTPS URLs are allowed".to_string());
    }
    
    // Check against allowlist of domains
    let allowed_domains: HashSet<&str> = [
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

async fn fetch_metadata(url_str: &str) -> Result<JsonValue, Error> {
    // Validate the URL first
    let validated_url = is_url_allowed(url_str)?;
    
    let client = Client::new();
    let response = client.get(validated_url.as_str()).send().await?;
    let json = response.json().await?;
    Ok(json)
}`}
            </pre>

            <h2>Key Security Measures</h2>
            <p>To prevent SSRF vulnerabilities in Rust Web3 applications:</p>

            <ol>
              <li>
                <strong>Use proper URL parsing:</strong> Leverage Rust's url crate to properly parse and validate URLs.
              </li>
              <li>
                <strong>Implement protocol restrictions:</strong> Only allow specific protocols (typically https://).
              </li>
              <li>
                <strong>Use domain allowlisting:</strong> Maintain a strict list of allowed domains.
              </li>
              <li>
                <strong>Avoid internal addresses:</strong> Block requests to private IP ranges, localhost, and internal
                domains.
              </li>
              <li>
                <strong>Implement network segmentation:</strong> Run services that make external requests in isolated
                environments.
              </li>
              <li>
                <strong>Use a proxy service:</strong> Route all external requests through a dedicated proxy that
                implements additional security controls.
              </li>
            </ol>

            <h2>Conclusion</h2>
            <p>
              While Rust provides excellent memory safety guarantees, developers must still implement proper input
              validation and security controls to prevent logical vulnerabilities like SSRF. In Web3 applications where
              the stakes are particularly high due to the financial value at risk, implementing robust security measures
              is essential.
            </p>

            <p>
              By following the secure implementation patterns outlined in this article, developers can build Rust-based
              Web3 applications that are resilient against SSRF attacks and other web security vulnerabilities.
            </p>

            <div className="mt-8 flex flex-col sm:flex-row gap-4">
              <Link href="/lab2">
                <Button className="w-full sm:w-auto">Try the SSRF Lab</Button>
              </Link>
              <Link href="https://github.com/Stephnoraa/Web3_Vulnerabilities" target="_blank" rel="noopener noreferrer">
                <Button variant="outline" className="w-full sm:w-auto gap-2">
                  <FileCode className="h-4 w-4" />
                  <span>View Code on GitHub</span>
                </Button>
              </Link>
              <Link
                href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="outline" className="w-full sm:w-auto gap-2">
                  <ExternalLink className="h-4 w-4" />
                  <span>OWASP SSRF Guide</span>
                </Button>
              </Link>
            </div>
          </article>
        </div>
      </main>
      <footer className="border-t bg-white/50 backdrop-blur-sm dark:bg-gray-950/50">
        <div className="container flex h-16 items-center px-4 text-sm text-gray-600 sm:px-6 lg:px-8 dark:text-gray-400">
          <p>© 2025 Web3 Security Labs. Educational purposes only.</p>
        </div>
      </footer>
    </div>
  )
}
