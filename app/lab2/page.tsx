import Link from "next/link"
import { ShieldCheck } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Navbar } from "@/components/navbar"
import { AlertTriangle, ExternalLink, FileCode } from "lucide-react"

export default function Lab2Page() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <div className="container px-4 py-8 md:py-12 max-w-5xl mx-auto">
          <div className="flex flex-col space-y-4 mb-8">
            <h1 className="text-3xl font-bold tracking-tighter">
              Lab 2: SSRF Vulnerability in NFT Metadata Fetcher (Rust)
            </h1>
            <p className="text-muted-foreground max-w-[700px]">
              Explore how Server-Side Request Forgery (SSRF) vulnerabilities can compromise internal systems and
              sensitive data. This lab demonstrates the risks associated with fetching NFT metadata from user-supplied
              URLs without proper validation, implemented in Rust for production-grade security analysis.
            </p>
          </div>

          <div className="grid sm:grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="border-2 border-red-500/50">
              <CardHeader>
                <CardTitle className="text-lg font-semibold flex items-center space-x-2">
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                  <span>Vulnerable: SSRF in NFT Metadata Fetcher (Rust)</span>
                </CardTitle>
                <CardDescription className="text-gray-500">
                  Exploit an SSRF vulnerability in a Rust-based NFT metadata service.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  This lab showcases a vulnerable Rust implementation of an NFT metadata fetcher that is susceptible to
                  SSRF attacks. The backend is built with Actix Web, demonstrating how even strongly-typed languages can
                  be vulnerable to web attacks.
                </p>
              </CardContent>
              <CardFooter className="flex justify-end">
                <Link href="/lab2/vulnerable">
                  <Button variant="destructive" className="bg-red-500 hover:bg-red-600 text-white">
                    Exploit Now
                  </Button>
                </Link>
              </CardFooter>
            </Card>

            <Card className="border-2 border-green-500/50">
              <CardHeader>
                <CardTitle className="text-lg font-semibold flex items-center space-x-2">
                  <ShieldCheck className="h-5 w-5 text-green-500" />
                  <span>Secure: SSRF Protected Metadata Fetcher (Rust)</span>
                </CardTitle>
                <CardDescription className="text-gray-500">
                  A secure Rust implementation with proper URL validation.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  This lab demonstrates a secure Rust implementation of an NFT metadata fetcher that prevents SSRF
                  attacks. It leverages Rust's strong type system and security-focused libraries to implement strict URL
                  validation and domain allowlisting.
                </p>
              </CardContent>
              <CardFooter className="flex justify-end">
                <Link href="/lab2/fixed">
                  <Button className="bg-green-500 hover:bg-green-600 text-white">Explore Secure Version</Button>
                </Link>
              </CardFooter>
            </Card>
          </div>

          <div className="my-12 rounded-md border p-4 bg-gray-50 dark:bg-gray-800">
            <h2 className="text-xl font-semibold mb-4">Understanding SSRF in Rust Web3 Applications</h2>
            <p className="text-gray-700 dark:text-gray-300">
              Server-Side Request Forgery (SSRF) vulnerabilities can affect applications written in any language,
              including Rust. Despite Rust's focus on memory safety and strong typing, web applications can still be
              vulnerable to logical security issues like SSRF if proper validation isn't implemented.
            </p>
            <p className="text-gray-700 dark:text-gray-300 mt-2">
              In the context of NFTs and decentralized applications, metadata fetchers are common components that
              retrieve information from external sources like IPFS, Arweave, or other storage solutions. This lab
              demonstrates how to properly implement URL validation in Rust to prevent SSRF attacks.
            </p>
            <div className="mt-4 flex space-x-4">
              <Link
                href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="outline" className="gap-2">
                  <ExternalLink className="h-4 w-4" />
                  <span>Learn More About SSRF</span>
                </Button>
              </Link>
              <Link href="https://github.com/Stephnoraa/Web3_Vulnerabilities" target="_blank" rel="noopener noreferrer">
                <Button variant="outline" className="gap-2">
                  <FileCode className="h-4 w-4" />
                  <span>View on GitHub</span>
                </Button>
              </Link>
            </div>
          </div>
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
