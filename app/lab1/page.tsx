import Link from "next/link"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertTriangle, ShieldCheck, FileCode } from "lucide-react"

export default function Lab1Page() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <div className="container px-4 py-8 md:py-12 max-w-5xl mx-auto">
          <div className="flex flex-col space-y-4 mb-8">
            <h1 className="text-3xl font-bold tracking-tighter">Lab 1: IDOR Vulnerability in Solana Relayer API</h1>
            <p className="text-muted-foreground max-w-[700px]">
              Explore how Insecure Direct Object Reference (IDOR) vulnerabilities can compromise transaction privacy and
              security in Solana relayer services.
            </p>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            <Card className="vulnerability-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-destructive" />
                  Vulnerable Implementation
                </CardTitle>
                <CardDescription>A Solana relayer API with an IDOR vulnerability</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm mb-4">
                  This implementation of a Solana relayer API contains an IDOR vulnerability that allows attackers to
                  access transaction data belonging to other users.
                </p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-start gap-2">
                    <div className="h-5 w-5 flex items-center justify-center rounded-full bg-destructive/10 text-destructive shrink-0 mt-0.5">
                      <span className="text-xs">!</span>
                    </div>
                    <span>No proper authorization checks on transaction endpoints</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <div className="h-5 w-5 flex items-center justify-center rounded-full bg-destructive/10 text-destructive shrink-0 mt-0.5">
                      <span className="text-xs">!</span>
                    </div>
                    <span>Direct exposure of sequential transaction IDs</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <div className="h-5 w-5 flex items-center justify-center rounded-full bg-destructive/10 text-destructive shrink-0 mt-0.5">
                      <span className="text-xs">!</span>
                    </div>
                    <span>Sensitive transaction data accessible by manipulating IDs</span>
                  </div>
                </div>
              </CardContent>
              <CardFooter>
                <Button asChild variant="destructive" className="w-full">
                  <Link href="/lab1/vulnerable">Explore Vulnerable Version</Link>
                </Button>
              </CardFooter>
            </Card>

            <Card className="fixed-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-green-600 dark:text-green-500" />
                  Fixed Implementation
                </CardTitle>
                <CardDescription>A secure Solana relayer API with proper authorization</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm mb-4">
                  This implementation fixes the IDOR vulnerability by implementing proper authorization checks and using
                  secure identifiers.
                </p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-start gap-2">
                    <div className="h-5 w-5 flex items-center justify-center rounded-full bg-green-600/10 text-green-600 dark:text-green-500 shrink-0 mt-0.5">
                      <span className="text-xs">✓</span>
                    </div>
                    <span>Proper authorization checks on all transaction endpoints</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <div className="h-5 w-5 flex items-center justify-center rounded-full bg-green-600/10 text-green-600 dark:text-green-500 shrink-0 mt-0.5">
                      <span className="text-xs">✓</span>
                    </div>
                    <span>Use of non-sequential, unpredictable UUIDs</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <div className="h-5 w-5 flex items-center justify-center rounded-full bg-green-600/10 text-green-600 dark:text-green-500 shrink-0 mt-0.5">
                      <span className="text-xs">✓</span>
                    </div>
                    <span>Wallet signature verification for transaction access</span>
                  </div>
                </div>
              </CardContent>
              <CardFooter>
                <Button
                  asChild
                  variant="outline"
                  className="w-full border-green-600/20 text-green-600 dark:text-green-500 hover:bg-green-600/10"
                >
                  <Link href="/lab1/fixed">Explore Fixed Version</Link>
                </Button>
              </CardFooter>
            </Card>
          </div>

          <div className="mt-12 space-y-6">
            <h2 className="text-2xl font-bold tracking-tighter">About IDOR Vulnerabilities in Web3</h2>
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <p>
                Insecure Direct Object Reference (IDOR) vulnerabilities occur when an application exposes a reference to
                an internal implementation object, such as a database key, without proper authorization checks. In Web3
                applications, IDOR vulnerabilities can have severe consequences:
              </p>

              <h3>Real-World Impact</h3>
              <ul>
                <li>
                  <strong>Transaction Privacy Breaches:</strong> Attackers can view transaction details of other users,
                  including amounts, wallet addresses, and timestamps.
                </li>
                <li>
                  <strong>Private Key Exposure:</strong> In some cases, poorly secured relayer services might expose
                  private key material or seed phrases.
                </li>
                <li>
                  <strong>Fund Theft:</strong> Information gathered through IDOR vulnerabilities can be used to plan
                  more sophisticated attacks.
                </li>
              </ul>

              <h3>Notable Incidents</h3>
              <p>
                In 2022, a major NFT marketplace had an IDOR vulnerability that allowed attackers to view private
                transaction data and pending NFT listings before they were public. This enabled front-running attacks
                where attackers could purchase NFTs just before high-value sales were announced.
              </p>

              <h3>Prevention Strategies</h3>
              <ul>
                <li>
                  <strong>Implement proper authorization:</strong> Always verify that the current user has permission to
                  access the requested resource.
                </li>
                <li>
                  <strong>Use unpredictable identifiers:</strong> Replace sequential IDs with UUIDs or other
                  non-sequential identifiers.
                </li>
                <li>
                  <strong>Implement cryptographic verification:</strong> Use wallet signatures to verify ownership and
                  authorization.
                </li>
                <li>
                  <strong>Apply the principle of least privilege:</strong> Only expose the minimum information necessary
                  for the application to function.
                </li>
              </ul>
            </div>

            <div className="flex flex-col sm:flex-row gap-4 mt-8">
              <Button asChild>
                <Link href="/lab1/vulnerable">Start Lab Exercise</Link>
              </Button>
              <Button asChild variant="outline">
                <Link href="/blog/idor-vulnerabilities">Read Case Study</Link>
              </Button>
              <Button asChild variant="secondary">
                <a
                  href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2"
                >
                  <FileCode className="h-4 w-4" />
                  View Source Code
                </a>
              </Button>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
