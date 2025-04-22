import Link from "next/link"
import Image from "next/image"
import { ArrowLeft, Calendar, Clock, Download, ExternalLink, Share, User } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function IdorVulnerabilitiesPage() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-50 dark:bg-slate-900">
      <header className="sticky top-0 z-10 border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80">
        <div className="container flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/blog" className="flex items-center gap-2">
            <ArrowLeft className="h-4 w-4" />
            <span className="text-sm font-medium">Back to Blog</span>
          </Link>
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon">
              <Share className="h-4 w-4" />
              <span className="sr-only">Share</span>
            </Button>
            <Button variant="ghost" size="icon">
              <Download className="h-4 w-4" />
              <span className="sr-only">Download</span>
            </Button>
          </div>
        </div>
      </header>

      <main className="flex-1 py-12">
        <article className="container px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl">
            <div className="mb-8">
              <h1 className="text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl dark:text-white">
                The Rise of IDOR Vulnerabilities in Web3 Platforms
              </h1>

              <div className="mt-4 flex flex-wrap items-center gap-4 text-sm text-slate-600 dark:text-slate-400">
                <div className="flex items-center gap-1">
                  <User className="h-4 w-4" />
                  <span>Dr. Sarah Chen, Security Researcher</span>
                </div>
                <div className="flex items-center gap-1">
                  <Calendar className="h-4 w-4" />
                  <span>April 15, 2025</span>
                </div>
                <div className="flex items-center gap-1">
                  <Clock className="h-4 w-4" />
                  <span>8 min read</span>
                </div>
              </div>
            </div>

            <div className="relative mb-10 aspect-video overflow-hidden rounded-xl">
              <Image
                src="/placeholder.svg?height=600&width=1200"
                alt="IDOR Vulnerabilities in Web3"
                width={1200}
                height={600}
                className="object-cover"
              />
            </div>

            <div className="prose prose-slate max-w-none dark:prose-invert">
              <h2>Executive Summary</h2>
              <p>
                Our comprehensive analysis of 137 Web3 platforms conducted between January and March 2025 revealed that
                42% were vulnerable to Insecure Direct Object Reference (IDOR) attacks. These vulnerabilities
                potentially exposed sensitive user data including wallet addresses, transaction histories, and in some
                cases, private API keys with elevated permissions.
              </p>

              <p>
                This article presents our findings, analyzes common patterns in vulnerable implementations, and provides
                concrete recommendations for Web3 developers to secure their applications against these attacks.
              </p>

              <h2>Introduction to IDOR in Web3 Context</h2>
              <p>
                Insecure Direct Object Reference (IDOR) vulnerabilities occur when an application provides direct access
                to objects based on user-supplied input without proper authorization checks. While this is a well-known
                vulnerability in traditional web applications, it presents unique challenges and risks in the Web3
                ecosystem.
              </p>

              <p>
                In Web3 applications, IDOR vulnerabilities often manifest in the off-chain components that support
                blockchain interactions, such as:
              </p>

              <ul>
                <li>Relayer services that facilitate transactions</li>
                <li>User profile and wallet management systems</li>
                <li>NFT metadata and transaction history APIs</li>
                <li>DeFi dashboard backends</li>
              </ul>

              <div className="not-prose my-8 rounded-xl bg-amber-50 p-6 dark:bg-amber-900/20">
                <h3 className="text-lg font-medium text-amber-800 dark:text-amber-400">Real-World Impact</h3>
                <p className="mt-2 text-amber-700 dark:text-amber-300">
                  In February 2025, a major NFT marketplace suffered a significant data breach due to an IDOR
                  vulnerability in their API. Attackers were able to access private collection data and user information
                  by simply manipulating API endpoint parameters. The estimated impact was $3.2M in losses due to
                  subsequent phishing attacks targeting exposed users.
                </p>
              </div>

              <h2>Research Methodology</h2>
              <p>Our research team analyzed 137 Web3 platforms across various categories:</p>

              <ul>
                <li>42 NFT marketplaces and platforms</li>
                <li>35 DeFi applications</li>
                <li>28 wallet services</li>
                <li>32 blockchain explorers and analytics platforms</li>
              </ul>

              <p>
                For each platform, we conducted a systematic assessment of API endpoints and user data access patterns,
                focusing on:
              </p>

              <ol>
                <li>Authentication mechanisms</li>
                <li>Authorization controls</li>
                <li>Parameter validation</li>
                <li>Access control implementations</li>
                <li>Session management</li>
              </ol>

              <h2>Key Findings</h2>

              <div className="not-prose my-8">
                <Tabs defaultValue="statistics">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="statistics">Statistics</TabsTrigger>
                    <TabsTrigger value="patterns">Vulnerability Patterns</TabsTrigger>
                    <TabsTrigger value="impact">Impact Analysis</TabsTrigger>
                  </TabsList>
                  <TabsContent value="statistics" className="rounded-xl border p-6">
                    <h3 className="mb-4 text-lg font-medium">Vulnerability Statistics</h3>
                    <div className="space-y-4">
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">NFT Platforms</span>
                          <span className="text-sm font-medium">52% Vulnerable</span>
                        </div>
                        <div className="mt-2 h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700">
                          <div className="h-2 rounded-full bg-amber-500" style={{ width: "52%" }}></div>
                        </div>
                      </div>
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">DeFi Applications</span>
                          <span className="text-sm font-medium">37% Vulnerable</span>
                        </div>
                        <div className="mt-2 h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700">
                          <div className="h-2 rounded-full bg-amber-500" style={{ width: "37%" }}></div>
                        </div>
                      </div>
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">Wallet Services</span>
                          <span className="text-sm font-medium">46% Vulnerable</span>
                        </div>
                        <div className="mt-2 h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700">
                          <div className="h-2 rounded-full bg-amber-500" style={{ width: "46%" }}></div>
                        </div>
                      </div>
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">Blockchain Explorers</span>
                          <span className="text-sm font-medium">28% Vulnerable</span>
                        </div>
                        <div className="mt-2 h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700">
                          <div className="h-2 rounded-full bg-amber-500" style={{ width: "28%" }}></div>
                        </div>
                      </div>
                    </div>
                  </TabsContent>
                  <TabsContent value="patterns" className="rounded-xl border p-6">
                    <h3 className="mb-4 text-lg font-medium">Common Vulnerability Patterns</h3>
                    <ul className="space-y-3">
                      <li className="flex items-start gap-2">
                        <span className="mt-1 text-amber-500">•</span>
                        <span>
                          <strong>Reliance on wallet authentication only:</strong> 73% of vulnerable applications
                          authenticated users via wallet signatures but failed to implement proper authorization checks
                          for data access.
                        </span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="mt-1 text-amber-500">•</span>
                        <span>
                          <strong>Predictable resource identifiers:</strong> 65% used sequential or easily guessable
                          identifiers for user resources.
                        </span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="mt-1 text-amber-500">•</span>
                        <span>
                          <strong>Insufficient access control in APIs:</strong> 81% of vulnerable applications had REST
                          APIs that failed to validate if the requesting user had permission to access the requested
                          resource.
                        </span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="mt-1 text-amber-500">•</span>
                        <span>
                          <strong>Missing session validation:</strong> 42% did not properly validate session tokens
                          against the requested resource owner.
                        </span>
                      </li>
                    </ul>
                  </TabsContent>
                  <TabsContent value="impact" className="rounded-xl border p-6">
                    <h3 className="mb-4 text-lg font-medium">Potential Impact</h3>
                    <div className="space-y-4">
                      <div className="rounded-lg border bg-white p-3 dark:bg-slate-800">
                        <h4 className="font-medium text-red-600 dark:text-red-400">Critical Impact (24%)</h4>
                        <p className="mt-1 text-sm">
                          Exposure of private keys, seed phrases, or API keys with administrative privileges
                        </p>
                      </div>
                      <div className="rounded-lg border bg-white p-3 dark:bg-slate-800">
                        <h4 className="font-medium text-amber-600 dark:text-amber-400">High Impact (38%)</h4>
                        <p className="mt-1 text-sm">
                          Access to transaction history, wallet balances, and personal information that could facilitate
                          targeted attacks
                        </p>
                      </div>
                      <div className="rounded-lg border bg-white p-3 dark:bg-slate-800">
                        <h4 className="font-medium text-yellow-600 dark:text-yellow-400">Medium Impact (27%)</h4>
                        <p className="mt-1 text-sm">
                          Exposure of non-public NFT metadata, collection statistics, or trading strategies
                        </p>
                      </div>
                      <div className="rounded-lg border bg-white p-3 dark:bg-slate-800">
                        <h4 className="font-medium text-blue-600 dark:text-blue-400">Low Impact (11%)</h4>
                        <p className="mt-1 text-sm">
                          Access to non-sensitive user preferences or public data before official release
                        </p>
                      </div>
                    </div>
                  </TabsContent>
                </Tabs>
              </div>

              <h2>Case Study: NFT Marketplace IDOR Vulnerability</h2>
              <p>
                One of the most severe vulnerabilities we discovered was in a popular NFT marketplace (name withheld
                pending responsible disclosure). The platform's API allowed users to view their NFT transaction history
                through an endpoint structured as:
              </p>

              <pre>
                <code>{`/api/users/{userId}/transactions`}</code>
              </pre>

              <p>
                The vulnerability stemmed from a lack of authorization checks. While the API required authentication via
                a wallet signature, it did not verify whether the authenticated user had permission to access the
                requested user's data. By simply changing the <code>userId</code> parameter, an attacker could access
                any user's complete transaction history.
              </p>

              <div className="not-prose my-8 rounded-xl bg-slate-100 p-6 dark:bg-slate-800">
                <h3 className="text-lg font-medium">Vulnerable Code Pattern</h3>
                <pre className="mt-4 overflow-auto rounded-md bg-slate-900 p-4 text-xs text-slate-50">
                  {`// Vulnerable implementation
app.get('/api/users/:userId/transactions', authenticateUser, async (req, res) => {
  const { userId } = req.params;
  
  try {
    // VULNERABLE: No authorization check to verify the requesting user
    // has permission to access this user's data
    const transactions = await db.getUserTransactions(userId);
    return res.json({ success: true, transactions });
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Failed to fetch transactions' });
  }
});`}
                </pre>

                <h3 className="mt-6 text-lg font-medium">Fixed Implementation</h3>
                <pre className="mt-4 overflow-auto rounded-md bg-slate-900 p-4 text-xs text-slate-50">
                  {`// Fixed implementation
app.get('/api/users/:userId/transactions', authenticateUser, async (req, res) => {
  const { userId } = req.params;
  
  try {
    // Check if the authenticated user is authorized to access this data
    if (req.user.id !== userId) {
      return res.status(403).json({ 
        success: false, 
        error: 'Unauthorized: You can only access your own transaction history' 
      });
    }
    
    const transactions = await db.getUserTransactions(userId);
    return res.json({ success: true, transactions });
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Failed to fetch transactions' });
  }
});`}
                </pre>
              </div>

              <h2>Recommendations for Web3 Developers</h2>
              <p>
                Based on our research, we recommend the following security measures to prevent IDOR vulnerabilities in
                Web3 applications:
              </p>

              <ol>
                <li>
                  <strong>Implement proper authorization checks:</strong> Always verify that the authenticated user has
                  permission to access the requested resource, even after successful authentication.
                </li>
                <li>
                  <strong>Use indirect references:</strong> Instead of sequential or predictable identifiers, use UUIDs
                  or other non-sequential identifiers for resources.
                </li>
                <li>
                  <strong>Implement contextual access controls:</strong> Validate access based on the relationship
                  between the user and the resource (e.g., ownership, membership, role).
                </li>
                <li>
                  <strong>Adopt the principle of least privilege:</strong> Ensure API endpoints and server-side
                  functions operate with the minimum necessary permissions.
                </li>
                <li>
                  <strong>Implement robust session validation:</strong> Verify that session tokens or wallet signatures
                  correspond to the appropriate user for each request.
                </li>
              </ol>

              <h2>Conclusion</h2>
              <p>
                IDOR vulnerabilities represent a significant risk to Web3 platforms, with 42% of the applications we
                analyzed being vulnerable to these attacks. While the blockchain itself may be secure, the off-chain
                components that support Web3 applications often introduce these traditional web vulnerabilities.
              </p>

              <p>
                By implementing proper authentication, authorization, and access control mechanisms, developers can
                significantly reduce the risk of IDOR vulnerabilities in their Web3 applications. We encourage all Web3
                developers to review their APIs and access control implementations in light of these findings.
              </p>

              <div className="not-prose my-8 rounded-xl border border-slate-200 p-6 dark:border-slate-700">
                <h3 className="text-lg font-medium">About the Research</h3>
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                  This research was conducted by the Web3 Security Research team between January and March 2025. All
                  vulnerabilities discovered during this research were disclosed responsibly to the affected platforms
                  before publication. For more information about our research methodology or to report security
                  vulnerabilities, please contact us at research@web3security.example.com.
                </p>
              </div>
            </div>

            <Separator className="my-10" />

            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium">Dr. Sarah Chen</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Lead Security Researcher, Web3 Security Research
                </p>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" asChild>
                  <Link href="/blog">
                    <ArrowLeft className="mr-2 h-4 w-4" />
                    Back to Blog
                  </Link>
                </Button>
                <Button size="sm" asChild>
                  <Link href="/lab1/vulnerable">
                    Try IDOR Lab
                    <ExternalLink className="ml-2 h-4 w-4" />
                  </Link>
                </Button>
              </div>
            </div>
          </div>
        </article>
      </main>

      <footer className="border-t bg-white py-8 dark:bg-slate-950">
        <div className="container px-4 text-center text-xs text-slate-500 sm:px-6 lg:px-8 dark:text-slate-400">
          <p>© 2025 Web3 Security Research. Educational purposes only.</p>
        </div>
      </footer>
    </div>
  )
}
