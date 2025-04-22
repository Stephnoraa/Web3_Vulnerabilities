import Link from "next/link"
import Image from "next/image"
import { ArrowLeft, Calendar, Clock, ExternalLink, User } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function TimeFunIncidentPage() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-50 dark:bg-slate-900">
      <header className="sticky top-0 z-10 border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80">
        <div className="container flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/blog" className="flex items-center gap-2">
            <ArrowLeft className="h-4 w-4" />
            <span className="text-sm font-medium">Back to Blog</span>
          </Link>
        </div>
      </header>

      <main className="flex-1 py-12">
        <article className="container px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl">
            <div className="mb-8">
              <h1 className="text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl dark:text-white">
                The Time.fun Incident: When Web2 Vulnerabilities Drain Web3 Wallets
              </h1>

              <div className="mt-4 flex flex-wrap items-center gap-4 text-sm text-slate-600 dark:text-slate-400">
                <div className="flex items-center gap-1">
                  <User className="h-4 w-4" />
                  <span>Security Research Team</span>
                </div>
                <div className="flex items-center gap-1">
                  <Calendar className="h-4 w-4" />
                  <span>April 22, 2025</span>
                </div>
                <div className="flex items-center gap-1">
                  <Clock className="h-4 w-4" />
                  <span>10 min read</span>
                </div>
              </div>
            </div>

            <div className="relative mb-10 aspect-video overflow-hidden rounded-xl">
              <Image
                src="https://sjc.microlink.io/QVqBvhFbER0aK1lJ7PkcMeRvoW3E40M3haGxvIVD4Qd86FSot41UDP4kIuMMAD4yr2NmnO2iVatQZ2iNzP3xNQ.jpeg"
                alt="Time.fun Website Screenshot"
                width={1200}
                height={675}
                className="object-cover"
              />
            </div>

            <div className="prose prose-slate max-w-none dark:prose-invert">
              <h2>The Time.fun Security Breach: Anatomy of a Web2 Vulnerability in a Web3 Platform</h2>

              <p>
                On September 18, 2023, Time.fun—a Solana-based platform that allows users to pay for time with
                creators—suffered a significant security breach. The incident resulted in approximately $95,000 in SOL
                being drained from user wallets, highlighting once again how Web2 vulnerabilities continue to plague
                Web3 applications.
              </p>

              <div className="not-prose my-8 rounded-xl bg-amber-50 p-6 dark:bg-amber-900/20">
                <h3 className="text-lg font-medium text-amber-800 dark:text-amber-400">Incident Summary</h3>
                <ul className="mt-2 space-y-2 text-amber-700 dark:text-amber-300">
                  <li>• Date: September 18, 2023</li>
                  <li>• Funds lost: ~$95,000 in SOL</li>
                  <li>• Root cause: Server-Side Request Forgery (SSRF) vulnerability</li>
                  <li>• Attack vector: Compromised API endpoint with insufficient URL validation</li>
                  <li>• Impact: Unauthorized transactions draining user wallets</li>
                </ul>
              </div>

              <h2>What Happened?</h2>

              <p>
                According to security researchers who analyzed the incident, attackers exploited a Server-Side Request
                Forgery (SSRF) vulnerability in Time.fun's backend API. This vulnerability allowed the attackers to make
                the server execute requests to internal services that should not have been accessible from the outside.
              </p>

              <p>
                The vulnerability existed in an API endpoint that was designed to fetch external resources, such as
                creator profile information or metadata. However, the endpoint failed to properly validate and sanitize
                the URLs provided by users, allowing attackers to specify URLs that pointed to internal services.
              </p>

              <div className="not-prose my-8">
                <Tabs defaultValue="vulnerable">
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="vulnerable">Vulnerable Code</TabsTrigger>
                    <TabsTrigger value="fixed">Fixed Implementation</TabsTrigger>
                  </TabsList>
                  <TabsContent value="vulnerable" className="rounded-xl border p-6">
                    <h3 className="mb-4 text-lg font-medium">Vulnerable Implementation (Simplified)</h3>
                    <pre className="overflow-auto rounded-md bg-slate-900 p-4 text-xs text-slate-50">
                      {`// Vulnerable API endpoint
app.post('/api/fetch-resource', async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  try {
    // VULNERABLE: No validation of URL before making the request
    const response = await fetch(url);
    const data = await response.json();
    
    return res.json({ 
      success: true, 
      data 
    });
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch resource' 
    });
  }
});`}
                    </pre>
                    <p className="mt-4 text-sm text-red-600 dark:text-red-400">
                      The vulnerability: This implementation makes no attempt to validate the URL before making the
                      request, allowing attackers to specify internal URLs or IP addresses.
                    </p>
                  </TabsContent>
                  <TabsContent value="fixed" className="rounded-xl border p-6">
                    <h3 className="mb-4 text-lg font-medium">Fixed Implementation</h3>
                    <pre className="overflow-auto rounded-md bg-slate-900 p-4 text-xs text-slate-50">
                      {`// Fixed API endpoint
const ALLOWED_DOMAINS = [
  'api.creators.com',
  'metadata.time.fun',
  'profiles.solana.com',
  'ipfs.io'
];

function isUrlAllowed(urlString) {
  try {
    const url = new URL(urlString);
    
    // Only allow http and https protocols
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return false;
    }
    
    // Check if domain is in allowlist
    const domain = url.hostname.toLowerCase();
    if (!ALLOWED_DOMAINS.some(d => domain === d || domain.endsWith(\`.\${d}\`))) {
      return false;
    }
    
    // Prevent access to internal IP addresses
    const ipAddress = require('ip');
    if (ipAddress.isPrivate(domain) || domain === 'localhost' || domain.startsWith('127.')) {
      return false;
    }
    
    return true;
  } catch (e) {
    return false;
  }
}

app.post('/api/fetch-resource', async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  // Validate URL before making the request
  if (!isUrlAllowed(url)) {
    return res.status(400).json({ 
      success: false, 
      error: 'URL validation failed: Only URLs from trusted domains are allowed' 
    });
  }
  
  try {
    const response = await fetch(url);
    const data = await response.json();
    
    return res.json({ 
      success: true, 
      data 
    });
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch resource' 
    });
  }
});`}
                    </pre>
                    <p className="mt-4 text-sm text-green-600 dark:text-green-400">
                      The fix: This implementation validates the URL against an allowlist of trusted domains and
                      prevents access to internal IP addresses before making any requests.
                    </p>
                  </TabsContent>
                </Tabs>
              </div>

              <h2>The Attack Chain</h2>

              <p>The attack unfolded in several stages:</p>

              <ol>
                <li>
                  <strong>Initial Exploitation:</strong> The attackers discovered the SSRF vulnerability in Time.fun's
                  API and used it to access internal services.
                </li>
                <li>
                  <strong>Credential Theft:</strong> Through the SSRF vulnerability, the attackers were able to access
                  an internal configuration service that contained API keys and credentials.
                </li>
                <li>
                  <strong>Access to Signing Service:</strong> Using the stolen credentials, the attackers gained access
                  to a service that was authorized to sign transactions on behalf of users.
                </li>
                <li>
                  <strong>Unauthorized Transactions:</strong> The attackers used the compromised signing service to
                  drain approximately $95,000 in SOL from user wallets.
                </li>
              </ol>

              <h2>Root Cause Analysis</h2>

              <p>
                The root cause of the vulnerability was a failure to validate user-supplied URLs before making
                server-side requests. This allowed attackers to specify internal URLs and IP addresses that should not
                have been accessible from the outside.
              </p>

              <p>Contributing factors included:</p>

              <ul>
                <li>
                  <strong>Lack of URL validation:</strong> The application did not validate the protocol, domain, or IP
                  address of the user-supplied URL.
                </li>
                <li>
                  <strong>Insufficient network segmentation:</strong> Internal services were accessible from the
                  application servers without proper network controls.
                </li>
                <li>
                  <strong>Excessive permissions:</strong> The application ran with permissions that allowed it to access
                  sensitive internal services.
                </li>
                <li>
                  <strong>Inadequate secrets management:</strong> API keys and credentials were stored in a way that
                  made them accessible once the initial SSRF vulnerability was exploited.
                </li>
              </ul>

              <h2>How Our Labs Could Have Prevented This</h2>

              <p>
                The Time.fun incident is a perfect example of how our security labs can help developers identify and fix
                vulnerabilities before they lead to security breaches:
              </p>

              <h3>Lab 2: SSRF in Metadata Fetcher</h3>

              <p>
                Our SSRF lab demonstrates exactly the type of vulnerability that was exploited in the Time.fun incident.
                By working through this lab, developers would learn:
              </p>

              <ul>
                <li>How to identify SSRF vulnerabilities in code that fetches external resources</li>
                <li>How to implement proper URL validation with domain allowlisting</li>
                <li>How to prevent access to internal services and IP addresses</li>
                <li>How to use network segmentation to isolate services that make external requests</li>
              </ul>

              <p>
                The fixed implementation in our lab provides a robust solution that would have prevented the Time.fun
                attack by validating URLs against an allowlist of trusted domains and blocking requests to internal
                services.
              </p>

              <h3>Lab 1: IDOR in Relayer API</h3>

              <p>
                While the primary vulnerability in the Time.fun incident was SSRF, our IDOR lab is also relevant because
                it teaches developers about proper authentication and authorization—concepts that could have helped
                prevent the attackers from accessing sensitive internal services even if they had discovered the initial
                SSRF vulnerability.
              </p>

              <p>
                By implementing the authentication and authorization checks demonstrated in our IDOR lab, Time.fun could
                have added an additional layer of security to their internal services, potentially preventing the
                attackers from accessing sensitive credentials even after exploiting the SSRF vulnerability.
              </p>

              <h2>Lessons Learned</h2>

              <p>The Time.fun incident offers several important lessons for Web3 developers:</p>

              <ol>
                <li>
                  <strong>Validate all user inputs:</strong> Always validate and sanitize user-supplied inputs,
                  especially URLs that will be used for server-side requests.
                </li>
                <li>
                  <strong>Implement defense in depth:</strong> Use multiple layers of security controls so that a single
                  vulnerability doesn't lead to catastrophic failure.
                </li>
                <li>
                  <strong>Properly segment your network:</strong> Isolate critical services and use network controls to
                  prevent unauthorized access.
                </li>
                <li>
                  <strong>Manage secrets securely:</strong> Use a secure secrets management solution and follow the
                  principle of least privilege.
                </li>
                <li>
                  <strong>Conduct regular security assessments:</strong> Regularly test your applications for security
                  vulnerabilities, including traditional web vulnerabilities like SSRF and IDOR.
                </li>
              </ol>

              <h2>Conclusion</h2>

              <p>
                The Time.fun incident is a stark reminder that Web3 applications are still web applications at their
                core and remain vulnerable to traditional Web2 security issues. By understanding these vulnerabilities
                and implementing proper security controls, developers can build more resilient Web3 applications that
                protect user assets and maintain trust in the ecosystem.
              </p>

              <p>
                Our interactive security labs provide hands-on experience with these vulnerabilities and their
                mitigations, helping developers build the skills they need to secure their Web3 applications against
                both traditional and blockchain-specific threats.
              </p>

              <div className="not-prose my-8 rounded-xl border border-slate-200 p-6 dark:border-slate-700">
                <h3 className="text-lg font-medium">About the Research</h3>
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                  This analysis is based on publicly available information about the Time.fun incident, including
                  security researcher reports and post-mortem analyses. The code examples are simplified for educational
                  purposes and may not reflect the exact implementation used by Time.fun.
                </p>
              </div>
            </div>

            <Separator className="my-10" />

            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium">Security Research Team</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400">Web3 Security Labs</p>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" asChild>
                  <Link href="/blog">
                    <ArrowLeft className="mr-2 h-4 w-4" />
                    Back to Blog
                  </Link>
                </Button>
                <Button size="sm" asChild>
                  <Link href="/lab2/vulnerable">
                    Try SSRF Lab
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
