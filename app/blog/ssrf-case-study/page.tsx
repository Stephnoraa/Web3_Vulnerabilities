import Link from "next/link"
import Image from "next/image"
import { ArrowLeft, Calendar, Clock, Download, ExternalLink, Share, User } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function SsrfCaseStudyPage() {
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
                SSRF Attacks Against NFT Platforms: A Case Study
              </h1>
              
              <div className="mt-4 flex flex-wrap items-center gap-4 text-sm text-slate-600 dark:text-slate-400">
                <div className="flex items-center gap-1">
                  <User className="h-4 w-4" />
                  <span>Alex Rodriguez, Security Engineer</span>
                </div>
                <div className="flex items-center gap-1">
                  <Calendar className="h-4 w-4" />
                  <span>April 10, 2025</span>
                </div>
                <div className="flex items-center gap-1">
                  <Clock className="h-4 w-4" />
                  <span>12 min read</span>
                </div>
              </div>
            </div>
            
            <div className="relative mb-10 aspect-video overflow-hidden rounded-xl">
              <Image 
                src="/placeholder.svg?height=600&width=1200" 
                alt="SSRF Attack Diagram" 
                width={1200} 
                height={600} 
                className="object-cover"
              />
            </div>
            
            <div className="prose prose-slate max-w-none dark:prose-invert">
              <h2>Executive Summary</h2>
              <p>
                In February 2025, a major NFT marketplace (referred to as "Platform X" for confidentiality) 
                experienced a significant security breach due to a Server-Side Request Forgery (SSRF) vulnerability 
                in their metadata fetching service. The attackers exploited this vulnerability to access internal 
                systems, extract sensitive configuration data, and ultimately compromise user accounts.
              </p>
              
              <p>
                This case study examines the attack vector, impact, and remediation steps, providing valuable 
                lessons for Web3 developers building similar systems.
              </p>
              
              <div className="not-prose my-8 rounded-xl bg-amber-50 p-6 dark:bg-amber-900/20">
                <h3 className="text-lg font-medium text-amber-800 dark:text-amber-400">Impact Summary</h3>
                <ul className="mt-2 space-y-2 text-amber-700 dark:text-amber-300">
                  <li>• Exposure of internal API keys and service credentials</li>
                  <li>• Access to internal admin interfaces and configuration data</li>
                  <li>• Compromise of approximately 1,200 user accounts</li>
                  <li>• Estimated financial impact: $2.3 million in stolen NFTs and tokens</li>
                  <li>• Significant reputational damage and temporary platform shutdown</li>
                </ul>
              </div>
              
              <h2>Background: The Vulnerable System</h2>
              <p>
                Platform X operated a service that allowed users to create and mint NFTs. As part of this process, 
                the platform needed to fetch metadata from various sources, including IPFS, Arweave, and user-provided 
                URLs. This functionality was implemented through a backend API endpoint that accepted a URL parameter 
                and fetched the content on behalf of the user.
              </p>
              
              <p>
                The vulnerable endpoint was designed to:
              </p>
              
              <ol>
                <li>Accept a URL from the user</li>
                <li>Fetch the content from that URL</li>
                <li>Parse and validate the metadata format</li>
                <li>Return the processed metadata to the user</li>
              </ol>
              
              <div className="not-prose my-8">
                <Tabs defaultValue="vulnerable">
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="vulnerable">Vulnerable Code</TabsTrigger>
                    <TabsTrigger value="fixed">Fixed Implementation</TabsTrigger>
                  </TabsList>
                  <TabsContent value="vulnerable" className="rounded-xl border p-6">
                    <h3 className="mb-4 text-lg font-medium">Vulnerable Implementation</h3>
                    <pre className="overflow-auto rounded-md bg-slate-900 p-4 text-xs text-slate-50">
{`// Vulnerable metadata fetcher endpoint
app.post('/api/fetch-metadata', async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  try {
    // VULNERABLE: No validation of URL before making the request
    const response = await fetch(url);
    const metadata = await response.json();
    
    // Process and validate metadata
    const processedMetadata = processMetadata(metadata);
    
    return res.json({ 
      success: true, 
      metadata: processedMetadata 
    });
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch metadata' 
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
{`// Fixed metadata fetcher endpoint
const ALLOWED_DOMAINS = [
  'ipfs.io',
  'arweave.net',
  'nftstorage.link',
  'example.com'
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
    try {
      const ipAddress = require('ip');
      if (ipAddress.isPrivate(domain) || domain === 'localhost' || domain.startsWith('127.')) {
        return false;
      }
    } catch (e) {
      // Not an IP address, continue with domain validation
    }
    
    return true;
  } catch (e) {
    return false;
  }
}

app.post('/api/fetch-metadata', async (req, res) => {
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
    const metadata = await response.json();
    
    // Process and validate metadata
    const processedMetadata = processMetadata(metadata);
    
    return res.json({ 
      success: true, 
      metadata: processedMetadata 
    });
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch metadata' 
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
              
              <h2>The Attack: How It Happened</h2>
              <p>
                The attackers discovered the SSRF vulnerability through routine API testing. They noticed that the 
                metadata fetching endpoint did not validate the provided URL, allowing them to make requests to 
                internal services that should not have been accessible from the outside.
              </p>
              
              <p>
                The attack progressed through several stages:
              </p>
              
              <h3>Stage 1: Internal Network Discovery</h3>
              <p>
                The attackers first used the vulnerability to scan the internal network by sending requests to 
                common internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and observing the responses. 
                This allowed them to map the internal network structure and identify potential targets.
              </p>
              
              <pre><code>POST /api/fetch-metadata
Content-Type: application/json

{
  "url": \"http://10.0.0.1:8080/"
}</code></pre>
              
              <h3>Stage 2: Accessing Internal Services</h3>
              <p>
                After identifying several internal services, the attackers focused on an internal admin dashboard 
                running on http://internal-admin.platform-x.local:8080. By sending a request to this internal URL 
                through the vulnerable endpoint, they were able to access the admin dashboard's API.
              </p>
              
              <pre><code>POST /api/fetch-metadata
Content-Type: application/json

{
  "url": "http://internal-admin.platform-x.local:8080/api/config"
}</code></pre>
              
              <h3>Stage 3: Credential Extraction</h3>
              <p>
                The internal admin API inadvertently exposed configuration data including API keys, database 
                credentials, and service tokens. The attackers extracted these credentials and used them to 
                gain further access to the platform's systems.
              </p>
              
              <h3>Stage 4: Account Compromise</h3>
              <p>
                Using the extracted credentials, the attackers were able to access the user database, compromise 
                approximately 1,200 high-value accounts, and transfer NFTs and tokens to their own wallets.
              </p>
              
              <div className="not-prose my-8 rounded-xl bg-slate-100 p-6 dark:bg-slate-800">
                <h3 className="text-lg font-medium">Attack Timeline</h3>
                <div className="mt-4 space-y-4">
                  <div className="flex gap-4">
                    <div className="w-24 flex-shrink-0 text-sm font-medium">Day 1</div>
                    <div>
                      <p className="text-sm">Initial discovery of the SSRF vulnerability</p>
                    </div>
                  </div>
                  <div className="flex gap-4">
                    <div className="w-24 flex-shrink-0 text-sm font-medium">Day 2-3</div>
                    <div>
                      <p className="text-sm">Internal network scanning and service discovery</p>
                    </div>
                  </div>
                  <div className="flex gap-4">
                    <div className="w-24 flex-shrink-0 text-sm font-medium">Day 4</div>
                    <div>
                      <p className="text-sm">Access to internal admin dashboard and credential extraction</p>
                    </div>
                  </div>
                  <div className="flex gap-4">
                    <div className="w-24 flex-shrink-0 text-sm font-medium">Day 5-6</div>
                    <div>
                      <p className="text-sm">Account compromise and asset theft</p>
                    </div>
                  </div>
                  <div className="flex gap-4">
                    <div className="w-24 flex-shrink-0 text-sm font-medium">Day 7</div>
                    <div>
                      <p className="text-sm">Incident detection and platform shutdown</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <h2>Detection and Response</h2>
              <p>
                The attack was eventually detected when the platform's monitoring systems flagged unusual patterns 
                of NFT transfers from multiple high-value accounts. The security team immediately:
              </p>
              
              <ol>
                <li>Shut down the vulnerable API endpoint</li>
                <li>Revoked all compromised credentials and API keys</li>
                <li>Temporarily suspended the platform to prevent further damage</li>
                <li>Initiated a forensic investigation to understand the full scope of the breach</li>
                <li>Notified affected users and regulatory authorities</li>
              </ol>
              
              <h2>Root Cause Analysis</h2>
              <p>
                The root cause of the vulnerability was a failure to validate user-supplied URLs before making 
                server-side requests. This allowed attackers to specify internal URLs and IP addresses that should 
                not have been accessible from the outside.
              </p>
              
              <p>
                Contributing factors included:
              </p>
              
              <ul>
                <li>
                  <strong>Lack of URL validation:</strong> The application did not validate the protocol, domain, 
                  or IP address of the user-supplied URL.
                </li>
                <li>
                  <strong>No network segmentation:</strong> Internal services were accessible from the application 
                  servers without proper network controls.
                </li>
                <li>
                  <strong>Excessive permissions:</strong> The application ran with permissions that allowed it to 
                  access sensitive internal services.
                </li>
                <li>
                  <strong>Insufficient monitoring:</strong> The unusual internal requests were not detected until 
                  after the attackers had already extracted sensitive data.
                </li>
              </ul>
              
              <h2>Remediation and Lessons Learned</h2>
              <p>
                Platform X implemented several security improvements to fix the vulnerability and prevent similar 
                attacks in the future:
              </p>
              
              <h3>1. URL Validation and Allowlisting</h3>
              <p>
                The most critical fix was implementing proper URL validation with an allowlist of trusted domains. 
                The application now only allows requests to specific trusted domains like IPFS gateways and other 
                known metadata sources.
              </p>
              
              <h3>2. Network Segmentation</h3>
              <p>
                The platform implemented strict network segmentation to isolate public-facing services from internal 
                administrative systems. Even if a future SSRF vulnerability is discovered, attackers would not be 
                able to access sensitive internal services.
              </p>
              
              <h3>3. Principle of Least Privilege</h3>
              <p>
                The application now runs with the minimum necessary permissions, following the principle of least 
                privilege. The metadata fetching service operates in a dedicated container with no access to 
                sensitive internal resources.
              </p>
              
              <h3>4. Enhanced Monitoring and Alerting</h3>
              <p>
                The platform implemented enhanced monitoring for unusual network requests, particularly those 
                targeting internal services or using internal IP addresses. Alerts are now triggered for any 
                suspicious activity.
              </p>
              
              <h2>Recommendations for Web3 Developers</h2>
              <p>
                Based on this case study, we recommend the following security measures for Web3 developers 
                implementing similar functionality:
              </p>
              
              <ol>
                <li>
                  <strong>Validate all user-supplied URLs:</strong> Implement strict validation of user-supplied 
                  URLs, including protocol, domain, and IP address checks.
                </li>
                <li>
                  <strong>Use an allowlist approach:</strong> Only allow requests to specific trusted domains 
                  rather than trying to block known bad domains or IP ranges.
                </li>
                <li>
                  <strong>Implement network segmentation:</strong> Isolate public-facing services from internal 
                  administrative systems and sensitive resources.
                </li>
                <li>
                  <strong>Follow the principle of least privilege:</strong> Run services with the minimum necessary 
                  permissions to perform their functions.
                </li>
                <li>
                  <strong>Implement proper monitoring and alerting:</strong> Monitor for unusual network requests 
                  and alert on suspicious activity.
                </li>
                <li>
                  <strong>Consider using a dedicated service:</strong> For metadata fetching, consider using a 
                  dedicated service that runs in an isolated environment with no access to internal resources.
                </li>
              </ol>
              
              <h2>Conclusion</h2>
              <p>
                The SSRF vulnerability in Platform X's metadata fetching service led to a significant security 
                breach with substantial financial and reputational impact. This case study highlights the importance 
                of proper URL validation and security controls in Web3 applications that interact with external 
                resources.
              </p>
              
              <p>
                By implementing the recommended security measures, Web3 developers can significantly reduce the risk 
                of similar vulnerabilities in their applications. Remember that while blockchain transactions may be 
                secure, the off-chain components of Web3 applications are still susceptible to traditional web 
                vulnerabilities like SSRF.
              </p>
              
              <div className="not-prose my-8 rounded-xl border border-slate-200 p-6 dark:border-slate-700">
                <h3 className="text-lg font-medium">About the Author</h3>
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                  Alex Rodriguez is a Security Engineer specializing in Web3 application security. With over 10 years 
                  of experience in web application security and 5 years focused on blockchain technologies, Alex has 
                  helped numerous Web3 projects identify and remediate security vulnerabilities before they could be 
                  exploited.
                </p>
              </div>
            </div>
            
            <Separator className="my-10" />
            
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium">Alex Rodriguez</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Security Engineer, Web3 Security Research
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
