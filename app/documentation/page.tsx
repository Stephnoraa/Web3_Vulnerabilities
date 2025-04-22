import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function DocumentationPage() {
  return (
    <div className="container mx-auto py-10 px-4 max-w-6xl">
      <h1 className="text-4xl font-bold mb-6 text-center">Web3 Security Documentation</h1>
      <p className="text-lg mb-8 text-center text-muted-foreground">
        Comprehensive documentation on Web2 vulnerabilities affecting Web3 applications
      </p>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="idor">IDOR</TabsTrigger>
          <TabsTrigger value="ssrf">SSRF</TabsTrigger>
          <TabsTrigger value="resources">Resources</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Web3 Security Overview</CardTitle>
              <CardDescription>
                Understanding the intersection of traditional web vulnerabilities and blockchain applications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p>
                Web3 applications combine traditional web technologies with blockchain infrastructure, creating a unique
                security landscape. While blockchain protocols themselves may be secure, the surrounding
                infrastructure—including frontends, APIs, and backend services—often suffer from traditional web
                vulnerabilities.
              </p>
              <p>
                Our research focuses on how classic Web2 vulnerabilities like IDOR and SSRF can impact Web3
                applications, potentially leading to significant security breaches and financial losses.
              </p>
              <div className="bg-muted p-4 rounded-md my-4">
                <h3 className="font-semibold mb-2">Key Statistics</h3>
                <ul className="list-disc pl-5 space-y-1">
                  <li>Over $3.1 billion lost to Web3 hacks in 2022</li>
                  <li>23% of Web3 vulnerabilities originate from traditional web security issues</li>
                  <li>API vulnerabilities account for 18% of all Web3 security incidents</li>
                  <li>The average cost of a Web3 security breach is $7.4 million</li>
                </ul>
              </div>
            </CardContent>
            <CardFooter>
              <Link href="/blog" className="w-full">
                <Button variant="outline" className="w-full">
                  Read Our Research Blog
                </Button>
              </Link>
            </CardFooter>
          </Card>
        </TabsContent>

        <TabsContent value="idor" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>IDOR in Web3</CardTitle>
              <CardDescription>Insecure Direct Object References in blockchain applications</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p>
                IDOR vulnerabilities occur when an application exposes a reference to an internal implementation object,
                such as a database key or file, without sufficient access control. In Web3 applications, IDORs can be
                particularly dangerous when they affect:
              </p>
              <ul className="list-disc pl-5 space-y-2">
                <li>
                  <span className="font-semibold">Relayer Services:</span> Unauthorized access to transaction data or
                  the ability to submit transactions on behalf of other users
                </li>
                <li>
                  <span className="font-semibold">NFT Metadata:</span> Unauthorized modification of NFT attributes or
                  images
                </li>
                <li>
                  <span className="font-semibold">User Profiles:</span> Access to private user data including wallet
                  addresses and transaction history
                </li>
                <li>
                  <span className="font-semibold">Admin Interfaces:</span> Unauthorized access to privileged functions
                </li>
              </ul>

              <div className="bg-muted p-4 rounded-md my-4">
                <h3 className="font-semibold mb-2">Real-World Impact</h3>
                <p>
                  In 2021, a major NFT marketplace suffered from an IDOR vulnerability that allowed attackers to view
                  private listing information before it was made public, enabling front-running attacks that resulted in
                  approximately $750,000 in losses.
                </p>
              </div>

              <h3 className="text-xl font-semibold mt-6 mb-2">Prevention Techniques</h3>
              <ol className="list-decimal pl-5 space-y-2">
                <li>Implement proper authorization checks for all API endpoints</li>
                <li>Use indirect references that are specific to each user session</li>
                <li>Verify wallet signatures for all sensitive operations</li>
                <li>Implement rate limiting to prevent enumeration attacks</li>
              </ol>
            </CardContent>
            <CardFooter>
              <div className="flex space-x-4 w-full">
                <Link href="/lab1" className="flex-1">
                  <Button variant="default" className="w-full">
                    Try IDOR Lab
                  </Button>
                </Link>
                <Link href="/blog/idor-vulnerabilities" className="flex-1">
                  <Button variant="outline" className="w-full">
                    Read Case Study
                  </Button>
                </Link>
              </div>
            </CardFooter>
          </Card>
        </TabsContent>

        <TabsContent value="ssrf" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>SSRF in Web3</CardTitle>
              <CardDescription>
                Server-Side Request Forgery vulnerabilities in blockchain infrastructure
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p>
                SSRF vulnerabilities allow attackers to induce server-side applications to make requests to unintended
                locations. In Web3 applications, SSRF can be exploited to:
              </p>
              <ul className="list-disc pl-5 space-y-2">
                <li>
                  <span className="font-semibold">Access Internal Services:</span> Reach internal blockchain nodes,
                  indexers, or databases
                </li>
                <li>
                  <span className="font-semibold">Bypass Authentication:</span> Access admin interfaces or internal APIs
                </li>
                <li>
                  <span className="font-semibold">Exfiltrate Sensitive Data:</span> Including private keys, API keys, or
                  user information
                </li>
                <li>
                  <span className="font-semibold">Manipulate Metadata:</span> Change NFT or token metadata by
                  redirecting metadata requests
                </li>
              </ul>

              <div className="bg-muted p-4 rounded-md my-4">
                <h3 className="font-semibold mb-2">Real-World Impact</h3>
                <p>
                  In 2022, a Web3 project's metadata server had an SSRF vulnerability that allowed attackers to access
                  the internal network, eventually leading to the compromise of private keys and the theft of
                  approximately $1.3 million in tokens.
                </p>
              </div>

              <h3 className="text-xl font-semibold mt-6 mb-2">Prevention Techniques</h3>
              <ol className="list-decimal pl-5 space-y-2">
                <li>Implement allowlists for external resources</li>
                <li>Validate and sanitize all user-supplied URLs</li>
                <li>Use dedicated services for metadata retrieval</li>
                <li>Implement network-level segmentation</li>
                <li>Deploy a Web Application Firewall (WAF)</li>
              </ol>
            </CardContent>
            <CardFooter>
              <div className="flex space-x-4 w-full">
                <Link href="/lab2" className="flex-1">
                  <Button variant="default" className="w-full">
                    Try SSRF Lab
                  </Button>
                </Link>
                <Link href="/blog/ssrf-case-study" className="flex-1">
                  <Button variant="outline" className="w-full">
                    Read Case Study
                  </Button>
                </Link>
              </div>
            </CardFooter>
          </Card>
        </TabsContent>

        <TabsContent value="resources" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Security Resources</CardTitle>
              <CardDescription>Tools, guides, and references for Web3 security research</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="border rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-2">Research Papers</h3>
                  <ul className="list-disc pl-5 space-y-2">
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Web3 Vulnerability Database
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        IDOR in DeFi Applications
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        SSRF Attack Vectors in NFT Platforms
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Blockchain Bridge Security Analysis
                      </a>
                    </li>
                  </ul>
                </div>

                <div className="border rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-2">Security Tools</h3>
                  <ul className="list-disc pl-5 space-y-2">
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Web3 Security Scanner
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Smart Contract Auditing Tools
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Blockchain Transaction Analyzer
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        API Security Testing Framework
                      </a>
                    </li>
                  </ul>
                </div>

                <div className="border rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-2">Training Materials</h3>
                  <ul className="list-disc pl-5 space-y-2">
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Web3 Security Fundamentals
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Blockchain Security Certification
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Smart Contract Security Workshop
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Web3 Penetration Testing Guide
                      </a>
                    </li>
                  </ul>
                </div>

                <div className="border rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-2">Community Resources</h3>
                  <ul className="list-disc pl-5 space-y-2">
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Web3 Security Forum
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Blockchain Security Discord
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Bug Bounty Programs
                      </a>
                    </li>
                    <li>
                      <a
                        href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Security Researcher Directory
                      </a>
                    </li>
                  </ul>
                </div>
              </div>
            </CardContent>
            <CardFooter>
              <Link
                href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                className="w-full"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button className="w-full">Visit Our GitHub Repository</Button>
              </Link>
            </CardFooter>
          </Card>
        </TabsContent>
      </Tabs>

      <div className="mt-12 border-t pt-8">
        <h2 className="text-2xl font-bold mb-4">Interactive Security Labs</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Lab 1: IDOR in Solana Relayer API</CardTitle>
              <CardDescription>
                Explore how Insecure Direct Object References can compromise blockchain relayer services
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="mb-4">
                This lab demonstrates a vulnerable Solana transaction relayer service that allows users to access and
                modify other users' transaction data due to improper access controls.
              </p>
              <div className="bg-muted p-4 rounded-md">
                <h4 className="font-semibold mb-2">Learning Objectives:</h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li>Understand how IDOR vulnerabilities manifest in Web3 applications</li>
                  <li>Learn to identify vulnerable API endpoints</li>
                  <li>Implement proper authorization checks using wallet signatures</li>
                  <li>Secure relayer services against unauthorized access</li>
                </ul>
              </div>
            </CardContent>
            <CardFooter>
              <Link href="/lab1" className="w-full">
                <Button variant="default" className="w-full">
                  Start Lab 1
                </Button>
              </Link>
            </CardFooter>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Lab 2: SSRF in Metadata Fetcher</CardTitle>
              <CardDescription>
                Learn how Server-Side Request Forgery can compromise NFT metadata services
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="mb-4">
                This lab demonstrates a vulnerable NFT metadata service that can be exploited to access internal network
                resources and potentially compromise private keys.
              </p>
              <div className="bg-muted p-4 rounded-md">
                <h4 className="font-semibold mb-2">Learning Objectives:</h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li>Understand how SSRF vulnerabilities impact Web3 infrastructure</li>
                  <li>Learn to identify vulnerable URL handling in metadata services</li>
                  <li>Implement proper URL validation and sanitization</li>
                  <li>Deploy network-level protections against SSRF attacks</li>
                </ul>
              </div>
            </CardContent>
            <CardFooter>
              <Link href="/lab2" className="w-full">
                <Button variant="default" className="w-full">
                  Start Lab 2
                </Button>
              </Link>
            </CardFooter>
          </Card>
        </div>
      </div>
    </div>
  )
}
