import Link from "next/link"
import { ArrowRight, BookOpen, Github, Shield, ShieldAlert, ShieldCheck } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"

export default function Home() {
  return (
    <div className="flex flex-col min-h-[calc(100vh-4rem)]">
      {/* Hero Section */}
      <section className="py-20 px-4 bg-gradient-to-b from-background to-muted">
        <div className="container mx-auto max-w-6xl text-center">
          <div className="inline-block p-2 px-3 mb-4 rounded-full bg-muted border text-sm font-medium">
            Educational Security Research
          </div>
          <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">
            Web2 Vulnerabilities in <span className="text-primary">Web3</span> Applications
          </h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto mb-8">
            Interactive security labs demonstrating how traditional web vulnerabilities can impact blockchain
            applications and infrastructure.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button asChild size="lg" className="gap-2">
              <Link href="#labs">
                Explore Labs <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
            <Button asChild variant="outline" size="lg" className="gap-2">
              <a href="https://github.com/Stephnoraa/Web3_Vulnerabilities" target="_blank" rel="noopener noreferrer">
                <Github className="h-4 w-4" />
                View on GitHub
              </a>
            </Button>
          </div>
        </div>
      </section>

      {/* Labs Section */}
      <section id="labs" className="py-20 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold tracking-tight mb-4">Interactive Security Labs</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Hands-on labs with vulnerable and fixed implementations to help you understand and mitigate common Web2
              vulnerabilities in Web3 applications.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            <Card className="border-2 border-red-500/20 dark:border-red-800/20 overflow-hidden">
              <CardHeader>
                <div className="flex justify-between items-start">
                  <CardTitle className="text-xl">Lab 1: IDOR Vulnerability</CardTitle>
                  <ShieldAlert className="h-5 w-5 text-red-500" />
                </div>
                <CardDescription>Insecure Direct Object Reference in a Solana Relayer API</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Explore how attackers can exploit IDOR vulnerabilities to access unauthorized user data and NFT
                  transactions in a Solana relayer service.
                </p>
                <div className="flex items-center gap-2 text-xs text-amber-600 dark:text-amber-400">
                  <Shield className="h-4 w-4" />
                  <span>Real-world impact: High</span>
                </div>
              </CardContent>
              <CardFooter className="flex gap-2">
                <Button asChild variant="destructive" className="flex-1">
                  <Link href="/lab1/vulnerable">Vulnerable Version</Link>
                </Button>
                <Button
                  asChild
                  variant="outline"
                  className="flex-1 border-green-600/20 text-green-600 dark:text-green-500 hover:bg-green-600/10"
                >
                  <Link href="/lab1/fixed">Fixed Version</Link>
                </Button>
              </CardFooter>
            </Card>

            <Card className="border-2 border-red-500/20 dark:border-red-800/20 overflow-hidden">
              <CardHeader>
                <div className="flex justify-between items-start">
                  <CardTitle className="text-xl">Lab 2: SSRF Vulnerability</CardTitle>
                  <ShieldAlert className="h-5 w-5 text-red-500" />
                </div>
                <CardDescription>Server-Side Request Forgery in an NFT Metadata Fetcher</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Learn how attackers can exploit SSRF vulnerabilities to access internal resources through a vulnerable
                  NFT metadata fetcher service.
                </p>
                <div className="flex items-center gap-2 text-xs text-amber-600 dark:text-amber-400">
                  <Shield className="h-4 w-4" />
                  <span>Real-world impact: Critical</span>
                </div>
              </CardContent>
              <CardFooter className="flex gap-2">
                <Button asChild variant="destructive" className="flex-1">
                  <Link href="/lab2/vulnerable">Vulnerable Version</Link>
                </Button>
                <Button
                  asChild
                  variant="outline"
                  className="flex-1 border-green-600/20 text-green-600 dark:text-green-500 hover:bg-green-600/10"
                >
                  <Link href="/lab2/fixed">Fixed Version</Link>
                </Button>
              </CardFooter>
            </Card>
          </div>

          <div className="mt-12 text-center">
            <Button asChild variant="outline" className="gap-2">
              <Link href="/documentation">
                <BookOpen className="h-4 w-4" />
                View Complete Documentation
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Research Section */}
      <section className="py-20 px-4 bg-muted">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold tracking-tight mb-4">Latest Research</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Our team analyzes real-world security incidents to provide actionable insights for Web3 developers.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <Card className="shadow-sm hover:shadow-md transition-shadow">
              <CardHeader>
                <CardTitle className="text-lg">The Rise of IDOR Vulnerabilities in Web3 Platforms</CardTitle>
                <CardDescription className="text-xs">April 15, 2025 • 8 min read</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Our analysis of 137 Web3 platforms revealed that 42% were vulnerable to IDOR attacks, potentially
                  exposing user wallet addresses and transaction history.
                </p>
              </CardContent>
              <CardFooter>
                <Button asChild variant="ghost" className="w-full gap-2">
                  <Link href="/blog/idor-vulnerabilities">
                    Read Article <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
              </CardFooter>
            </Card>

            <Card className="shadow-sm hover:shadow-md transition-shadow">
              <CardHeader>
                <CardTitle className="text-lg">SSRF Attacks Against NFT Platforms: A Case Study</CardTitle>
                <CardDescription className="text-xs">April 10, 2025 • 12 min read</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  How a major NFT marketplace was compromised through an SSRF vulnerability, leading to exposure of
                  private API keys and internal infrastructure.
                </p>
              </CardContent>
              <CardFooter>
                <Button asChild variant="ghost" className="w-full gap-2">
                  <Link href="/blog/ssrf-case-study">
                    Read Article <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
              </CardFooter>
            </Card>

            <Card className="shadow-sm hover:shadow-md transition-shadow">
              <CardHeader>
                <CardTitle className="text-lg">Web3 Security Incident Report: Q1 2025</CardTitle>
                <CardDescription className="text-xs">April 5, 2025 • 15 min read</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Our quarterly analysis of security incidents affecting Web3 projects. In Q1 2025, we tracked 47
                  incidents resulting in approximately $52M in losses.
                </p>
              </CardContent>
              <CardFooter>
                <Button asChild variant="ghost" className="w-full gap-2">
                  <Link href="/blog">
                    Read Article <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
              </CardFooter>
            </Card>
          </div>

          <div className="mt-12 text-center">
            <Button asChild className="gap-2">
              <Link href="/blog">
                View All Research <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Why It Matters Section */}
      <section className="py-20 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold tracking-tight mb-4">Why Web2 Vulnerabilities Matter in Web3</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              While blockchain protocols may be secure, the surrounding infrastructure often inherits traditional web
              vulnerabilities.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="flex flex-col items-center text-center">
              <div className="mb-4 rounded-full bg-primary/10 p-3">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-xl font-medium mb-2">Off-Chain Components</h3>
              <p className="text-sm text-muted-foreground">
                Most Web3 applications rely on traditional web infrastructure for their off-chain components, inheriting
                all their vulnerabilities.
              </p>
            </div>

            <div className="flex flex-col items-center text-center">
              <div className="mb-4 rounded-full bg-primary/10 p-3">
                <ShieldAlert className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-xl font-medium mb-2">High-Value Targets</h3>
              <p className="text-sm text-muted-foreground">
                Web3 projects often manage high-value assets, making them attractive targets for attackers exploiting
                traditional vulnerabilities.
              </p>
            </div>

            <div className="flex flex-col items-center text-center">
              <div className="mb-4 rounded-full bg-primary/10 p-3">
                <ShieldCheck className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-xl font-medium mb-2">Security Mindset</h3>
              <p className="text-sm text-muted-foreground">
                Web3 developers need both blockchain security knowledge and traditional web security expertise to build
                secure applications.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 bg-primary text-primary-foreground">
        <div className="container mx-auto max-w-6xl text-center">
          <h2 className="text-3xl font-bold tracking-tight mb-4">Ready to Improve Your Web3 Security Knowledge?</h2>
          <p className="text-xl opacity-90 max-w-2xl mx-auto mb-8">
            Explore our interactive labs, read our research, and contribute to the Web3 security community.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button asChild size="lg" variant="secondary" className="gap-2">
              <Link href="#labs">
                Start Learning <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
            <Button
              asChild
              size="lg"
              variant="outline"
              className="gap-2 bg-transparent border-primary-foreground/20 hover:bg-primary-foreground/10"
            >
              <a href="https://github.com/Stephnoraa/Web3_Vulnerabilities" target="_blank" rel="noopener noreferrer">
                <Github className="h-4 w-4" />
                Contribute on GitHub
              </a>
            </Button>
          </div>
        </div>
      </section>
    </div>
  )
}
