import Link from "next/link"
import { ArrowLeft, Calendar, Clock, Tag, User } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"

export default function BlogPage() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-50 dark:bg-slate-900">
      <header className="sticky top-0 z-10 border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80">
        <div className="container flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="flex items-center gap-2">
            <ArrowLeft className="h-4 w-4" />
            <span className="text-sm font-medium">Back to Home</span>
          </Link>
          <h1 className="text-lg font-medium">Web3 Security Research Blog</h1>
          <div className="w-24"></div> {/* Spacer for centering */}
        </div>
      </header>

      <main className="flex-1 py-12">
        <div className="container px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-4xl">
            <div className="mb-12">
              <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white">Research Blog</h1>
              <p className="mt-2 text-slate-600 dark:text-slate-400">
                In-depth analysis of Web2 vulnerabilities in Web3 contexts, based on real-world research and incidents
              </p>
            </div>

            <div className="grid gap-8 md:grid-cols-2">
              <Card className="shadow-md hover:shadow-lg transition-shadow">
                <CardHeader>
                  <CardTitle className="text-xl">
                    The Time.fun Incident: When Web2 Vulnerabilities Drain Web3 Wallets
                  </CardTitle>
                  <CardDescription className="flex items-center gap-4 text-xs">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" /> April 22, 2025
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> 10 min read
                    </span>
                    <span className="flex items-center gap-1">
                      <User className="h-3 w-3" /> Security Research Team
                    </span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    An in-depth analysis of the September 2023 Time.fun security breach where an SSRF vulnerability led
                    to approximately $95,000 in SOL being drained from user wallets. Learn how proper security controls
                    could have prevented this incident.
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> SSRF
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Solana
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Case Study
                    </span>
                  </div>
                </CardContent>
                <CardFooter>
                  <Button className="w-full" asChild>
                    <Link href="/blog/time-fun-incident">Read Full Article</Link>
                  </Button>
                </CardFooter>
              </Card>

              <Card className="shadow-md hover:shadow-lg transition-shadow">
                <CardHeader>
                  <CardTitle className="text-xl">The Rise of IDOR Vulnerabilities in Web3 Platforms</CardTitle>
                  <CardDescription className="flex items-center gap-4 text-xs">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" /> April 15, 2025
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> 8 min read
                    </span>
                    <span className="flex items-center gap-1">
                      <User className="h-3 w-3" /> Dr. Sarah Chen
                    </span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Our analysis of 137 Web3 platforms revealed that 42% were vulnerable to IDOR attacks, potentially
                    exposing user wallet addresses and transaction history. This article explores the patterns we
                    discovered and provides recommendations for developers.
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> IDOR
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Web3
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Research
                    </span>
                  </div>
                </CardContent>
                <CardFooter>
                  <Button className="w-full" asChild>
                    <Link href="/blog/idor-vulnerabilities">Read Full Article</Link>
                  </Button>
                </CardFooter>
              </Card>

              <Card className="shadow-md hover:shadow-lg transition-shadow">
                <CardHeader>
                  <CardTitle className="text-xl">SSRF Attacks Against NFT Platforms: A Case Study</CardTitle>
                  <CardDescription className="flex items-center gap-4 text-xs">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" /> April 10, 2025
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> 12 min read
                    </span>
                    <span className="flex items-center gap-1">
                      <User className="h-3 w-3" /> Alex Rodriguez
                    </span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    How a major NFT marketplace was compromised through an SSRF vulnerability, leading to exposure of
                    private API keys and internal infrastructure. This case study examines the attack vector, impact,
                    and remediation steps.
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> SSRF
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> NFT
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Case Study
                    </span>
                  </div>
                </CardContent>
                <CardFooter>
                  <Button className="w-full" asChild>
                    <Link href="/blog/ssrf-case-study">Read Full Article</Link>
                  </Button>
                </CardFooter>
              </Card>

              <Card className="shadow-md hover:shadow-lg transition-shadow">
                <CardHeader>
                  <CardTitle className="text-xl">Web3 Security Incident Report: Q1 2025</CardTitle>
                  <CardDescription className="flex items-center gap-4 text-xs">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" /> April 5, 2025
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> 15 min read
                    </span>
                    <span className="flex items-center gap-1">
                      <User className="h-3 w-3" /> Security Team
                    </span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Our quarterly analysis of security incidents affecting Web3 projects. In Q1 2025, we tracked 47
                    incidents resulting in approximately $52M in losses. Traditional web vulnerabilities accounted for
                    63% of these incidents.
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Report
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Statistics
                    </span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-800 dark:bg-slate-700 dark:text-slate-300">
                      <Tag className="mr-1 h-3 w-3" /> Analysis
                    </span>
                  </div>
                </CardContent>
                <CardFooter>
                  <Button className="w-full" asChild>
                    <Link href="/blog/q1-2025-report">Read Full Article</Link>
                  </Button>
                </CardFooter>
              </Card>
            </div>

            <Separator className="my-12" />

            <div className="rounded-xl bg-white p-8 shadow-md dark:bg-slate-800">
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
                Subscribe to Our Research Newsletter
              </h2>
              <p className="mt-2 text-slate-600 dark:text-slate-400">
                Get the latest Web3 security research, vulnerability reports, and best practices delivered to your
                inbox.
              </p>

              <form className="mt-6 flex gap-2">
                <input
                  type="email"
                  placeholder="Enter your email"
                  className="flex-1 rounded-md border border-slate-300 bg-transparent px-3 py-2 text-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-400 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-700 dark:text-slate-50 dark:focus:ring-slate-400 dark:focus:ring-offset-slate-900"
                />
                <Button type="submit">Subscribe</Button>
              </form>
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t bg-white py-8 dark:bg-slate-950">
        <div className="container px-4 text-center text-xs text-slate-500 sm:px-6 lg:px-8 dark:text-slate-400">
          <p>© 2025 Web3 Security Research. Educational purposes only.</p>
        </div>
      </footer>
    </div>
  )
}
