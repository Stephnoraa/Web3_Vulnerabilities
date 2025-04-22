import Link from "next/link"
import { Github, Twitter, Linkedin, Mail } from "lucide-react"

export function Footer() {
  return (
    <footer className="border-t py-8 mt-12">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Web3 Security Labs</h3>
            <p className="text-sm text-muted-foreground">
              Educational resources for understanding Web2 vulnerabilities in Web3 applications.
            </p>
            <div className="flex space-x-4">
              <Link href="https://github.com/Stephnoraa/Web3_Vulnerabilities" target="_blank" rel="noopener noreferrer">
                <Github className="h-5 w-5 text-muted-foreground hover:text-foreground transition-colors" />
              </Link>
              <Link href="https://twitter.com" target="_blank" rel="noopener noreferrer">
                <Twitter className="h-5 w-5 text-muted-foreground hover:text-foreground transition-colors" />
              </Link>
              <Link href="https://linkedin.com" target="_blank" rel="noopener noreferrer">
                <Linkedin className="h-5 w-5 text-muted-foreground hover:text-foreground transition-colors" />
              </Link>
              <Link href="mailto:contact@web3securitylabs.com">
                <Mail className="h-5 w-5 text-muted-foreground hover:text-foreground transition-colors" />
              </Link>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-4">Labs</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link href="/lab1" className="text-muted-foreground hover:text-foreground transition-colors">
                  IDOR in Solana Relayer
                </Link>
              </li>
              <li>
                <Link href="/lab2" className="text-muted-foreground hover:text-foreground transition-colors">
                  SSRF in Metadata Fetcher
                </Link>
              </li>
              <li>
                <Link href="/documentation" className="text-muted-foreground hover:text-foreground transition-colors">
                  Documentation
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-4">Research</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link href="/blog" className="text-muted-foreground hover:text-foreground transition-colors">
                  Blog
                </Link>
              </li>
              <li>
                <Link
                  href="/blog/wormhole-incident"
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  Wormhole Incident
                </Link>
              </li>
              <li>
                <Link
                  href="/blog/opensea-idor"
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  OpenSea IDOR Case
                </Link>
              </li>
              <li>
                <Link
                  href="/blog/solana-wallet-drainer"
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  Solana Wallet Drainer
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-4">Resources</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link href="/about" className="text-muted-foreground hover:text-foreground transition-colors">
                  About Us
                </Link>
              </li>
              <li>
                <Link href="/contact" className="text-muted-foreground hover:text-foreground transition-colors">
                  Contact
                </Link>
              </li>
              <li>
                <Link
                  href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                  className="text-muted-foreground hover:text-foreground transition-colors"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  GitHub Repository
                </Link>
              </li>
            </ul>
          </div>
        </div>

        <div className="border-t mt-8 pt-6 text-center text-sm text-muted-foreground">
          <p>© {new Date().getFullYear()} Web3 Security Labs. All rights reserved.</p>
          <p className="mt-1">
            Created for educational purposes only. Do not use these techniques on systems without proper authorization.
          </p>
        </div>
      </div>
    </footer>
  )
}
