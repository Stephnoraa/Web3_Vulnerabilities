import type React from "react"
import Link from "next/link"
import { ModeToggle } from "./mode-toggle"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Menu, Github, BookOpen, FlaskRoundIcon as Flask, FileText } from "lucide-react"

export function Navbar() {
  return (
    <header className="border-b sticky top-0 z-50 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between px-4">
        <div className="flex items-center gap-6 md:gap-10">
          <Link href="/" className="flex items-center space-x-2">
            <Shield className="h-6 w-6" />
            <span className="font-bold text-lg hidden md:inline-block">Web3 Security Labs</span>
          </Link>
          <nav className="hidden md:flex gap-6">
            <Link href="/lab1" className="text-sm font-medium transition-colors hover:text-primary">
              Lab 1: IDOR
            </Link>
            <Link href="/lab2" className="text-sm font-medium transition-colors hover:text-primary">
              Lab 2: SSRF
            </Link>
            <Link href="/blog" className="text-sm font-medium transition-colors hover:text-primary">
              Blog
            </Link>
            <Link href="/documentation" className="text-sm font-medium transition-colors hover:text-primary">
              Documentation
            </Link>
          </nav>
        </div>
        <div className="flex items-center gap-4">
          <Link
            href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden md:block"
          >
            <Button variant="outline" size="sm" className="gap-2">
              <Github className="h-4 w-4" />
              <span>GitHub</span>
            </Button>
          </Link>
          <ModeToggle />
          <DropdownMenu>
            <DropdownMenuTrigger asChild className="md:hidden">
              <Button variant="outline" size="icon">
                <Menu className="h-5 w-5" />
                <span className="sr-only">Toggle menu</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Navigation</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link href="/lab1" className="flex items-center gap-2 cursor-pointer w-full">
                  <Flask className="h-4 w-4" />
                  <span>Lab 1: IDOR</span>
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href="/lab2" className="flex items-center gap-2 cursor-pointer w-full">
                  <Flask className="h-4 w-4" />
                  <span>Lab 2: SSRF</span>
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href="/blog" className="flex items-center gap-2 cursor-pointer w-full">
                  <FileText className="h-4 w-4" />
                  <span>Blog</span>
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href="/documentation" className="flex items-center gap-2 cursor-pointer w-full">
                  <BookOpen className="h-4 w-4" />
                  <span>Documentation</span>
                </Link>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link
                  href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                  className="flex items-center gap-2 cursor-pointer w-full"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Github className="h-4 w-4" />
                  <span>GitHub</span>
                </Link>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}

function Shield(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
      <path d="m12 8 3 3-3 3-3-3 3-3Z" />
    </svg>
  )
}
