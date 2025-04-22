"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { ArrowLeft, Copy, ExternalLink, Info, LogIn, ShieldCheck, User, ShieldAlert } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

interface Transaction {
  id: string
  type: string
  amount: string
  timestamp: string
  status: string
  signature: string
}

interface NFT {
  id: string
  name: string
  collection: string
  image: string
}

export default function FixedLab() {
  const [userId, setUserId] = useState("1")
  const [userData, setUserData] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [copied, setCopied] = useState(false)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentUser, setCurrentUser] = useState({ id: "1", name: "Alice" })
  const [requestLog, setRequestLog] = useState<string[]>([])

  const login = () => {
    setIsAuthenticated(true)
    setCurrentUser({ id: "1", name: "Alice" })
    fetchUserData("1")
    
    // Add to request log
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19)
    setRequestLog(prev => [...prev, `[${timestamp}] POST /api/auth/login - User authenticated: Alice (ID: 1)`])
  }

  const fetchUserData = async (id: string) => {
    setLoading(true)
    setError("")
    
    // Add to request log
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19)
    setRequestLog(prev => [...prev, `[${timestamp}] GET /api/users/${id}`])

    try {
      // Simulating API call to fixed endpoint with authentication check
      setTimeout(() => {
        // In the fixed version, we check if the requested user ID matches the authenticated user's ID
        if (!isAuthenticated) {
          setError("Authentication required")
          setUserData(null)
          setLoading(false)
          setRequestLog(prev => [...prev, `[${timestamp}] 401 Unauthorized - Authentication required`])
          return
        }

        if (id !== currentUser.id) {
          setError("Access denied: You can only view your own data")
          setUserData(null)
          setLoading(false)
          setRequestLog(prev => [...prev, `[${timestamp}] 403 Forbidden - User ${currentUser.id} attempted to access data for user ${id}`])
          return
        }

        // Only return data if authenticated and authorized
        setUserData({
          id: "1",
          name: "Alice",
          walletAddress: "AcME1XyBfXJKUd5dNoYz9F4UdaZ1pEMVr9Jv5e7SSYp",
          balance: "45.32 SOL",
          transactions: [
            {
              id: "tx1",
              type: "Send",
              amount: "5.2 SOL",
              timestamp: "2025-04-15 14:32:11",
              status: "Confirmed",
              signature: "5KtP9UYpn...",
            },
            {
              id: "tx2",
              type: "Receive",
              amount: "12.0 SOL",
              timestamp: "2025-04-14 09:15:43",
              status: "Confirmed",
              signature: "3xQm7UYzr...",
            },
            {
              id: "tx3",
              type: "NFT Mint",
              amount: "0.05 SOL",
              timestamp: "2025-04-10 18:22:05",
              status: "Confirmed",
              signature: "9pLm2RYxq...",
            },
          ],
          nfts: [
            {
              id: "nft1",
              name: "Solana Monkey #1234",
              collection: "SMB",
              image: "/placeholder.svg?height=150&width=150",
            },
            { id: "nft2", name: "DeGods #5678", collection: "DeGods", image: "/placeholder.svg?height=150&width=150" },
          ],
          privateApiKey: "sk_live_alice_12345abcdef",
        })
        setRequestLog(prev => [...prev, `[${timestamp}] 200 OK - User data retrieved successfully`])
        setLoading(false)
      }, 800)
    } catch (err) {
      setError("Failed to fetch user data")
      setLoading(false)
      setRequestLog(prev => [...prev, `[${timestamp}] 500 Internal Server Error`])
    }
  }

  useEffect(() => {
    // Don't auto-fetch in the fixed version - require authentication first
    // Initialize request log
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19)
    setRequestLog([
      `[${timestamp}] Server started`,
      `[${timestamp}] Listening on port 3000`,
      `[${timestamp}] Relayer API initialized with authentication middleware`
    ])
  }, [])

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleFetchClick = () => {
    fetchUserData(userId)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-teal-50 dark:from-slate-900 dark:to-slate-800">
      <header className="sticky top-0 z-10 border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80">
        <div className="container flex h-16 items-center px-4 sm:px-6 lg:px-8">
          <Link
            href="/"
            className="flex items-center gap-2 text-sm text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-50"
          >
            <ArrowLeft className="h-4 w-4" />
            <span>Back to Labs</span>
          </Link>
          <div className="ml-auto flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-full bg-green-100 px-3 py-1 text-xs text-green-700 dark:bg-green-900/30 dark:text-green-400">
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>Fixed Version</span>
            </div>
          </div>
        </div>
      </header>
      <main className="container px-4 py-8 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-8 rounded-lg bg-white/70 p-4 backdrop-blur-sm dark:bg-slate-800/70">
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">
              Lab 1: Fixed IDOR Vulnerability in Solana Relayer API
            </h1>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
              This lab demonstrates the fixed version of the Insecure Direct Object Reference (IDOR) vulnerability in a
              Solana relayer API. Authentication and authorization checks have been implemented to prevent unauthorized
              access.
            </p>
            <div className="mt-4 flex flex-wrap gap-4">
              <div className="flex items-center gap-2 rounded-full bg-green-100 px-3 py-1 text-xs text-green-700 dark:bg-green-900/30 dark:text-green-400">
                <Info className="h-3.5 w-3.5" />
                <span>Fix: Authentication and authorization checks implemented</span>
              </div>
              <div className="flex items-center gap-2 rounded-full bg-purple-100 px-3 py-1 text-xs text-purple-700 dark:bg-purple-900/30 dark:text-purple-400">
                <User className="h-3.5 w-3.5" />
                <span>Try accessing data for user ID: 2 (Bob)</span>
              </div>
            </div>
          </div>

          <div className="grid gap-6 lg:grid-cols-4">
            <div className="lg:col-span-3">
              {!isAuthenticated ? (
                <Card className="mx-auto max-w-md">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Authentication Required</CardTitle>
                    <CardDescription className="text-xs">Please log in to access user data</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-col gap-4">
                      <div>
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                          In the fixed version, authentication is required before accessing any user data.
                        </p>
                      </div>
                      <Button onClick={login} className="gap-2">
                        <LogIn className="h-4 w-4" />
                        <span>Log in as Alice (User ID: 1)</span>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <>
                  <div className="mb-6 flex items-center gap-4">
                    <div className="flex-1">
                      <div className="flex gap-2">
                        <Input
                          type="text"
                          placeholder="Enter user ID"
                          value={userId}
                          onChange={(e) => setUserId(e.target.value)}
                          className="max-w-xs"
                        />
                        <Button onClick={handleFetchClick} disabled={loading} size="sm">
                          {loading ? "Loading..." : "Fetch User Data"}
                        </Button>
                      </div>
                      <div className="mt-2 flex flex-col gap-1 text-xs">
                        <p className="text-slate-500 dark:text-slate-400">
                          Current endpoint:{" "}
                          <code className="rounded bg-slate-100 px-1 py-0.5 text-xs font-mono dark:bg-slate-700">
                            /api/users/{userId}
                          </code>
                        </p>
                        <p className="text-green-600 dark:text-green-400">
                          Logged in as: {currentUser.name} (User ID: {currentUser.id})
                        </p>
                      </div>
                    </div>
                    <div className="hidden md:block">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="outline" size="sm" className="gap-2 text-xs">
                              <ExternalLink className="h-3.5 w-3.5" />
                              <span>API Docs</span>
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p className="text-xs">API documentation would be available here in a real lab</p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
                  </div>

                  {error && (
                    <div className="mb-6 rounded-lg bg-red-100 p-3 text-sm text-red-700 dark:bg-red-900/30 dark:text-red-400">
                      {error}
                    </div>
                  )}

                  {userData && (
                    <div className="grid gap-6 lg:grid-cols-3">
                      <Card className="lg:col-span-1">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-base">User Profile</CardTitle>
                          <CardDescription className="text-xs">User and wallet information</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-3">
                            <div>
                              <h3 className="text-xs font-medium text-slate-500 dark:text-slate-400">User ID</h3>
                              <p className="text-sm text-slate-900 dark:text-slate-50">{userData.id}</p>
                            </div>
                            <div>
                              <h3 className="text-xs font-medium text-slate-500 dark:text-slate-400">Name</h3>
                              <p className="text-sm text-slate-900 dark:text-slate-50">{userData.name}</p>
                            </div>
                            <div>
                              <h3 className="text-xs font-medium text-slate-500 dark:text-slate-400">Wallet Address</h3>
                              <div className="flex items-center gap-2">
                                <code className="rounded bg-slate-100 px-2 py-1 text-xs font-mono dark:bg-slate-700">
                                  {userData.walletAddress}
                                </code>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-5 w-5"
                                  onClick={() => copyToClipboard(userData.walletAddress)}
                                >
                                  <Copy className="h-3 w-3" />
                                  <span className="sr-only">Copy address</span>
                                </Button>
                              </div>
                            </div>
                            <div>
                              <h3 className="text-xs font-medium text-slate-500 dark:text-slate-400">Balance</h3>
                              <p className="text-base font-bold text-slate-900 dark:text-slate-50">{userData.balance}</p>
                            </div>
                            <Separator />
                            <div className="rounded-md bg-green-50 p-3 dark:bg-green-900/20">
                              <h3 className="flex items-center gap-2 text-xs font-medium text-green-700 dark:text-green-400">
                                <ShieldCheck className="h-3.5 w-3.5" />
                                Private API Key (Protected)
                              </h3>
                              <div className="mt-2 flex items-center gap-2">
                                <code className="rounded bg-green-100 px-2 py-1 text-xs font-mono text-green-800 dark:bg-green-900/40 dark:text-green-300">
                                  {userData.privateApiKey}
                                </code>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-5 w-5 text-green-700 dark:text-green-400"
                                  onClick={() => copyToClipboard(userData.privateApiKey)}
                                >
                                  {copied ? <span className="text-[10px]">Copied!</span> : <Copy className="h-3 w-3" />}
                                  <span className="sr-only">Copy API key</span>
                                </Button>
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card className="lg:col-span-2">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-base">Wallet Activity</CardTitle>
                          <CardDescription className="text-xs">Transactions and NFTs</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <Tabs defaultValue="transactions">
                            <TabsList className="mb-4 h-8">
                              <TabsTrigger value="transactions" className="text-xs">Transactions</TabsTrigger>
                              <TabsTrigger value="nfts" className="text-xs">NFTs</TabsTrigger>
                            </TabsList>
                            <TabsContent value="transactions">
                              <div className="rounded-md border">
                                <div className="grid grid-cols-5 gap-4 border-b bg-slate-50 p-2 text-xs font-medium text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                                  <div>Type</div>
                                  <div>Amount</div>
                                  <div>Date</div>
                                  <div>Status</div>
                                  <div>Signature</div>
                                </div>
                                {userData.transactions.map((tx: Transaction) => (
                                  <div key={tx.id} className="grid grid-cols-5 gap-4 border-b p-2 text-xs last:border-0">
                                    <div>{tx.type}</div>
                                    <div>{tx.amount}</div>
                                    <div>{tx.timestamp}</div>
                                    <div>
                                      <span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-[10px] font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
                                        {tx.status}
                                      </span>
                                    </div>
                                    <div className="flex items-center gap-1">
                                      <code className="rounded bg-slate-100 px-1 py-0.5 text-[10px] font-mono dark:bg-slate-700">
                                        {tx.signature}
                                      </code>
                                      <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-4 w-4"
                                        onClick={() => copyToClipboard(tx.signature)}
                                      >
                                        <Copy className="h-2.5 w-2.5" />
                                        <span className="sr-only">Copy signature</span>
                                      </Button>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </TabsContent>
                            <TabsContent value="nfts">
                              <div className="grid gap-4 sm:grid-cols-2 md:grid-cols-3">
                                {userData.nfts.map((nft: NFT) => (
                                  <div key={nft.id} className="rounded-lg border bg-white p-3 dark:bg-slate-800">
                                    <img
                                      src={nft.image || "/placeholder.svg"}
                                      alt={nft.name}
                                      className="aspect-square w-full rounded-md object-cover"
                                    />
                                    <h3 className="mt-2 text-xs font-medium text-slate-900 dark:text-slate-50">{nft.name}</h3>
                                    <p className="text-[10px] text-slate-500 dark:text-slate-400">{nft.collection}</p>
                                  </div>
                                ))}
                              </div>
                            </TabsContent>
                          </Tabs>
                        </CardContent>
                      </Card>
                    </div>
                  )}
                </>
              )}
            </div>
            
            <div className="lg:col-span-1">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Server Logs</CardTitle>
                  <CardDescription className="text-xs">API request and response logs</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-[400px] overflow-auto rounded border bg-black p-3 font-mono text-xs text-green-400">
                    {requestLog.map((log, index) => (
                      <div key={index} className="mb-1">
                        {log.includes("ERROR") || log.includes("401") || log.includes("403") ? (
                          <span className="text-red-400">{log}</span>
                        ) : log.includes("404") ? (
                          <span className="text-amber-400">{log}</span>
                        ) : (
                          <span>{log}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          <div className="mt-8 rounded-lg bg-green-50 p-4 dark:bg-green-900/20">
            <h2 className="flex items-center gap-2 text-base font-medium text-green-800 dark:text-green-400">
              <ShieldCheck className="h-4 w-4" />
              Security Fix Explanation
            </h2>
            <p className="mt-2 text-sm text-green-700 dark:text-green-300">
              This version fixes the IDOR vulnerability by implementing proper authentication and authorization checks:
            </p>
            <ul className="mt-2 space-y-2 text-sm text-green-700 dark:text-green-300">
              <li className="flex items-start gap-2">
                <span className="mt-1">•</span>
                <span>Authentication: Users must log in before accessing any data</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1">•</span>
                <span>Authorization: Users can only access their own data, not other users' data</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1">•</span>
                <span>
                  Session validation: The server verifies the user's session and permissions before returning data
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1">•</span>
                <span>Error handling: Clear error messages without leaking sensitive information</span>
              </li>
            </ul>
            
            <div className="mt-4 rounded-md bg-white p-3 dark:bg-slate-800">
              <h3 className="text-xs font-medium text-slate-900 dark:text-slate-50">Fixed Code Pattern</h3>
              <pre className="mt-2 overflow-auto rounded-md bg-slate-900 p-3 text-xs text-slate-50">
{`// Fixed implementation
app.get('/api/users/:userId', authenticateUser, async (req, res) => {
  const { userId } = req.params;
  
  try {
    // Check if the authenticated user is authorized to access this data
    if (req.user.id !== userId) {
      return res.status(403).json({ 
        error: 'Access denied: You can only access your own data' 
      });
    }
    
    const userData = await db.getUserData(userId);
    
    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    return res.json(userData);
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch user data' });
  }
});`}
              </pre>
            </div>
            
            <div className="mt-4">
              <Link href="/lab1/vulnerable">
                <Button variant="outline" className="gap-2 text-xs">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>View Vulnerable Version</span>
                </Button>
              </Link>
            </div>
          </div>
          
          <div className="mt-8">
            <h2 className="text-base font-medium text-slate-900 dark:text-slate-50">Additional Resources</h2>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <Link 
                href="/blog/idor-vulnerabilities" 
                className="rounded-lg border bg-white p-4 transition-shadow hover:shadow-md dark:bg-slate-800"
              >
                <h3 className="text-sm font-medium text-slate-900 dark:text-slate-50">
                  The Rise of IDOR Vulnerabilities in Web3 Platforms
                </h3>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Our research on IDOR vulnerabilities across 137 Web3 platforms
                </p>
              </Link>
              <Link 
                href="https://github.com/Stephnoraa/Web3_Vulnerabilities"
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-lg border bg-white p-4 transition-shadow hover:shadow-md dark:bg-slate-800"
              >
                <h3 className="text-sm font-medium text-slate-\
