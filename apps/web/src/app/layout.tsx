import type { Metadata } from "next";
import "@fontsource/public-sans/400.css";
import "@fontsource/public-sans/500.css";
import "@fontsource/public-sans/600.css";
import "./globals.css";
export const metadata: Metadata = {
  title: "SecureWallet · Digital Wallet AppSec Lab",
  description:
    "Explore a realistic demo wallet, its secure implementation, and a local-only application security assessment lab.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
