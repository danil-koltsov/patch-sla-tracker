import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { DataFooter } from "../components/DataFooter.tsx";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.SITE_URL ?? "http://localhost:3000"),
  title: { default: "Patch SLA Tracker", template: "%s · Patch SLA Tracker" },
  description:
    "How long Apple users stay exposed to security flaws: backport delays between OS branches, exploited-vulnerability timelines, and disclosure lag. Sourced from Apple, CISA KEV and NVD.",
  robots: { index: true, follow: true },
  // No images, not even a favicon: an empty data URL stops the browser's /favicon.ico request.
  icons: { icon: "data:," },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="skip" href="#content">
          Skip to content
        </a>
        <header className="site">
          <div className="wrap">
            <a className="home" href="/">
              Patch SLA Tracker
            </a>
            <nav aria-label="Main">
              <ul>
                <li>
                  <a href="/apple">Apple</a>
                </li>
                <li>
                  <a href="/methodology">Methodology</a>
                </li>
              </ul>
            </nav>
          </div>
        </header>
        <main id="content" className="wrap">
          {children}
        </main>
        <DataFooter />
      </body>
    </html>
  );
}
