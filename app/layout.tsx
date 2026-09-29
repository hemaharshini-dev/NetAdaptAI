import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "NetAdaptAI | Compliance workspace",
  description: "Review network configuration against the current CIS Cisco IOS XE prototype benchmark rules.",
};
export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
