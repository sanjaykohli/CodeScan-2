"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck, Info, Github } from "lucide-react";

const Navbar = () => {
  const pathname = usePathname();

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <Link href="/" className="navbar-logo">
          <ShieldCheck size={20} className="navbar-logo-icon" />
          CodeScan
        </Link>
        <div className="navbar-links">
          <Link href="/" className={`navbar-link ${pathname === "/" ? "navbar-link-active" : ""}`}>
            <ShieldCheck size={16} className="navbar-link-icon" />
            Analyzer
          </Link>
          <Link href="/github" className={`navbar-link ${pathname === "/github" ? "navbar-link-active" : ""}`}>
            <Github size={16} className="navbar-link-icon" />
            GitHub
          </Link>
          <Link href="/info" className={`navbar-link ${pathname === "/info" ? "navbar-link-active" : ""}`}>
            <Info size={16} className="navbar-link-icon" />
            Checks
          </Link>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
