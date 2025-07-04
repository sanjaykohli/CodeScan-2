import Link from "next/link";
import { ShieldCheck, Info, Github } from "lucide-react";
import GitHubIcon from "./GitHubIcon";

const Navbar = () => (
  <div className="navbar">
    <div className="navbar-container">
      <Link href="/" className="navbar-logo">
        <ShieldCheck className="navbar-logo-icon" />
        CodeScan
      </Link>
      <div className="navbar-links">
        <Link href="/" className="navbar-link">
          <ShieldCheck className="navbar-link-icon" /> Home
        </Link>
        <Link href="/github" className="navbar-link">
          <GitHubIcon className="navbar-link-icon" /> GitHub
        </Link>
        <Link href="/info" className="navbar-link">
          <Info className="navbar-link-icon" /> Info
        </Link>
      </div>
    </div>
  </div>
);

export default Navbar;