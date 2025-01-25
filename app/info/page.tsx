import Navbar from "../components/Navbar";
import { ShieldAlert, CheckCircle, AlertTriangle } from "lucide-react";

const Info = () => {
  const securityParameters = [
    {
      title: "Unsafe Functions",
      description: "Code using unsafe functions like eval or os.system is flagged.",
      icon: AlertTriangle
    },
    {
      title: "SQL Injection",
      description: "We look for patterns that suggest SQL injection vulnerabilities.",
      icon: ShieldAlert
    },
    {
      title: "Sensitive Data",
      description: "Plaintext passwords or API keys in the code will be flagged.",
      icon: AlertTriangle
    },
    {
      title: "Security Headers",
      description: "Lack of essential HTTP headers like X-Content-Type-Options.",
      icon: CheckCircle
    },
    {
      title: "Debugging Statements",
      description: "We check for unnecessary console logs or print statements.",
      icon: AlertTriangle
    },
    {
      title: "Dependency Usage",
      description: "Third-party libraries should be secure and up-to-date.",
      icon: ShieldAlert
    },
    {
      title: "Hardcoded Credentials",
      description: "Hardcoded credentials in the code pose security risks.",
      icon: AlertTriangle
    }
  ];

  return (
    <div className="page-container">
      <Navbar />
      <div className="content-wrapper">
        <div className="info-card">
          <h1 className="page-title">
            <ShieldAlert className="title-icon" /> Security Evaluation Parameters
          </h1>
          <p className="info-description">
            We evaluate code security based on comprehensive parameters:
          </p>
          <ul className="parameters-list">
            {securityParameters.map(({title, description, icon: Icon}) => (
              <li key={title} className="parameter-item">
                <Icon className="parameter-icon" />
                <div className="parameter-details">
                  <h4 className="parameter-title">{title}</h4>
                  <p className="parameter-description">{description}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Info;