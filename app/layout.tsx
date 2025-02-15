// /app/layout.tsx

import React from 'react';
import './globals.css'; // Add global styles

interface LayoutProps {
  children: React.ReactNode; // This represents the content passed into the layout
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <html lang="en">
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Secure Code Checker</title>
      </head>
      <body>
        <header>
          <h1>Secure Code Checker</h1>
        </header>
        <main>{children}</main> {/* Render content passed into this layout */}
        <footer>
          <p></p>
        </footer>
      </body>
    </html>
  );
};

export default Layout;
