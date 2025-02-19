"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

export default function OAuthCallback() {
  const searchParams = useSearchParams();
  const code = searchParams.get("code");
  const [message, setMessage] = useState("Processing authentication...");

  useEffect(() => {
    if (code) {
      setMessage("Authorization Code Received: " + code);
      
      // שלח את הקוד לשרת שלך (אם יש לך API לטיפול באימות)
      fetch("/api/github-auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      })
        .then((res) => res.json())
        .then((data) => {
          if (data.access_token) {
            setMessage("✅ Authentication successful! You are logged in.");
            // כאן תוכל לשמור את ה-Access Token ב-LocalStorage או להפנות את המשתמש
          } else {
            setMessage("❌ Authentication failed. Please try again.");
          }
        })
        .catch(() => setMessage("❌ Error communicating with server."));
    } else {
      setMessage("❌ No authorization code found. Please log in again.");
    }
  }, [code]);

  return (
    <div style={{ textAlign: "center", marginTop: "50px" }}>
      <h2>GitHub OAuth Callback</h2>
      <p>{message}</p>
    </div>
  );
}
