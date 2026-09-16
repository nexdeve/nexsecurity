<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0a0a,100:ef4444&height=160&section=header&text=NexSecurity&fontSize=44&fontColor=ffffff&animation=fadeIn&fontAlignY=44&desc=Comprehensive%20security%20toolkit%20—%20XSS,%20CSRF,%20SQLi%20p&descAlignY=64&descColor=e2e8f0" />

[![Category](https://img.shields.io/badge/Security-ef4444?style=for-the-badge)](https://github.com/nexdeve/nexsecurity)
[![License](https://img.shields.io/badge/License-Apache_2.0-6366f1?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Author](https://img.shields.io/badge/By-NexDeve-076AF4?style=for-the-badge)](https://nexdeve.com)
[![Status](https://img.shields.io/badge/Status-Active-10b981?style=for-the-badge)](https://github.com/nexdeve/nexsecurity)

**Comprehensive security toolkit — XSS, CSRF, SQLi protection and secure headers**

By [nexdeve.com](https://nexdeve.com) · [Telegram](https://t.me/+c34_uTIBJEpkZGM9)

</div>

---

## Overview

> Comprehensive security toolkit — XSS, CSRF, SQLi protection and secure headers. Part of the **NexDeve** open-source ecosystem — professional-grade tools built for real-world production use.

**Category:** Security
**Tech stack:** TypeScript, Node.js, helmet, csurf, DOMPurify

---

## Installation

```bash
npm install @nexdeve/nexsecurity
```

---

## Quick Start

```typescript
import { NexSecurity } from '@nexdeve/nexsecurity';
import express from 'express';

const app = express();
const sec = new NexSecurity();

// Apply all security middlewares at once
app.use(sec.middleware({
  rateLimit:   { windowMs: 15 * 60 * 1000, max: 100 },
  cors:        { origin: ['https://nexdeve.com'] },
  headers:     true,   // CSP, HSTS, X-Frame-Options
  xss:         true,   // sanitize all inputs
  csrf:        true,   // CSRF token validation
  sqlInjection: true,  // block SQLi patterns
}));

// Sanitize user input
const clean = sec.sanitize(userInput);

// Hash password
const hash = await sec.hashPassword(plaintext);
const valid = await sec.verifyPassword(plaintext, hash);
```

---

## API Reference

| Method | Description |
|--------|-------------|
| `sec.middleware(config)` | Apply all protections at once |
| `sec.sanitize(input)` | XSS sanitize user input |
| `sec.hashPassword(plain)` | bcrypt/argon2 password hash |
| `sec.verifyPassword(plain, hash)` | Verify hashed password |
| `sec.generateCSRF()` | Generate CSRF token |
| `sec.scanSQL(input)` | Detect SQL injection patterns |
| `sec.validateJWT(token, secret)` | Verify JWT with strict checks |
| `sec.encryptData(data, key)` | AES-256-GCM encrypt |

---

## Features

- Production-ready, battle-tested codebase
- Full TypeScript / type-safe API
- Comprehensive error handling
- Docker & CI/CD ready
- Well-documented with examples
- Actively maintained by [NexDeve](https://nexdeve.com)

---

## Part of NexDeve Ecosystem

Explore all 75+ open-source tools at [github.com/nexdeve](https://github.com/nexdeve)

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:ef4444,100:0f0a0a&height=80&section=footer" />

Made with ❤️ by [**NexDeve**](https://nexdeve.com) · [nexdeve.com](https://nexdeve.com) · [Telegram](https://t.me/+c34_uTIBJEpkZGM9)

</div>
