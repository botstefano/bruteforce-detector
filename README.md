# Centinela — Brute Force Detector & Mitigation Platform

Adaptive rule-based and machine-learning brute force attack detector and mitigation microservice with a modern React + Tailwind CSS dashboard and live attack simulator.

## Features

- **Real-Time WAF & Machine Learning Ensembles**: Combines heuristic rules with Isolation Forest, One-Class SVM, and Local Outlier Factor anomaly detection.
- **Interactive React Dashboard**: Live event stream via Socket.io, active blocked IPs management, and system metrics.
- **Live Attack Simulator & Bot Runner**: Launch fast bursts, low-and-slow stealth attacks, and distributed botnets against demo login endpoints.
- **Scientific Reports & Export**: Detailed precision, recall, F1-score, FP, FN, VP, VN metrics with CSV, JSON, Markdown, and LaTeX export capabilities.
- **Demo Logins Showcase**: Compare secure Centinela protection against vulnerable logins, CAPTCHA anti-bot challenges, and 2FA / TOTP authentication.

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start development server (Express backend + Vite React dev middleware):
   ```bash
   npm run dev
   ```

3. Build for production:
   ```bash
   npm run build
   npm start
   ```
