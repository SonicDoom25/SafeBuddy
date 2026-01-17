# 🛡️ SafeBuddy  
### Your companion for safer links

SafeBuddy is a human-centric web application that helps users quickly check whether a URL is safe or unsafe.  
Unlike traditional link checkers, SafeBuddy not only detects potential threats but also clearly explains *why* a link may be risky, helping users make informed and confident browsing decisions.

---

## 🚨 Problem Statement

People receive unknown or suspicious links every day through WhatsApp, email, SMS, and social media.  
These links may lead to phishing scams, malware downloads, fake login pages, or harmful redirects.  
Most users cannot easily identify whether a link is safe, putting their data, money, and privacy at risk.

There is a need for a simple and reliable tool that:
- Quickly checks any URL
- Clearly indicates whether it is safe or unsafe
- Explains the reason for the risk in easy-to-understand language

---

## 💡 Solution Overview

SafeBuddy provides a fast and easy way to analyze any URL.  
Users simply paste a link, and the system evaluates it using trusted threat intelligence signals such as phishing patterns, blacklist data, suspicious redirects, certificate issues, and domain reputation.

The result is displayed clearly as **Safe** or **Unsafe**.  
If a link is unsafe, SafeBuddy explains the exact reason—such as phishing, malware, expired domains, or risky redirects—using simple wording and visual cues.

---

## ✨ Key Features

- 🔍 Check any URL to determine if it is safe or unsafe  
- 🧠 Clear explanation of why a link is unsafe (phishing, malware, redirects, etc.)  
- 🎯 Human-centric, user-friendly interface  
- ⚡ Instant results with simple, readable output  
- 🔗 Supports both normal and shortened URLs  
- 🧭 Helps users make informed decisions before clicking links  

---

## 🌟 What Makes SafeBuddy Different?

Most existing link checkers only provide a binary result (safe/unsafe) or use technical jargon.  
SafeBuddy focuses on **explainable security** by:

- Explaining *what the risk is* and *why it matters*
- Avoiding fear-based or technical warnings
- Designing the UI for non-technical users

This reduces human error and improves real-world online safety.

---

## 🏗️ High-Level Architecture

SafeBuddy follows a layered architecture:

1. **User & Browser Layer** – Users interact via a web browser  
2. **Trust UI (Frontend)** – Displays Safe / Unsafe results and explanations  
3. **Frontend Logic Layer** – Converts threat data into human-readable reasons  
4. **Backend Adapter Layer** – Handles communication with threat intelligence services  
5. **External Threat Intelligence** – Provides phishing and malware detection data  

The system separates threat detection from user explanation, keeping the interface calm and understandable.

---

## 🔮 Future Enhancements

- 🌐 Chrome browser extension for real-time link checking  
- 📧 Automatic scanning of links in emails and messages  
- 🚨 Alerts for newly discovered phishing or malware sites  
- 📱 Mobile application for faster access  
- 👤 User accounts to track previously scanned links  
- 📊 Risk severity levels (Low, Medium, High, Critical)  

---

## 🧑‍🤝‍🧑 Target Users

- Students and general internet users  
- Non-technical users  
- Anyone who receives unknown links and wants to browse safely  

---

## 🏁 Conclusion

SafeBuddy is designed to protect **people**, not just systems.  
By combining trusted threat detection with clear, human-friendly explanations, it helps users stay informed, avoid scams, and browse the internet more safely.

---

## 📌 Project Status

This project is currently under active development as part of **Hyphen 2026** and focuses on a functional, UI-driven prototype.

---

