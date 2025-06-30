#  **Legato-Key: Modern & Tamper-Proof Certification**

**Legato Key** is a modern system designed to help you issue **tamper-proof, cryptographically signed digital documents** without abandoning the physical format.
It isn't a corporate product—it was crafted by a luthier with a computer science background whose every design choice reflects real-world instrument appraisal needs.

## 🌿 The Legato Key Ecosystem is composed of:
- **📱 The Legato Key App**: A free, client-side verification app.
- **🧾 Op'n Czami**: An open-source authority dashboard to generate and sign certificates.

## Why Use Legato Key?

Traditional paper certificates or valuations can be lost, damaged, forged, or even digitally manipulated.
In the world of fine instruments, where trust and provenance are fundamental, that's a real risk and liability. 

Legato Key solves this by issuing **linked physical + digital certificates**:

- ✅ A physical certificate to hold.
- ✅ Tamper-proof digital certificates anyone can verify online.
- ✅ Proof your signature hasn't been altered or faked.

### 🔐 How It Works

Legato Key binds physical and digital worlds with cryptographic signatures:

✅ **Tamper-proof digital certificates**  
🔗 **Cryptographically Bound** — Ties the printed document and its digital counterpart.  
🌍 **Verifiable by Anyone** — Online, instantly, without needing to contact you.  
🖼️ **Image + Text Protected** — Covers visual and written content alike.  
🔓 **No Vendor Lock-in** — You stay independent, with no forced subscriptions.  

---

# 🖥️ Op'n Cezami — The Authority Dashboard 
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)
![Open Source](https://img.shields.io/badge/Open%20Source-✔-brightgreen)
![Status](https://img.shields.io/badge/status-RC2-orange.svg)

Op'n Cezami is a professional-grade, open-source signing tool for creating **verifiable digital certificates** backed by strong cryptography.

## 🧠 Transparent by Design
> ❗ Follows a **self-sovereign** and **open** model — you're in control.
> *"Don't Trust — Verify."*

Op'n Czami is **fully open source**. This means:

✅ **Auditability** — Anyone can inspect the code.  
🔓 **Freedom** — No corporate control.  
🤝 **Community-Driven** — Anyone can create a compatible app or variant.  
🕰️ **Longevity + Interoperability** — Built to last.

## 💼 Core Features (Always Free)

- Create cryptographically signed digital certificates.
- Use the Legato Key QR system.
- Modify and share (LGPL license).
- Use personally or commercially.

**No fees, no subscriptions. Just freedom.**


## ⚙️ Optional Pro Tools (🧩 Paid License yet still open source)

If you're managing high-volume operations or need legal-grade evidence, I've got you covered.

### Annual License Tools (à la carte)
- 🧾 **Batch Signing** — Sign hundreds of certificates in minutes.
- ⛓️ **Tamper-Evident Audit Trail**: When enabled, the application maintains a cryptographically chained log of every signing and upload event. Similar to a blockchain, any attempt to tamper with the log is immediately detectable.
- 🖋️ **Watermarking Tool** — Add your brand or logo automatically.

## Need Help With Your Logo or Organizing Your Workflow?
You can hire me for consulting services.

---

# 📱 Legato Phone App 

Also free, available on Android, and possibly on iPhone. (curently under developement)

---

# Technical Details 
    
## 📁 File Structure Overview
| File/Folder             | Purpose                                         |
| ----------------------- | ----------------------------------------------- |
| `OpnCzami`              | Main app                                        |
| `opn_czami_settings`    | App config file                                 |
| `abracadabra-*.key`     | 🔑 Your private signing key (**BACK THIS UP!**) |
| `my-legato-link.json`   | Public identity info                            |
| `my-legato-link-logo.*` | Your uploaded logo                              |
| `Audit-Trail-*.log`     | Tamper-evident activity log                     |
| `/Signed_Legato_Keys/`  | Output QR codes                                 |
| `/Signed_Proofs/`       | Final images with watermarks                    |

---

# FAQ

❓ **"Is it compatible with the system you designed 14 years ago for a renowned bow expert?"**

No.
Legato-Key was built from the ground up with a completely different philosophy:

| Old Design                  | Legato                                      |
| --------------------------- | ------------------------------------------- |
| Proprietary & Closed Source | Open standard & Open source                |
| Manual Human Check          | Automated via cascaded cryptographic checks|
| QR used solely as a link    | QR = cryptographic signature               |
| Centralized infrastructure  | Self-sovereign, open, and offline-capable  |
| Single point of failure     | Resilient to single point of failure       |
| Online only                 | Online with offline fallback               |

Anyone can verify a Legato Key certificate independently—with no account, no server, no company involved.
