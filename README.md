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


## ⚙️ Extra Pro Tools: (🧩 Paid License yet still open source)

You're managing high-volume operations or need legal-grade evidence, entreprise log? I've got you covered.

### Annual License Tools (à la carte)
- 🧾 **Batch Signing** — Sign hundreds of certificates in minutes.
- ⛓️ **Tamper-Evident Audit Trail**: When enabled, the application maintains a cryptographically chained log of every signing and upload event. Similar to a blockchain, any attempt to tamper with the log is immediately detectable.
- 🖋️ **Watermarking Tool** — Add your brand or logo automatically to images
- 🤝 Priority Support — Get direct technical assistance when you need it most.


## 🎨 Need help with design, branding, or workflow setup?

   Need help with your logo, certificate layout, or integration process? You can hire me to streamline and style your setup.
 

## 🖥️ Download & Install Op'n Czami

### 🪟 For Windows Users

You can install **Op'n Czami** on Windows using the official installer:

➡️ [Download for Windows (.exe)](https://github.com/Frederic-LM/Opn-Czami/releases/download/RC2/Setup-OpnCzame.exe)

1. Download the file.
2. Double-click the `.exe` to launch the installer.
3. Follow the on-screen instructions.

✅ Free to use — no registration required.

---

### 🍎 For macOS Users (Apple Silicon)
❗macOS Build Notice:
Due to performance issues caused by Apple's handling of Python GUI apps, I’ve decided to stop officially supporting the macOS build.
You can still build it yourself from the source but I remove the pre compiled .dmg and  I recommend running the Windows version via an emulator (like UTM or Parallels) for a smoother experience.

➡️ [Download for macOS (.dmg)](https://github.com/Frederic-LM/Opn-Czami/releases/download/MacOSDmg/opnczami.dmg)
1. Download the `.dmg` file.
2. Open it and drag **Op'n Czami** into your Applications folder.
3. If you see a security warning, right-click the app and choose **Open** to allow it.

🧠 *Tested on Apple Silicon (M1/M2/M3M4).* 
You can download and run the macOS version, but be aware that it may feel sluggish or awkward to use. This isn’t a bug — it’s a *“feature”* related to the cult of the fruit (🍎) decided to handles **Tcl/Tk GUI applications written in Python**.
Specifically, macOS enforces **Force Click** behavior on the trackpad, which can require a hard press for clicks to register properly. This affects interaction with the app’s interface.

### Workaround Tips:
- **Disable Force Click** in your Trackpad settings (System Settings > Trackpad > Point & Click).
- Use the **Tab key** to navigate quickly through interface elements.
It's unfortunate, as the app runs fast and smoothly on macOS — if only it didn’t force users to long-press to click. Hopefully, this behavior will improve with future updates to macOS or the Tcl/Tk libraries.

🔒 Notarization: App may require permissions due to macOS Gatekeeper.

---

If you run into any issues during installation, feel free to open an issue on the [GitHub Issues page](https://github.com/Frederic-LM/Opn-Czami/issues).



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


