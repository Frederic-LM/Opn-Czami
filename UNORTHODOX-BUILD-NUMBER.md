# UNORTHODOX-BUILD-NUMBER.md

## Versioning & Build Numbers

This document explains the **custom build numbering scheme** used in this project.
The versioning here diverged (quite unintentionally) from standard semantic versioning.
it’s a bit particular but there’s a logic to it, and this document aims to capture that logic.

---

### **Initial Commit   Op’n Czami V0 / V1 (up to v4.4.2 “Cadense”)**

These were the **monolithic builds**.

So all calls were implicit, and the structure worked elegantly as a single cohesive unit. It was stable, and performed well (on windows).

---

### **Op’n Czami V2 (up to 2.3.0)**

V2 introduced a **non–retro-compatible rebuild** featuring a complete overhaul of the cryptographic algorithms and the introduction of the **Legato Key** system.
Internally, this was referred to as *Legato Key v2*, which later evolved into the public **Legato Key v1 (LKey)** release.

I initially kept going on my monolithic design in build `2.0.0`,
but soon transitioned toward **partial modularity**, introducing clearer submodels and separated logic layers.
This stage marked the start of moving away from an “all-in-one” structure toward a model-oriented design.

---

### **Op’n Czami (UI-Agnostic) V1 & V2  Not Released**

These versions represented an **experimental attempt to make the V2 run properly on macOS**.
They were never published, because during the process, I discovered the real underlying issue:
on macOS, **Tkinter only behaves correctly when the UI and core logic are fully separated**.

The goal here was to make the app **UI-agnostic**, allowing different interfaces to connect to the same logical core.
This led to a deep architectural refactor splitting the code into:

* **Tkinter GUI** (for PC)
* **PyQt GUI** (native on macOS)
* **Core Logic** (shared between both)

The Tkinter separation worked flawlessly.
PyQt, while smooth, was painful to integrate and about just one-third functional as the communication layer between UI and logic was Hellish to implement

Then, during debugging, I semi-accidentally (read: out of contempt fixing PyQT) launched the *separated* Tkinter UI on macOS instead of PyQt and, surprisingly it worked almost perfectly (with the exception of drag-and-drop tab).
The path was clear: **Tkinter could run cross-platform after proper separation of concerns**, I could drop the PyQt GUI dev.
So that to **V3**.

---

### **Op’n Czami V3**

V3 marks the **complete dismantling of the monolithic Tkinter GUI** and a full **separation of concerns** between interface and logic.
This version runs fluently on both macOS and Windows without compromise. 

---

### **Op’n Czami V4 aka is it Penelope's spiral, or Ulysse's return**
V4 is essensialy applying the dismantling of teh gui to the logic, for the pain of it. I could not bare to see my slim controler getting so fat, work was a lot harder than I thougth, creating a Bus, and injecting dependency. Thought i nver get the end of it I hope it paid.
I removed the Interplaneraty file System block chain intergation, because it was too niche too geek and offered to little value at this point in time.
But I incorparted something new and much more fun, a dashbord module that non only remplace the stand alone pyton reader, but also give insight of the system usage and disaplays in a world map. feature is pro pro, but part of the code is open and publish (the part that will be on your server to process the insight)

#### Versioning logic:

* `x` → new feature or structural improvement
* `y` → stable intermediate commit or bug-fix milestone

Example:
`V3.x.y` → a stable, cross-platform build with clear modular separation.






