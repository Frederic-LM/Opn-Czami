The application expects a standard **CSV** (Comma-Separated Values) or **Excel (`.xlsx`)** file with the following strict characteristics:

1.  **No Header Row:** The file must **not** contain a header row like "File Path" or "Summary". The data must start on the very first line. The code explicitly reads the file assuming there are no headers (`header=None`).

2.  **Two Columns:** Each row must contain exactly two columns of data.
    *   **Column 1:** The file path to the proof image.
    *   **Column 2:** The summary text for the certificate.

3.  **Relative Image Paths:** This is the most critical part. The file paths in the first column **must be relative** to a "base folder" that you will be prompted to select when you click the "Load Data File..." button.
    *   **Security:** You cannot use absolute paths (like `C:\Users\YourName\Documents\image.jpg`) or paths that try to go "up" the directory tree (like `..\..\some_other_folder\image.jpg`). This is a security feature to prevent the application from accessing unintended files.

---

### How the Process Works in the Application

1.  You click **"📂 Load Data File..."**.
2.  A dialog box appears asking you to **"Select the Base Folder Containing Your Proof Images"**. This is the parent folder for all the images listed in your CSV/XLSX file.
3.  After selecting the base folder, another dialog appears asking you to **select your `.csv` or `.xlsx` file**.
4.  The application then reads your data file and combines the "base folder" path with the "relative path" from your file to find each image.

---

### Example Directory Structure

Imagine you have organized your files like this on your computer:

```
C:\Work\Violin_Certificates\
│
├── Batch-Job-May.xlsx
│
├── stradivarius-1715\
│   ├── front.jpg
│   ├── back.jpg
│   └── scroll.png
│
└── guarneri-1741\
    ├── front.jpg
    └── details.jpg
```

In this scenario, your **Base Folder** would be `C:\Work\Violin_Certificates\`. The paths inside your `.xlsx` or `.csv` file would be relative to this folder.

---

### Sample CSV File

Create a file named `batch_data.csv` with the following content. Remember, no header row.

**`batch_data.csv`**
```csv
stradivarius-1715/front.jpg,"Certificate of authenticity for the 'Titian' Stradivarius violin, dated 1715. Instrument is in excellent condition and authentic in all its major parts. Examined on May 20, 2025."
stradivarius-1715/back.jpg,"Detail shot of the one-piece back of the 'Titian' Stradivarius, showing the flame and varnish characteristics."
guarneri-1741/front.jpg,"Valuation for the 'Vieuxtemps' Guarneri 'del Gesù' violin, 1741. Current market valuation: $16,000,000 USD."
```

**Analysis of the CSV:**
*   **Line 1:** The path `stradivarius-1715/front.jpg` will be correctly combined with your selected base folder. The summary is enclosed in double quotes because it contains a comma.
*   **Line 2:** Shows a path to a different image within the same sub-folder.
*   **Line 3:** Points to a file in a completely different sub-folder (`guarneri-1741`).

### Sample Excel (`.xlsx`) File

If you prefer using Excel, the structure is just as simple.

1.  Open a new blank workbook in Microsoft Excel, Google Sheets, or LibreOffice Calc.
2.  In cell **A1**, enter the first relative path.
3.  In cell **B1**, enter the corresponding summary.
4.  Continue filling rows for each document you want to process.
5.  Save the file as an `.xlsx` file (e.g., `batch_data.xlsx`).

Here is what your Excel sheet should look like:

| | A | B |
| :--- | :--- | :--- |
| **1** | `stradivarius-1715/front.jpg` | `Certificate of authenticity for the 'Titian' Stradivarius violin...` |
| **2** | `stradivarius-1715/back.jpg` | `Detail shot of the one-piece back of the 'Titian' Stradivarius...` |
| **3** | `guarneri-1741/front.jpg` | `Valuation for the 'Vieuxtemps' Guarneri 'del Gesù' violin, 1741...` |

**Important Note on Summaries:** The summary text is limited to **400 characters**. The application will flag any summary longer than this as an error during the loading phase.
