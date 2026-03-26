**Project1.py - Systems Security Toolkit**
=

Description:
This is a Python command-line application that provides a set of security tools. It includes file hashing with salting, file integrity verification, Shannon entropy calculation, and a Two-Factor Authentication (2FA) module. It features an interactive Greek-language menu for easy navigation.

Prerequisites:
Before running the script, you must install the pyotp library, which is required for the 2FA functionality. You can install it via your terminal:
pip install pyotp

Features & Menu Options:
---
1. Hash Calculation (Υπολογισμός Hash):
- Reads a user-specified file in binary mode.
- Generates a random 16-byte salt and combines it with the file data.
- Calculates the hash using one or all of the following algorithms: MD5, SHA-1, SHA-256, SHA-3 (Keccak).
- Saves the algorithm name, the hex-encoded salt, and the final hash into a new <filename>.hash file.

---
2. Integrity Check (Έλεγχος Ακεραιότητας):
- Security Gateway: Prompts the user to pass a 2FA check before proceeding.
- Reads the original file and the associated .hash file.
- Recalculates the hash using the stored salt and compares it to the saved hash.
- Alerts the user if the file is untouched or if it has been altered/corrupted.
---
3. Entropy Calculation (Υπολογισμός Εντροπίας):
- Reads a file in binary mode and counts the frequency of each byte (0-255).
- Calculates the file's randomness using the Shannon Entropy formula.
- Outputs a score from 0.0 to 8.0. (Encrypted or highly compressed files will score close to 8.0, while plain text files will score much lower).
---
4. 2FA Authentication:
- Generates a Time-Based One-Time Password (TOTP) using a secure Base32 secret key.
- Displays the current 6-digit OTP to the console and asks the user to input it for verification.
---
5. Exit (Έξοδος):
- Closes the application.

How to Run:
---
Open your terminal or command prompt, navigate to the folder containing the file, and run:
python Project1.py

Files:
---
All the .txt file I provided in the repository are my sample txt files and their hash version which I applied all of the algorythms, you are free to use a new .txt if you desire
