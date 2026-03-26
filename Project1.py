import hashlib
import math
import os
import secrets
import pyotp # type: ignore

secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)

def check_2fa():
    current_otp = totp.now()
    print(f"\n[SYSTEM] Your OTP is: {current_otp}")

    user_in = input("Enter the 6-digit OTP to continue: ")

    if totp.verify(user_in):
        print("Success: Access granted.")
        return True
    else:
        print("Error: Access denied. Incorrect OTP.")
        return False

def do_hash():
    fname = input("Enter the filename to hash: ")
    try:
        with open(fname, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("File not found.")
        return

    s = os.urandom(16)
    data_with_salt = s + file_data

    print("\nAvailable Algorithms:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256")
    print("4. SHA-3 (Keccak)")
    print("5. All")

    c = input("Select an algorithm (1-5): ")
    my_algos = []
    if c == "1":
        my_algos.append("md5")
    elif c == "2":
        my_algos.append("sha1")
    elif c == "3":
        my_algos.append("sha256")
    elif c == "4":
        my_algos.append("sha3_256")
    elif c == "5":
        my_algos.extend(["md5", "sha1", "sha256", "sha3_256"])
    else:
        print("Invalid selection.")
        return

    hash_file = f"{fname}.hash"
    with open(hash_file, "w") as out_f:
        for a in my_algos:
            h = hashlib.new(a)
            h.update(data_with_salt)
            res = h.hexdigest()
            print(f"{a.upper()} Hash: {res}")
            out_f.write(f"{a}:{s.hex()}:{res}\n")

    print(f"Hashes and salt have been saved to {hash_file}")

def check_file():
    print("\n--- Critical Action: 2FA Required ---")
    if not check_2fa():
        return

    fname = input("Enter the filename to check: ")
    hash_file = f"{fname}.hash"

    try:
        with open(fname, "rb") as f:
            file_data = f.read()
        with open(hash_file, "r") as in_f:
            lines = in_f.readlines()
    except FileNotFoundError:
        print("The original file or the hash file was not found.")
        return

    is_ok = True

    for line in lines:
        if not line.strip():
            continue

        parts = line.strip().split(":")
        if len(parts) != 3:
            continue

        algo = parts[0]
        saved_salt = bytes.fromhex(parts[1])
        saved_hash = parts[2]

        test_data = saved_salt + file_data
        h = hashlib.new(algo)
        h.update(test_data)
        new_hash = h.hexdigest()

        if new_hash != saved_hash:
            is_ok = False
            break

    if is_ok:
        print("\nThe file has not been modified.")
    else:
        print("\nThe file has been altered or corrupted.")

def get_entropy():
    fname = input("Enter the filename for analysis: ")
    try:
        with open(fname, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("File not found.")
        return

    if not file_data:
        print("The file is empty. Entropy is 0.")
        return

    total = len(file_data)
    counts = {}

    for b in file_data:
        counts[b] = counts.get(b, 0) + 1

    ent = 0.0
    for count in counts.values():
        prob = count / total
        ent -= prob * math.log2(prob)

    print(f"\nShannon Entropy: {ent:.3f}")

def main():
    while True:
        print("\n--- Options Menu ---")
        print("1. Calculate Hash")
        print("2. Check Integrity")
        print("3. Calculate Entropy")
        print("4. Test 2FA Authentication")
        print("5. Exit")

        choice = input("Select a function (1-5): ")

        if choice == "1":
            do_hash()
        elif choice == "2":
            check_file()
        elif choice == "3":
            get_entropy()
        elif choice == "4":
            check_2fa()
        elif choice == "5":
            print("Exiting program...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
