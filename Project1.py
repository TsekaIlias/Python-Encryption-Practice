import hashlib
import math
import os
import secrets
import pyotp # type: ignore

#pip install pyotp - για 2FA


secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)


def check_2fa():
    current_otp = totp.now()
    print(f"\n[SYSTEM] Το OTP σας είναι: {current_otp}")

    user_in = input("Εισάγετε το 6-ψήφιο OTP για συνέχεια: ")

    if totp.verify(user_in):
        print("Επιτυχία: Η πρόσβαση επιτράπηκε.")
        return True
    else:
        print("Σφάλμα: Η πρόσβαση απορρίφθηκε. Λάθος OTP.")
        return False


def do_hash():
    fname = input("Εισάγετε το όνομα του αρχείου για hash: ")
    try:
        with open(fname, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("Το αρχείο δεν βρέθηκε.")
        return

    s = os.urandom(16)
    data_with_salt = s + file_data

    print("\nΔιαθέσιμοι Αλγόριθμοι:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256")
    print("4. SHA-3 (Keccak)")
    print("5. Όλοι")

    c = input("Επιλέξτε αλγόριθμο (1-5): ")
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
        print("Μη έγκυρη επιλογή.")
        return

    hash_file = f"{fname}.hash"
    with open(hash_file, "w") as out_f:
        for a in my_algos:
            h = hashlib.new(a)
            h.update(data_with_salt)
            res = h.hexdigest()
            print(f"{a.upper()} Hash: {res}")
            out_f.write(f"{a}:{s.hex()}:{res}\n")

    print(f"Τα hashes και το salt αποθηκεύτηκαν στο {hash_file}")


def check_file():
    print("\n--- Κρίσιμη Ενέργεια: Απαιτείται 2FA ---")
    if not check_2fa():
        return

    fname = input("Εισάγετε το όνομα του αρχείου για έλεγχο: ")
    hash_file = f"{fname}.hash"

    try:
        with open(fname, "rb") as f:
            file_data = f.read()
        with open(hash_file, "r") as in_f:
            lines = in_f.readlines()
    except FileNotFoundError:
        print("Το αρχικό αρχείο ή το αρχείο hash δεν βρέθηκε.")
        return

    is_ok = True

    for line in lines:
        if not line.strip():
            continue

        parts = line.strip().split(":")
        if len(parts) != 3:
            continue

        a = parts[0]
        saved_s = bytes.fromhex(parts[1])
        saved_h = parts[2]

        test_data = saved_s + file_data
        h = hashlib.new(a)
        h.update(test_data)
        new_h = h.hexdigest()

        if new_h != saved_h:
            is_ok = False
            break

    if is_ok:
        print("\nΤο αρχείο δεν έχει τροποποιηθεί")
    else:
        print("\nΤο αρχείο έχει αλλοιωθεί")


def get_entropy():
    fname = input("Εισάγετε το όνομα του αρχείου για ανάλυση: ")
    try:
        with open(fname, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("Το αρχείο δεν βρέθηκε.")
        return

    if not file_data:
        print("Το αρχείο είναι κενό. Η εντροπία είναι 0.")
        return

    total = len(file_data)
    counts = {}

    for b in file_data:
        counts[b] = counts.get(b, 0) + 1

    ent = 0.0
    for count in counts.values():
        prob = count / total
        ent -= prob * math.log2(prob)

    print(f"\nShannon Εντροπία: {ent:.3f}")


def main():
    while True:
        print("\n--- Μενού Επιλογών ---")
        print("1. Υπολογισμός Hash")
        print("2. Έλεγχος Ακεραιότητας")
        print("3. Υπολογισμός Εντροπίας")
        print("4. 2FA Authentication")
        print("5. Έξοδος")

        c = input("Επιλέξτε μια λειτουργία (1-5): ")

        if c == "1":
            do_hash()
        elif c == "2":
            check_file()
        elif c == "3":
            get_entropy()
        elif c == "4":
            check_2fa()
        elif c == "5":
            print("Έξοδος από το πρόγραμμα...")
            break
        else:
            print("Μη έγκυρη επιλογή. Παρακαλώ δοκιμάστε ξανά.")


if __name__ == "__main__":
    main()
