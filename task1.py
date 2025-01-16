import hashlib
import math
import mmh3

class BloomFilter:
    def __init__(self, size, num_hashes):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    def add(self, item):
        for i in range(self.num_hashes):
            index = mmh3.hash(item, i) % self.size
            self.bit_array[index] = 1

    def contains(self, item):
        for i in range(self.num_hashes):
            index = mmh3.hash(item, i) % self.size
            if self.bit_array[index] == 0:
                return False
        return True
    
def check_password_uniqueness(bloom_filter, passwords):
    results = {}
    for password in passwords:
        if not isinstance(password, str) or not password.strip():
            results[password] = "Некоректне значення"
            continue
        if bloom_filter.contains(password):
            results[password] = "вже використаний"
        else:
            bloom_filter.add(password)
            results[password] = "унікальний"
    return results


if __name__ == "__main__":
    bloom = BloomFilter(size=1000, num_hashes=3)
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest", None, " "]
    results = check_password_uniqueness(bloom, new_passwords_to_check)
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")
