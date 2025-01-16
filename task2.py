import time
import random
import re
import math
import mmh3
import json

class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z
        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)
        return E

def load_log_file(file_path):
    ip_addresses = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            try:
                log_entry = json.loads(line.strip())
                ip = log_entry.get("remote_addr")
                if ip:
                    ip_addresses.append(ip)
            except json.JSONDecodeError:
                continue 
    return ip_addresses


def exact_unique_count(ip_addresses):
    start_time = time.time()
    unique_ips = set(ip_addresses)
    execution_time = time.time() - start_time
    return len(unique_ips), execution_time

def hyperloglog_unique_count(ip_addresses, precision=14):
    hll = HyperLogLog(p=precision)
    start_time = time.time()
    for ip in ip_addresses:
        hll.add(ip)
    execution_time = time.time() - start_time
    return hll.count(), execution_time

if __name__ == "__main__":
    file_path = "lms-stage-access.log"
    ip_addresses = load_log_file(file_path)

    exact_count, exact_time = exact_unique_count(ip_addresses)
    hll_count, hll_time = hyperloglog_unique_count(ip_addresses, precision=14)

    print("Результати порівняння:")
    print(f"{'':<25}{'Точний підрахунок':<25}{'HyperLogLog':<25}")
    print(f"{'Унікальні елементи':<25}{exact_count:<25}{hll_count:<25}")
    print(f"{'Час виконання (сек.)':<25}{exact_time:<25.2f}{hll_time:<25.2f}")
