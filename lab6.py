import math
import random

def is_prime(n: int) -> bool:
    """Перевіряє, чи є число простим."""
    if n < 2:
        return False
    for i in range(2, math.isqrt(n) + 1):
        if n % i == 0:
            return False
    return True

def generate_4digit_prime() -> int:
    """Генерує випадкове 4-значне просте число."""
    while True:
        p = random.randint(1000, 9999)
        if is_prime(p):
            return p

def get_prime_factors(n: int) -> set[int]:
    """Знаходить усі прості дільники числа n."""
    factors = set()
    d = 2
    temp = n
    while d * d <= temp:
        if temp % d == 0:
            factors.add(d)
            while temp % d == 0:
                temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)
    return factors

def find_primitive_root(p: int) -> int:
    """
    Знаходить первісний корінь g (a) за модулем p.
    За малою теоремою Ферма та властивостями груп, g є первісним коренем,
    якщо для кожного простого дільника q числа (p - 1):
    g^((p-1)/q) != 1 (mod p).
    """
    phi = p - 1
    factors = get_prime_factors(phi)

    for g in range(2, p):
        is_root = True
        for q in factors:
            if pow(g, phi // q, p) == 1:
                is_root = False
                break
        if is_root:
            return g
    return -1


def main():
    print("Алгоритм обміну ключами Діффі-Геллмана")

    p = generate_4digit_prime()
    print(f"\n1. Обрано 4-значне просте число p = {p}")

    a = find_primitive_root(p)
    print(f"2. Знайдено первісний корінь a = {a} (за модулем {p})")

    xA = random.randint(2, p - 2)
    xB = random.randint(2, p - 2)

    print(f"\n3. Секретний ключ Аліси (xA) = {xA}")
    print(f"   Секретний ключ Боба (xB)   = {xB}")

    yA = pow(a, xA, p)
    yB = pow(a, xB, p)

    print(f"\n   Відкритий ключ Аліси (yA = a^xA mod p) = {yA}")
    print(f"   Відкритий ключ Боба   (yB = a^xB mod p) = {yB}")

    k = pow(yB, xA, p)
    k_prime = pow(yA, xB, p)

    print(f"\n4. Спільний ключ, обчислений Алісою (k)  = {k}")
    print(f"   Спільний ключ, обчислений Бобом   (k') = {k_prime}")

    # Перевірка рівності
    if k == k_prime:
        print("\n[РЕЗУЛЬТАТ] k == k'. Ключі успішно узгоджено!")
    else:
        print("\n[ПОМИЛКА] Ключі не збігаються!")

if __name__ == "__main__":
    main()