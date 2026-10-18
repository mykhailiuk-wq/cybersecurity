import math
import hashlib

def is_prime(n: int) -> bool:
    """Перевіряє, чи є число простим."""
    if n < 2:
        return False
    for i in range(2, int(math.isqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def mod_inverse(e: int, phi: int) -> int:
    """Обчислює мультиплікативне обернене значення e mod phi (d = e^-1 mod phi)."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("e та phi повинні бути взаємно простими!")
    return x % phi

def generate_keypair(p: int, q: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Генерує пару ключів (Public Key, Private Key) на основі двох простих чисел p та q."""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Обидва числа p та q повинні бути простими!")
    elif p == q:
        raise ValueError("p та q не повинні бути однаковими!")

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if e >= phi or math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)

    return ((e, n), (d, n))

def hash_message(message: str) -> int:
    """Обчислює хеш-значення повідомлення за допомогою SHA-256 та повертає його як число."""
    digest = hashlib.sha256(message.encode('utf-8')).hexdigest()
    return int(digest, 16)

def sign_message(message: str, private_key: tuple[int, int]) -> int:
    """
    Створює цифровий підпис повідомлення за допомогою закритого ключа.
    S = (H(M) % n)^d mod n
    """
    d, n = private_key
    m_hash = hash_message(message) % n
    signature = pow(m_hash, d, n)
    return signature

def verify_signature(message: str, signature: int, public_key: tuple[int, int]) -> bool:
    """
    Перевіряє чинність цифрового підпису за допомогою відкритого ключа.
    H' = S^e mod n
    """
    e, n = public_key
    m_hash = hash_message(message) % n
    decrypted_hash = pow(signature, e, n)
    return m_hash == decrypted_hash


def main():
    print("=== Криптографічна система цифрового підпису RSA ===")
    p = 61
    q = 53
    print(f"\n1. Генерація ключів з простих чисел p={p}, q={q}...")
    
    public_key, private_key = generate_keypair(p, q)
    print(f"   Відкритий ключ (Public Key)  [e, n]: {public_key}")
    print(f"   Закритий ключ  (Private Key) [d, n]: {private_key}")

    message = input("\n2. Введіть повідомлення для підписання: ")

    signature = sign_message(message, private_key)
    print(f"\n3. Цифровий підпис (числове значення S): {signature}")

    print("\n4. Перевірка підпису для оригінального повідомлення...")
    is_valid = verify_signature(message, signature, public_key)
    if is_valid:
        print("   [УСПІХ] Підпис ВІРНИЙ! Повідомлення цілісне та автентичне.")
    else:
        print("   [ПОМИЛКА] Підпис НЕВІРНИЙ!")

    print("\n5. Симуляція модифікації (підробки) тексту...")
    tampered_message = message + "!"
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print(f"   Перевірка тексту '{tampered_message}':")
    if is_valid_tampered:
        print("   [УСПІХ] Підпис ВІРНИЙ!")
    else:
        print("   [УВАГА] Підпис НЕВІРНИЙ! Текст було змінено після підписання.")

if __name__ == "__main__":
    main()