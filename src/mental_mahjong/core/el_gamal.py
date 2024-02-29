#!/usr/bin/env python3

from typing import Final, TypeAlias
from Crypto.Util import number


Parameters: TypeAlias = tuple[int, int, int, int, int]
Ciphertext: TypeAlias = tuple[int, int]
Signature: TypeAlias = tuple[int, int]


class ElGamal:
    def __init__(self) -> None:
        """Creates a new instance of `ElGamal`.

        Initializes the parameters for the ElGamal cryptosystem.
        """
        self._L: Final = 3072
        self._N: Final = 256
        self._p: Final = 0xC26736C062B2B52B84BB3E353BEE05E505A6FADBA8849268B5AA6C1DA9003119DFBF206D46AE7828C9D92CA7B31F56CD74F3A5C35E660A9DD2B3A2C7B87FDD2C45EBEC9C10C55080A40D647006C866AA01634E25C92F4FCD7798CF14B6CEBF9E7E3FB73AFCE54DFC9D953643F5D59A5A57F54CFB65FD2F17E03ABB202A773F8ACA090F759F33CE11CEBA90B5F1BB72531CE9E33A672CB0C733B09D30DC9E3DBE1A2956695C43ED7BCE03064007D84F0B2DD071596F905D4C9936EABAC882CF163CE2084C0A40AD629D9D678120EB4943E37810FBD21DCBEA54982FD89575D99B972996A27561A8FD522769F9E75E14F05CD1E89B57A0EFC08EDBA8328855512E8FF9F843DC30DCDC9101413DEA360CE60EBC6DBB730843C4FE5307C723CC047B127655F0FCBB44869E4B79A828FE4AA4F224F00DC41F3A9A11DF293395C2185196C77A0C6EAF0643DFAFC1183312734758EE57787B73E7834C94E005EB7BB634D588B209688071147B1B0244F3AE36409D5E9C23EB0ED18CDEDBD738480FA935
        assert 2 ** (self._L - 1) <= self._p
        assert self._p < 2**self._L
        assert number.isPrime(self._p)
        self._q: Final = (
            0xFF7443CE4E6975E30D75E5EE8FBD192A026DD42E4C30FED6B16D961D658390AF
        )
        assert 2 ** (self._N - 1) <= self._q
        assert self._q < 2**self._N
        assert number.isPrime(self._q)
        assert (self._p - 1) % self._q == 0
        self._g: Final = 0x2C496818D412D89025282FB47ACAE90A0895C7244C601FD8E3B24888B40224A6DA18EB9CB2F412B8C5C3808FF358848C5DBE919EA72BC9156D7062687917A9E40B1FF6492A171C742BD4D966F348296AE01E71EDB66C1A58028F04791ED8482A4B0C676530097864A70364FD4228852B459927F4EC08773196B4CE03761DDD8CF931F2A86E24CCB7F990DAA22FA79FEF8398FE15D9CD978B0406BF321301319CA035E3DFF0DF10DB4F7185A254B0FE2C70604B57409B333D76A8467D999670E8F9BE5E36D8D6E014AB2366937B8F757C47FB32F3AEAFC822AA6012BE49FFB0FF0E3CB2A6AEFF0E3636B6FF1A355858C0DD6788ECAD0D9B7908D500E3DE2FE448C6EA6B2A151CE5C6520A8589A54A655CB47A5A7A8317A462698BFC864F60C4B608D594C22B1F9B3BEBDE56C8E4884B218AAB5B0E0196C40E5AF1FBDCCB04CBC4DDA57131D072BC074E877648C8E9771F9AABD53FAA755B1C07646C0DF0E2680D726A3010B8D90D68293D460F1E3DA5B400DD37A702A61A300BB880779431FBC0
        assert pow(self._g, self._q, self._p) == 1

    @property
    def parameters(self) -> Parameters:
        """Returns the parameters of the ElGamal cryptosystem."""
        return self._L, self._N, self._p, self._q, self._g

    def generate_key_pair(self) -> tuple[int, int]:
        """Generates a new key pair for the ElGamal cryptosystem.

        Returns:
            A tuple of two integers: a private key and a public key.
        """
        private_key = number.getRandomNBitInteger(self._N)
        public_key = pow(self._g, private_key, self._p)
        return private_key, public_key

    def encrypt(
        self, public_key: int, m: int, nonce: int | None = None
    ) -> tuple[Ciphertext, int]:
        """Encrypts a plaintext using the ElGamal cryptosystem.

        Args:
            public_key: The public key.
            m: The plaintext.
            nonce: The nonce. If `None`, a random nonce is used.

        Returns:
            A tuple of the ciphertext and the nonce.
        """
        if public_key <= 0 or public_key >= self._p:
            raise ValueError("An invalid public key.")
        if m < 0 or m >= self._p:
            raise ValueError("The plaintext must be in the range [0, p).")
        if nonce is not None and (nonce < 0 or nonce >= self._q):
            raise ValueError("An invalid nonce.")

        if nonce is None:
            nonce = number.getRandomRange(0, self._q)
        a = pow(self._g, nonce, self._p)
        b = (m * pow(public_key, nonce, self._p)) % self._p
        return (a, b), nonce

    def reencrypt(
        self, public_key: int, ciphertext: Ciphertext
    ) -> tuple[Ciphertext, int]:
        """Re-encrypts a ciphertext using the ElGamal cryptosystem.

        Args:
            public_key: The public key.
            ciphertext: The ciphertext.

        Returns:
            A tuple of the re-encrypted ciphertext and the nonce.
        """
        a, b = ciphertext
        nonce = number.getRandomRange(0, self._q)
        a = (a * pow(self._g, nonce, self._p)) % self._p
        b = (b * pow(public_key, nonce, self._p)) % self._p
        return (a, b), nonce

    def decrypt(self, private_key: int, ciphertext: Ciphertext) -> int:
        """Decrypts a ciphertext using the ElGamal cryptosystem.

        Args:
            private_key: The private key.
            ciphertext: The ciphertext.

        Returns:
            The plaintext.
        """
        a, b = ciphertext
        denominator = pow(a, self._p - private_key - 1, self._p)
        return (b * denominator) % self._p

    def sign(self, private_key: int, m: int) -> Signature:
        """Signs a message using the ElGamal cryptosystem.

        Args:
            private_key: The private key.
            m: The message.

        Returns:
            The signature.
        """
        while True:
            k = number.getRandomRange(0, self._p)
            if number.GCD(k, self._p - 1) == 1:
                break

        r = pow(self._g, k, self._p)
        s = (
            number.inverse(k, self._p - 1)
            * (self._p + m - private_key * r - 1)
        ) % (self._p - 1)
        assert m % (self._p - 1) == (private_key * r + k * s) % (self._p - 1)

        return r, s

    def verify(self, public_key: int, m: int, signature: Signature) -> bool:
        """Verifies a signature using the ElGamal cryptosystem.

        Args:
            public_key: The public key.
            m: The message.
            signature: The signature.

        Returns:
            `True` if the signature is valid; otherwise, `False`.
        """
        r, s = signature
        if r <= 0 or r >= self._p:
            return False
        if s <= 0 or s >= self._p:
            return False

        lhs = pow(self._g, m, self._p)
        rhs = (pow(public_key, r, self._p) * pow(r, s, self._p)) % self._p
        return lhs == rhs


def _main() -> None:
    el_gamal = ElGamal()
    private_key, public_key = el_gamal.generate_key_pair()

    plaintext = 0xDEADBEEF
    ciphertext, _ = el_gamal.encrypt(public_key, plaintext)
    decrypted_text = el_gamal.decrypt(private_key, ciphertext)
    assert decrypted_text == plaintext

    reencrypted_ciphertext, _ = el_gamal.reencrypt(public_key, ciphertext)
    decrypted_text = el_gamal.decrypt(private_key, reencrypted_ciphertext)
    assert decrypted_text == plaintext

    signature = el_gamal.sign(private_key, plaintext)
    assert el_gamal.verify(public_key, plaintext, signature)


if __name__ == "__main__":
    _main()
