#!/usr/bin/env python3

from typing import Final, TypeAlias
from Crypto.Util import number


Parameters: TypeAlias = tuple[int, int, int, int, int]
Ciphertext: TypeAlias = tuple[int, int]
Signature: TypeAlias = tuple[int, int]


class ElGamal:
    def __init__(self, L: int) -> None:
        """Creates a new instance of `ElGamal`.

        Initializes the parameters for the ElGamal cryptosystem.

        Args:
            L: The length of the modulus `p` in bits. The value of `L`
                must be 512, 1024, 2048, or 3072.
        """
        if L == 512:
            N = 160
            p = 0xa6886942c71169464b1b565db7dbed36bf4767935c7775e1d2b96751ed8c9510517f5442e8bb75a406cf66df1812109143f3364a4b69e353d23305be24a897f9
            q = 0xd324e6b0ef9964f0e29d5449532101ebb8582ea1
            g = 0x6151ba366f46c90aa1df61e1cab13b61ca8fbd8c1d6eec140e3d15b391bedb139b7dc5391b81395e3b5a808210910d0681a98378c2d42469195fa346a5943eeb
        elif L == 1024:
            N = 160
            p = 0xa339d6a3f1e976c08cf331e890168892e8934a9df7ee7be4de978fe9189c7650884932a5b0e156df75fe078b3a346e68597513c1615d100b6180763508c46a46df8bb6266a6f745fb830672e9ac4921a652a1482812cfd2027b9673e33339142c17ee8ee7b524ce542c9e44a99bd2a27cf35ec57b50b47c5dd1198d560c991dd
            q = 0xa8518574fe1b5127e44b6ea6af9c936e7e4770cf
            g = 0x6e40b07f7d32db643a2b110c1ec8d0f26cd6a33117ddcda2fbf72b1c2c35b31d4186c8d440da40c09173f5e3d478e382e26ecceaf2adc35ff54b3fa64c2533f2eac25e5d7c315eb450372789bcd92830d85864e2d539d76eee0d7a994a0df8d9e930b06e8074c4e9eb03ce732c8636e966fe5737e193d5ce99bb0dca5b1cf569
        elif L == 2048:
            N = 224
            p = 0x8223b673ba317076b5b62581426bc991e7a1f91715a719d5eb5feeefc2d557d0254eddd478b31a56c69f3da6e3949f576a0d1e271a6629fda99937aa83ea21e2670c82ea09d46e819808f966063950bc387bb820bfc55607497f34ed902e5a24fe6f815a289dcef532c238978a5e119016c972fdf0ab73d9e4c1e69a3e15828e76b2a259bce7132a4445940d34200a1296f9f97fac5f8a9c14d8221d17b8362b3093465c85e1464aa1fdb93a64396c242c660fe815ddf93e331f80d120f8af2d2f7c1712cbd6b7e3ccb8b67604bd3d9f7fd59d4e4fba245206c1f02cdbef945cb8d9aaf1174e450086e8d28760db1f9c305dbc8a4b7fff17a03dfe8da43c9979
            q = 0xa233b7e935b33538322c2e3eece35225869f591d55f9afcc8e635a93
            g = 0x1d5efe9d4cab6b73988b2dde9b20959998d19b5589ce7010c3ed83aa81efe080118b341194ca43582211d93f42e8745ee05805b2cdc2dfa279eabce00549f3f7414221e3f6627c6554add08d668adba9dad2bfee61c574967268979b853138dfdc29ae4e6c33f9108c02b9d9253bf8db415385315fbb8f643200f26c9d87dba3f415efa5ae3db144f69a3ebba8ee16d044ca1d2c98fc8eaf1e72c33e935e14fd29c6ad053b385e62a2b5066edd8dad121fdd26b62a7205b4b18776c063aef2a0142869b475dee6ae1fcaf9e4ed6308381d868c4028e1ac2c7e75e63e2749a41c7ecdc2181643bd067c00bdbbba292f3df81bab51d3f983b38fd4d5fb9a45dee
        elif L == 3072:
            N = 256
            p = 0xa1a29d649f1b84085ee3b8ce8352bfcf8aeed042afc4e41d43704f8b9ffbef3d46dc3bc3bdcbcde10ff0dc4b0ba890148b85204fb22f20beb23826806fa1789cccfff26496551754abf5fd9e14adad6ea3e661eb5c8e58e07784f37c78a93d59c7a4f11fa433895906658098636650cfd666fd2fdd2058b99b0ba2ab4c63368499887be6910536b27298eea5391bd3fa5ec53d87e87ddcf6b91804f7bc08657e800b848465fd3780a60222b0bdecb61e9b83f12fcc00b29d4589b265bb489ab61633d1f977769f68250c5ed2733ef7eb2671c1b54514f22153e9486f675d95a9c06f2cbe01fcffa74553b5bc43e2375bc01a5a33c2ea26368966e7c0ab5906ac51f70892328b358f06a706c90738875cedcab647f305ad282660b1be3b5631c1905ae31b7d83bbc6b0504b393d3df1568aee36d4a402448e928e16b688547af16722ac2db5ac70c87d8a269c9eacd97821c68888e2c20debbb8bf856b646ce97378392c7ec90551708efb95379fc92c014a22972940ec732bc8561696df2a9f1
            q = 0xddf6a1073edc7993fe372ab162ed46b7a1f24d58506adb242badba890e77dd17
            g = 0x370333b61202b70e3b41dd20782faf35cb7b97e3d213600833cdb4e025d08ae28568223c418ec30ffbe769d3ae402726a35bb3ce4e6442155f807b64eceb2472cca8b28c9db5c6c29d3d15b05518b9e849a8b9b5048785155a58f0e703ff5494de793393dc817ba5c6eec73502bafe08c11ebf30d27a132f57b217557ff275f9b8c122d76a2996197e9478b1a17297caa390b4f6acfb11b03d2a501d3aa3aa6ef8f271888eaac5664539185637851b18b84158013c7cd93634a1a8cd13ee79fd50d385abd560e702a9e9dbc744e95f6d1b0d0a84c5e3cc5c90f0aa085ab226572669e52197d8ef2182c061e8177c0a44ffd687bc14134934f8ecd0df17027d06f578c81c5669874eb1db9f7428a836ff8c76d06fc6ff716d7cc5adb086b4b062313a638ef8a8a5ae03e71a8dc5bea2fa4eabf264289b2e94aa2f45c2c2be893f13ababbb2b6c6180f6f054254d8aadeae69cfdb64f5b538cb7fb46b97931e6cbdbe695c2a8ce83146d3ccf9c0f304e82053703f22c1be681566497f183e337c
        else:
            errmsg = "The parameter `L' must be 512, 1024, 2048, or 3072."
            raise ValueError(errmsg)

        assert number.isPrime(p)
        assert p.bit_length() == L
        assert number.isPrime(q)
        assert q.bit_length() == N
        # [Furukawa, 2005] and [Groth and Lu, 2007] require the
        # following condition.
        assert q % 3 == 2
        assert (p - 1) % q == 0
        assert pow(g, q, p) == 1

        self._L: Final = L
        self._N: Final = N
        self._p: Final = p
        self._q: Final = q
        self._g: Final = g

    @property
    def parameters(self) -> Parameters:
        """Returns the parameters of the ElGamal cryptosystem."""
        return self._L, self._N, self._p, self._q, self._g

    def generate_key_pair(self) -> tuple[int, int]:
        """Generates a new key pair for the ElGamal cryptosystem.

        Returns:
            A tuple of two integers: a private key and the corresponding
            public key.
        """
        private_key = number.getRandomRange(0, self._q)
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
        self, public_key: int, ciphertext: Ciphertext, nonce: int | None = None
    ) -> tuple[Ciphertext, int]:
        """Re-encrypts a ciphertext using the ElGamal cryptosystem.

        Args:
            public_key: The public key.
            ciphertext: The ciphertext.
            nonce: The nonce. If `None`, a random nonce is used.

        Returns:
            A tuple of the re-encrypted ciphertext and the nonce.
        """
        a, b = ciphertext
        if nonce is None:
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
        if m <= 0 or m >= self._p:
            errmsg = "The message must be in the range (0, p)."
            raise ValueError(errmsg)

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
        if m <= 0 or m >= self._p:
            errmsg = "The message must be in the range (0, p)."
            raise ValueError(errmsg)

        r, s = signature
        if r <= 0 or r >= self._p:
            return False
        if s <= 0 or s >= self._p:
            return False

        lhs = pow(self._g, m, self._p)
        rhs = (pow(public_key, r, self._p) * pow(r, s, self._p)) % self._p
        return lhs == rhs


def _main() -> None:
    el_gamal = ElGamal(3072)
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
