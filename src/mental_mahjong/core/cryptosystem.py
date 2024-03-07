from hashlib import sha256
import logging
from multiprocessing import Process
import random
import time
from typing import Final
from Crypto.Util import number
from mental_mahjong.core import (
    ElGamalParameters,
    ElGamalCiphertext,
    ElGamal,
    Communicator,
    agree_on_random_integer,
)


_CHALLENGE_BIT_LENGTH: Final = 128


class Cryptosystem:
    def _agree_on_key(self) -> None:
        L, _, p, _, _ = self._el_gamal.parameters

        # Each player generates their local private key and the
        # corresponding local public key.
        self._my_private_key, my_public_key = (
            self._el_gamal.generate_key_pair()
        )

        # Generates the commitment of the local public key.
        hasher = sha256()
        hasher.update(my_public_key.to_bytes(L // 8, "big"))
        my_salt = number.getRandomNBitInteger(256)
        hasher.update(my_salt.to_bytes(256 // 8, "big"))
        my_commitment = int.from_bytes(hasher.digest(), "big")

        # Communicates the commitments of the local public key.
        logging.debug(
            "(%d): Communicating the commitments of individual public keys...",
            self._communicator.rank,
        )
        data_list = self._communicator.all_to_all(
            {
                "type": "DistributedCryptosystem._agree_on_key.commitment",
                "rank": self._communicator.rank,
                "commitment": my_commitment,
            },
        )
        logging.debug(
            "(%d): Communicated the commitments of individual public keys.",
            self._communicator.rank,
        )

        commitments: list[int] = [
            -1 for _ in range(self._communicator.world_size)
        ]
        commitments[self._communicator.rank] = my_commitment
        for data in data_list:
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "DistributedCryptosystem._agree_on_key.commitment":
                raise RuntimeError("An invalid message.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if "commitment" not in data:
                raise RuntimeError("An invalid message.")
            opponent_commitment = data["commitment"]
            if not isinstance(opponent_commitment, int):
                raise RuntimeError("An invalid message.")
            if commitments[opponent_rank] != -1:
                raise RuntimeError("An invalid message.")
            commitments[opponent_rank] = opponent_commitment
        for c in commitments:
            if c == -1:
                errmsg = "An invalid message."
                raise RuntimeError(errmsg)

        # Communicates the local public keys.
        logging.debug(
            "(%d): Communicating the individual public keys...",
            self._communicator.rank,
        )
        data_list = self._communicator.all_to_all(
            {
                "type": "DistributedCryptosystem._agree_on_key.reveal",
                "rank": self._communicator.rank,
                "public_key": my_public_key,
                "salt": my_salt,
            },
        )
        logging.debug(
            "(%d): Communicated the individual public keys.",
            self._communicator.rank,
        )

        # Verifies the commitments of the local public keys.
        self._individual_public_keys: list[int] = [
            -1 for _ in range(self._communicator.world_size)
        ]
        self._individual_public_keys[self._communicator.rank] = my_public_key
        for data in data_list:
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "DistributedCryptosystem._agree_on_key.reveal":
                raise RuntimeError("An invalid message.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if "public_key" not in data:
                raise RuntimeError("An invalid message.")
            opponent_public_key = data["public_key"]
            if not isinstance(opponent_public_key, int):
                raise RuntimeError("An invalid message.")
            if "salt" not in data:
                raise RuntimeError("An invalid message.")
            opponent_salt = data["salt"]
            if not isinstance(opponent_salt, int):
                raise RuntimeError("An invalid message.")

            hasher = sha256()
            hasher.update(opponent_public_key.to_bytes(L // 8, "big"))
            hasher.update(opponent_salt.to_bytes(256 // 8, "big"))
            if hasher.digest() != commitments[opponent_rank].to_bytes(
                256 // 8, "big"
            ):
                raise RuntimeError("An invalid commitment.")

            if self._individual_public_keys[opponent_rank] != -1:
                raise RuntimeError("An invalid message.")
            self._individual_public_keys[opponent_rank] = opponent_public_key

        # Computes the global public key.
        self._global_public_key = 1
        for individual_public_key in self._individual_public_keys:
            if individual_public_key == -1:
                raise RuntimeError(
                    "Failed to communicate an opponent's public key."
                )
            self._global_public_key = (
                self._global_public_key * individual_public_key
            ) % p

    def __init__(self, communicator: Communicator, L: int) -> None:
        self._communicator = communicator
        self._el_gamal = ElGamal(L)

        self._agree_on_key()

    @property
    def parameters(self) -> ElGamalParameters:
        return self._el_gamal.parameters

    @property
    def communicator(self) -> Communicator:
        return self._communicator

    @property
    def global_public_key(self) -> int:
        return self._global_public_key

    def plaintext_equality_test(
        self,
        ciphertext0: ElGamalCiphertext,
        ciphertext1: ElGamalCiphertext,
    ) -> bool:
        logging.debug(
            "(%d): Executing a plaintext equality test...",
            self._communicator.rank,
        )

        _, _, p, q, g = self._el_gamal.parameters

        a0, b0 = ciphertext0
        a1, b1 = ciphertext1
        epsilon = (a0 * number.inverse(a1, p)) % p
        zeta = (b0 * number.inverse(b1, p)) % p

        z = number.getRandomRange(0, q)
        r = number.getRandomRange(0, q)
        commitment = (pow(g, z, p) * pow(self._global_public_key, r, p)) % p

        data_list = self._communicator.all_to_all(
            {
                "type": "plaintext_equality_test_commitment",
                "rank": self._communicator.rank,
                "commitment": commitment,
            },
        )
        commitments: list[int] = [
            -1 for _ in range(self._communicator.world_size)
        ]
        commitments[self._communicator.rank] = commitment
        for data in data_list:
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "plaintext_equality_test_commitment":
                raise RuntimeError("An invalid message type.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if "commitment" not in data:
                raise RuntimeError("An invalid message.")
            opponent_commitment = data["commitment"]
            if not isinstance(opponent_commitment, int):
                raise RuntimeError("An invalid message.")

            if commitments[opponent_rank] != -1:
                raise RuntimeError("An invalid message.")
            commitments[opponent_rank] = opponent_commitment
        for c in commitments:
            if c == -1:
                raise RuntimeError("An invalid message.")

        # TODO: Implement the rest of the protocol.

        data_list = self._communicator.all_to_all(
            {
                "type": "plaintext_equality_test_ciphertext",
                "rank": self._communicator.rank,
                "ciphertext": [epsilon, zeta],
            },
        )
        ciphertexts: list[ElGamalCiphertext] = [
            (-1, -1) for _ in range(self._communicator.world_size)
        ]
        ciphertexts[self._communicator.rank] = (epsilon, zeta)
        for data in data_list:
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "plaintext_equality_test_ciphertext":
                raise RuntimeError("An invalid message type.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if "ciphertext" not in data:
                raise RuntimeError("An invalid message.")
            opponent_ciphertext = data["ciphertext"]
            if not isinstance(opponent_ciphertext, list):
                raise RuntimeError("An invalid message.")
            if len(opponent_ciphertext) != 2:
                raise RuntimeError("An invalid message.")
            epsilon, zeta = opponent_ciphertext
            if not isinstance(epsilon, int):
                raise RuntimeError("An invalid message.")
            if not isinstance(zeta, int):
                raise RuntimeError("An invalid message.")

            if ciphertexts[opponent_rank] != (-1, -1):
                raise RuntimeError("An invalid message.")
            ciphertexts[opponent_rank] = (epsilon, zeta)

        ciphertext: ElGamalCiphertext = (1, 1)
        for a, b in ciphertexts:
            ciphertext = ((ciphertext[0] * a) % p, (ciphertext[1] * b) % p)

        plaintext = self.decrypt_publicly(ciphertext)

        logging.debug(
            "(%d): Executed a plaintext equality test.",
            self._communicator.rank,
        )

        return plaintext == 1

    def _chaum_pedersen_1993(
        self, prover_rank: int, verifier_rank: int, a: int, b: int
    ) -> bool:
        if prover_rank < 0 or prover_rank >= self._communicator.world_size:
            raise ValueError(f"{prover_rank}: An invalid prover rank.")
        if verifier_rank < 0 or verifier_rank >= self._communicator.world_size:
            raise ValueError(f"{verifier_rank}: An invalid verifier rank.")
        if prover_rank == verifier_rank:
            raise ValueError("The prover and verifier must be different.")
        if self._communicator.rank not in (prover_rank, verifier_rank):
            raise ValueError("The caller must be a prover or a verifier.")

        _, _, p, q, g = self._el_gamal.parameters

        if self._communicator.rank == prover_rank:
            logging.debug(
                "(%d): Executing the Chaum-Pedersen protocol as a prover...",
                self._communicator.rank,
            )

            s = number.getRandomRange(0, q)
            commitment0 = pow(g, s, p)
            commitment1 = pow(a, s, p)

            logging.debug(
                "(%d): Sending commitments...",
                self._communicator.rank,
            )
            self._communicator.send(
                verifier_rank,
                {
                    "type": "chaum_pedersen_1993_commitment",
                    "rank": self._communicator.rank,
                    "commitments": [commitment0, commitment1],
                },
            )
            logging.debug(
                "(%d): Sent the commitments.",
                self._communicator.rank,
            )

            logging.debug(
                "(%d): Receiving a challenge...",
                self._communicator.rank,
            )
            data = self._communicator.recv(verifier_rank)
            logging.debug(
                "(%d): Received a challenge.",
                self._communicator.rank,
            )
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "chaum_pedersen_1993_challenge":
                raise RuntimeError("An invalid message type.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if opponent_rank != verifier_rank:
                raise RuntimeError("An invalid message.")
            if "challenge" not in data:
                raise RuntimeError("An invalid message.")
            challenge = data["challenge"]
            if not isinstance(challenge, int):
                raise RuntimeError("An invalid message.")

            response = (s + (challenge * self._my_private_key) % q) % q

            self._communicator.send(
                verifier_rank,
                {
                    "type": "chaum_pedersen_1993_response",
                    "rank": self._communicator.rank,
                    "response": response,
                },
            )

            data = self._communicator.recv(verifier_rank)
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "chaum_pedersen_1993_result":
                raise RuntimeError("An invalid message type.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if opponent_rank != verifier_rank:
                raise RuntimeError("An invalid message.")
            if "result" not in data:
                raise RuntimeError("An invalid message.")
            opponent_result = data["result"]
            if not isinstance(opponent_result, bool):
                raise RuntimeError("An invalid message.")

            logging.debug(
                "(%d): Executed the Chaum-Pedersen protocol as a prover.",
                self._communicator.rank,
            )

            return opponent_result

        assert self._communicator.rank == verifier_rank
        logging.debug(
            "(%d): Executing the Chaum-Pedersen protocol as a verifier...",
            self._communicator.rank,
        )

        logging.debug(
            "(%d): Receiving the commitments...",
            self._communicator.rank,
        )
        data = self._communicator.recv(prover_rank)
        logging.debug(
            "(%d): Received the commitments.",
            self._communicator.rank,
        )
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "chaum_pedersen_1993_commitment":
            raise RuntimeError("An invalid message type.")
        if "rank" not in data:
            raise RuntimeError("An invalid message.")
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if opponent_rank != prover_rank:
            raise RuntimeError("An invalid message.")
        if "commitments" not in data:
            raise RuntimeError("An invalid message.")
        opponent_commitments = data["commitments"]
        if not isinstance(opponent_commitments, list):
            raise RuntimeError("An invalid message.")
        if len(opponent_commitments) != 2:
            raise RuntimeError("An invalid message.")
        commitment0, commitment1 = opponent_commitments
        if not isinstance(commitment0, int):
            raise RuntimeError("An invalid message.")
        if not isinstance(commitment1, int):
            raise RuntimeError("An invalid message.")

        challenge = number.getRandomRange(0, q)

        logging.debug(
            "(%d): Sending a challenge...",
            self._communicator.rank,
        )
        self._communicator.send(
            prover_rank,
            {
                "type": "chaum_pedersen_1993_challenge",
                "rank": self._communicator.rank,
                "challenge": challenge,
            },
        )
        logging.debug(
            "(%d): Sent a challenge.",
            self._communicator.rank,
        )

        logging.debug(
            "(%d): Receiving the response...",
            self._communicator.rank,
        )
        data = self._communicator.recv(prover_rank)
        logging.debug(
            "(%d): Received the response.",
            self._communicator.rank,
        )
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "chaum_pedersen_1993_response":
            raise RuntimeError("An invalid message type.")
        if "rank" not in data:
            raise RuntimeError("An invalid message.")
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if opponent_rank != prover_rank:
            raise RuntimeError("An invalid message.")
        if "response" not in data:
            raise RuntimeError("An invalid message.")
        response = data["response"]
        if not isinstance(response, int):
            raise RuntimeError("An invalid message.")

        result = True
        y = self._individual_public_keys[prover_rank]
        if pow(g, response, p) != (commitment0 * pow(y, challenge, p)) % p:
            result = False
        if pow(a, response, p) != (commitment1 * pow(b, challenge, p)) % p:
            result = False

        self._communicator.send(
            prover_rank,
            {
                "type": "chaum_pedersen_1993_result",
                "rank": self._communicator.rank,
                "result": result,
            },
        )

        logging.debug(
            "(%d): Executed the Chaum-Pedersen protocol as a verifier.",
            self._communicator.rank,
        )

        return result

    def encrypt(
        self, m: int, nonce: int | None = None
    ) -> tuple[ElGamalCiphertext, int]:
        _, _, p, q, _ = self._el_gamal.parameters
        if m <= 0 or m >= p:
            errmsg = "The plaintext must be in the range (0, p)."
            raise ValueError(errmsg)
        if nonce is not None and (nonce < 0 or nonce >= q):
            errmsg = "The nonce must be in the range [0, q)."
            raise ValueError(errmsg)

        if nonce is None:
            nonce = agree_on_random_integer(self._communicator, q)

        return self._el_gamal.encrypt(self._global_public_key, m, nonce)

    def reencrypt(
        self, ciphertext: ElGamalCiphertext, nonce: int | None = None
    ) -> tuple[ElGamalCiphertext, int]:
        _, _, _, q, _ = self._el_gamal.parameters
        if nonce is not None and (nonce < 0 or nonce >= q):
            errmsg = "The nonce must be in the range [0, q)."
            raise ValueError(errmsg)

        if nonce is None:
            nonce = agree_on_random_integer(self._communicator, q)

        return self._el_gamal.reencrypt(
            self._global_public_key, ciphertext, nonce
        )

    def decrypt_privately(
        self, rank: int, ciphertext: ElGamalCiphertext
    ) -> int | None:
        if rank < 0 or rank >= self._communicator.world_size:
            raise ValueError(f"{rank}: An invalid rank.")

        logging.debug(
            "(%d): Decrypting the ciphertext privately...",
            self._communicator.rank,
        )

        _, _, p, _, _ = self._el_gamal.parameters

        a, b = ciphertext

        if rank == self._communicator.rank:
            plaintext = b
            for i in range(self._communicator.world_size):
                if i == self._communicator.rank:
                    continue

                logging.debug(
                    "(%d): Receiving the decryption key...",
                    self._communicator.rank,
                )
                data = self._communicator.recv(i)
                logging.debug(
                    "(%d): Received the decryption key.",
                    self._communicator.rank,
                )
                if not isinstance(data, dict):
                    raise RuntimeError("An invalid message.")
                if "type" not in data:
                    raise RuntimeError("An invalid message.")
                _type = data["type"]
                if not isinstance(_type, str):
                    raise RuntimeError("An invalid message.")
                if _type != "decrypt_key":
                    raise RuntimeError("An invalid message type.")
                if "rank" not in data:
                    raise RuntimeError("An invalid message.")
                opponent_rank = data["rank"]
                if not isinstance(opponent_rank, int):
                    raise RuntimeError("An invalid message.")
                if opponent_rank != i:
                    raise RuntimeError("An invalid message.")
                if "key" not in data:
                    raise RuntimeError("An invalid message.")
                key = data["key"]
                if not isinstance(key, int):
                    raise RuntimeError("An invalid message.")

                if not self._chaum_pedersen_1993(i, rank, a, key):
                    raise RuntimeError("Failed to verify the decryption key.")
                plaintext = (plaintext * number.inverse(key, p)) % p

            key = pow(a, self._my_private_key, p)
            plaintext = (plaintext * number.inverse(key, p)) % p

            logging.debug(
                "(%d): Decrypted the ciphertext privately.",
                self._communicator.rank,
            )

            return plaintext

        key = pow(a, self._my_private_key, p)

        logging.debug(
            "(%d): Sending the decryption key...",
            self._communicator.rank,
        )
        self._communicator.send(
            rank,
            {
                "type": "decrypt_key",
                "rank": self._communicator.rank,
                "key": key,
            },
        )
        logging.debug(
            "(%d): Sent the decryption key.",
            self._communicator.rank,
        )

        if not self._chaum_pedersen_1993(
            self._communicator.rank, rank, a, key
        ):
            raise RuntimeError("Failed to prove the decryption key.")

        logging.debug(
            "(%d): Decrypted the ciphertext privately.",
            self._communicator.rank,
        )

        return None

    def decrypt_publicly(self, ciphertext: ElGamalCiphertext) -> int:
        logging.debug(
            "(%d): Decrypting the ciphertext publicly...",
            self._communicator.rank,
        )

        # TODO: Implement a more efficient decryption algorithm.
        plaintext = -1
        for rank in range(self._communicator.world_size):
            m = self.decrypt_privately(rank, ciphertext)
            if m is not None:
                plaintext = m

        logging.debug(
            "(%d): Decrypted the ciphertext publicly.",
            self._communicator.rank,
        )

        return plaintext

    def furukawa_2005(
        self, rank: int, ciphertexts: list[ElGamalCiphertext]
    ) -> None:
        if rank < 0 or rank >= self._communicator.world_size:
            errmsg = f"{rank}: An invalid rank."
            raise ValueError(errmsg)

        logging.debug(
            "(%d): Executing Furukawa 2005 protocol...",
            self._communicator.rank,
        )

        g = [-1]
        g.extend([x for x, _ in ciphertexts])
        m = [-1]
        m.extend([y for _, y in ciphertexts])

        _, _, p, q, g[0] = self._el_gamal.parameters
        m[0] = self._global_public_key

        f: list[int] = []
        for _ in range(5 + len(ciphertexts)):
            f.append(agree_on_random_integer(self._communicator, q))
            f[-1] = pow(g[0], f[-1], p)

        if self._communicator.rank == rank:
            permutation = list(range(len(ciphertexts)))
            random.shuffle(permutation)
            inverse_permutation = [-1 for _ in enumerate(ciphertexts)]
            for i, j in enumerate(permutation):
                inverse_permutation[j] = i

            a: list[list[int]] = []
            aa: list[int] = []
            for i in range(5 + len(ciphertexts)):
                a.append([])
                aa.append(-1)
                for j in range(5 + len(ciphertexts)):
                    a[-1].append(-1)

            # A_{0, i} (i = 1, 2, ..., k)
            for i in range(len(ciphertexts)):
                a[4][5 + i] = number.getRandomRange(0, q)

            # A_{j, i} (i = 1, 2, ..., k, j = 1, 2, ..., k)
            for i, _ in enumerate(ciphertexts):
                for j, _ in enumerate(ciphertexts):
                    if permutation[i] == j:
                        a[5 + i][5 + j] = 1
                    else:
                        a[5 + i][5 + j] = 0

            # g'_{i} (i = (0), 1, 2, ..., k)
            # m'_{i} (i = (0), 1, 2, ..., k)
            gg: list[int] = [-1]
            mm: list[int] = [-1]
            for i, _ in enumerate(ciphertexts):
                ciphertext = ciphertexts[inverse_permutation[i]]
                gg.append((pow(g[0], a[4][5 + i], p) * ciphertext[0]) % p)
                mm.append((pow(m[0], a[4][5 + i], p) * ciphertext[1]) % p)

            # {A_{\nu, 0}, A'_{\nu}} (\nu = -4, -3, ..., k)
            for i in range(5 + len(ciphertexts)):
                a[i][4] = number.getRandomRange(0, q)
                aa[i] = number.getRandomRange(0, q)

            # A_{-1, i} (i = 1, 2, ..., k)
            for i in range(len(ciphertexts)):
                a[3][5 + i] = number.getRandomRange(0, q)

            # A_{-2, i} (i = 1, 2, ..., k)
            for i, _ in enumerate(ciphertexts):
                a[2][5 + i] = 0
                for j, _ in enumerate(ciphertexts):
                    a[2][5 + i] = (
                        a[2][5 + i]
                        + 3 * pow(a[5 + j][4], 2, q) * a[5 + j][5 + i]
                    ) % q

            # A_{-3, i} (i = 1, 2, ..., k)
            for i, _ in enumerate(ciphertexts):
                a[1][5 + i] = 0
                for j, _ in enumerate(ciphertexts):
                    a[1][5 + i] = (
                        a[1][5 + i] + 3 * a[5 + j][4] * a[5 + j][5 + i]
                    ) % q

            # A_{-4, i} (i = 1, 2, ..., k)
            for i, _ in enumerate(ciphertexts):
                a[0][5 + i] = 0
                for j, _ in enumerate(ciphertexts):
                    a[0][5 + i] = (
                        a[0][5 + i] + 2 * a[5 + j][4] * a[5 + j][5 + i]
                    ) % q

            # f'_{\mu} (\mu = 0, 1, ..., k)
            ff = []
            for i in range(1 + len(ciphertexts)):
                ff.append(1)
                for j in range(5 + len(ciphertexts)):
                    ff[-1] = (ff[-1] * pow(f[j], a[j][4 + i], p)) % p

            # f'_0
            ff0 = 1
            for i in range(5 + len(ciphertexts)):
                ff0 = (ff0 * pow(f[i], aa[i], p)) % p

            # g'_0
            gg[0] = 1
            for i in range(1 + len(ciphertexts)):
                gg[0] = (gg[0] * pow(g[i], a[4 + i][4], p)) % p

            # m'_0
            mm[0] = 1
            for i in range(1 + len(ciphertexts)):
                mm[0] = (mm[0] * pow(m[i], a[4 + i][4], p)) % p

            # w
            w = (-a[2][4] - aa[1]) % q
            assert w >= 0
            for i, _ in enumerate(ciphertexts):
                w = (w + pow(a[5 + i][4], 3, q)) % q

            # w'
            ww = (-a[0][4]) % q
            for i, _ in enumerate(ciphertexts):
                ww = (ww + pow(a[5 + i][4], 2, q)) % q
                assert ww >= 0

            commitment: list[int] = [ff0, w, ww]
            commitment.extend(ff)

            logging.debug(
                "(%d): Broadcasting a commitment...", self._communicator.rank
            )
            self._communicator.broadcast(
                {
                    "type": "Cryptosystem.furukawa_2005.commitment",
                    "rank": self._communicator.rank,
                    "shuffled_ciphertexts": [[x, y] for x, y in zip(gg, mm)],
                    "commitment": commitment,
                },
            )
            logging.debug(
                "(%d): Broadcasted a commitment.", self._communicator.rank
            )

            logging.debug(
                "(%d): Receiving challenges...", self._communicator.rank
            )
            data_list = self._communicator.gather()
            logging.debug(
                "(%d): Received challenges.", self._communicator.rank
            )
            for data in data_list:
                if not isinstance(data, dict):
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                if "type" not in data:
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                _type = data["type"]
                if not isinstance(_type, str):
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                if _type != "Cryptosystem.furukawa_2005.challenge":
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                if "rank" not in data:
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                opponent_rank = data["rank"]
                if not isinstance(opponent_rank, int):
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                if "challenge" not in data:
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                challenge = data["challenge"]
                if not isinstance(challenge, list):
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)
                if len(challenge) != 1 + len(ciphertexts):
                    errmsg = "An invalid message."
                    raise RuntimeError(errmsg)

                r: list[int] = []
                for i in range(5 + len(ciphertexts)):
                    r.append(0)
                    for j in range(1 + len(ciphertexts)):
                        r[-1] = (r[-1] + a[i][4 + j] * challenge[j]) % q

                rr: list[int] = []
                for i in range(5 + len(ciphertexts)):
                    rr.append(aa[i])
                    for j, _ in enumerate(ciphertexts):
                        rr[-1] = (
                            rr[-1] + a[i][5 + j] * pow(challenge[1 + j], 2, q)
                        ) % q

                logging.debug(
                    "(%d): Sending response...", self._communicator.rank
                )
                self._communicator.send(
                    opponent_rank,
                    {
                        "type": "Cryptosystem.furukawa_2005.response",
                        "rank": self._communicator.rank,
                        "response": [r, rr],
                    },
                )
                logging.debug("(%d): Sent response.", self._communicator.rank)

            logging.debug(
                "(%d): Executed Furukawa 2005 protocol.",
                self._communicator.rank,
            )

            return

        logging.debug(
            "(%d): Receiving a commitment...", self._communicator.rank
        )
        data = self._communicator.recv(rank)
        logging.debug("(%d): Received a commitment.", self._communicator.rank)
        if not isinstance(data, dict):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if "type" not in data:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        _type = data["type"]
        if not isinstance(_type, str):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if _type != "Cryptosystem.furukawa_2005.commitment":
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if "rank" not in data:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if opponent_rank != rank:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if "shuffled_ciphertexts" not in data:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        shuffled_ciphertexts = data["shuffled_ciphertexts"]
        if not isinstance(shuffled_ciphertexts, list):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if len(shuffled_ciphertexts) != 1 + len(ciphertexts):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        gg = [x for x, _ in shuffled_ciphertexts]
        mm = [y for _, y in shuffled_ciphertexts]
        if "commitment" not in data:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        values = data["commitment"]
        if not isinstance(values, list):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if len(values) != 3 + (1 + len(ciphertexts)):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        ff0, w, ww = values[0:3]
        ff = values[3:]

        challenge = [1]
        challenge.extend(
            [number.getRandomRange(0, q) for _ in enumerate(ciphertexts)]
        )

        logging.debug("(%d): Sending a challenge...", self._communicator.rank)
        self._communicator.send(
            rank,
            {
                "type": "Cryptosystem.furukawa_2005.challenge",
                "rank": self._communicator.rank,
                "challenge": challenge,
            },
        )
        logging.debug("(%d): Sent a challenge.", self._communicator.rank)

        logging.debug(
            "(%d): Receiving the response...", self._communicator.rank
        )
        data = self._communicator.recv(rank)
        logging.debug("(%d): Received the response.", self._communicator.rank)
        if not isinstance(data, dict):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if "type" not in data:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        _type = data["type"]
        if not isinstance(_type, str):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if _type != "Cryptosystem.furukawa_2005.response":
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if "rank" not in data:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if opponent_rank != rank:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if "response" not in data:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        response = data["response"]
        if not isinstance(response, list):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if len(response) != 2:
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        r = response[0]
        if not isinstance(r, list):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if len(r) != 5 + len(ciphertexts):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        rr = response[1]
        if not isinstance(rr, list):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)
        if len(rr) != 5 + len(ciphertexts):
            errmsg = "An invalid message."
            raise RuntimeError(errmsg)

        alpha = number.getRandomRange(0, q)

        lhs = 1
        for i in range(5 + len(ciphertexts)):
            lhs = (lhs * pow(f[i], (r[i] + alpha * rr[i]) % q, p)) % p
        rhs = (ff[0] * pow(ff0, alpha, p)) % p
        for i, _ in enumerate(ciphertexts):
            rhs = (
                rhs
                * pow(
                    ff[1 + i],
                    challenge[1 + i] + alpha * pow(challenge[1 + i], 2, q),
                    p,
                )
            ) % p
        if lhs != rhs:
            errmsg = "An invalid proof."
            raise RuntimeError(errmsg)

        lhs = 1
        for i in range(1 + len(ciphertexts)):
            lhs = (lhs * pow(g[i], r[4 + i], p)) % p
        rhs = 1
        for i in range(1 + len(ciphertexts)):
            rhs = (rhs * pow(gg[i], challenge[i], p)) % p
        if lhs != rhs:
            errmsg = "An invalid proof."
            raise RuntimeError(errmsg)

        lhs = 1
        for i in range(1 + len(ciphertexts)):
            lhs = (lhs * pow(m[i], r[4 + i], p)) % p
        rhs = 1
        for i in range(1 + len(ciphertexts)):
            rhs = (rhs * pow(mm[i], challenge[i], p)) % p
        if lhs != rhs:
            errmsg = f"({self._communicator.rank}): An invalid proof."
            raise RuntimeError(errmsg)

        lhs = 0
        for i, _ in enumerate(ciphertexts):
            lhs = (lhs + pow(r[5 + i], 3, q) - pow(challenge[1 + i], 3, q)) % q
            assert lhs >= 0
        if lhs != (r[2] + rr[1] + w) % q:
            errmsg = "An invalid proof."
            raise RuntimeError(errmsg)

        lhs = 0
        for i, _ in enumerate(ciphertexts):
            lhs = (lhs + pow(r[5 + i], 2, q) - pow(challenge[1 + i], 2, q)) % q
            assert lhs >= 0
        if lhs != (r[0] + ww) % q:
            errmsg = "An invalid proof."
            raise RuntimeError(errmsg)

        logging.debug(
            "(%d): Executed Furukawa 2005 protocol.", self._communicator.rank
        )


def _process_main(local_urls: list[str], opponent_urls: list[str]) -> None:
    logging.basicConfig(level=logging.DEBUG)

    communicator = Communicator(local_urls, opponent_urls)
    cryptosystem = Cryptosystem(communicator, 512)

    plaintext = 0xDEADBEEF
    ciphertext, _ = cryptosystem.encrypt(plaintext)

    for rank in range(communicator.world_size):
        decrypted_plaintext = cryptosystem.decrypt_privately(rank, ciphertext)
        if rank == communicator.rank:
            assert decrypted_plaintext == plaintext
        else:
            assert decrypted_plaintext is None

    _, _, p, _, g = cryptosystem.parameters

    plaintexts = [pow(g, i, p) for i in range(0, 136)]
    ciphertexts = []
    for plaintext in plaintexts:
        ciphertext, _ = cryptosystem.encrypt(plaintext)
        ciphertexts.append(ciphertext)

    start_time = time.time()
    for rank in range(communicator.world_size):
        cryptosystem.furukawa_2005(rank, ciphertexts)
    end_time = time.time()
    print(f"Elapsed time: {end_time - start_time} [s]")

    decrypted_plaintexts = []
    for ciphertext in ciphertexts:
        decrypted_plaintext = cryptosystem.decrypt_publicly(ciphertext)
        decrypted_plaintexts.append(decrypted_plaintext)
    plaintexts.sort()
    decrypted_plaintexts.sort()
    assert decrypted_plaintexts == plaintexts


def _main() -> None:
    processes: list[Process] = []

    local_urls = [
        "tcp://127.0.0.1:5555",
        "tcp://127.0.0.1:5556",
        "tcp://127.0.0.1:5557",
    ]
    opponent_urls = [
        "tcp://127.0.0.1:5558",
        "tcp://127.0.0.1:5561",
        "tcp://127.0.0.1:5564",
    ]
    process = Process(target=_process_main, args=(local_urls, opponent_urls))
    process.start()
    processes.append(process)

    local_urls = [
        "tcp://127.0.0.1:5558",
        "tcp://127.0.0.1:5559",
        "tcp://127.0.0.1:5560",
    ]
    opponent_urls = [
        "tcp://127.0.0.1:5555",
        "tcp://127.0.0.1:5562",
        "tcp://127.0.0.1:5565",
    ]
    process = Process(target=_process_main, args=(local_urls, opponent_urls))
    process.start()
    processes.append(process)

    local_urls = [
        "tcp://127.0.0.1:5561",
        "tcp://127.0.0.1:5562",
        "tcp://127.0.0.1:5563",
    ]
    opponent_urls = [
        "tcp://127.0.0.1:5556",
        "tcp://127.0.0.1:5559",
        "tcp://127.0.0.1:5566",
    ]
    process = Process(target=_process_main, args=(local_urls, opponent_urls))
    process.start()
    processes.append(process)

    local_urls = [
        "tcp://127.0.0.1:5564",
        "tcp://127.0.0.1:5565",
        "tcp://127.0.0.1:5566",
    ]
    opponent_urls = [
        "tcp://127.0.0.1:5557",
        "tcp://127.0.0.1:5560",
        "tcp://127.0.0.1:5563",
    ]
    process = Process(target=_process_main, args=(local_urls, opponent_urls))
    process.start()
    processes.append(process)

    for process in processes:
        process.join()


if __name__ == "__main__":
    _main()
