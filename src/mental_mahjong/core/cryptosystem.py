from hashlib import sha256
import logging
from multiprocessing import Process
import random
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

        # Each player generates their individual private key and the
        # corresponding public key.
        self._my_private_key, my_public_key = ElGamal().generate_key_pair()

        # Generates the commitment of my public key.
        hasher = sha256()
        hasher.update(my_public_key.to_bytes(L // 8, "big"))
        my_commitment = int.from_bytes(hasher.digest(), "big")

        # Communicates the commitments of the distributed public key.
        logging.debug(
            "(%d): Communicating the commitments of individual public keys...",
            self._communicator.rank,
        )
        data_list = self._communicator.all_to_all(
            {
                "type": "public_key_commitment",
                "rank": self._communicator.rank,
                "commitment": my_commitment,
            },
        )
        logging.debug(
            "(%d): Communicated my public key commitment.",
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
            if _type != "public_key_commitment":
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

        # Communicates the individual public keys.
        logging.debug(
            "(%d): Communicating the individual public keys...",
            self._communicator.rank,
        )
        data_list = self._communicator.all_to_all(
            {
                "type": "public_key_reveal",
                "rank": self._communicator.rank,
                "public_key": my_public_key,
            },
        )
        logging.debug(
            "(%d): Communicated the individual public keys.",
            self._communicator.rank,
        )

        # Verifies the commitments of the distributed public keys.
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
            if _type != "public_key_reveal":
                raise RuntimeError("An invalid message type.")
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

            hasher = sha256()
            hasher.update(opponent_public_key.to_bytes(L // 8, "big"))
            if hasher.digest() != commitments[opponent_rank].to_bytes(
                32, "big"
            ):
                raise RuntimeError("An invalid commitment.")

            if self._individual_public_keys[opponent_rank] != -1:
                raise RuntimeError("An invalid message.")
            self._individual_public_keys[opponent_rank] = opponent_public_key

        self._global_public_key = 1
        for individual_public_key in self._individual_public_keys:
            if individual_public_key == -1:
                raise RuntimeError(
                    "Failed to communicate an opponent's public key."
                )
            self._global_public_key = (
                self._global_public_key * individual_public_key
            ) % p

    def __init__(self, communicator: Communicator) -> None:
        self._communicator = communicator
        self._el_gamal = ElGamal()

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

    def encrypt(self, m: int) -> tuple[ElGamalCiphertext, int]:
        _, _, p, q, _ = self._el_gamal.parameters
        if m <= 0 or m >= p:
            errmsg = "The plaintext must be in the range [0, p)."
            raise ValueError(errmsg)

        nonce = agree_on_random_integer(self._communicator, q)
        return self._el_gamal.encrypt(self._global_public_key, m, nonce)

    def _plaintext_equivalence_proof(
        self,
        prover_rank: int,
        original_ciphertext: ElGamalCiphertext,
        reencrypted_ciphertext: ElGamalCiphertext,
        nonce: int | None,
    ) -> bool:
        if prover_rank < 0 or prover_rank >= self._communicator.world_size:
            msg = f"{prover_rank}: An invalid rank."
            raise ValueError(msg)
        if (prover_rank == self._communicator.rank) != (nonce is not None):
            msg = "An invalid argument."
            raise ValueError(msg)

        logging.debug(
            "(%d): Executing a plaintext equivalence proof...",
            self._communicator.rank,
        )

        L, N, p, _, g = self._el_gamal.parameters
        a0, b0 = original_ciphertext
        a1, b1 = reencrypted_ciphertext
        a = (a1 * number.inverse(a0, p)) % p
        b = (b1 * number.inverse(b0, p)) % p

        z = agree_on_random_integer(self._communicator, 2**L)
        gg = (pow(self._global_public_key, z, p) * g) % p
        yy = (pow(b, z, p) * a) % p

        if prover_rank == self._communicator.rank:
            assert nonce is not None

            e = number.getRandomRange(0, 2**N)
            w = pow(gg, e, p)

            logging.debug(
                "(%d): Broadcasting a commitment for plaintext equivalence proof...",
                self._communicator.rank,
            )
            self._communicator.broadcast(
                {
                    "type": "plaintext_equivalence_proof_commitment",
                    "rank": self._communicator.rank,
                    "commitment": w,
                }
            )
            logging.debug(
                "(%d): Broadcasted a commitment for plaintext equivalence proof.",
                self._communicator.rank,
            )

            logging.debug(
                "(%d): Receiving challenges for plaintext equivalence proof...",
                self._communicator.rank,
            )
            data_list = self._communicator.gather()
            logging.debug(
                "(%d): Received challenges for plaintext equivalence proof.",
                self._communicator.rank,
            )
            challenges: list[int] = []
            for data in data_list:
                if not isinstance(data, dict):
                    raise RuntimeError("An invalid message.")
                if "type" not in data:
                    raise RuntimeError("An invalid message.")
                _type = data["type"]
                if not isinstance(_type, str):
                    raise RuntimeError("An invalid message.")
                if _type != "plaintext_equivalence_proof_challenge":
                    raise RuntimeError("An invalid message type.")
                if "rank" not in data:
                    raise RuntimeError("An invalid message.")
                opponent_rank = data["rank"]
                if not isinstance(opponent_rank, int):
                    raise RuntimeError("An invalid message.")
                if "challenge" not in data:
                    raise RuntimeError("An invalid message.")
                challenge = data["challenge"]
                if not isinstance(challenge, int):
                    raise RuntimeError("An invalid message.")
                challenges.append(challenge)

            responses: list[dict] = []
            for challenge in challenges:
                response = (nonce * challenge + e) % p
                responses.append(
                    {
                        "type": "plaintext_equivalence_proof_response",
                        "rank": self._communicator.rank,
                        "response": response,
                    },
                )

            logging.debug(
                "(%d): Sending responses for plaintext equivalence proof...",
                self._communicator.rank,
            )
            self._communicator.send_each_element(responses)
            logging.debug(
                "(%d): Sent responses for plaintext equivalence proof.",
                self._communicator.rank,
            )

            logging.debug(
                "(%d): Communicating the result of plaintext equivalence proof...",
                self._communicator.rank,
            )
            data_list = self._communicator.all_to_all(
                {
                    "type": "plaintext_equivalence_proof_result",
                    "rank": self._communicator.rank,
                    "result": True,
                },
            )
            logging.debug(
                "(%d): Communicated the result of plaintext equivalence proof.",
                self._communicator.rank,
            )
            result = True
            for data in data_list:
                if not isinstance(data, dict):
                    raise RuntimeError("An invalid message.")
                if "type" not in data:
                    raise RuntimeError("An invalid message.")
                _type = data["type"]
                if not isinstance(_type, str):
                    raise RuntimeError("An invalid message.")
                if _type != "plaintext_equivalence_proof_result":
                    raise RuntimeError("An invalid message type.")
                if "rank" not in data:
                    raise RuntimeError("An invalid message.")
                opponent_rank = data["rank"]
                if not isinstance(opponent_rank, int):
                    raise RuntimeError("An invalid message.")
                if "result" not in data:
                    raise RuntimeError("An invalid message.")
                result = data["result"]
                if not isinstance(result, bool):
                    raise RuntimeError("An invalid message.")
                if not result:
                    result = False

            logging.debug(
                "(%d): Executed a plaintext equivalence proof.",
                self._communicator.rank,
            )

            return result

        logging.debug(
            "(%d): Receiving a commitment for plaintext equivalence proof...",
            self._communicator.rank,
        )
        data = self._communicator.recv(prover_rank)
        logging.debug(
            "(%d): Received a commitment for plaintext equivalence proof.",
            self._communicator.rank,
        )
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "plaintext_equivalence_proof_commitment":
            raise RuntimeError("An invalid message type.")
        if "rank" not in data:
            raise RuntimeError("An invalid message.")
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if opponent_rank != prover_rank:
            raise RuntimeError("An invalid message.")
        if "commitment" not in data:
            raise RuntimeError("An invalid message.")
        w = data["commitment"]
        if not isinstance(w, int):
            raise RuntimeError("An invalid message.")

        challenge = number.getRandomNBitInteger(_CHALLENGE_BIT_LENGTH)
        logging.debug(
            "(%d): Sending a challenge for plaintext equivalence proof...",
            self._communicator.rank,
        )
        self._communicator.send(
            prover_rank,
            {
                "type": "plaintext_equivalence_proof_challenge",
                "rank": self._communicator.rank,
                "challenge": challenge,
            },
        )
        logging.debug(
            "(%d): Sent a challenge for plaintext equivalence proof.",
            self._communicator.rank,
        )

        logging.debug(
            "(%d): Receiving a response for plaintext equivalence proof...",
            self._communicator.rank,
        )
        data = self._communicator.recv(prover_rank)
        logging.debug(
            "(%d): Received a response for plaintext equivalence proof.",
            self._communicator.rank,
        )
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "plaintext_equivalence_proof_response":
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
        s = data["response"]
        if not isinstance(s, int):
            raise RuntimeError("An invalid message.")

        result = pow(gg, s, p) == (w * pow(yy, challenge, p)) % p

        logging.debug(
            "(%d): Communicating the result of plaintext equivalence proof...",
            self._communicator.rank,
        )
        data_list = self._communicator.all_to_all(
            {
                "type": "plaintext_equivalence_proof_result",
                "rank": self._communicator.rank,
                "result": result,
            },
        )
        logging.debug(
            "(%d): Communicated the result of plaintext equivalence proof.",
            self._communicator.rank,
        )
        result = True
        for data in data_list:
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "plaintext_equivalence_proof_result":
                raise RuntimeError("An invalid message type.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if "result" not in data:
                raise RuntimeError("An invalid message.")
            result = data["result"]
            if not isinstance(result, bool):
                raise RuntimeError("An invalid message.")
            if not result:
                result = False

        logging.debug(
            "(%d): Executed a plaintext equivalence proof.",
            self._communicator.rank,
        )

        return result

    def _disjunctive_schnorr_identification_protocol(
        self,
        prover_rank: int,
        gg0: int,
        yy0: int,
        nonce0: int | None,
        gg1: int,
        yy1: int,
        nonce1: int | None,
    ) -> bool:
        if prover_rank < 0 or prover_rank >= self._communicator.world_size:
            msg = f"{prover_rank}: An invalid rank."
            raise ValueError(msg)
        if (prover_rank == self._communicator.rank) != (
            nonce0 is not None or nonce1 is not None
        ):
            msg = "An invalid argument."
            raise ValueError(msg)
        if nonce0 is not None and nonce1 is not None:
            msg = "An invalid argument."
            raise ValueError(msg)

        logging.debug(
            "(%d): Executing disjunctive Schnorr identification protocol...",
            self._communicator.rank,
        )

        _, _, p, q, _ = self._el_gamal.parameters

        if prover_rank == self._communicator.rank:
            assert nonce0 is not None or nonce1 is not None

            challenges: list[int]
            responses: list[dict]

            if nonce0 is not None:
                assert nonce1 is None

                e0 = number.getRandomRange(1, q)
                s1 = number.getRandomRange(1, q)
                c1 = number.getRandomNBitInteger(_CHALLENGE_BIT_LENGTH)
                w0 = pow(gg0, e0, p)
                w1 = (number.inverse(pow(gg1, s1, p), p) * pow(yy1, c1, p)) % p

                logging.debug(
                    "(%d): Broadcasting commitments for disjunctive Schnorr identification protocol...",
                    self._communicator.rank,
                )
                self._communicator.broadcast(
                    {
                        "type": "disjunctive_schnorr_identification_protocol_commitments",
                        "rank": prover_rank,
                        "commitments": [w0, w1],
                    },
                )
                logging.debug(
                    "(%d): Broadcasted commitments for disjunctive Schnorr identification protocol.",
                    self._communicator.rank,
                )

                logging.debug(
                    "(%d): Receiving challenges for disjunctive Schnorr identification protocol...",
                    self._communicator.rank,
                )
                data_list = self._communicator.gather()
                logging.debug(
                    "(%d): Received challenges for disjunctive Schnorr identification protocol.",
                    self._communicator.rank,
                )
                challenges = []
                for data in data_list:
                    if not isinstance(data, dict):
                        raise RuntimeError("An invalid message.")
                    if "type" not in data:
                        raise RuntimeError("An invalid message.")
                    _type = data["type"]
                    if not isinstance(_type, str):
                        raise RuntimeError("An invalid message.")
                    if (
                        _type
                        != "disjunctive_schnorr_identification_protocol_challenge"
                    ):
                        raise RuntimeError("An invalid message type.")
                    if "rank" not in data:
                        raise RuntimeError("An invalid message.")
                    opponent_rank = data["rank"]
                    if not isinstance(opponent_rank, int):
                        raise RuntimeError("An invalid message.")
                    if "challenge" not in data:
                        raise RuntimeError("An invalid message.")
                    challenge = data["challenge"]
                    if not isinstance(challenge, int):
                        raise RuntimeError("An invalid message.")
                    challenges.append(challenge)

                responses = []
                for c in challenges:
                    if not isinstance(c, int):
                        raise RuntimeError("An invalid message.")
                    c0 = (c ^ c1) % q
                    s0 = ((c0 * nonce0) % q + (q - e0)) % q
                    response = [s0, s1, c0, c1]
                    responses.append(
                        {
                            "type": "disjunctive_schnorr_identification_protocol_response",
                            "rank": prover_rank,
                            "response": response,
                        },
                    )

                logging.debug(
                    "(%d): Sending responses for disjunctive Schnorr identification protocol...",
                    self._communicator.rank,
                )
                self._communicator.send_each_element(responses)
                logging.debug(
                    "(%d): Sent responses for disjunctive Schnorr identification protocol.",
                    self._communicator.rank,
                )
            else:
                assert nonce1 is not None

                e1 = number.getRandomRange(0, q)
                s0 = number.getRandomRange(0, q)
                c0 = number.getRandomNBitInteger(_CHALLENGE_BIT_LENGTH)
                w0 = (number.inverse(pow(gg0, s0, p), p) * pow(yy0, c0, p)) % p
                w1 = pow(gg1, e1, p)

                logging.debug(
                    "(%d): Broadcasting commitments for disjunctive Schnorr identification protocol...",
                    self._communicator.rank,
                )
                self._communicator.broadcast(
                    {
                        "type": "disjunctive_schnorr_identification_protocol_commitments",
                        "rank": prover_rank,
                        "commitments": [w0, w1],
                    },
                )
                logging.debug(
                    "(%d): Broadcasted commitments for disjunctive Schnorr identification protocol.",
                    self._communicator.rank,
                )

                logging.debug(
                    "(%d): Receiving challenges for disjunctive Schnorr identification protocol...",
                    self._communicator.rank,
                )
                data_list = self._communicator.gather()
                logging.debug(
                    "(%d): Received challenges for disjunctive Schnorr identification protocol.",
                    self._communicator.rank,
                )
                challenges = []
                for data in data_list:
                    if not isinstance(data, dict):
                        raise RuntimeError("An invalid message.")
                    if "type" not in data:
                        raise RuntimeError("An invalid message.")
                    _type = data["type"]
                    if not isinstance(_type, str):
                        raise RuntimeError("An invalid message.")
                    if (
                        _type
                        != "disjunctive_schnorr_identification_protocol_challenge"
                    ):
                        raise RuntimeError("An invalid message type.")
                    if "rank" not in data:
                        raise RuntimeError("An invalid message.")
                    opponent_rank = data["rank"]
                    if not isinstance(opponent_rank, int):
                        raise RuntimeError("An invalid message.")
                    if "challenge" not in data:
                        raise RuntimeError("An invalid message.")
                    challenge = data["challenge"]
                    if not isinstance(challenge, int):
                        raise RuntimeError("An invalid message.")
                    challenges.append(challenge)

                responses = []
                for c in challenges:
                    if not isinstance(c, int):
                        raise RuntimeError("An invalid message.")
                    c1 = (c ^ c0) % q
                    s1 = ((c1 * nonce1) % q + (q - e1)) % q
                    response = [s0, s1, c0, c1]
                    responses.append(
                        {
                            "type": "disjunctive_schnorr_identification_protocol_response",
                            "rank": prover_rank,
                            "response": response,
                        },
                    )

                logging.debug(
                    "(%d): Sending responses for disjunctive Schnorr identification protocol...",
                    self._communicator.rank,
                )
                self._communicator.send_each_element(responses)
                logging.debug(
                    "(%d): Sent responses for disjunctive Schnorr identification protocol.",
                    self._communicator.rank,
                )

            logging.debug(
                "(%d): Communicating the result of disjunctive Schnorr identification protocol...",
                self._communicator.rank,
            )
            data_list = self._communicator.all_to_all(
                {
                    "type": "disjunctive_schnorr_identification_protocol_result",
                    "rank": self._communicator.rank,
                    "result": True,
                },
            )
            logging.debug(
                "(%d): Communicated the result of disjunctive Schnorr identification protocol.",
                self._communicator.rank,
            )
            result = True
            for data in data_list:
                if not isinstance(data, dict):
                    raise RuntimeError("An invalid message.")
                if "type" not in data:
                    raise RuntimeError("An invalid message.")
                _type = data["type"]
                if not isinstance(_type, str):
                    raise RuntimeError("An invalid message.")
                if (
                    _type
                    != "disjunctive_schnorr_identification_protocol_result"
                ):
                    raise RuntimeError("An invalid message type.")
                if "rank" not in data:
                    raise RuntimeError("An invalid message.")
                opponent_rank = data["rank"]
                if not isinstance(opponent_rank, int):
                    raise RuntimeError("An invalid message.")
                if "result" not in data:
                    raise RuntimeError("An invalid message.")
                result = data["result"]
                if not isinstance(result, bool):
                    raise RuntimeError("An invalid message.")
                if not result:
                    result = False

            logging.debug(
                "(%d): Executed disjunctive Schnorr identification protocol.",
                self._communicator.rank,
            )

            return result

        assert nonce0 is None
        assert nonce1 is None

        logging.debug(
            "(%d): Receiving commitments for disjunctive Schnorr identification protocol...",
            self._communicator.rank,
        )
        data = self._communicator.recv(prover_rank)
        logging.debug(
            "(%d): Received commitments for disjunctive Schnorr identification protocol.",
            self._communicator.rank,
        )
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "disjunctive_schnorr_identification_protocol_commitments":
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
        commitments = data["commitments"]
        if not isinstance(commitments, list):
            raise RuntimeError("An invalid message.")
        if len(commitments) != 2:
            raise RuntimeError("An invalid message.")
        w0, w1 = commitments
        if not isinstance(w0, int):
            raise RuntimeError("An invalid message.")
        if not isinstance(w1, int):
            raise RuntimeError("An invalid message.")

        challenge = number.getRandomNBitInteger(_CHALLENGE_BIT_LENGTH)

        logging.debug(
            "(%d): Sending a challenge for disjunctive Schnorr identification protocol...",
            self._communicator.rank,
        )
        self._communicator.send(
            prover_rank,
            {
                "type": "disjunctive_schnorr_identification_protocol_challenge",
                "rank": prover_rank,
                "challenge": challenge,
            },
        )
        logging.debug(
            "(%d): Sent a challenge for disjunctive Schnorr identification protocol.",
            self._communicator.rank,
        )

        logging.debug(
            "(%d): Receiving a response for disjunctive Schnorr identification protocol...",
            self._communicator.rank,
        )
        data = self._communicator.recv(prover_rank)
        logging.debug(
            "(%d): Received a response for disjunctive Schnorr identification protocol.",
            self._communicator.rank,
        )
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "disjunctive_schnorr_identification_protocol_response":
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
        if not isinstance(response, list):
            msg = f"{type(response)}: An invalid message."
            raise RuntimeError(msg)
        if len(response) != 4:
            msg = f"{len(response)}: An invalid message."
            raise RuntimeError(msg)
        s0, s1, c0, c1 = response
        if not isinstance(s0, int):
            raise RuntimeError("An invalid message.")
        if not isinstance(s1, int):
            raise RuntimeError("An invalid message.")
        if not isinstance(c0, int):
            raise RuntimeError("An invalid message.")
        if not isinstance(c1, int):
            raise RuntimeError("An invalid message.")

        result = True
        if pow(yy0, c0, p) != (pow(gg0, s0, p) * w0) % p:
            result = False
        if pow(yy1, c1, p) != (pow(gg1, s1, p) * w1) % p:
            result = False

        logging.debug(
            "(%d): Communicating the result of disjunctive Schnorr identification protocol...",
            self._communicator.rank,
        )
        data_list = self._communicator.all_to_all(
            {
                "type": "disjunctive_schnorr_identification_protocol_result",
                "rank": self._communicator.rank,
                "result": result,
            },
        )
        logging.debug(
            "(%d): Communicated the result of disjunctive Schnorr identification protocol.",
            self._communicator.rank,
        )
        for data in data_list:
            if not isinstance(data, dict):
                raise RuntimeError("An invalid message.")
            if "type" not in data:
                raise RuntimeError("An invalid message.")
            _type = data["type"]
            if not isinstance(_type, str):
                raise RuntimeError("An invalid message.")
            if _type != "disjunctive_schnorr_identification_protocol_result":
                raise RuntimeError("An invalid message type.")
            if "rank" not in data:
                raise RuntimeError("An invalid message.")
            opponent_rank = data["rank"]
            if not isinstance(opponent_rank, int):
                raise RuntimeError("An invalid message.")
            if "result" not in data:
                raise RuntimeError("An invalid message.")
            result = data["result"]
            if not isinstance(result, bool):
                raise RuntimeError("An invalid message.")
            if not result:
                logging.debug(
                    "(%d): Executed disjunctive Schnorr identification protocol.",
                    self._communicator.rank,
                )
                return False

        logging.debug(
            "(%d): Executed disjunctive Schnorr identification protocol.",
            self._communicator.rank,
        )
        return result

    def _disjunctive_plaintext_equivalence_proof(
        self,
        prover_rank: int,
        reencrypted_ciphertext: ElGamalCiphertext,
        ciphertext0: ElGamalCiphertext,
        nonce0: int | None,
        ciphertext1: ElGamalCiphertext,
        nonce1: int | None,
    ) -> bool:
        if prover_rank < 0 or prover_rank >= self._communicator.world_size:
            msg = f"{prover_rank}: An invalid rank."
            raise ValueError(msg)
        if (prover_rank == self._communicator.rank) != (
            nonce0 is not None or nonce1 is not None
        ):
            msg = "An invalid argument."
            raise ValueError(msg)
        if nonce0 is not None and nonce1 is not None:
            msg = "An invalid argument."
            raise ValueError(msg)

        logging.debug(
            "(%d): Executing disjunctive plaintext equivalence proof...",
            self._communicator.rank,
        )

        L, _, p, _, g = self._el_gamal.parameters
        aa0, bb0 = reencrypted_ciphertext
        aa1, bb1 = ciphertext0
        aa2, bb2 = ciphertext1

        a1 = (aa0 * number.inverse(aa1, p)) % p
        b1 = (bb0 * number.inverse(bb1, p)) % p
        a2 = (aa0 * number.inverse(aa2, p)) % p
        b2 = (bb0 * number.inverse(bb2, p)) % p

        z0 = agree_on_random_integer(self._communicator, 2**L)
        gg0 = (pow(self._global_public_key, z0, p) * g) % p
        yy0 = (pow(b1, z0, p) * a1) % p
        if nonce0 is not None:
            assert pow(gg0, nonce0, p) == yy0

        z1 = agree_on_random_integer(self._communicator, 2**L)
        gg1 = (pow(self._global_public_key, z1, p) * g) % p
        yy1 = (pow(b2, z1, p) * a2) % p
        if nonce1 is not None:
            assert pow(gg1, nonce1, p) == yy1

        result = self._disjunctive_schnorr_identification_protocol(
            prover_rank,
            gg0,
            yy0,
            nonce0,
            gg1,
            yy1,
            nonce1,
        )

        logging.debug(
            "(%d): Executed disjunctive plaintext equivalence proof.",
            self._communicator.rank,
        )

        return result

    def oblivious_swap(
        self,
        rank: int,
        ciphertext0: ElGamalCiphertext,
        ciphertext1: ElGamalCiphertext,
        flag: bool,
    ) -> tuple[ElGamalCiphertext, ElGamalCiphertext]:
        if rank < 0 or rank >= self._communicator.world_size:
            msg = f"{rank}: An invalid rank."
            raise ValueError(msg)
        if rank != self._communicator.rank and flag:
            msg = "An invalid argument."
            raise ValueError(msg)

        logging.debug(
            "(%d): Executing Millimix primitive...", self._communicator.rank
        )

        _, _, p, q, _ = self._el_gamal.parameters
        original_ciphertexts_product = (
            (ciphertext0[0] * ciphertext1[0]) % p,
            (ciphertext0[1] * ciphertext1[1]) % p,
        )

        if rank == self._communicator.rank:
            if not flag:
                (
                    reencrypted_ciphertext0,
                    nonce0,
                ) = self._el_gamal.reencrypt(
                    self._global_public_key, ciphertext0
                )
                (
                    reencrypted_ciphertext1,
                    nonce1,
                ) = self._el_gamal.reencrypt(
                    self._global_public_key, ciphertext1
                )
            else:
                (
                    reencrypted_ciphertext0,
                    nonce0,
                ) = self._el_gamal.reencrypt(
                    self._global_public_key, ciphertext1
                )
                (
                    reencrypted_ciphertext1,
                    nonce1,
                ) = self._el_gamal.reencrypt(
                    self._global_public_key, ciphertext0
                )

            logging.debug(
                "(%d): Broadcasting reencrypted ciphertexts...",
                self._communicator.rank,
            )
            self._communicator.broadcast(
                {
                    "type": "millimix_primitive_reencryption",
                    "rank": self._communicator.rank,
                    "reencrypted_ciphertexts": [
                        [
                            reencrypted_ciphertext0[0],
                            reencrypted_ciphertext0[1],
                        ],
                        [
                            reencrypted_ciphertext1[0],
                            reencrypted_ciphertext1[1],
                        ],
                    ],
                }
            )
            logging.debug(
                "(%d): Broadcasted reencrypted ciphertexts.",
                self._communicator.rank,
            )

            if not flag:
                result = self._disjunctive_plaintext_equivalence_proof(
                    rank,
                    reencrypted_ciphertext0,
                    ciphertext0,
                    nonce0,
                    ciphertext1,
                    None,
                )
            else:
                result = self._disjunctive_plaintext_equivalence_proof(
                    rank,
                    reencrypted_ciphertext0,
                    ciphertext0,
                    None,
                    ciphertext1,
                    nonce0,
                )
            if not result:
                raise RuntimeError("An invalid proof.")

            reencrypted_ciphertexts_product = (
                (reencrypted_ciphertext0[0] * reencrypted_ciphertext1[0]) % p,
                (reencrypted_ciphertext0[1] * reencrypted_ciphertext1[1]) % p,
            )
            result = self._plaintext_equivalence_proof(
                rank,
                original_ciphertexts_product,
                reencrypted_ciphertexts_product,
                (nonce0 + nonce1) % q,
            )
            if not result:
                raise RuntimeError("An invalid proof.")

            logging.debug(
                "(%d): Executed Millimix primitive.", self._communicator.rank
            )

            return (reencrypted_ciphertext0, reencrypted_ciphertext1)

        logging.debug(
            "(%d): Receiving reencrypted ciphertexts...",
            self._communicator.rank,
        )
        data = self._communicator.recv(rank)
        logging.debug(
            "(%d): Received reencrypted ciphertexts.", self._communicator.rank
        )
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "millimix_primitive_reencryption":
            raise RuntimeError("An invalid message type.")
        if "rank" not in data:
            raise RuntimeError("An invalid message.")
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if opponent_rank != rank:
            raise RuntimeError("An invalid message.")
        if "reencrypted_ciphertexts" not in data:
            raise RuntimeError("An invalid message.")
        reencrypted_ciphertexts = data["reencrypted_ciphertexts"]
        if not isinstance(reencrypted_ciphertexts, list):
            raise RuntimeError("An invalid message.")
        if len(reencrypted_ciphertexts) != 2:
            raise RuntimeError("An invalid message.")
        for reencrypted_ciphertext in reencrypted_ciphertexts:
            if not isinstance(reencrypted_ciphertext, list):
                raise RuntimeError("An invalid message.")
            if len(reencrypted_ciphertext) != 2:
                raise RuntimeError("An invalid message.")
            for c in reencrypted_ciphertext:
                if not isinstance(c, int):
                    raise RuntimeError("An invalid message.")

        reencrypted_ciphertext0 = ElGamalCiphertext(
            (
                reencrypted_ciphertexts[0][0],
                reencrypted_ciphertexts[0][1],
            )
        )
        reencrypted_ciphertext1 = ElGamalCiphertext(
            (
                reencrypted_ciphertexts[1][0],
                reencrypted_ciphertexts[1][1],
            )
        )

        result = self._disjunctive_plaintext_equivalence_proof(
            rank,
            reencrypted_ciphertext0,
            ciphertext0,
            None,
            ciphertext1,
            None,
        )
        if not result:
            raise RuntimeError("An invalid proof.")

        reencrypted_ciphertexts_product = (
            (reencrypted_ciphertext0[0] * reencrypted_ciphertext1[0]) % p,
            (reencrypted_ciphertext0[1] * reencrypted_ciphertext1[1]) % p,
        )
        result = self._plaintext_equivalence_proof(
            rank,
            original_ciphertexts_product,
            reencrypted_ciphertexts_product,
            None,
        )
        if not result:
            raise RuntimeError("An invalid proof.")

        logging.debug(
            "(%d): Executed Millimix primitive.", self._communicator.rank
        )

        return (reencrypted_ciphertext0, reencrypted_ciphertext1)

    def _millimix(self, permutation: list[int], ciphertexts: list[ElGamalCiphertext]) -> None:
        if len(ciphertexts) != len(permutation):
            errmsg = "The length of ciphertexts and permutation must be the same."
            raise ValueError(errmsg)

        permutation = permutation.copy()

        if len(ciphertexts) <= 1:
            return

        es: list[list[int]] = [[] for _ in range(len(ciphertexts) // 2)]
        for i in range(len(ciphertexts) // 2):
            index0 = i * 2
            u = permutation[index0] // 2
            index1 = i * 2 + 1
            v = permutation[index1] // 2
            es[u].append(i)
            es[v].append(i)
        s: set[int] = set()
        flags = [False for _ in range(len(ciphertexts) // 2)]
        for i in range(len(ciphertexts) // 2):
            index0 = i * 2
            index1 = i * 2 + 1
            if permutation[index0] not in (0, 1) and permutation[index1] not in (0, 1):
                continue
            if permutation[index0] == 1 or permutation[index1] == 0:
                u = permutation[index1] // 2
                v = permutation[index0] // 2
                flags[i] = True
            else:
                u = permutation[index0] // 2
                v = permutation[index1] // 2
            s.add(i)
            while v != u:
                if es[v][0] == i:
                    j = es[v][1]
                else:
                    assert es[v][1] == i
                    j = es[v][0]
                if permutation[j * 2] // 2 == v:
                    w = permutation[j * 2 + 1] // 2
                else:
                    assert permutation[j * 2 + 1] // 2 == v
                    w = permutation[j * 2] // 2
                    flags[j] = True
                s.add(j)
                v = w
                i = j
        for i in range(len(ciphertexts) // 2):
            if i in s:
                continue
            index0 = i * 2
            index1 = i * 2 + 1
            if permutation[index0] in (0, 1) or permutation[index1] in (0, 1):
                continue
            u = permutation[index0] // 2
            v = permutation[index1] // 2
            s.add(i)
            while v != u:
                if es[v][0] == i:
                    j = es[v][1]
                else:
                    assert es[v][1] == i
                    j = es[v][0]
                if permutation[j * 2] // 2 == v:
                    w = permutation[j * 2 + 1] // 2
                else:
                    assert permutation[j * 2 + 1] // 2 == v
                    w = permutation[j * 2] // 2
                    flags[j] = True
                s.add(j)
                v = w
                i = j
        for i in range(len(ciphertexts) // 2):
            index0 = i * 2
            index1 = i * 2 + 1
            if flags[i]:
                permutation[index0], permutation[index1] = permutation[index1], permutation[index0]
            ciphertexts[index0], ciphertexts[index1] = self.oblivious_swap(
                self._communicator.rank,
                ciphertexts[index0],
                ciphertexts[index1],
                flags[i],
            )

        ciphertexts0: list[ElGamalCiphertext] = []
        permutation0: list[int] = []
        for i in range(len(ciphertexts) // 2):
            ciphertexts0.append(ciphertexts[i * 2])
            permutation0.append(permutation[i * 2] // 2)
        self._millimix(permutation0, ciphertexts0)
        new_permutation0 = [-1 for _ in range(len(ciphertexts) // 2)]
        for i in range(len(ciphertexts) // 2):
            ciphertexts[i * 2] = ciphertexts0[i]
            new_permutation0[permutation0[i]] = permutation[i * 2]

        ciphertexts1: list[ElGamalCiphertext] = []
        permutation1: list[int] = []
        for i in range(len(ciphertexts) // 2):
            ciphertexts1.append(ciphertexts[i * 2 + 1])
            permutation1.append(permutation[i * 2 + 1] // 2)
        self._millimix(permutation1, ciphertexts1)
        new_permutation1 = [-1 for _ in range(len(ciphertexts) // 2)]
        for i in range(len(ciphertexts) // 2):
            ciphertexts[i * 2 + 1] = ciphertexts1[i]
            new_permutation1[permutation1[i]] = permutation[i * 2 + 1]

        for i in range(1, len(ciphertexts) // 2):
            if new_permutation0[i] == i * 2:
                assert new_permutation1[i] == i * 2 + 1
                flag = False
            else:
                assert new_permutation0[i] == i * 2 + 1
                assert new_permutation1[i] == i * 2
                flag = True
            index0 = i * 2
            index1 = i * 2 + 1
            ciphertexts[index0], ciphertexts[index1] = self.oblivious_swap(
                self._communicator.rank,
                ciphertexts[index0],
                ciphertexts[index1],
                flag,
            )

    def millimix(self, rank: int, ciphertexts: list[ElGamalCiphertext]) -> None:
        if rank < 0 or rank >= self._communicator.world_size:
            errmsg = f"{rank}: An invalid rank."
            raise ValueError(errmsg)

        logging.debug(
            "(%d): Executing millimix...", self._communicator.rank
        )

        if len(ciphertexts) <= 1:
            logging.debug(
                "(%d): Executed millimix.", self._communicator.rank
            )

            return

        original_size = len(ciphertexts)
        power_of_two = 1
        while power_of_two < original_size:
            power_of_two *= 2
        for _ in range(power_of_two - original_size):
            padding, _ = self.encrypt(1)
            ciphertexts.append(padding)

        if rank == self._communicator.rank:
            permutation = [i for i in range(original_size)]
            random.shuffle(permutation)
            for i in range(original_size, len(ciphertexts)):
                permutation.append(i)

            self._millimix(permutation, ciphertexts)

            while len(ciphertexts) > original_size:
                ciphertexts.pop()

            logging.debug(
                "(%d): Executed millimix.", self._communicator.rank
            )

            return

        for i in range(len(ciphertexts) // 2):
            index0 = i * 2
            index1 = i * 2 + 1
            ciphertexts[index0], ciphertexts[index1] = self.oblivious_swap(
                rank,
                ciphertexts[index0],
                ciphertexts[index1],
                False,
            )

        ciphertexts0: list[ElGamalCiphertext] = []
        for i in range(len(ciphertexts) // 2):
            ciphertexts0.append(ciphertexts[i * 2])
        self.millimix(rank, ciphertexts0)
        for i in range(len(ciphertexts) // 2):
            ciphertexts[i * 2] = ciphertexts0[i]

        ciphertexts1: list[ElGamalCiphertext] = []
        for i in range(len(ciphertexts) // 2):
            ciphertexts1.append(ciphertexts[i * 2 + 1])
        self.millimix(rank, ciphertexts1)
        for i in range(len(ciphertexts) // 2):
            ciphertexts[i * 2 + 1] = ciphertexts1[i]

        for i in range(1, len(ciphertexts) // 2):
            index0 = i * 2
            index1 = i * 2 + 1
            ciphertexts[index0], ciphertexts[index1] = self.oblivious_swap(
                rank,
                ciphertexts[index0],
                ciphertexts[index1],
                False,
            )

        while len(ciphertexts) > original_size:
            ciphertexts.pop()

        logging.debug("(%d): Executed millimix.", self._communicator.rank)

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


def _process_main(local_urls: list[str], opponent_urls: list[str]) -> None:
    logging.basicConfig(level=logging.DEBUG)

    communicator = Communicator(local_urls, opponent_urls)
    cryptosystem = Cryptosystem(communicator)

    plaintext = 0xDEADBEEF
    ciphertext, _ = cryptosystem.encrypt(plaintext)

    for rank in range(communicator.world_size):
        decrypted_plaintext = cryptosystem.decrypt_privately(rank, ciphertext)
        if rank == communicator.rank:
            assert decrypted_plaintext == plaintext
        else:
            assert decrypted_plaintext is None

    plaintexts = [i for i in range(1, 136 + 1)]
    ciphertexts: list[ElGamalCiphertext] = []
    for plaintext in plaintexts:
        ciphertext, _ = cryptosystem.encrypt(plaintext)
        ciphertexts.append(ciphertext)

    for rank in range(communicator.world_size):
        cryptosystem.millimix(rank, ciphertexts)

    decrypted_plaintexts: list[int] = []
    for ciphertext in ciphertexts:
        decrypted_plaintext = cryptosystem.decrypt_privately(0, ciphertext)
        if cryptosystem.communicator.rank != 0:
            assert decrypted_plaintext is None
            continue
        assert decrypted_plaintext is not None
        decrypted_plaintexts.append(decrypted_plaintext)
    if cryptosystem.communicator.rank == 0:
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
