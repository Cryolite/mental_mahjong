from hashlib import sha256
import logging
import random
from Crypto.Util import number
from mental_mahjong.core import Communicator


def agree_on_random_integer(
    communicator: Communicator, upper_bound: int
) -> int:
    """Agrees on a random integer.

    This function implements a cooperation protocol among participants
    of the communicator. It ensures that all participants agree on a
    random integer within the specified range [0, upper_bound).

    Args:
        communicator: Facilitates the cooperation among its
            participants.
        upper_bound: The exclusive upper bound of the random integer to
            be agreed upon. Must be a positive integer.

    Returns:
        The agreed-upon random integer within the range [0, upper_bound).
    """
    upper_bound_bit_length = 3072
    if upper_bound > 2**upper_bound_bit_length:
        msg = f"{upper_bound}: The upper bound is too large."
        raise ValueError(msg)

    world_size = communicator.world_size
    rank = communicator.rank

    logging.debug("(%d): Agreeing on an integer...", rank)

    # Generates a random integer.
    integer = number.getRandomRange(0, upper_bound)

    # Generates a commitment of the random integer.
    hasher = sha256()
    hasher.update(integer.to_bytes(upper_bound_bit_length // 8, "big"))
    salt = number.getRandomNBitInteger(256)
    hasher.update(salt.to_bytes(32, "big"))
    commitment = int.from_bytes(hasher.digest(), "big")

    # Communicates the commitments of the random integer.
    data_list = communicator.all_to_all(
        {
            "type": "integer_commitment",
            "rank": rank,
            "commitment": commitment,
        },
    )

    commitments: list[int] = [-1 for _ in range(world_size)]
    commitments[rank] = commitment
    for data in data_list:
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")

        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "integer_commitment":
            raise RuntimeError("An invalid message type.")

        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if opponent_rank < 0 or opponent_rank >= world_size:
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

    # Communicates the random integers and the salts.
    data_list = communicator.all_to_all(
        {
            "type": "integer_reveal",
            "rank": rank,
            "integer": integer,
            "salt": salt,
        },
    )

    # Verifies the commitments of the random integers.
    integers: list[int] = [-1 for _ in range(world_size)]
    integers[rank] = integer
    for data in data_list:
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "integer_reveal":
            raise RuntimeError("An invalid message type.")
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if opponent_rank < 0 or opponent_rank >= world_size:
            raise RuntimeError("An invalid message.")
        opponent_integer = data["integer"]
        if not isinstance(opponent_integer, int):
            raise RuntimeError("An invalid message.")
        if opponent_integer < 0 or opponent_integer >= upper_bound:
            raise RuntimeError("An invalid message.")
        opponent_salt = data["salt"]
        if not isinstance(opponent_salt, int):
            raise RuntimeError("An invalid message.")

        hasher = sha256()
        hasher.update(
            opponent_integer.to_bytes(upper_bound_bit_length // 8, "big")
        )
        hasher.update(opponent_salt.to_bytes(32, "big"))
        if hasher.digest() != commitments[opponent_rank].to_bytes(32, "big"):
            raise RuntimeError("An invalid commitment.")

        integers[opponent_rank] = opponent_integer
    result = 0
    for i in integers:
        if i == -1:
            raise RuntimeError("An invalid message.")
        result = (result + i) % upper_bound

    logging.debug("(%d): Agreed on an integer.", rank)

    return result


def agree_on_seats(communicator: Communicator) -> list[int]:
    """Agrees on seats.

    This function implements a cooperation protocol among participants
    of the communicator. It ensures that all participants agree on
    seat arrangements.

    Args:
        communicator: Facilitates the cooperation among its
            participants.

    Returns:
        A list of seats. Each seat is represented by an integer
        between 0 and the number of participants minus one.
    """
    logging.debug("(%d): Agreeing on seats...", communicator.rank)

    if communicator.world_size not in [3, 4]:
        raise ValueError("The number of players is invalid.")

    # All players generate a permutation of seats. The actual seats
    # are determined by the composition of these permutations.
    permutations: list[list[int]] = [[] for _ in range(communicator.world_size)]

    # Generates a permutation of seats and broadcast its
    # commitment.
    my_permutation = [i for i in range(communicator.world_size)]
    random.shuffle(my_permutation)
    permutations[communicator.rank] = my_permutation

    # Generates a salt for the permutation of seats.
    my_salt = number.getRandomNBitInteger(256)

    # Generates a commitment of the permutation of seats.
    hasher = sha256()
    hasher.update(str(my_permutation).encode("UTF-8"))
    hasher.update(my_salt.to_bytes(32, "big"))
    my_commitment = int.from_bytes(hasher.digest(), "big")

    # Communicates the commitments of the permutations of seats.
    logging.debug(
        "(%d): Communicating seat permutation commitments...",
        communicator.rank,
    )
    data_list = communicator.all_to_all(
        {
            "type": "seat_permutation_commitment",
            "rank": communicator.rank,
            "commitment": my_commitment,
        },
    )
    logging.debug(
        "(%d): Communicated seat permutation commitments.", communicator.rank
    )
    commitments: list[int] = [-1 for _ in range(communicator.world_size)]
    commitments[communicator.rank] = my_commitment
    for data in data_list:
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "seat_permutation_commitment":
            raise RuntimeError("An invalid message type.")
        if "rank" not in data:
            raise RuntimeError("An invalid message.")
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if opponent_rank < 0 or opponent_rank >= communicator.world_size:
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

    # Communicates the permutations of seats.
    logging.debug(
        "(%d): Communicating seat permutations...",
        communicator.rank,
    )
    data_list = communicator.all_to_all(
        {
            "type": "seat_permutation_reveal",
            "rank": communicator.rank,
            "permutation": my_permutation,
            "salt": my_salt,
        },
    )
    logging.debug("(%d): Communicated seat permutations.", communicator.rank)

    # Verifies the commitments of the permutations of seats.
    for data in data_list:
        if not isinstance(data, dict):
            raise RuntimeError("An invalid message.")
        if "type" not in data:
            raise RuntimeError("An invalid message.")
        _type = data["type"]
        if not isinstance(_type, str):
            raise RuntimeError("An invalid message.")
        if _type != "seat_permutation_reveal":
            raise RuntimeError("An invalid message type.")
        if "rank" not in data:
            raise RuntimeError("An invalid message.")
        opponent_rank = data["rank"]
        if not isinstance(opponent_rank, int):
            raise RuntimeError("An invalid message.")
        if "permutation" not in data:
            raise RuntimeError("An invalid message.")
        if len(permutations[opponent_rank]) != 0:
            raise RuntimeError("An invalid message.")
        opponent_permutation = data["permutation"]
        if not isinstance(opponent_permutation, list):
            raise RuntimeError("An invalid message.")
        if len(opponent_permutation) != 4:
            raise RuntimeError("An invalid message.")
        if not all(isinstance(i, int) for i in opponent_permutation):
            raise RuntimeError("An invalid message.")
        if "salt" not in data:
            raise RuntimeError("An invalid message.")
        opponent_salt = data["salt"]
        if not isinstance(opponent_salt, int):
            raise RuntimeError("An invalid message.")

        permutations[opponent_rank] = opponent_permutation

        hasher = sha256()
        hasher.update(str(opponent_permutation).encode("UTF-8"))
        hasher.update(opponent_salt.to_bytes(32, "big"))
        if hasher.digest() != commitments[opponent_rank].to_bytes(32, "big"):
            raise RuntimeError("An invalid commitment.")

    # Determines the actual seats.
    seats = [i for i in range(communicator.world_size)]
    for i in range(communicator.world_size):
        for j in range(communicator.world_size):
            seats[j] = permutations[i][seats[j]]

    logging.debug("(%d): Agreed on seats.", communicator.rank)

    return seats
