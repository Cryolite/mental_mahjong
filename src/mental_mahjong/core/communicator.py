import json
from typing import Any, Final
from Crypto.Util import number
import zmq


class Communicator:
    def _agree_on_ranks(self) -> None:
        assert len(self._server_sockets) == len(self._client_sockets)

        _BIT_LENGTH: Final = 1024
        numbers: list[int] = []
        while True:
            my_number = number.getRandomRange(0, 2 ** _BIT_LENGTH)
            numbers.append(my_number)

            for client_socket in self._client_sockets:
                client_socket.send(my_number.to_bytes(_BIT_LENGTH // 8, "big"))

            for server_socket in self._server_sockets:
                data = server_socket.recv()
                opponent_number = int.from_bytes(data, "big")
                numbers.append(opponent_number)
                server_socket.send(b"OK")

            for client_socket in self._client_sockets:
                data = client_socket.recv()
                if data != b"OK":
                    raise RuntimeError("An invalid message.")

            if len(set(numbers)) == len(self._server_sockets) + 1:
                break

            numbers.clear()

        self._ranks = [0 for _ in enumerate(numbers)]
        for i, _ in enumerate(numbers):
            for j, _ in enumerate(numbers):
                if numbers[i] > numbers[j]:
                    self._ranks[i] += 1

        self._rank_to_index: list[int] = [-1 for _ in enumerate(numbers)]
        for i, r in enumerate(self._ranks):
            self._rank_to_index[r] = i

    def __init__(
        self, local_urls: list[str], opponent_urls: list[str]
    ) -> None:
        """Creates a new instance of `Communicator`.

        This function implements a cooperation protocol among multiple
        processes. The processes agree on their ranks and then they can
        communicate with each other.

        Args:
            local_urls: A list of URLs for the local processes.
            opponent_urls: A list of URLs for the opponent processes.
        """
        if len(local_urls) != len(opponent_urls):
            raise ValueError("The number of local URLs and opponent URLs must be the same.")

        ctx = zmq.Context()
        self._server_sockets: list[zmq.Socket] = []
        self._client_sockets: list[zmq.Socket] = []
        for local_url, opponent_url in zip(local_urls, opponent_urls):
            server_socket = ctx.socket(zmq.REP)
            server_socket.bind(local_url)
            self._server_sockets.append(server_socket)
            client_socket = ctx.socket(zmq.REQ)
            client_socket.connect(opponent_url)
            self._client_sockets.append(client_socket)

        self._agree_on_ranks()

    def __del__(self) -> None:
        for server_socket in self._server_sockets:
            server_socket.close()
        for client_socket in self._client_sockets:
            client_socket.close()

    @property
    def world_size(self) -> int:
        """The number of processes in the world."""
        assert len(self._server_sockets) + 1 == len(self._ranks)
        assert len(self._client_sockets) + 1 == len(self._ranks)
        return len(self._ranks)

    @property
    def rank(self) -> int:
        """The rank of the current process."""
        return self._ranks[0]

    def send(self, rank: int, data: Any) -> None:
        """Sends a message to the process with the specified rank.

        Args:
            rank: The rank of the process to send the message to.
            data: The message to send.
        """
        if rank < 0 or rank >= self.world_size:
            raise ValueError(f"{rank}: An invalid rank.")
        if rank == self.rank:
            raise ValueError("Trying to send a message to myself.")

        index = self._rank_to_index[rank]
        assert index != 0
        index -= 1
        json_data = json.dumps(data)
        byte_data = json_data.encode("UTF-8")
        self._client_sockets[index].send(byte_data)
        byte_data = self._client_sockets[index].recv()
        if byte_data != b"OK":
            raise RuntimeError("An invalid message.")

    def send_each_element(self, data_list: list[Any]) -> None:
        """Sends each message to the corresponding process.

        This function is the inverse of `gather`. It sends each message
        to the corresponding process.

        Args:
            data_list: A list of messages to send.
        """
        if len(data_list) != self.world_size - 1:
            raise ValueError("The length of `data_list` must be `world_size - 1`.")

        for client_socket, data in zip(self._client_sockets, data_list):
            json_data = json.dumps(data)
            byte_data = json_data.encode("UTF-8")
            client_socket.send(byte_data)

        for client_socket in self._client_sockets:
            byte_data = client_socket.recv()
            if byte_data != b"OK":
                raise RuntimeError("An invalid message.")

    def broadcast(self, data: Any) -> None:
        """Broadcasts a message to all processes.

        Args:
            data: The message to broadcast.
        """
        json_data = json.dumps(data)
        byte_data = json_data.encode("UTF-8")
        for client_socket in self._client_sockets:
            client_socket.send(byte_data)

        for client_socket in self._client_sockets:
            byte_data = client_socket.recv()
            if byte_data != b"OK":
                raise RuntimeError("An invalid message.")

    def recv(self, rank: int) -> Any:
        """Receives a message from the process with the specified rank.

        Args:
            rank: The rank of the process to receive the message from.

        Returns:
            The received message.
        """
        if rank < 0 or rank >= self.world_size:
            raise ValueError(f"{rank}: An invalid rank.")
        if rank == self.rank:
            raise ValueError("Trying to receive a message from myself.")

        index = self._rank_to_index[rank]
        assert index != 0
        index -= 1
        byte_data = self._server_sockets[index].recv()
        json_data = byte_data.decode("UTF-8")
        data = json.loads(json_data)
        self._server_sockets[index].send(b"OK")

        return data

    def gather(self) -> list[Any]:
        """Gathers messages from all processes.

        Returns:
            A list of received messages.
        """
        data_list: list[Any] = []
        for server_socket in self._server_sockets:
            byte_data = server_socket.recv()
            json_data = byte_data.decode("UTF-8")
            data = json.loads(json_data)
            data_list.append(data)

            server_socket.send(b"OK")

        return data_list

    def all_to_all(self, data: Any) -> list[Any]:
        """Sends a message to and receives a message from all processes.

        Args:
            data: The message to send.

        Returns:
            A list of received messages.
        """
        json_data = json.dumps(data)
        byte_data = json_data.encode("UTF-8")
        for client_socket in self._client_sockets:
            client_socket.send(byte_data)

        data_list: list[Any] = []
        for server_socket in self._server_sockets:
            byte_data = server_socket.recv()
            json_data = byte_data.decode("UTF-8")
            data = json.loads(json_data)
            data_list.append(data)
            server_socket.send(b"OK")

        for client_socket in self._client_sockets:
            byte_data = client_socket.recv()
            if byte_data != b"OK":
                raise RuntimeError("An invalid message.")

        return data_list
