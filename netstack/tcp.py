"""TCP connection state machine (RFC 793).

Implements the classic three-way handshake and FIN teardown as a
pure state machine over :class:`netstack.packets.TCPSegment` objects —
no sockets, no real network.  Two instances can be wired together to
simulate a full client<->server conversation (see ``cli handshake``
and the tests).

Client (active open)::

    CLOSED --connect()--> SYN_SENT --SYN+ACK--> ESTABLISHED
                  (sends SYN)        (sends ACK)

Server (passive open)::

    CLOSED --listen()--> LISTEN --SYN--> SYN_RCVD --ACK--> ESTABLISHED
                                     (sends SYN+ACK)

Teardown (either side)::

    ESTABLISHED --close()--> FIN_WAIT_1 --ACK--> FIN_WAIT_2
                  (sends FIN)        --FIN--> TIME_WAIT --timeout--> CLOSED
    ESTABLISHED --FIN received--> CLOSE_WAIT --close()--> LAST_ACK
                  (sends ACK)                        (sends FIN)
                                                     --ACK--> CLOSED

Sequence numbers start from a fixed initial value by default so
simulations are deterministic; pass ``isn`` to vary them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .packets import FLAG_ACK, FLAG_FIN, FLAG_SYN, TCPSegment, flag_names

# States (RFC 793, section 3.2)
CLOSED = "CLOSED"
LISTEN = "LISTEN"
SYN_SENT = "SYN_SENT"
SYN_RCVD = "SYN_RCVD"
ESTABLISHED = "ESTABLISHED"
FIN_WAIT_1 = "FIN_WAIT_1"
FIN_WAIT_2 = "FIN_WAIT_2"
CLOSE_WAIT = "CLOSE_WAIT"
CLOSING = "CLOSING"
LAST_ACK = "LAST_ACK"
TIME_WAIT = "TIME_WAIT"


@dataclass
class TcpEvent:
    """One entry in the connection's trace log."""
    action: str
    detail: str = ""


class TcpConnection:
    """One endpoint of a TCP connection."""

    def __init__(self, local_port: int, remote_port: int = 0, isn: int = 1000) -> None:
        self.local_port = local_port
        self.remote_port = remote_port
        self.state = CLOSED
        self.isn = isn & 0xFFFFFFFF
        self.next_seq = self.isn          # next sequence number to send
        self.next_ack = 0                 # next sequence number expected
        self.trace: list[TcpEvent] = []
        self._log("init", f"state={CLOSED} isn={self.isn}")

    # -- helpers ------------------------------------------------------
    def _log(self, action: str, detail: str = "") -> None:
        self.trace.append(TcpEvent(action, detail))

    def _segment(self, flags: int, seq: int, ack: int = 0) -> TCPSegment:
        return TCPSegment(
            src_port=self.local_port,
            dst_port=self.remote_port,
            seq=seq,
            ack=ack,
            flags=flags,
        )

    def _transition(self, new_state: str, why: str) -> None:
        self._log("state", f"{self.state} -> {new_state} ({why})")
        self.state = new_state

    # -- passive / active open ----------------------------------------
    def listen(self) -> None:
        """Passive open: CLOSED -> LISTEN (server side)."""
        if self.state != CLOSED:
            raise ValueError(f"listen() only valid from CLOSED, now {self.state}")
        self._transition(LISTEN, "passive open")

    def connect(self) -> TCPSegment:
        """Active open: CLOSED -> SYN_SENT, returns the SYN segment."""
        if self.state != CLOSED:
            raise ValueError(f"connect() only valid from CLOSED, now {self.state}")
        self.next_seq = self.isn + 1  # SYN consumes one sequence number
        self._transition(SYN_SENT, "active open")
        seg = self._segment(FLAG_SYN, self.isn)
        self._log("send", f"SYN seq={self.isn}")
        return seg

    # -- incoming segments --------------------------------------------
    def on_segment(self, seg: TCPSegment) -> TCPSegment | None:
        """Feed an incoming segment; returns a reply segment or None.

        Raises ValueError for segments that make no sense in the
        current state (e.g. data before the handshake finishes).
        """
        flags = seg.flags
        self._log(
            "recv",
            f"{flag_names(flags)} seq={seg.seq} ack={seg.ack} (state={self.state})",
        )

        if self.state == LISTEN:
            if flags & FLAG_SYN:
                # SYN received: remember peer, send SYN+ACK.
                self.remote_port = seg.src_port
                self.next_ack = seg.seq + 1
                self.next_seq = self.isn + 1
                self._transition(SYN_RCVD, "SYN received")
                reply = self._segment(FLAG_SYN | FLAG_ACK, self.isn, self.next_ack)
                self._log("send", f"SYN|ACK seq={self.isn} ack={self.next_ack}")
                return reply
            raise ValueError(f"unexpected {flag_names(flags)} in LISTEN")

        if self.state == SYN_SENT:
            if flags & FLAG_SYN and flags & FLAG_ACK:
                # SYN-ACK: peer accepted; acknowledge it.
                if seg.ack != self.next_seq:
                    raise ValueError(
                        f"bad SYN-ACK ack {seg.ack}, expected {self.next_seq}"
                    )
                self.next_ack = seg.seq + 1
                self._transition(ESTABLISHED, "SYN-ACK received")
                reply = self._segment(FLAG_ACK, self.next_seq, self.next_ack)
                self._log("send", f"ACK seq={self.next_seq} ack={self.next_ack}")
                return reply
            if flags & FLAG_SYN:
                # Simultaneous open: not implemented for this simulator.
                raise ValueError("simultaneous open (bare SYN in SYN_SENT) not supported")
            raise ValueError(f"unexpected {flag_names(flags)} in SYN_SENT")

        if self.state == SYN_RCVD:
            if flags & FLAG_ACK:
                if seg.ack != self.next_seq:
                    raise ValueError(
                        f"bad ACK {seg.ack}, expected {self.next_seq}"
                    )
                self._transition(ESTABLISHED, "ACK received, handshake complete")
                return None
            raise ValueError(f"unexpected {flag_names(flags)} in SYN_RCVD")

        if self.state == ESTABLISHED:
            if flags & FLAG_FIN:
                self.next_ack = seg.seq + 1
                self._transition(CLOSE_WAIT, "FIN received")
                reply = self._segment(FLAG_ACK, self.next_seq, self.next_ack)
                self._log("send", f"ACK seq={self.next_seq} ack={self.next_ack}")
                return reply
            if flags & FLAG_ACK:
                self._log("recv", "ACK (data ack, staying ESTABLISHED)")
                return None
            raise ValueError(f"unexpected {flag_names(flags)} in ESTABLISHED")

        if self.state == FIN_WAIT_1:
            if flags & FLAG_FIN and flags & FLAG_ACK:
                self.next_ack = seg.seq + 1
                self._transition(TIME_WAIT, "FIN+ACK received")
                reply = self._segment(FLAG_ACK, self.next_seq, self.next_ack)
                self._log("send", f"ACK seq={self.next_seq} ack={self.next_ack}")
                return reply
            if flags & FLAG_ACK:
                self._transition(FIN_WAIT_2, "FIN acknowledged")
                return None
            if flags & FLAG_FIN:
                self.next_ack = seg.seq + 1
                self._transition(CLOSING, "FIN received while closing")
                reply = self._segment(FLAG_ACK, self.next_seq, self.next_ack)
                self._log("send", f"ACK seq={self.next_seq} ack={self.next_ack}")
                return reply
            raise ValueError(f"unexpected {flag_names(flags)} in FIN_WAIT_1")

        if self.state == FIN_WAIT_2:
            if flags & FLAG_FIN:
                self.next_ack = seg.seq + 1
                self._transition(TIME_WAIT, "FIN received")
                reply = self._segment(FLAG_ACK, self.next_seq, self.next_ack)
                self._log("send", f"ACK seq={self.next_seq} ack={self.next_ack}")
                return reply
            raise ValueError(f"unexpected {flag_names(flags)} in FIN_WAIT_2")

        if self.state == CLOSING:
            if flags & FLAG_ACK:
                self._transition(TIME_WAIT, "FIN acknowledged")
                return None
            raise ValueError(f"unexpected {flag_names(flags)} in CLOSING")

        if self.state == LAST_ACK:
            if flags & FLAG_ACK:
                self._transition(CLOSED, "final ACK received")
                return None
            raise ValueError(f"unexpected {flag_names(flags)} in LAST_ACK")

        if self.state == TIME_WAIT:
            self._log("recv", "segment ignored in TIME_WAIT")
            return None

        raise ValueError(f"no transition defined for state {self.state}")

    # -- close ----------------------------------------------------------
    def close(self) -> TCPSegment:
        """Initiate teardown: send FIN. Valid from ESTABLISHED/CLOSE_WAIT."""
        if self.state == ESTABLISHED:
            fin_seq = self.next_seq
            self.next_seq += 1  # FIN consumes one sequence number
            self._transition(FIN_WAIT_1, "active close")
            seg = self._segment(FLAG_FIN | FLAG_ACK, fin_seq, self.next_ack)
            self._log("send", f"FIN|ACK seq={fin_seq} ack={self.next_ack}")
            return seg
        if self.state == CLOSE_WAIT:
            fin_seq = self.next_seq
            self.next_seq += 1
            self._transition(LAST_ACK, "passive close")
            seg = self._segment(FLAG_FIN | FLAG_ACK, fin_seq, self.next_ack)
            self._log("send", f"FIN|ACK seq={fin_seq} ack={self.next_ack}")
            return seg
        raise ValueError(f"close() only valid from ESTABLISHED/CLOSE_WAIT, now {self.state}")

    def time_wait_timeout(self) -> None:
        """2MSL timer expiry: TIME_WAIT -> CLOSED."""
        if self.state != TIME_WAIT:
            raise ValueError(f"time_wait_timeout() only valid in TIME_WAIT, now {self.state}")
        self._transition(CLOSED, "2MSL timeout")

    def trace_text(self) -> str:
        """Human-readable trace of everything this connection did."""
        return "\n".join(
            f"  [{i:02d}] {e.action}: {e.detail}" for i, e in enumerate(self.trace)
        )


def simulate_handshake(client_isn: int = 1000, server_isn: int = 5000) -> tuple[TcpConnection, TcpConnection]:
    """Run a full client<->server three-way handshake in-process.

    Returns ``(client, server)`` with both in ESTABLISHED state.
    """
    client = TcpConnection(local_port=49152, remote_port=80, isn=client_isn)
    server = TcpConnection(local_port=80, remote_port=49152, isn=server_isn)
    server.listen()
    syn = client.connect()
    syn_ack = server.on_segment(syn)
    assert syn_ack is not None
    ack = client.on_segment(syn_ack)
    assert ack is not None
    server.on_segment(ack)
    return client, server
