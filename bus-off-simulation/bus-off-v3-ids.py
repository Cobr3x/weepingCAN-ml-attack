"""can_sim_dynamic.py

Dynamic CAN simulator with an independent transmission timer for each ECU.
ECUs with lower identifiers (higher priority) wait longer between transmissions.
ECUs with higher identifiers (lower priority) wait less between transmissions.

IMPLEMENTED CORRECTIONS:
1. START_SLOT removed: every PENDING ECU participates in arbitration immediately.
2. ACTIVE ERROR FLAG: 6 DOMINANT bits (0) while TEC < 128.
3. PASSIVE ERROR FLAG: 8 RECESSIVE bits (1) while TEC >= 128.
4. TEC is decremented by 1 after a successful transmission.
5. During a collision, both ECUs increment TEC by 8.
"""

# Enable postponed annotation evaluation so forward references do not depend on declaration order.
from __future__ import annotations

# Standard-library modules provide timing, concurrency, queues, statistics, and data containers.
import time
import threading
import queue
import random
from collections import deque, Counter, defaultdict
import math
import sys
from dataclasses import dataclass
from enum import Enum, auto
from typing import Deque, Dict, List, Optional, Tuple

# python-can is optional; the in-process simulator continues to work when it is unavailable.
try:
    import can  # python-can
    CAN_AVAILABLE = True
except Exception:
    CAN_AVAILABLE = False
# Low-level SocketCAN integration uses operating-system sockets and native CAN frame packing.
import os
import socket
import struct

# Linux SocketCAN flags used to identify and classify diagnostic error frames.
CAN_ERR_FLAG = 0x20000000
CAN_ERR_PROT = 0x00000008  # Error class "protocol violation", used here for bit-monitoring diagnostics.

# Open and bind a raw CAN socket to the requested physical or virtual CAN interface.
def sockcan_open(iface: str):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s

# Send a normal diagnostic frame identifying an ECU that emitted an active error indication.
def sockcan_send_error_active_diag(sock, ecu_name: str):
    arb_id = 0x7FF  # Reserved diagnostic ID; choose an identifier not used by simulated data frames.
    payload = bytes([ord(ecu_name[0]), ord('E'), ord('A'), 0, 0, 0, 0, 0])
    sockcan_send_data(sock, arb_id, payload)

# Serialize up to eight payload bytes into the native SocketCAN can_frame layout.
def sockcan_send_data(sock, arb_id: int, data: bytes):
    dlc = min(len(data), 8)
    frame = struct.pack("=IB3x8s", arb_id & 0x1FFFFFFF, dlc, data[:8].ljust(8, b"\x00"))
    sock.send(frame)

# Emit a SocketCAN protocol error frame containing compact diagnostic metadata.
def sockcan_send_error_active(sock, ecu_name: str, offender_code: int = 1):
    # Build a SocketCAN error frame by combining CAN_ERR_FLAG with the protocol-error class.
    can_id = CAN_ERR_FLAG | CAN_ERR_PROT
    # The diagnostic payload shown by candump contains the ECU initial, "E", "A", and the offender code.
    payload = bytes([ord(ecu_name[0]) & 0xFF, ord('E'), ord('A'), offender_code & 0xFF]).ljust(8, b"\x00")
    frame = struct.pack("=IB3x8s", can_id, 8, payload)
    sock.send(frame)


# Represent the two CAN bus levels; a dominant zero overrides a recessive one.
class BitValue(Enum):
    DOMINANT = 0
    RECESSIVE = 1

    @staticmethod
    def from_int(v: int) -> "BitValue":
        return BitValue.DOMINANT if v == 0 else BitValue.RECESSIVE

    def __int__(self) -> int:
        return 0 if self is BitValue.DOMINANT else 1


# Track each ECU fault-confinement state as derived from its transmission error counter.
class NodeState(Enum):
    ERROR_ACTIVE = auto()
    ERROR_PASSIVE = auto()
    BUS_OFF = auto()


# Enumerate the master state-machine phases used to coordinate one complete bus transaction.
class MasterState(Enum):
    IDLE = auto()
    ARBITRATION = auto()
    TRANSMIT = auto()
    ERROR_FLAG = auto()
    ERROR_DELIM = auto()
    EOF = auto()
    INTERFRAME = auto()


# Label every generated bit with its logical CAN frame field for diagnostics and fault injection.
class Field(Enum):
    SOF = auto()
    ID = auto()
    RTR = auto()
    IDE = auto()
    R0 = auto()
    DLC = auto()
    DATA = auto()
    CRC = auto()
    CRC_DELIM = auto()
    ACK_SLOT = auto()
    ACK_DELIM = auto()
    EOF = auto()
    INTERMISSION = auto()
    STUFF = auto()


# Store the immutable-style metadata submitted by an ECU for arbitration.
@dataclass
class TransmissionRequest:
    slave_name: str
    slave_id: int
    arbitration_id: int
    data: bytes
    timestamp: float


# Represent one resolved bus bit broadcast to every registered ECU receive queue.
@dataclass
class BitTransmission:
    bit_value: BitValue
    timestamp: float
    sender_name: str
    field: Field


# Compute the CAN CRC using the standard 15-bit polynomial 0x4599.
def _crc15_can(bits: List[int]) -> int:
    """Compute CRC-15/CAN over a bit stream."""
    poly = 0x4599
    crc = 0
    for b in bits:
        msb = (crc >> 14) & 1
        crc = ((crc << 1) & 0x7FFF) | (b & 1)
        if msb:
            crc ^= poly
    return crc & 0x7FFF


# Build a base-format CAN frame while keeping each bit aligned with its field label.
class CANBitStream:
    """Build a *stuffed* CAN base frame bit stream and per-bit field labels."""

    # Clamp the arbitration ID and payload to the supported 11-bit, eight-byte base-frame limits.
    def __init__(self, arbitration_id: int, data: bytes, r0: BitValue = BitValue.RECESSIVE):
        self.arb_id = arbitration_id & 0x7FF
        self.data = data[:8]
        self.r0 = r0

        self.bits: List[BitValue] = []
        self.fields: List[Field] = []
        self._build()

    # Append a bit and its field label together so the parallel arrays remain synchronized.
    def _push(self, bit: BitValue, field: Field):
        self.bits.append(bit)
        self.fields.append(field)

    # Assemble the logical frame before CAN bit stuffing is applied.
    def _build_unstuffed_payload_bits(self) -> Tuple[List[BitValue], List[Field]]:
        bits: List[BitValue] = []
        fields: List[Field] = []

        def push(bit: BitValue, field: Field):
            bits.append(bit)
            fields.append(field)

        # SOF
        push(BitValue.DOMINANT, Field.SOF)

        # 11-bit ID (MSB first)
        for i in range(10, -1, -1):
            push(BitValue.from_int((self.arb_id >> i) & 1), Field.ID)

        # Control field (base frame)
        push(BitValue.DOMINANT, Field.RTR)
        push(BitValue.DOMINANT, Field.IDE)
        push(self.r0, Field.R0)

        # DLC 4 bits
        dlc = len(self.data)
        for i in range(3, -1, -1):
            push(BitValue.from_int((dlc >> i) & 1), Field.DLC)

        # DATA bytes
        for byte in self.data:
            for i in range(7, -1, -1):
                push(BitValue.from_int((byte >> i) & 1), Field.DATA)

        # CRC
        crc_input = [int(b) for b in bits]
        crc = _crc15_can(crc_input)
        for i in range(14, -1, -1):
            push(BitValue.from_int((crc >> i) & 1), Field.CRC)

        # CRC delimiter
        push(BitValue.RECESSIVE, Field.CRC_DELIM)
        # ACK slot
        push(BitValue.RECESSIVE, Field.ACK_SLOT)
        push(BitValue.RECESSIVE, Field.ACK_DELIM)
        # EOF 7 recessive
        for _ in range(7):
            push(BitValue.RECESSIVE, Field.EOF)
        # Intermission 3 recessive
        for _ in range(3):
            push(BitValue.RECESSIVE, Field.INTERMISSION)

        return bits, fields

    # Insert a complementary bit after every run of five identical stuffable bits.
    @staticmethod
    def _apply_bit_stuffing(bits: List[BitValue], fields: List[Field]) -> Tuple[List[BitValue], List[Field]]:
        """Stuff from SOF through end of CRC sequence (inclusive)."""
        out_bits: List[BitValue] = []
        out_fields: List[Field] = []

        run_val: Optional[BitValue] = None
        run_len = 0

        def should_stuff(idx: int) -> bool:
            return fields[idx] in {
                Field.SOF, Field.ID, Field.RTR, Field.IDE, Field.R0, Field.DLC, Field.DATA, Field.CRC
            }

        for i, (b, f) in enumerate(zip(bits, fields)):
            out_bits.append(b)
            out_fields.append(f)

            if not should_stuff(i):
                run_val = None
                run_len = 0
                continue

            if run_val is None or b != run_val:
                run_val = b
                run_len = 1
            else:
                run_len += 1

            if run_len == 5:
                stuffed = BitValue.DOMINANT if b is BitValue.RECESSIVE else BitValue.RECESSIVE
                out_bits.append(stuffed)
                out_fields.append(Field.STUFF)
                run_val = None
                run_len = 0

        return out_bits, out_fields

    # Build the raw sequence first, then expose its stuffed representation to transmitters.
    def _build(self):
        raw_bits, raw_fields = self._build_unstuffed_payload_bits()
        stuffed_bits, stuffed_fields = self._apply_bit_stuffing(raw_bits, raw_fields)
        self.bits = stuffed_bits
        self.fields = stuffed_fields


# Provide deterministic bus-bit overrides for repeatable protocol-error tests.
class FaultInjector:
    """Optional: inject deterministic faults for testing."""

    def __init__(self, *, flip_r0_every_n_frames: int = 0):
        self.flip_r0_every_n_frames = flip_r0_every_n_frames
        self._frame_count = 0

    def on_new_frame(self):
        self._frame_count += 1

    def override_bus_bit(self, field: Field, current_bus: BitValue) -> BitValue:
        if self.flip_r0_every_n_frames and field == Field.R0:
            if (self._frame_count % self.flip_r0_every_n_frames) == 0:
                return BitValue.DOMINANT
        return current_bus


# Model one ECU, including scheduling, fault counters, pending frames, and transmission progress.
class BaseECU:
    # Initialize ECU identity, worker threads, periodic scheduling, and error-flag state.
    def __init__(
        self,
        name: str,
        slave_id: int,
        arb_id: int,
        master: "CANMaster",
        tx_period: float = 2.0,
        start_delay: float = 0.0,
        auto_tx: bool = True,
    ):
        self.name = name
        self.slave_id = slave_id
        self.arb_id = arb_id & 0x7FF
        self.master = master

        # Each ECU owns an independent periodic transmission schedule.
        self.tx_period = tx_period
        self.start_delay = start_delay
        self.next_tx_time = 0.0

        # TEC and REC are the CAN fault-confinement counters used to derive the node state.
        self.tec = 0
        self.rec = 0
        self.state = NodeState.ERROR_ACTIVE

        # Separate daemon threads create outgoing requests and consume simulated bus broadcasts.
        self._stop = False
        self.auto_tx = bool(auto_tx)
        self._tx_thread = threading.Thread(target=self._tx_loop, daemon=True)
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)

        # Transmission state
        self._pending_req: Optional[TransmissionRequest] = None
        self._bitstream: Optional[CANBitStream] = None
        self._cursor = 0
        self._currently_transmitting = False

        self._silence_bit_errors = False  # used to ignore repeated bit-errors in ERROR_PASSIVE

        # Per-ECU error-flag emission (to model ACTIVE vs PASSIVE behaviour correctly)
        #   - ERR_ACTIVE: drives the bus dominant (0) and will force an error-frame
        #   - ERR_PASSIVE: drives recessive (1) and does NOT affect the bus if another sender drives dominant
        self._tx_mode: str = "NORMAL"  # NORMAL | ERR_ACTIVE | ERR_PASSIVE
        self._err_flag_bits_left: int = 0
        self.master.register_slave(self)

        

    # Start reception immediately and periodic transmission only when auto_tx is enabled.
    def start(self):
        print(f"[{self.name}] START slave_id={self.slave_id} ID=0x{self.arb_id:03X} period={self.tx_period:.2f}s")
        self.next_tx_time = time.time() + self.start_delay
        self._rx_thread.start()
        if self.auto_tx:
            self._tx_thread.start()

    # Submit exactly one deterministic frame without relying on the periodic scheduler.
    def request_once(self, data: bytes, *, arbitration_id: Optional[int] = None):
        """Queue exactly one transmission (used for deterministic tests)."""
        if self.is_bus_off():
            print(f"[{self.name}] request_once ignored (BUS_OFF)")
            return
        if self._pending_req is not None:
            print(f"[{self.name}] request_once ignored (already pending)")
            return
        now = time.time()
        aid = self.arb_id if arbitration_id is None else (arbitration_id & 0x7FF)
        self._pending_req = TransmissionRequest(
            slave_name=self.name,
            slave_id=self.slave_id,
            arbitration_id=aid,
            data=data[:8],
            timestamp=now,
        )
        self._bitstream = None
        self._cursor = 0
        self.master.submit_request(self._pending_req)

    def stop(self):
        self._stop = True

    # Recalculate ERROR_ACTIVE, ERROR_PASSIVE, or BUS_OFF from the current TEC threshold.
    def _update_state(self):
        if self.tec >= 256:
            self.state = NodeState.BUS_OFF
        elif self.tec >= 128:
            self.state = NodeState.ERROR_PASSIVE
        else:
            self.state = NodeState.ERROR_ACTIVE

    # ---- Master-facing API ----

    # BUS_OFF nodes are excluded from arbitration and further transmissions.
    def is_bus_off(self) -> bool:
        return self.state is NodeState.BUS_OFF

    # A frame becomes eligible only after both request metadata and its bitstream exist.
    def has_pending_frame(self) -> bool:
        return (self._pending_req is not None) and (self._bitstream is not None) and (not self.is_bus_off())

    # Lazily construct the bitstream when the master is ready to collect the request.
    def begin_frame_if_needed(self):
        """Ensure bitstream is ready for a pending request."""
        if self._pending_req is None or self._bitstream is not None:
            return
        self._bitstream = CANBitStream(self._pending_req.arbitration_id, self._pending_req.data, r0=BitValue.RECESSIVE)
        self._cursor = 0


    # Switch from normal frame output to a finite active or passive error-flag sequence.
    def _enter_error_flag(self, *, active: bool):
        """Emit the error flag while preserving the failed frame for immediate retransmission."""
        self._silence_bit_errors = True
        self._tx_mode = "ERR_ACTIVE" if active else "ERR_PASSIVE"
        self._err_flag_bits_left = 6

        # Keep the original request and bitstream: after the error handling and
        # interframe interval, the same frame must immediately contend again.
        # The periodic next_tx_time is intentionally left unchanged.
        self._cursor = 0

    def is_emitting_error_flag_active(self) -> bool:
        return self._tx_mode == "ERR_ACTIVE"

    # Inspect the next bus contribution without advancing frame or error-flag progress.
    def peek_next_bit(self) -> Optional[Tuple[BitValue, Field]]:
        # If we are emitting an error flag, output it ONLY for the configured number of bits.
        # After that, this ECU stops contributing bits to the bus (as requested).
        if self._tx_mode == "ERR_ACTIVE":
            if self._err_flag_bits_left <= 0:
                return None
            return BitValue.DOMINANT, Field.DATA
        if self._tx_mode == "ERR_PASSIVE":
            if self._err_flag_bits_left <= 0:
                return None
            return BitValue.RECESSIVE, Field.DATA

        if not self.has_pending_frame():
            return None
        assert self._bitstream is not None
        if self._cursor >= len(self._bitstream.bits):
            return None
        return self._bitstream.bits[self._cursor], self._bitstream.fields[self._cursor]
    # Advance one normal frame bit or consume one error-flag bit.
    def advance(self):
        # During error-flag emission, we do not advance the original frame.
        if self._tx_mode in {"ERR_ACTIVE", "ERR_PASSIVE"}:
            if self._err_flag_bits_left > 0:
                self._err_flag_bits_left -= 1
            return
        self._cursor += 1

    # Rewind the preserved request so it can contend again after an unsuccessful attempt.
    def reset_for_retransmission(self):
        self._cursor = 0
        self._currently_transmitting = False
        self._tx_mode = "NORMAL"
        self._err_flag_bits_left = 0

    def mark_as_transmitting(self, value: bool):
        self._currently_transmitting = value

    # Detect bit-monitoring mismatches outside the arbitration window.
    def on_bus_bit(self, bus_bit: BitValue, field: Field, *, arbitration_window: bool):
        """Bit monitoring for the *current transmitter*."""
        if not self._currently_transmitting:
            return
        # Once an ECU has entered error-flag emission, it must not keep reporting bit errors.
        if self._tx_mode in {"ERR_ACTIVE", "ERR_PASSIVE"}:
            return
        if self._silence_bit_errors:
            return
        nxt = self.peek_next_bit()
        if nxt is None:
            return
        sent_bit, _sent_field = nxt
        if sent_bit is BitValue.RECESSIVE and bus_bit is BitValue.DOMINANT:
            if arbitration_window:
                return
            self.master.report_bit_error(self.slave_id, offender="bit_monitoring")

    # Apply bounded counter changes and immediately refresh the ECU fault state.
    def apply_error_update(self, *, tec_delta: int = 0, rec_delta: int = 0):
        self.tec = max(0, self.tec + tec_delta)
        self.rec = max(0, self.rec + rec_delta)
        self._update_state()

    def apply_success_update(self):
        """Apply the successful-transmission rule by decrementing TEC by one."""
        self.tec = max(0, self.tec - 1)
        self._update_state()

    def get_time_until_tx(self) -> float:
        """Return the remaining time, in seconds, before the next scheduled transmission."""
        return max(0.0, self.next_tx_time - time.time())

    # ---- Internal threads ----

    # Periodically generate identifiable payloads without blocking the master state machine.
    def _tx_loop(self):
        if not self.auto_tx:
            return
        
        while not self._stop:
            if self.is_bus_off():
                time.sleep(0.2)
                continue
            
            now = time.time()
            if now >= self.next_tx_time:
                # Create a new request only when this ECU does not already have one pending.
                if self._pending_req is None:
                    data = bytes([self.slave_id] * 8)  # Fill the payload with the slave ID so the source ECU is easy to identify.
                    self._pending_req = TransmissionRequest(
                        slave_name=self.name,
                        slave_id=self.slave_id,
                        arbitration_id=self.arb_id,
                        data=data,
                        timestamp=now,
                    )
                    self._bitstream = None
                    self._cursor = 0
                    self.master.submit_request(self._pending_req)
                    print(f"[{self.name}] WANTS TO TRANSMIT (ID=0x{self.arb_id:03X}) TEC={self.tec} REC={self.rec} State={self.state.name}")
                
                # Schedule the next periodic transmission relative to the current time.
                self.next_tx_time = now + self.tx_period
            
            time.sleep(0.05)

    # Consume broadcast bits; transmission-side monitoring is coordinated by the master.
    def _rx_loop(self):
        while not self._stop:
            bt = self.master.get_bit_for_slave(self.slave_id, timeout=0.1)
            if bt is None:
                continue


# Detect suspicious same-ID collisions by analyzing their frequency and DATA-bit concentration.
class SimpleCANIDS:
    """
    Minimal IDS based on two indicators:
      1) the number of collisions per arbitration ID within a time window;
      2) the concentration of collisions on the same DATA-field bit.

    It does not assume in advance which node is the attacker or the victim.
    """

    # Configure the sliding window, alert thresholds, and duplicate-alert cooldown.
    def __init__(
        self,
        window_s: float = 120.0,
        min_collisions: int = 1,
        mode_share_th: float = 0.75,
        entropy_th: float = 2.0,
        cooldown_s: float = 1.0,
    ):
        self.window_s = float(window_s)
        self.min_collisions = int(min_collisions)
        self.mode_share_th = float(mode_share_th)
        self.entropy_th = float(entropy_th)
        self.cooldown_s = float(cooldown_s)

        # Keep a time-ordered collision history for each arbitration identifier.
        # events[arb_id] = deque[(timestamp, data_bit_index, offender_name)]
        self.events = defaultdict(deque)
        self._last_alert_ts: Dict[int, float] = {}

    # Remove observations that have aged beyond the configured sliding window.
    def _prune(self, arb_id: int, now: float):
        dq = self.events[arb_id]
        cutoff = now - self.window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    # Measure how concentrated the collision positions are across DATA bits.
    @staticmethod
    def _entropy(counts: Counter) -> float:
        total = sum(counts.values())
        if total <= 0:
            return 0.0
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log(probability + 1e-12, 2)
        return entropy

    # Record one DATA-bit collision together with its time and apparent offender.
    def observe_collision(
        self,
        arb_id: int,
        bit_idx: int,
        offender_name: str,
        ts: Optional[float] = None,
    ):
        now = time.time() if ts is None else float(ts)
        dq = self.events[int(arb_id) & 0x7FF]
        dq.append((now, int(bit_idx), str(offender_name)))
        self._prune(int(arb_id) & 0x7FF, now)

    # Evaluate whether recent collisions satisfy the IDS alert criteria.
    def check_alert(self, arb_id: int, ts: Optional[float] = None):
        arb_id = int(arb_id) & 0x7FF
        now = time.time() if ts is None else float(ts)
        self._prune(arb_id, now)
        dq = self.events.get(arb_id)
        if not dq:
            return None

        collisions = len(dq)
        if collisions < self.min_collisions:
            return None

        # The modal DATA bit and entropy summarize positional concentration.
        bit_counts = Counter(bit for _, bit, _ in dq)
        mode_bit, mode_count = bit_counts.most_common(1)[0]
        mode_share = mode_count / collisions
        entropy = self._entropy(bit_counts)

        last_alert = self._last_alert_ts.get(arb_id, 0.0)
        if now - last_alert < self.cooldown_s:
            return None

        concentrated = mode_share >= self.mode_share_th or entropy <= self.entropy_th
        if not concentrated:
            return None

        # Count offender names only for diagnostic ranking; detection does not assume an attacker.
        offender_counts = Counter(name for _, _, name in dq)
        top_offender, top_offender_count = offender_counts.most_common(1)[0]

        self._last_alert_ts[arb_id] = now
        return {
            "arb_id": arb_id,
            "window_s": self.window_s,
            "collisions": collisions,
            "mode_bit": mode_bit,
            "mode_share": mode_share,
            "entropy": entropy,
            "top_offender": top_offender,
            "top_offender_share": top_offender_count / collisions,
        }

# Coordinate arbitration, bit resolution, error handling, IDS observation, and frame lifecycle.
class CANMaster:
    # Initialize timing, queues, state-machine data, optional SocketCAN output, and IDS state.
    def __init__(
        self,
        tick_ms: float = 0.1,
        forward_to_socketcan: bool = False,
        can_channel: str = "vcan0",
        fault_injector: Optional[FaultInjector] = None,
        gather_window_s: float = 0.30,
    ):
        self.tick = tick_ms / 1000.0
        self.state = MasterState.IDLE
        self.clock = 0

        # Each registered ECU receives bus bits through its own queue.
        self.slaves: Dict[int, BaseECU] = {}
        self.bit_queues: Dict[int, "queue.Queue[BitTransmission]"] = {}
        self._pending_starts: "queue.Queue[TransmissionRequest]" = queue.Queue()

        # The main worker advances the bus while a second worker prints periodic status snapshots.
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._status_thread = threading.Thread(target=self._status_loop, daemon=True)

        # These collections describe the contenders, active senders, winner, and current frame field.
        # Bus activity
        self._contenders: List[int] = []
        self._active_senders: List[int] = []
        self._winner: Optional[int] = None
        self._current_field: Field = Field.INTERMISSION
        self._arbitration_window = False
        
        # The gather window groups requests arriving close together into one arbitration round.
        # Arbitration gather window (to simulate the master "waiting a bit" to collect contenders)
        self.gather_window_s = float(gather_window_s)
        self._collecting = False
        self._collect_deadline = 0.0
        self._collect_contenders: set[int] = set()
        
        # Per-frame error bookkeeping tracks affected senders and frame validity.
        # Error handling
        self._error_senders: List[int] = []  # Every ECU required to emit an error flag for the current frame.
        self._passive_error_senders: set[int] = set()  # ECUs that reported a passive bit error during the current frame.
        self._error_flag_bits_left = 0
        self._error_delim_bits_left = 0
        self._frame_ok = True

        # Active error flags are emitted inside TRANSMIT so their dominant bits remain visible.
        # Per-frame ACTIVE error handling (modelled inside TRANSMIT, not as a global immediate abort)
        self._active_error_frame = False
        self._error_flag_ticks = 0  # counts emitted ACTIVE error-flag bits
        self._rec_bumped_for_error = False

        self._fault = fault_injector or FaultInjector()

        # SocketCAN
        self._can_iface = os.getenv("CAN_IFACE", "vcan0")  
        try:
            self._sockcan = sockcan_open(self._can_iface)
            print(f"[MASTER] SocketCAN OK on {self._can_iface}")
        except OSError as e:
            print(f"[MASTER] SocketCAN DISABLED on {self._can_iface}: {e}")
            self._sockcan = None

        # Configure the IDS to alert only after repeated, positionally concentrated DATA collisions.
        # Simple IDS: detect repeated collisions concentrated on the same DATA bit.
        self.ids = SimpleCANIDS(
            window_s=12.0,
            min_collisions=10,
            mode_share_th=0.75,
            entropy_th=2.0,
            cooldown_s=10.0,
        )
        self.ids_stop_on_alert = True
        self._err_active_sent = False 

    # Register or replace an ECU by slave ID and allocate its independent receive queue.
    def register_slave(self, ecu: BaseECU):
        self.slaves[ecu.slave_id] = ecu
        self.bit_queues[ecu.slave_id] = queue.Queue()

    # Queue a new transmission intent for collection by the master worker.
    def submit_request(self, req: TransmissionRequest):
        self._pending_starts.put(req)

    # Wait briefly for the next bus bit delivered to a specific ECU.
    def get_bit_for_slave(self, slave_id: int, timeout: float = 0.01) -> Optional[BitTransmission]:
        q = self.bit_queues.get(slave_id)
        if q is None:
            return None
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None

    # Launch both the bus state machine and the independent status reporter.
    def start(self):
        print("[MASTER] START")
        self._thread.start()
        self._status_thread.start()

    # Request shutdown and wait briefly for the main master thread to finish.
    def stop(self):
        self._stop = True
        self._thread.join(timeout=2)
        print("[MASTER] STOP")

    # Report status only while the bus is idle to avoid mixing snapshots with bit traces.
    def _status_loop(self):
        """Print a periodic snapshot of the simulated bus and every ECU state."""
        while not self._stop:
            time.sleep(3.0)  # Refresh the status display every three seconds.
            
            if self.state == MasterState.IDLE:
                print(f"\n{'='*100}")
                print(f"STATUS BUS (IDLE)")
                print(f"{'='*100}")
                
                for sid in sorted(self.slaves.keys()):
                    ecu = self.slaves[sid]
                    time_left = ecu.get_time_until_tx()
                    
                    if ecu.is_bus_off():
                        status = "BUS-OFF"
                    elif ecu._pending_req is not None:
                        status = "PENDING"
                    elif time_left > 0:
                        status = f"Waiting {time_left:.2f}s"
                    else:
                        status = "READY"
                    
                    print(f"  [{ecu.name:6s}] ID=0x{ecu.arb_id:03X} | TEC={ecu.tec:3d} REC={ecu.rec:3d} | {ecu.state.name:13s} | {status}")
                
                print(f"{'='*100}\n")

    # ---- Error reporting ----

    # Convert a transmitter bit error into one IDS observation when it occurred in DATA.
    def _ids_observe_bit_error(self, sender: BaseECU):
        """Record only DATA-field bit errors in the IDS."""
        arb_id = sender.arb_id
        if self._winner is not None and self._winner in self.slaves:
            arb_id = self.slaves[self._winner].arb_id

        # Use the transmitter cursor to locate the absolute bit position in the stuffed frame.
        bit_idx_abs = int(getattr(sender, "_cursor", -1))
        bitstream = getattr(sender, "_bitstream", None)
        fields = getattr(bitstream, "fields", None) if bitstream is not None else None

        # The simple IDS is designed to detect concentration on DATA bits; errors
        # in all other frame fields are deliberately excluded from its statistics.
        if fields is None or bit_idx_abs < 0 or bit_idx_abs >= len(fields):
            return
        if fields[bit_idx_abs] is not Field.DATA:
            return

        # Convert the absolute frame position into a zero-based DATA-field bit index.
        data_pos = sum(1 for field in fields[:bit_idx_abs] if field is Field.DATA)
        self.ids.observe_collision(
            arb_id=arb_id,
            bit_idx=data_pos,
            offender_name=sender.name,
        )

        # Emit a compact alert only when the sliding-window thresholds are satisfied.
        alert = self.ids.check_alert(arb_id)
        if alert is None:
            return

        print(
            f"[IDS] ALERT on ID=0x{alert['arb_id']:03X} | "
            f"collisions={alert['collisions']} in {alert['window_s']:.1f}s | "
            f"mode_bit={alert['mode_bit']} ({alert['mode_share'] * 100:.1f}%) | "
            f"entropy={alert['entropy']:.3f} | "
            f"top_off={alert['top_offender']} "
            f"({alert['top_offender_share'] * 100:.1f}%)"
        )
        # Optionally stop immediately after an alert so external test scripts can detect completion.
        if self.ids_stop_on_alert:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)

    # Process one transmitter bit-monitoring error according to its pre-error fault state.
    def report_bit_error(self, sender_slave_id: int, offender: str = "unknown"):
        """Called by an ECU when it detects a bit-monitoring error.

        IMPORTANT behavioural model (as requested):
        - If the sender is ERROR_ACTIVE at the moment it detects the error, it emits an ACTIVE error flag (dominant 0),
          which forces an error on the bus. Other transmitters may detect it later (e.g., due to bit-stuffing).
        - If the sender is ERROR_PASSIVE at the moment it detects the error, it emits a PASSIVE error flag (recessive 1),
          which does NOT disturb the bus when another transmitter keeps driving dominant bits. The frame may still complete OK.
        """
        # Ignore reports from unknown nodes or nodes already disconnected by BUS_OFF.
        sender = self.slaves.get(sender_slave_id)
        if sender is None or sender.is_bus_off():
            return

        # If it already switched to an error-flag mode, ignore repeated notifications.
        if getattr(sender, "_tx_mode", "NORMAL") != "NORMAL":
            return
        if getattr(sender, "_silence_bit_errors", False):
            return

        # Select active or passive behavior from the state observed before applying the TEC penalty.
        pre_state = sender.state

        # -------------------------------
        # ERROR PASSIVE: send recessive error flag, do NOT abort the frame
        # -------------------------------
        # A passive flag is recessive and therefore does not force another transmitter off the bus.
        if pre_state is NodeState.ERROR_PASSIVE:
            print(f"\n[MASTER] BIT ERROR (PASSIVE) detected by {sender.name} (offender={offender}) -> recessive error flag, frame continues")
            self._ids_observe_bit_error(sender)
            sender.apply_error_update(tec_delta=8)
            sender._enter_error_flag(active=False)
            print(f"[MASTER] {sender.name}: TEC={sender.tec} (+8 for PASSIVE error) State={sender.state.name}")
            return

        # -------------------------------
        # ERROR ACTIVE: send dominant error flag, frame becomes an error-frame
        # -------------------------------
        # An active flag drives dominant and invalidates the current frame for all participants.
        print(f"\n[MASTER] BIT ERROR (ACTIVE) detected by {sender.name} (offender={offender}) -> dominant error flag, frame aborted")
        self._ids_observe_bit_error(sender)
        if self._sockcan is not None and not getattr(self, "_err_active_sent", False):
            sockcan_send_data(self._sockcan, 0x7FF, b"\x00" * 6)
            self._err_active_sent = True
        self._frame_ok = False
        self._active_error_frame = True

        sender.apply_error_update(tec_delta=8)
        sender._enter_error_flag(active=True)
        print(f"[MASTER] {sender.name}: TEC={sender.tec} (+8 for ACTIVE error) State={sender.state.name}")

        # Listening nodes increment REC once per active error frame; transmitters are excluded.
        # REC +1 for listeners (only once per error-frame)
        if not self._rec_bumped_for_error:
            active_set = set(self._active_senders or [])
            for sid, ecu in self.slaves.items():
                if ecu.is_bus_off():
                    continue
                if sid in active_set:
                    continue
                ecu.rec = max(0, ecu.rec + 1)
            self._rec_bumped_for_error = True
    # Dispatch exactly one state-specific handler on every simulation tick.
    def _loop(self):
        while not self._stop:
            self.clock += 1
            if self.state == MasterState.IDLE:
                self._handle_idle()
            elif self.state == MasterState.ARBITRATION:
                self._handle_arbitration_step()
            elif self.state == MasterState.TRANSMIT:
                self._handle_transmit_step()
            elif self.state == MasterState.ERROR_FLAG:
                self._handle_error_flag_step()
            elif self.state == MasterState.ERROR_DELIM:
                self._handle_error_delim_step()
            elif self.state == MasterState.EOF:
                self._handle_eof()
            elif self.state == MasterState.INTERFRAME:
                self._handle_interframe()

            time.sleep(self.tick)

    # Drain all queued start intents and prepare the corresponding ECU bitstreams.
    def _drain_start_intents(self) -> List[int]:
        """Collect ALL pending start intents."""
        new_contenders: List[int] = []
        while True:
            try:
                req = self._pending_starts.get_nowait()
            except queue.Empty:
                break
            ecu = self.slaves.get(req.slave_id)
            if ecu is None or ecu.is_bus_off():
                continue
            ecu._pending_req = req
            ecu._bitstream = None
            ecu._cursor = 0
            ecu.begin_frame_if_needed()
            if ecu.has_pending_frame() and req.slave_id not in new_contenders:
                new_contenders.append(req.slave_id)
        return new_contenders

    # Broadcast one resolved bus bit to every registered ECU without blocking the master.
    def _broadcast(self, bus_bit: BitValue, sender_name: str, field: Field):
        bt = BitTransmission(bus_bit, time.time(), sender_name, field)
        for q in self.bit_queues.values():
            try:
                q.put_nowait(bt)
            except Exception:
                pass

    # Collect pending ECUs, wait for the gather deadline, and initialize a new arbitration round.
    def _handle_idle(self):
        # 1) Always drain new start intents (ECU that just asked to transmit).
        #    NOTE: we must NOT rely only on this queue, because requests can arrive
        #    while the bus is busy (TRANSMIT/ARBITRATION). In that case the ECU is
        #    already in PENDING, but its intent might have been drained earlier.
        self._drain_start_intents()

        # Use one timestamp for every gather-window decision in this state-machine iteration.
        now = time.time()

        # 2) Contenders are ALL ECU that currently have a pending frame.
        pending_ids = [
            sid
            for sid, ecu in self.slaves.items()
            if (not ecu.is_bus_off()) and ecu.has_pending_frame()
        ]

        # 3) If no one is pending, nothing to do.
        if not pending_ids and not self._collecting:
            return

        # 4) Start or continue the gather window.
        if not self._collecting:
            self._collecting = True
            self._collect_deadline = now + self.gather_window_s
            self._collect_contenders = set(pending_ids)

            names = ", ".join(self.slaves[s].name for s in self._collect_contenders)
            print(
                f"[MASTER] IDLE: gather window ({self.gather_window_s:.2f}s) | Pending now: {names if names else '-'}"
            )
            return

        # Collect new contenders that became pending during the window.
        self._collect_contenders |= set(pending_ids)

        # If (for any reason) nobody is pending anymore, stop collecting.
        if not self._collect_contenders:
            self._collecting = False
            return

        # Wait until the gather window expires.
        if now < self._collect_deadline:
            return

        # 5) Window expired -> start arbitration with everything collected.
        contenders = list(self._collect_contenders)
        self._collecting = False
        self._collect_contenders = set()

        # Preserve insertion order while removing duplicate contender identifiers.
        self._contenders = list(dict.fromkeys(contenders))
        self._winner = None
        self._active_senders = []
        self._frame_ok = True
        self._error_senders = []
        self._fault.on_new_frame()

        # Prepare all ECU for arbitration (bitstream ready).
        for sid in self._contenders:
            self.slaves[sid].begin_frame_if_needed()
            self.slaves[sid].reset_for_retransmission()

        names = ", ".join(self.slaves[s].name for s in self._contenders)
        print()
        print(f"[MASTER] IDLE->ARBITRATION | Contenders: {names}")
        self.state = MasterState.ARBITRATION

    # Read one contender arbitration bit without mutating its cursor.
    def _get_arbitration_bit(self, ecu: BaseECU) -> Optional[Tuple[BitValue, Field]]:
        nxt = ecu.peek_next_bit()
        if nxt is None:
            return None
        bit, field = nxt
        return bit, field

    # Resolve wired-AND arbitration one bit at a time and remove losing contenders.
    def _handle_arbitration_step(self):
        self._arbitration_window = True

        offered: List[Tuple[int, BitValue, Field]] = []
        for sid in list(self._contenders):
            ecu = self.slaves[sid]
            if ecu.is_bus_off() or not ecu.has_pending_frame():
                self._contenders.remove(sid)
                continue
            nxt = self._get_arbitration_bit(ecu)
            if nxt is None:
                self._contenders.remove(sid)
                continue
            b, f = nxt
            offered.append((sid, b, f))

        if not offered:
            self.state = MasterState.IDLE
            return

        # The bus is dominant whenever at least one contender offers a dominant bit.
        bus_bit = BitValue.DOMINANT if any(b is BitValue.DOMINANT for _, b, _ in offered) else BitValue.RECESSIVE
        self._current_field = offered[0][2]
        bus_bit = self._fault.override_bus_bit(self._current_field, bus_bit)

        # Print every arbitration bit together with each contender contribution.
        contenders_str = " | ".join([f"{self.slaves[sid].name}={int(b)}" for sid, b, _ in offered])
        print(f"  [ARB] {self._current_field.name:12s} | {contenders_str} -> BUS={int(bus_bit)}")

        self._broadcast(bus_bit, sender_name="BUS", field=self._current_field)

        # A node loses arbitration only by sending recessive while observing dominant in ID or RTR.
        if self._current_field in {Field.ID, Field.RTR}:
            losers: List[int] = []
            for sid, b, _f in offered:
                if b is BitValue.RECESSIVE and bus_bit is BitValue.DOMINANT:
                    losers.append(sid)
            for sid in losers:
                ecu = self.slaves[sid]
                print(f"  [ARB] {ecu.name} loses arbitration")
                ecu.reset_for_retransmission()
                self._contenders.remove(sid)

        for sid, _b, _f in offered:
            if sid in self._contenders:
                self.slaves[sid].advance()

        # A single remaining contender becomes the winner and enters normal transmission.
        if len(self._contenders) == 1:
            self._winner = self._contenders[0]
            self._active_senders = [self._winner]
            win_ecu = self.slaves[self._winner]
            win_ecu.mark_as_transmitting(True)
            print(f"[MASTER] WINNER: {win_ecu.name} (ID=0x{win_ecu.arb_id:03X}) -> TRANSMIT")
            # Reset per-frame error bookkeeping
            self._frame_ok = True
            self._active_error_frame = False
            self._error_flag_ticks = 0
            self._rec_bumped_for_error = False
            self._error_senders = []
            self.state = MasterState.TRANSMIT
            return

        # Multiple contenders surviving through RTR have identical arbitration fields.
        if self._current_field == Field.RTR and len(self._contenders) > 1:
            self._active_senders = list(self._contenders)
            self._winner = self._active_senders[0]
            for sid in self._active_senders:
                self.slaves[sid].mark_as_transmitting(True)
            names = ",".join(self.slaves[s].name for s in self._active_senders)
            print(f"[MASTER] COLLISION! Same ID/RTR: {names} -> TRANSMIT (error imminent)")
            # Reset per-frame error bookkeeping
            self._frame_ok = True
            self._active_error_frame = False
            self._error_flag_ticks = 0
            self._rec_bumped_for_error = False
            self._error_senders = []
            self.state = MasterState.TRANSMIT

    # Resolve active sender bits, perform bit monitoring, and advance or terminate the frame.
    def _handle_transmit_step(self):
        assert self._winner is not None

        _ = self._drain_start_intents()

        if not self._active_senders:
            self._active_senders = [self._winner]

        # Normal transmitters and error-flag emitters share the same next-bit interface.
        offered: List[Tuple[int, BitValue, Field]] = []
        for sid in list(self._active_senders):
            ecu = self.slaves[sid]
            nxt = ecu.peek_next_bit()
            if nxt is None:
                continue
            b, f = nxt
            offered.append((sid, b, f))

        # No offered bits means every active sender has completed or abandoned its contribution.
        if not offered:
            for sid in self._active_senders:
                self.slaves[sid].mark_as_transmitting(False)
            self.state = MasterState.EOF
            return

        # Divergent field labels reveal desynchronized streams, so the bus bit is labeled STUFF.
        field = offered[0][2]
        if any(f != field for _sid, _b, f in offered):
            field = Field.STUFF
        self._current_field = field
        self._arbitration_window = field in {Field.SOF, Field.ID, Field.RTR}

        # Resolve the physical bus value before applying any deterministic fault override.
        bus_bit = BitValue.DOMINANT if any(b is BitValue.DOMINANT for _sid, b, _f in offered) else BitValue.RECESSIVE
        bus_bit = self._fault.override_bus_bit(field, bus_bit)

        # Print every transmitted bit and, during collisions, every sender contribution.
        if len(self._active_senders) > 1:
            senders_str = " | ".join([f"{self.slaves[sid].name}={int(b)}" for sid, b, _ in offered])
            print(f"  [TX]  {self._current_field.name:12s} | {senders_str} -> BUS={int(bus_bit)}")
        else:
            print(f"  [TX]  {self._current_field.name:12s} | {self.slaves[self._winner].name}={int(bus_bit)}")

        self._broadcast(bus_bit, sender_name="BUS", field=field)

        # Let each active transmitter compare its intended value with the resolved bus bit.
        for sid, _b, _f in offered:
            self.slaves[sid].on_bus_bit(bus_bit, field, arbitration_window=self._arbitration_window)

        if self.state == MasterState.TRANSMIT:
            for sid, _b, _f in offered:
                self.slaves[sid].advance()
        # Terminate the failed frame after six emitted active error-flag bits.
        # If an ACTIVE error flag is being emitted, count its bits and terminate the frame after 6 bits.
        has_active_err_flag = any(self.slaves[sid].is_emitting_error_flag_active() for sid, _b, _f in offered)
        if has_active_err_flag:
            self._error_flag_ticks += 1
            if self._error_flag_ticks >= 6:
                # Mark as error-frame so the existing EOF error handling is used.
                self._error_senders = list(set(self._active_senders or []))
                for sid in (self._active_senders or []):
                    self.slaves[sid].mark_as_transmitting(False)
                self.state = MasterState.EOF


    # Emit the legacy global error-flag sequence for the senders stored in _error_senders.
    def _handle_error_flag_step(self):
        """Handle an ACTIVE (6 dominant bits) or PASSIVE (8 recessive bits) error flag."""
        if not self._error_senders:
            self.state = MasterState.ERROR_DELIM
            return

        # Determine which type of error flag must be emitted.
        active_senders = [
            sid for sid in self._error_senders
            if sid in self.slaves and self.slaves[sid].state is NodeState.ERROR_ACTIVE
        ]
        passive_senders = [
            sid for sid in self._error_senders
            if sid in self.slaves and self.slaves[sid].state is NodeState.ERROR_PASSIVE
        ]

        if active_senders:
            # ACTIVE ERROR FLAG: six DOMINANT bits.
            flag_bit = BitValue.DOMINANT
            flag_type = "ACTIVE"
            senders_str = ", ".join([self.slaves[sid].name for sid in active_senders])
        else:
            # PASSIVE ERROR FLAG: eight RECESSIVE bits.
            flag_bit = BitValue.RECESSIVE
            flag_type = "PASSIVE"
            senders_str = ", ".join([self.slaves[sid].name for sid in passive_senders])

        print(
            f"  [ERR] ERROR_FLAG_{flag_type} | {senders_str} -> BUS={int(flag_bit)} "
            f"(bit {7-self._error_flag_bits_left}/{'6' if flag_type=='ACTIVE' else '8'})"
        )

        # Consume one bit from the remaining error-flag counter.
        self._error_flag_bits_left -= 1

        if self._error_flag_bits_left <= 0:
            # Emitting a passive error flag is not itself a successful frame.
            # TEC is reduced only if the preserved frame is retransmitted and
            # subsequently reaches EOF successfully.
            self.state = MasterState.ERROR_DELIM

    # Emit the recessive delimiter separating an error flag from the next interframe period.
    def _handle_error_delim_step(self):
        """Handle the ERROR DELIMITER, represented by eight RECESSIVE bits."""
        if self._error_delim_bits_left <= 0:
            self.state = MasterState.INTERFRAME
            return
        
        delim_bit = BitValue.RECESSIVE
        print(f"  [ERR] ERROR_DELIM | BUS={int(delim_bit)} (bit {9-self._error_delim_bits_left}/8)")
        self._broadcast(delim_bit, sender_name="ERROR_DELIM", field=Field.STUFF)
        
        self._error_delim_bits_left -= 1
        
        if self._error_delim_bits_left <= 0:
            self.state = MasterState.INTERFRAME

    # Finalize successful senders, update counters, or prepare failed frames for retransmission.
    def _handle_eof(self):
        if self._frame_ok and self._winner is not None:
            # Only ECUs that actually completed their normal frame reach a
            # successful transmission. An ECU that emitted a passive error flag
            # keeps its failed request pending for immediate retransmission.
            # Only senders that completed a normal bitstream are considered successful.
            successful_senders: List[int] = []
            for sid in (self._active_senders or [self._winner]):
                ecu = self.slaves[sid]
                if (
                    ecu._tx_mode == "NORMAL"
                    and ecu._pending_req is not None
                    and ecu._bitstream is not None
                    and ecu._cursor >= len(ecu._bitstream.bits)
                ):
                    successful_senders.append(sid)

            # Forward one successfully completed frame and apply transmitter recovery.
            if successful_senders:
                sender0 = self.slaves[successful_senders[0]]
                req0 = sender0._pending_req
                if req0 is not None:
                    print(f"[MASTER] Frame OK: ID=0x{req0.arbitration_id:03X} data={req0.data.hex().upper()}")
                    if self._sockcan is not None:
                        sockcan_send_data(self._sockcan, req0.arbitration_id, req0.data)

                for sid in successful_senders:
                    ecu = self.slaves[sid]
                    ecu.apply_success_update()
                    print(f"[MASTER] {ecu.name}: TEC={ecu.tec} (-1 for successful transmission) State={ecu.state.name}")
                    ecu._pending_req = None
                    ecu._cursor = 0
                    ecu._bitstream = None

                # A valid received frame allows listening nodes to reduce REC by one.
                # Listening nodes reduce REC after a valid frame. A transmitter
                # whose frame failed is not treated as a successful sender.
                successful_set = set(successful_senders)
                for sid, ecu in self.slaves.items():
                    if sid in successful_set or ecu.is_bus_off():
                        continue
                    if ecu.rec > 0:
                        ecu.rec -= 1
                        print(f"[MASTER] {ecu.name}: REC={ecu.rec} (-1 for successfully received frame)")
        else:
            # Error frames retain their requests so affected senders can retry immediately.
            if self._error_senders or self._active_error_frame:
                print("[MASTER] Frame ERROR -> immediate retransmission")

            # All failed transmitters preserve their original requests and are
            # reset to SOF. They will participate in arbitration again as soon
            # as the interframe handling returns the master to IDLE.
            for sid in (self._active_senders or []):
                ecu = self.slaves[sid]
                if not ecu.is_bus_off() and ecu._pending_req is not None:
                    ecu.reset_for_retransmission()

        self.state = MasterState.INTERFRAME

    # Clear all per-frame state and return the master to IDLE for the next gather window.
    def _handle_interframe(self):
        self._err_active_sent = False
        self._contenders = []
        self._active_senders = []
        self._winner = None
        self._error_senders = []
        self._frame_ok = True
        self._active_error_frame = False
        self._error_flag_ticks = 0
        self._rec_bumped_for_error = False
        # Reset passive-error bookkeeping for the completed frame.
        self._passive_error_senders.clear()
        for ecu in self.slaves.values():
            ecu._silence_bit_errors = False
            ecu._tx_mode = "NORMAL"
            ecu._err_flag_bits_left = 0
        self.state = MasterState.IDLE



# Configure the demonstration topology and run until BUS_OFF, an IDS alert, or interruption.
def main():
    print("=" * 100)
    print("CAN BUS SIMULATOR - DYNAMIC ARBITRATION TEST")
    print("=" * 100)
    print("\nConfiguration:")
    print("  - ECUs with LOWER IDs (HIGH priority) -> LONGER period (transmit LESS frequently)")
    print("  - ECUs with HIGHER IDs (LOW priority) -> SHORTER period (transmit MORE frequently)")
    print("  - 2 ECUs with the SAME ID -> generate a COLLISION and increment TEC\n")
    print("\nTested scenarios:")
    print("  1. A single ECU transmitting by itself")
    print("  2. Arbitration between ECUs with different IDs")
    print("  3. Collision between ECUs with the same ID")
    print("  4. An ECU requesting transmission while another ECU is transmitting\n")
    print("\nIMPLEMENTED FIXES:")
    print("  - START_SLOT removed: all PENDING ECUs participate in arbitration IMMEDIATELY")
    print("  - Collision: BOTH ECUs increment their TEC by +8")
    print("  - ERROR FLAG ACTIVE: 6 bit DOMINANT (TEC < 128)")
    print("  - ERROR FLAG PASSIVE: 8 bit RECESSIVE (TEC >= 128)")
    print("  - TEC -= 1 after a successful transmission")
    print("  - Immediate automatic retransmission after every error (without waiting for tx_period)")
    print("  - PASSIVE ERROR FLAG: +8 for the error, -1 after successful retransmission = net increase of +7")
    print("  - Simple IDS: collision rate plus concentration on the DATA bit\n")

    # Create the master before the ECUs so every submitted request has an active consumer.
    master = CANMaster(
        tick_ms=0.5,
        forward_to_socketcan=False,
        can_channel="vcan0",
        fault_injector=None,
    )
    master.start()

    # ========================================
    # ECU CONFIGURATION - OPTIMIZED TIMING
    # ========================================
    # The following start times are selected to create deliberate overlaps:
    # T=0 s: ECU_A starts alone, exercising the single-transmitter scenario.
    # T=2 s: ECU_B and ECU_C start together, exercising arbitration between different IDs.
    # T=4 s: ECU_D and ECU_E start together, exercising a same-ID collision.
    # T=6 s: ECU_A transmits again while other ECUs may also be active.
    
    # ECU_A: low ID (0x050), high priority, six-second period, starts almost immediately.
    ecu_a = BaseECU("ECU_A", 1, 0x050, master, tx_period=6.0, start_delay=0.1, auto_tx=True)
    
    # ECU_B: medium-low ID (0x100), medium-high priority, eight-second period, starts at T=2 s.
    ecu_b = BaseECU("ECU_B", 2, 0x100, master, tx_period=8.0, start_delay=2.0, auto_tx=True)
    
    # ECU_C: medium-high ID (0x200), medium-low priority, ten-second period, starts with ECU_B.
    ecu_c = BaseECU("ECU_C", 3, 0x200, master, tx_period=10.0, start_delay=2.0, auto_tx=True)
    
    # ECU_D: high ID (0x300), low priority, configured with a fourteen-second period, starts at T=4 s.
    ecu_d = BaseECU("ECU_D", 4, 0x300, master, tx_period=14.0, start_delay=4.0, auto_tx=True)
    
    # ECU_E: same ID as ECU_D, intentionally causing a collision; starts at T=4 s.
    ecu_e = BaseECU("ECU_E", 5, 0x300, master, tx_period=14.0, start_delay=4.0, auto_tx=True)

    print("Configured ECUs:")
    print(f"  - ECU_A: ID=0x050 (HIGH priority)        -> TX every 6.0s  (start: 0.1s)")
    print(f"  - ECU_B: ID=0x100 (MEDIUM-HIGH priority) -> TX every 8.0s  (start: 2.0s)")
    print(f"  - ECU_C: ID=0x200 (MEDIUM-LOW priority)  -> TX every 10.0s (start: 2.0s)")
    print(f"  - ECU_D: ID=0x300 (LOW priority)         -> TX every 12.0s (start: 4.0s)")
    print(f"  - ECU_E: ID=0x300 (COLLISION with D!)    -> TX every 14.0s (start: 4.0s)")
    print("\n" + "=" * 100)

    # Start ECU workers only after the master state-machine threads are running.
    ecu_a.start()
    ecu_b.start()
    ecu_c.start()
    ecu_d.start()
    ecu_e.start()

    print("\nSimulation started! (Press Ctrl+C to stop)\n")

    # Keep the main thread alive while daemon workers execute the simulation.
    try:
        while True:
            time.sleep(1.0)
            
            # Stop the demonstration once any ECU reaches the BUS_OFF state.
            if any(ecu.is_bus_off() for ecu in [ecu_a, ecu_b, ecu_c, ecu_d, ecu_e]):
                print(f"\n{'*'*100}")
                print(f"BUS-OFF DETECTED!")
                print(f"{'*'*100}")
                print(f"  ECU_A: TEC={ecu_a.tec:3d} REC={ecu_a.rec:3d} State={ecu_a.state.name}")
                print(f"  ECU_B: TEC={ecu_b.tec:3d} REC={ecu_b.rec:3d} State={ecu_b.state.name}")
                print(f"  ECU_C: TEC={ecu_c.tec:3d} REC={ecu_c.rec:3d} State={ecu_c.state.name}")
                print(f"  ECU_D: TEC={ecu_d.tec:3d} REC={ecu_d.rec:3d} State={ecu_d.state.name}")
                print(f"  ECU_E: TEC={ecu_e.tec:3d} REC={ecu_e.rec:3d} State={ecu_e.state.name}")
                print(f"{'*'*100}")
                break
            
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted manually")

    # Stop all worker threads and print the final fault-confinement counters.
    print(f"\n{'='*100}")
    print("[FINAL STATUS]")
    print(f"{'='*100}")
    print(f"  ECU_A: TEC={ecu_a.tec:3d} REC={ecu_a.rec:3d} State={ecu_a.state.name}")
    print(f"  ECU_B: TEC={ecu_b.tec:3d} REC={ecu_b.rec:3d} State={ecu_b.state.name}")
    print(f"  ECU_C: TEC={ecu_c.tec:3d} REC={ecu_c.rec:3d} State={ecu_c.state.name}")
    print(f"  ECU_D: TEC={ecu_d.tec:3d} REC={ecu_d.rec:3d} State={ecu_d.state.name}")
    print(f"  ECU_E: TEC={ecu_e.tec:3d} REC={ecu_e.rec:3d} State={ecu_e.state.name}")
    print(f"{'='*100}\n")

    ecu_a.stop()
    ecu_b.stop()
    ecu_c.stop()
    ecu_d.stop()
    ecu_e.stop()
    master.stop()


# Run the interactive simulation only when this module is executed as a script.
if __name__ == "__main__":
    main()
