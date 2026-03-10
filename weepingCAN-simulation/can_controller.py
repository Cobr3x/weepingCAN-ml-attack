#!/usr/bin/env python3
# weeping_can_simulator_cli.py

# General dependencies
import threading
import time
from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional, Tuple
import can

# Project dependencies
#from ids import SimpleCANIDS

# --- Bit Value ---
class BitValue(Enum):
    DOMINANT = 0
    RECESSIVE = 1

    @staticmethod
    def from_int(v: int) -> "BitValue":
        return BitValue.DOMINANT if v == 0 else BitValue.RECESSIVE

    def __int__(self) -> int:
        return 0 if self is BitValue.DOMINANT else 1


class NodeState(Enum):
    ERROR_ACTIVE = auto()
    ERROR_PASSIVE = auto()
    BUS_OFF = auto()


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


@dataclass
class BitTransmission:
    bit_value: BitValue
    timestamp: float
    sender_name: str
    field: Field


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


class CANBitStream:
    """Build a *stuffed* CAN base frame bit stream and per-bit field labels."""

    def __init__(self, arbitration_id: int, data: bytes, r0: BitValue = BitValue.RECESSIVE):
        self.arb_id = arbitration_id & 0x7FF
        self.data = data[:8]
        self.r0 = r0

        self.bits: List[BitValue] = []
        self.fields: List[Field] = []
        self._build()

    def _push(self, bit: BitValue, field: Field):
        self.bits.append(bit)
        self.fields.append(field)

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

    @staticmethod
    def _apply_bit_stuffing(
        bits: List[BitValue], fields: List[Field]
    ) -> Tuple[List[BitValue], List[Field]]:
        """Stuff from SOF through end of CRC sequence (inclusive)."""
        out_bits: List[BitValue] = []
        out_fields: List[Field] = []

        run_val: Optional[BitValue] = None
        run_len = 0

        def should_stuff(idx: int) -> bool:
            return fields[idx] in {
                Field.SOF,
                Field.ID,
                Field.RTR,
                Field.IDE,
                Field.R0,
                Field.DLC,
                Field.DATA,
                Field.CRC,
            }

        for idx, (b, f) in enumerate(zip(bits, fields)):
            out_bits.append(b)
            out_fields.append(f)

            if not should_stuff(idx):
                run_val = None
                run_len = 0
                continue

            if run_val is None:
                run_val = b
                run_len = 1
            else:
                if b == run_val:
                    run_len += 1
                    if run_len == 5:
                        stuffed = BitValue.RECESSIVE if run_val is BitValue.DOMINANT else BitValue.DOMINANT
                        out_bits.append(stuffed)
                        out_fields.append(Field.STUFF)
                        run_val = stuffed
                        run_len = 1
                else:
                    run_val = b
                    run_len = 1

        return out_bits, out_fields

    def _build(self):
        raw_bits, raw_fields = self._build_unstuffed_payload_bits()
        stuffed_bits, stuffed_fields = self._apply_bit_stuffing(raw_bits, raw_fields)
        self.bits = stuffed_bits
        self.fields = stuffed_fields


def bytes_to_bits(data: bytes) -> List[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


# --- CAN Bus Master ---
class CANBusMaster:
    """
    Simplified simulator:
    - arbitrates frames between multiple ECUs
    - handles collisions and error flags
    - exposes state for CLI UI
    """
    def __init__(self, use_vcan: bool = False, enable_ids: bool = False, collect_window: float = 0.002):
        self.ecus = {}
        self.pending = []
        self.lock = threading.Lock()
        self._stop = False
        self._thread = None
        self.collect_window = collect_window 
        self.use_vcan = use_vcan
        self.enable_ids = enable_ids
        self.vcan_bus = None
        if self.use_vcan:
            try:
                self.vcan_bus = can.interface.Bus(channel='vcan0', interface='socketcan')
            except Exception:
                self.vcan_bus = None

        if self.enable_ids:
            self.ids = SimpleCANIDS(window_s=180.0, min_collisions=2, mode_share_th=0.6, entropy_th=0.75, cooldown_s=0.0)

        # Uncomment to stop the simulation when a collision is detected
        # self.ids_stop_on_alert = True

        # UI shared state
        self.ui_state = {
            "arbitration_line": "",
            "bus_signal": "",
            "current_bit": "0",
            "collision_line": "",
            "last_frame": None,
            "ids_alert": "",
        }

        if not self.enable_ids:
            self.ui_state["ids_alert"] = "Disable"

    def register_ecu(self, ecu):
        self.ecus[ecu.slave_id] = ecu

    def submit_transmission(self, ecu, data: bytes, arb_id: int, r0: BitValue = BitValue.RECESSIVE):
        # Retransmission mechanism avoidance: discard policy
        with self.lock:
            if ecu not in (ecuname for ecuname, _, _, _ in self.pending):
                self.pending.append((ecu, data, arb_id, r0))

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop = True
        try:
            if self.vcan_bus is not None:
                self.vcan_bus.shutdown()
        except Exception:
            pass
    
    def _run(self):
        while not self._stop:
            with self.lock:
                if self.pending:
                    contenders = self.pending[:]
                    self.pending.clear()
                    self._process_contenders(contenders)
            time.sleep(self.collect_window)

    def _process_contenders(self, contenders):
        # NO-collision assumption
        if len(contenders) == 1:
            ecu, data, arb_id, r0 = contenders[0]
            if ecu.is_bus_off():
                return
        #    self._transmit_frame(ecu, data, arb_id, r0)
        #    return
        else:
            contenders = [c for c in contenders if not c[0].is_bus_off()]
            if not contenders:
                return

        winner = self._perform_arbitration(contenders)
        if winner is None or winner[0] is None:
            return

        winner_ecu, winner_data, winner_id, winner_r0 = winner
        self._transmit_frame(winner_ecu, winner_data, winner_id, winner_r0)

    def _perform_arbitration(self, contenders):
        bitstreams = []
        for ecu, data, arb_id, r0 in contenders:
            bs = CANBitStream(arb_id, data, r0=r0)
            bitstreams.append((ecu, bs, arb_id, data, r0))

        active = list(range(len(bitstreams)))
        bit_idx = 0
        bus_bitstream = ""

        while len(active) > 1:
            time.sleep(0.02)
            if bit_idx >= min(len(bitstreams[i][1].bits) for i in active):
                break

            offered = []
            for i in active:
                # bit extraction from i-frame
                ecu, bs, _, _, _ = bitstreams[i]
                if bit_idx < len(bs.bits):
                    bit = bs.bits[bit_idx]
                    field = bs.fields[bit_idx]
                    offered.append((i, ecu, bit, field))

            if not offered:
                break

            bus_bit = BitValue.DOMINANT if any(bit is BitValue.DOMINANT for _, _, bit, _ in offered) else BitValue.RECESSIVE
            bus_bitstream += str(int(bus_bit))
            field = offered[0][3]

            contenders_str = " | ".join([f"{ecu.name}={int(bit)}" for _, ecu, bit, _ in offered])
            self.ui_state["bus_signal"] = f"{bus_bitstream} "
            self.ui_state["current_bit"] = f"CURRENT BIT={int(bus_bit)}"
            self.ui_state["arbitration_line"] = f"{contenders_str}"

            # During ID arbitration, recessive loses
            if field in {Field.SOF, Field.ID, Field.RTR}:
                losers = []
                for i, ecu, bit, _ in offered:
                    if bit is BitValue.RECESSIVE and bus_bit is BitValue.DOMINANT:
                        losers.append(i)

                for loser_idx in sorted(losers, reverse=True):
                    if loser_idx in active:
                        active.remove(loser_idx)

            bit_idx += 1

            # Same ID collision
            if field == Field.RTR and len(active) > 1:
                names = ", ".join([bitstreams[i][0].name for i in active])
                self.ui_state["collision_line"] = f"POSSIBLE COLLISION! Same ID between: {names}"
                # Two ECUs transmitting the same ID -> possible collision to be handled
                return self._handle_collision(bitstreams, active, bit_idx)
                

        if len(active) == 1:
            time.sleep(0.02)
            winner_idx = active[0]
            ecu, bs, _, _, _ = bitstreams[winner_idx]

            #Live bus print until the end
            while bit_idx < len(bs.bits):
                bus_bit = bs.bits[bit_idx]
                field = bs.fields[bit_idx]
                bit_idx += 1
                if field == Field.RTR:
                    bus_bitstream = ""
                    time.sleep(0.02)
                bus_bitstream += str(int(bus_bit))
                contenders_str = f"{ecu.name}={int(bus_bit)}"
                self.ui_state["arbitration_line"] = f"{contenders_str}"
                self.ui_state["bus_signal"] = f"{bus_bitstream} "
                self.ui_state["current_bit"] = f"CURRENT BIT={int(bus_bit)}"

            winner_ecu, _, winner_id, winner_data, winner_r0 = bitstreams[winner_idx]
            self.ui_state["collision_line"] = f"WINNER: {winner_ecu.name} (ID=0x{winner_id:03X})"
            return winner_ecu, winner_data, winner_id, winner_r0

        return None, None, None, None
    
    def _transmit_frame(self, winner_ecu, data, arb_id, r0):

        self.ui_state["last_frame"] = {
            "ecu": winner_ecu.name,
            "id": arb_id,
            "data": data.hex().upper(),
        }

        if self.use_vcan and self.vcan_bus is not None:
            try:
                msg = can.Message(
                    arbitration_id=arb_id,
                    data=data,
                    is_extended_id=False
                )
                self.vcan_bus.send(msg)
            except Exception:
                pass

        winner_ecu.tec = max(0, winner_ecu.tec - 1)
        winner_ecu._update_state()

        for ecu in self.ecus.values():
            if ecu != winner_ecu and not ecu.is_bus_off() and ecu.rec > 0:
                ecu.rec -= 1

    def _handle_collision(self, bitstreams, active, start_bit_idx):
        import sys, os

        bit_idx = start_bit_idx
        error_detected = False
        offender_ecu = None

        offered_at_error = None
        bus_bit_at_error = None
        bus_bitstream = ""

        while len(active) > 0 and not error_detected:
            time.sleep(0.02)
            offered = []
            for i in active:
                ecu, bs, _, _, _ = bitstreams[i]
                if bit_idx < len(bs.bits):
                    bit = bs.bits[bit_idx]
                    field = bs.fields[bit_idx]
                    offered.append((i, ecu, bit, field))

            if not offered:
                break

            bus_bit = BitValue.DOMINANT if any(bit is BitValue.DOMINANT for _, _, bit, _ in offered) else BitValue.RECESSIVE
            bus_bitstream += str(int(bus_bit))
            field = offered[0][3]

            contenders_str = " | ".join([f"{ecu.name}={int(bit)}" for _, ecu, bit, _ in offered])
            self.ui_state["bus_signal"] = f"{bus_bitstream} "
            self.ui_state["current_bit"] = f"CURRENT BIT={int(bus_bit)}"
            self.ui_state["arbitration_line"] = f"{contenders_str}"

            for _, ecu, bit, _ in offered:
                if bit is BitValue.RECESSIVE and bus_bit is BitValue.DOMINANT:
                    if field not in {Field.SOF, Field.ID, Field.RTR}:
                        error_detected = True
                        offender_ecu = ecu

                        any_idx = offered[0][0]
                        arb_id = bitstreams[any_idx][2]

                        if hasattr(self, "ids") and self.ids is not None:
                            if field == Field.DATA:
                                bs = bitstreams[any_idx][1]
                                data_pos = 0
                                for j in range(bit_idx):
                                    if bs.fields[j] == Field.DATA:
                                        data_pos += 1
                                self.ids.observe_collision(arb_id=arb_id, bit_idx=data_pos, offender_name=ecu.name)

                            alert = self.ids.check_alert(arb_id)
                            if alert:
                                self.ui_state["ids_alert"] = (
                                    f"IDS ALERT ID=0x{alert['arb_id']:03X} "
                                    f"coll={alert['collisions']} H={alert['entropy']:.2f} "
                                    f"top={alert['top_offender']} ({alert['top_offender_share']*100:.1f}%)"
                                )
                                if self.ids_stop_on_alert:
                                    self.ui_state["ids_alert"] = (
                                        f"IDS ALERT ID=0x{alert['arb_id']:03X} - SIMULATION STOPPED - "
                                        f"coll={alert['collisions']} H={alert['entropy']:.2f} "
                                        f"top={alert['top_offender']} ({alert['top_offender_share']*100:.1f}%)"
                                    )

                                    time.sleep(0.2)
                                    sys.stdout.flush()
                                    sys.stderr.flush()
                                    os._exit(0)

                        offered_at_error = offered[:]
                        bus_bit_at_error = bus_bit
                        break

            bit_idx += 1

        if not (error_detected and offender_ecu):
            return None, None, None, None

        self._send_error_flag(offender_ecu)

        involved = [bitstreams[i][0] for i in active]

        if offender_ecu.state is NodeState.ERROR_ACTIVE:
            for ecu in involved:
                ecu.tec += 8
                ecu._update_state()

            for ecu in self.ecus.values():
                if ecu not in involved and not ecu.is_bus_off():
                    ecu.rec += 1

            return None, None, None, None

        offender_ecu.tec += 7
        offender_ecu._update_state()

        winner_idx = None
        if offered_at_error is not None and bus_bit_at_error is BitValue.DOMINANT:
            for i, ecu, bit, _ in offered_at_error:
                if ecu is not offender_ecu and bit is BitValue.DOMINANT:
                    winner_idx = i
                    break

        if winner_idx is None:
            for i in active:
                ecu = bitstreams[i][0]
                if ecu is not offender_ecu:
                    winner_idx = i
                    break

        if winner_idx is None:
            return None, None, None, None

        winner_ecu, _, winner_id, winner_data, winner_r0 = bitstreams[winner_idx]
        self.ui_state["collision_line"] = f"(PASSIVE FLAG) {winner_ecu.name} continues original frame"
        return winner_ecu, winner_data, winner_id, winner_r0

    def _send_error_flag_active(self, offender_ecu):
        # assume 6 DOMINANT + 8 RECESSIVE (6-12 DOMINANT ignored)
        biterror_counter = 0
        bus_bitstream = ""
        self.ui_state["collision_line"] = f"SENDED ERROR FLAG ACTIVE by {offender_ecu.name}"
        self.ui_state["arbitration_line"] = "ACTIVE ERROR FLAGE"
        for biterror_counter in range(14):
            time.sleep(0.02)
            if biterror_counter < 6:
                bus_bitstream += "0"
                bus_bit = BitValue.DOMINANT
            else:
                bus_bitstream += "1"
                bus_bit = BitValue.RECESSIVE
            self.ui_state["bus_signal"] = f"{bus_bitstream} "
            self.ui_state["current_bit"] = f"CURRENT BIT={int(bus_bit)}"

        if self.use_vcan and self.vcan_bus is not None:
            try:
                error_msg = can.Message(
                    arbitration_id=0x7FF,
                    data=[0x00] * 6,
                    is_extended_id=False
                )
                self.vcan_bus.send(error_msg)
            except Exception:
                pass

    def _send_error_flag_passive(self, offender_ecu):
        self.ui_state["collision_line"] = f"ERROR FLAG PASSIVE by {offender_ecu.name}"
        bus_bitstream = ""
        self.ui_state["arbitration_line"] = "PASSIVE ERROR FLAGE"
        self.ui_state["current_bit"] = f"CURRENT BIT={int(BitValue.RECESSIVE)}"
        for i in range(6):
            time.sleep(0.02)
            bus_bitstream += "1"
            self.ui_state["bus_signal"] = f"{bus_bitstream} "

    def _send_error_flag(self, offender_ecu):
        if offender_ecu.state is NodeState.ERROR_PASSIVE:
            self._send_error_flag_passive(offender_ecu)
        else:
            self._send_error_flag_active(offender_ecu)
