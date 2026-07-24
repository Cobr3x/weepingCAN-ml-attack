# General dependencies 
import threading
import time
import csv
import math
from collections import defaultdict, deque, Counter
from typing import Optional


class CANIDS:
    """
    IDS minimal layer:
      1) collision rate per ID in window W
      2) bit index concentration (mode share or low entropy)

    Observer:
        - victim_identification 
        - target_monitoring 
        - attacker_inference 
        - pattern_recognition
    """

    def __init__(
        self,
        observer_mode: bool = False,
        window_s: float = 120.0,
        min_collisions: int = 3,
        mode_share_th: float = 0.75,
        entropy_th: float = 2.0,
        cooldown_s: float = 1.0,
        observer_window: float = 3.0,
        anomaly_sensitivity: int = 3
    ):
        self.window_s = window_s
        self.observer_mode = observer_mode
        self.min_collisions = min_collisions
        self.mode_share_th = mode_share_th
        self.entropy_th = entropy_th
        self.cooldown_s = cooldown_s
        self.observer_window = observer_window
        self.anomaly_sensitivity = anomaly_sensitivity

        # IDs
        self.victim_id: Optional[int] = None    # victim
        self.attacker_ids: Optional[int] = []  # attacker

        # Control
        self._lock = threading.Lock()
        self._stop = False
        self._observer_thread = None
        self._anomaly_observed: bool = False
        self._anomaly_counter = 0
        self._avg_dT: float = 0.0
        self._avg_dA: float = 0.0

        # DEBUG
        self._debug = None

        # Traffic and TEC 
        self._IDC: dict[int, int] = {}   # TRAFFIC HISTORY (frequency per ID)
        self._IDEC: dict[int, int] = {}  # ID ERROR COUNTER
        self._IDTEC: dict[int, int] = {}  # ID EFFECTIVE TRANSIMISSION ERROR COUNTER (Victim's TEC)
        self._avg_freq: dict[int, int] = {}
        self._victim_is_errorpassive: dict[int, bool] = {}  

        # Collision events for entropy-based IDS
        self.events = defaultdict(deque)  # arb_id -> deque[(ts, bit_idx, offender_name)]
        self._last_alert_ts = {}          # arb_id -> ts

        # Observer internal state machine
        # victim_identification → target_monitoring → cooldown → pattern_recognition
        self._state: str = "victim_identification"

        # Cooldown phase parameters
        self._cooldown_freq: dict[int, int] = {}
        self._cooldown_steps: int = 0
        self._cooldown_window: int = 1  # number of observer cycles in cooldown

        # Estimated TECs
        self._last_victim_TEC: int = 0
        self._last_attacker_TEC: int = 0

        # Recovery counter parameter (time before stop observing)
        self._recovery_reactivity: int = 5

        if self.observer_mode:
            self.start()

    def start(self):
        self._observer_thread = threading.Thread(target=self._observer_loop, daemon=True)
        self._observer_thread.start()

    def stop(self):
        self._stop = True

    def _prune(self, arb_id: int, now: float):
        dq = self.events[arb_id]
        cutoff = now - self.window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    # - Observer input by controller - #
    def notify_observer(self, arb_id: int):
        with self._lock:
            self._IDC[arb_id] = self._IDC.get(arb_id, 0) + 1
            if self._IDTEC.get(arb_id, 0) > 0:
               self._IDTEC[arb_id] = self._IDTEC.get(arb_id) - 1

    def observe_collision(self, arb_id: int, bit_idx: int, offender_name: str, ts: float | None = None, error_passive: bool = False):
        now = time.time() if ts is None else float(ts)
        dq = self.events[arb_id]
        dq.append((now, int(bit_idx), str(offender_name)))
        self._prune(arb_id, now)
        if error_passive:
            self._victim_is_errorpassive[arb_id] = True
        with self._lock:
            self._IDEC[arb_id] = self._IDEC.get(arb_id, 0) + 1
            self._IDTEC[arb_id] = self._IDTEC.get(arb_id, 0) + 8

    # - Helpers - #
    @staticmethod
    def _entropy(counts: Counter) -> float:
        total = sum(counts.values())
        if total <= 0:
            return 0.0
        H = 0.0
        for c in counts.values():
            p = c / total
            H -= p * math.log(p + 1e-12, 2)
        return H

    @staticmethod
    def _dict_diff(new: dict[int, int], old: dict[int, int]) -> dict[int, int]:
        keys = set(new) | set(old)
        return {k: new.get(k, 0) - old.get(k, 0) for k in keys}

    @staticmethod
    def _dict_add(a: dict[int, int], b: dict[int, int]) -> dict[int, int]:
        keys = set(a) | set(b)
        return {k: a.get(k, 0) + b.get(k, 0) for k in keys}
    
    @staticmethod
    def _dict_fraction(a: dict[int, int], b: int) -> dict[int, int]:
        if b == 0:
            return {k: 0.0 for k in a} 
        return {k: int(a[k] / b) for k in a}

    # - Observer Loop - #

    def _observer_loop(self):
        # Initial snapshots
        with self._lock:
            snapshot_error = dict(self._IDEC)
            snapshot_frequency = dict(self._IDC)

        time.sleep(self.observer_window)
        self._avg_freq = self._dict_diff(dict(self._IDC), snapshot_frequency)

        # TEC estimates
        victim_TEC = 0
        attacker_TEC = 0

        while not self._stop:
            # Take current copies under lock
            with self._lock:
                current_IDEC = dict(self._IDEC)
                current_IDC = dict(self._IDC)
                current_IDTEC = dict(self._IDTEC)

            # Per-cycle diffs
            diff_error = self._dict_diff(current_IDEC, snapshot_error)
            diff_frequency = self._dict_diff(current_IDC, snapshot_frequency)

            # -- STATE MACHINE --
            if self._state == "victim_identification":
                # define attacked ID observing increasing TEC derivative
                # pick ID with max positive diff_error
                candidates = [(arb_id, d) for arb_id, d in diff_error.items() if d > 0]
                if candidates:
                    self.victim_id = max(candidates, key=lambda x: x[1])[0]
                    victim_TEC = current_IDTEC.get(self.victim_id, 0)
                    self._last_victim_TEC = victim_TEC
                    self.attacker_ids = []
                    self._cooldown_freq.clear()
                    self._cooldown_steps = 0
                    self._state = "target_monitoring"
                    snapshot_error = current_IDEC
                    snapshot_frequency = current_IDC
                    continue

            elif self._state == "target_monitoring":
                # victim TEC is increasing (target_monitoring phase)
                if self.victim_id is None:
                    self._state = "victim_identification"
                else:
                    timer_window = time.time()
                    while self._state == "target_monitoring":
                        current_TEC = current_IDTEC.get(self.victim_id, 0)
                        dTEC = current_TEC - self._last_victim_TEC
                        if dTEC >= 0:
                            # still increasing: track victim TEC
                            victim_TEC = current_TEC
                            self._last_victim_TEC = victim_TEC
                            if time.time() - timer_window > self.observer_window:
                                self._avg_freq = self._dict_fraction(self._dict_add(self._avg_freq, diff_frequency), 2)
                                timer_window = time.time()
                            with self._lock:
                                current_IDTEC = dict(self._IDTEC)
                            time.sleep(0.2)
                        else:
                            # increasing stop → enter cooldown
                            self._state = "attacker_inference"
                            self._cooldown_freq.clear()
                            self._cooldown_steps = 0

            elif self._state == "attacker_inference":
                # observe most common ID sent in this phase to infer attacker

                current_TEC = current_IDTEC.get(self.victim_id, 0)
                dTEC = current_TEC - self._last_victim_TEC

                for arb_id, df in self._dict_diff(diff_frequency, self._avg_freq).items():
                    if df > 2:
                        self._cooldown_freq[arb_id] = self._cooldown_freq.get(arb_id, 0) + df
                self._cooldown_steps += 1

                if self._cooldown_steps >= self._cooldown_window: #and not dTEC > 0:
                    if self._cooldown_freq:
                        max_freq = max(self._cooldown_freq.values())/self._cooldown_steps

                        # Attacker IDs estimation threshold
                        threshold = int(max_freq * 0.3)
                        self.attacker_ids = [
                            can_id for can_id, freq in self._cooldown_freq.items()
                            if int(freq/self._cooldown_steps) >= threshold and can_id != self.victim_id
                        ]
                        # victim TEC
                        if self.victim_id is not None:
                            victim_TEC = current_IDTEC.get(self.victim_id, 0)
                        else:
                            victim_TEC = 0

                        # attacker TEC initialization
                        self.attacker_ids
                        attacker_sent = 0
                        for id in self.attacker_ids:
                            attacker_sent += diff_frequency.get(id, 0)
                        attacker_TEC = victim_TEC - attacker_sent
                        self._last_victim_TEC = victim_TEC
                        self._last_attacker_TEC = attacker_TEC
                        self.avg_aTEC = attacker_TEC
                        self._state = "pattern_recognition"
                    else:
                        # no info → reset
                        self._state = "victim_identification"
                        self.victim_id = None
                        self.attacker_ids = []                        

            elif self._state == "pattern_recognition":
                # TEC estimation of victim and attacker, and ALARM condition
                if self.victim_id is None or not self.attacker_ids:
                    self._state = "victim_identification"
                else:
                    victim_delta = diff_error.get(self.victim_id, 0)
                    attacker_sent = 0
                    for id in self.attacker_ids:
                        attacker_sent += diff_frequency.get(id, 0)
                    victim_sent = diff_frequency.get(self.victim_id, 0)
                    victim_TEC = self._last_victim_TEC + 8*victim_delta - victim_sent
                    if self._victim_is_errorpassive.get(self.victim_id, False):
                        victim_TEC += victim_delta

                    # attacker TEC:
                    # - increases from victim TEC growth (collisions)
                    # - decreases when attacker sends frames

                    attacker_TEC = self._last_attacker_TEC - attacker_sent
                    if self._victim_is_errorpassive.get(self.victim_id, False):
                        attacker_TEC -= victim_sent
                    else:
                        attacker_TEC += 8*victim_delta

                    if attacker_TEC < 0:
                        attacker_TEC = 0

                    # ALARM: attacker TEC decreasing while victim TEC still increases
                    dT = victim_TEC - self._last_victim_TEC
                    dA = attacker_TEC - self._last_attacker_TEC

                    # Detection parameters
                    self._avg_dT = 0.4 * self._avg_dT + 0.6 * dT
                    self._avg_dA = 0.6 * self._avg_dA + 0.4 * dA


                    if self._avg_dT > 0 and self._avg_dA < 0:
                        self._anomaly_counter += 1
                    else:
                        self._anomaly_counter = 0

                    if self._anomaly_counter >= self.anomaly_sensitivity:
                        self._anomaly_observed = True                      

                    self._last_victim_TEC = victim_TEC
                    self._last_attacker_TEC = attacker_TEC

                    # recovery: if victim TEC stops increasing for long, reset
                    if victim_delta <= 0:
                        if self._recovery_reactivity == 0:
                            self._state = "victim_identification"
                            self._anomaly_observed = False
                            self._anomaly_counter = 0
                            self.victim_id = None
                            self.attacker_ids = []
                            self._recovery_reactivity = 5
                        else:
                            self._recovery_reactivity -= 1
                    else:
                        self._recovery_reactivity = 5

            # update snapshots for next derivative computation
            snapshot_error = current_IDEC
            snapshot_frequency = current_IDC

            time.sleep(self.observer_window)

    # - Alert check from the controller side - #

    def check_alert(self, arb_id: int, ts: float | None = None):
        now = time.time() if ts is None else float(ts)
       
        with self._lock:
            info = {
                "phase": self._state,
                "aID": self.attacker_ids,
                "vID": self.victim_id,
                "aTEC": self._last_attacker_TEC,
                "vTEC": self._last_victim_TEC,
                "observer": self._anomaly_observed,
            }

        self._prune(arb_id, now)
        dq = self.events.get(arb_id)
        if not dq:
            return info

        n = len(dq)
        if n < self.min_collisions:
            return info

        bits = [b for _, b, _ in dq]
        bit_counts = Counter(bits)
        mode_bit, mode_cnt = bit_counts.most_common(1)[0]
        mode_share = mode_cnt / n
        H = self._entropy(bit_counts)

        last = self._last_alert_ts.get(arb_id, 0.0)
        if now - last < self.cooldown_s:
            return info

        concentrated = (mode_share >= self.mode_share_th) or (H <= self.entropy_th)
        if not concentrated:
            return info

        offenders = [o for _, _, o in dq]
        off_counts = Counter(offenders)
        top_off, top_off_cnt = off_counts.most_common(1)[0]
        top_off_share = top_off_cnt / n

        self._last_alert_ts[arb_id] = now
        return {
            "state": True,
            "observer": self._anomaly_observed,
            "arb_id": arb_id,
            "window_s": self.window_s,
            "collisions": n,
            "mode_bit": mode_bit,
            "mode_share": mode_share,
            "entropy": H,
            "top_offender": top_off,
            "top_offender_share": top_off_share
        }

# - Logger - #

class IDSLogger(threading.Thread):
    def __init__(self, ids, master, filename="ids_log.csv", period=0.01):
        super().__init__()
        self.ids = ids
        self.filename = filename
        self.period = period
        self.running = True
        self.master = master

        with open(self.filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "victim_TEC",
                "attacker_TEC",
                "state"
            ])

    def run(self):
        while self.running:
            now = time.time()

            anomaly = 0
            if getattr(self.ids, "_anomaly_observed", "False"):
                anomaly = 1
            else:
                anomaly = 0

            row = [
                now,
                getattr(self.ids, "_last_victim_TEC", 0),
                getattr(self.ids, "_last_attacker_TEC", 0),
                getattr(self.ids, "_state", "NA"),
                anomaly,
                getattr(self.master, "aTEC", 0),
            ]

            with open(self.filename, "a", newline="") as f:
                csv.writer(f).writerow(row)

            time.sleep(self.period)

    def stop(self):
        self.running = False

