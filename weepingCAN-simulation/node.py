# General dependencies 
import threading
import time

# Project dependencies
from can_controller import CANBusMaster, NodeState, BitValue

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

