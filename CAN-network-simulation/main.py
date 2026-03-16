#!/usr/bin/env python3
# weeping_can_simulator_cli.py

# General dependencies
import threading
import time

# Project dependencies
from can_controller import CANBusMaster
from node import BaseECU
from gui import UIScreen

def main():
    master = CANBusMaster(use_vcan=False, enable_ids=False)

    ecu1 = BaseECU("ECU_1", slave_id=1, arb_id=0x100, master=master, tx_period=0.5, start_delay=0.0)
    ecu2 = BaseECU("ECU_2", slave_id=2, arb_id=0x200, master=master, tx_period=0.7, start_delay=0.1)
    ecu3 = BaseECU("ECU_3", slave_id=3, arb_id=0x300, master=master, tx_period=0.9, start_delay=0.2)
    ecu4 = BaseECU("ECU_4", slave_id=4, arb_id=0x200, master=master, tx_period=0.7, start_delay=0.1)

    master.start()
    ecu1.start()
    ecu2.start()
    ecu3.start()
    ecu4.start()

    ui = UIScreen(master)
    ui_thread = threading.Thread(target=ui.run, daemon=True)
    ui_thread.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        ui.running = False
        master.stop()
        ecu1.stop()
        #ecu2.stop()
        #ecu3.stop()
        #ecu4.stop()


if __name__ == "__main__":
    main()
