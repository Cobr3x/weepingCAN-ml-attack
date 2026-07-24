# General dependencies
import time
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.align import Align

# Project dependencies
from can_controller import CANBusMaster
from node import BaseECU, NodeState

# CLI UI with Rich
class UIScreen:
    def __init__(self, master: CANBusMaster):
        self.master = master
        self.running = True

    def _render_top(self):
        txt = Text()
        txt.append("CAN BUS SIMULATOR\n", style="bold cyan")
        txt.append("Bit-level arbitration, error handling.\n", style="italic")
        return Panel(txt, title="Simulator", border_style="cyan")

    def _render_middle(self):
        arb = self.master.ui_state.get("arbitration_line", "No arbitration yet")
        current_bit = self.master.ui_state.get("current_bit", "")
        coll = self.master.ui_state.get("collision_line", "")
        last = self.master.ui_state.get("last_frame", None)
        ids_alert = self.master.ui_state.get("ids_alert", "")

        table = Table(expand=True)
        table.add_column("Field")
        table.add_column("Details")

        table.add_row("Arbitration", arb)
        table.add_row("Bus signal", current_bit)
        table.add_row("Collision", coll if coll else "-")

        if last:
            table.add_row(
                "Last Frame",
                f"ID=0x{last['id']:03X} by {last['ecu']} data={last['data']}"
            )
        else:
            table.add_row("Last Frame", "-")

        table.add_row("IDS", ids_alert if ids_alert else "No alert")

        return Panel(table, title="Bus Arbitration & IDS", border_style="blue")

    def _render_bus(self):
        signal = self.master.ui_state.get("bus_signal", "")
        return Panel(Align.center(signal, vertical="middle"), expand=True, title="Live Bus", border_style="yellow")

    def _render_bottom(self):
        table = Table(expand=True)
        table.add_column("ECU")
        table.add_column("ID")
        table.add_column("TEC")
        table.add_column("REC")
        table.add_column("State")
        table.add_column("Next TX")

        for ecu in self.master.ecus.values():
            if isinstance(ecu, BaseECU):
                state_style = "green"
                if ecu.state is NodeState.ERROR_PASSIVE:
                    state_style = "yellow"
                elif ecu.state is NodeState.BUS_OFF:
                    state_style = "red"

                table.add_row(
                    ecu.name,
                    f"0x{ecu.arb_id:03X}",
                    str(ecu.tec),
                    str(ecu.rec),
                    f"[{state_style}]{ecu.state.name}[/]",
                    f"{ecu.get_time_until_tx():.2f}s"
                )

        return Panel(table, title="ECU Runtime State", border_style="green")

    def _compose(self):
        layout = Layout()
        layout.split(
            Layout(self._render_top(), name="top", size=5),
            Layout(self._render_middle(), name="middle", size=11),
            Layout(self._render_bus(), name="middle", size=3),
            Layout(self._render_bottom(), name="bottom")
        )
        return layout

    def run(self):
        with Live(self._compose(), refresh_per_second=10, screen=True) as live:
            while self.running:
                live.update(self._compose())
                #time.sleep(0.01)
