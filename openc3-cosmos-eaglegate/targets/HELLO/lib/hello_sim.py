from openc3.interfaces.simulated_target import SimulatedTarget
from openc3.packets.packet import Packet


class HelloSim(SimulatedTarget):
    def __init__(self, target_name):
        super().__init__(target_name)
        self.count = 0
        self.set_rates()

    def set_rates(self):
        # Send telemetry once per second
        self.tlm_delay = 1.0

    def write(self, packet):
        # Called when a command is received
        print(f"Received command: {packet.packet_name}")

    def read(self, count, time):
        # Called periodically to generate telemetry
        self.count += 1
        packet = Packet("HELLO", "HELLO_TLM")
        packet.write("MESSAGE", "Hello, COSMOS!")
        packet.write("COUNT", self.count)
        return [packet]