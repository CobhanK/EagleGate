from openc3.script import *

cmd("HELLO HELLO_CMD with MESSAGE 'Hello, world!'")
wait_check("HELLO HELLO_TLM MESSAGE == 'Hello, COSMOS!'", 5)
print("Got hello world telemetry back!")