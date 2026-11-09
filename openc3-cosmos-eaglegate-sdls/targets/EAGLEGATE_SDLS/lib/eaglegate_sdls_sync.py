"""Cutting a byte stream into frames: the attached sync marker (ASM) and the
fixed frame length.

Works the same for TCP (frames split or merged across reads) and UDP (one
frame per datagram). With an ASM, bytes that are not part of a frame (noise,
a partial frame after a reconnect, a sender that is not framing at all) are
skipped up to the next ASM and reported, so they can be quarantined. Without
an ASM the stream must already be aligned: every frame_length bytes is a frame.
"""

SKIPPED_KEEP = 4096  # bytes of each skipped run kept as evidence


class FrameSync:
    def __init__(self, asm, frame_length):
        self.asm = bytes(asm)
        self.frame_length = frame_length
        self.cadu_length = len(self.asm) + frame_length
        self.buffer = bytearray()
        self.skipped_total = 0
        self.sync_losses = 0        # times bytes had to be skipped to find an ASM
        self.in_lock = False

    def reset(self):
        self.buffer = bytearray()
        self.in_lock = False

    def feed(self, data):
        """Add bytes; return a list of events in stream order:
          ("frame", frame_bytes, cadu_bytes)   frame without / with its ASM
          ("skipped", kept_bytes, count)       bytes that were not in a frame"""
        self.buffer += data
        events = []
        if not self.asm:
            while len(self.buffer) >= self.frame_length:
                frame = bytes(self.buffer[:self.frame_length])
                del self.buffer[:self.frame_length]
                events.append(("frame", frame, frame))
            return events

        while True:
            index = self.buffer.find(self.asm)
            if index < 0:
                # Keep a tail that could be the start of an ASM split across reads
                keep = len(self.asm) - 1
                if len(self.buffer) > keep:
                    self._skip(events, len(self.buffer) - keep)
                break
            if index > 0:
                self._skip(events, index)
            if len(self.buffer) < self.cadu_length:
                break
            cadu = bytes(self.buffer[:self.cadu_length])
            del self.buffer[:self.cadu_length]
            self.in_lock = True
            events.append(("frame", cadu[len(self.asm):], cadu))
        return events

    def _skip(self, events, count):
        skipped = bytes(self.buffer[:count])
        del self.buffer[:count]
        self.skipped_total += count
        if self.in_lock:
            self.sync_losses += 1  # was locked; the next frame did not start with the ASM
        self.in_lock = False
        events.append(("skipped", skipped[:SKIPPED_KEEP], count))
