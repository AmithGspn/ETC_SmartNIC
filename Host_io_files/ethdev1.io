; Define input ports for the pipeline (from physical ports)
port in 0 ethdev 0000:07:00.0 rxq 0 bsz 32  ; First physical port
port in 1 ethdev 0000:08:00.0 rxq 0 bsz 32  ; Second physical port

; Define output ports for the pipeline (sending to the ring buffer)
port out 0 ring RING0 bsz 1
port out 1 ethdev 0000:08:00.0 txq 0 bsz 32
