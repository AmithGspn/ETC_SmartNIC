; Define input ports for the pipeline (from ring buffer)
port in 1 ring RING44 bsz 1

; Define output ports for the pipeline (to physical ports)
port out 0 ethdev 0000:07:00.0 txq 14 bsz 1
port out 1 ethdev 0000:08:00.0 txq 14 bsz 1
