; Define input ports for the pipeline (from ring buffer)
port in 0 ring RING4 bsz 1

; Define output ports for the pipeline (to physical ports)
port out 0 ethdev 0000:07:00.0 txq 1 bsz 1
port out 1 ethdev 0000:08:00.0 txq 1 bsz 1
