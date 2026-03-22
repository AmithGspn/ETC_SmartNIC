; Define input ports for the pipeline (from ring buffer)
port in 0 ring RING3 bsz 1

; Define output ports for the pipeline (to ring buffers)
port out 0 ring RING4 bsz 1
port out 1 ring RING5 bsz 1
