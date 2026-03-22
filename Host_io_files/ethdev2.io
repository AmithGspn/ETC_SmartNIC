; Define input ports for the pipeline (from ring buffer)
port in 0 ring RING0 bsz 1

; Define output ports for the pipeline (to ring buffers)
port out 0 ring RING1 bsz 1
port out 1 ring RING2 bsz 1
