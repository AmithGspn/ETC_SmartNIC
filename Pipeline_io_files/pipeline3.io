; Define input ports for the second pipeline (from physical ports)
port in 0 ring RING1 bsz 1

; Define output ports for the second pipeline (to physical ports)
port out 0 ethdev 0000:03:00.0 txq 0 bsz 1   ; First physical output port
port out 1 ethdev 0000:03:00.1 txq 0 bsz 1   ; Second physical output port
