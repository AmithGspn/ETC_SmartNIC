; Define input ports for the first pipeline (from physical ports)
port in 0 ethdev 0000:03:00.0 rxq 0 bsz 32  ; First physical port
port in 1 ethdev 0000:03:00.1 rxq 0 bsz 32  ; Second physical port

; Define output ports for the first pipeline (sending to the ring buffer)
port out 0 ring RING0 bsz 1                  ; First pipeline's output (sent to RING0)
port out 1 ethdev 0000:03:00.1 txq 0 bsz 32  ; Second physical output port


