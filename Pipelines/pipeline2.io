; Define input ports for the second pipeline (from physical ports)
port in 0 ring RING0 bsz 1                  ; Input port for the second pipeline (from the first pipeline's output)

; Define output ports for the second pipeline (to physical ports)
port out 0 ring RING1 bsz 1   ; First physical output port
port out 1 ring RING2 bsz 1   ; Second physical output port

