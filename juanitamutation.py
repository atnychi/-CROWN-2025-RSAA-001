import random

def mutate_sbox():
    sbox = list(range(256))
    random.shuffle(sbox)
    return bytes(sbox)

def apply_mutated_sbox(data: bytes, sbox: bytes) -> bytes:
    return bytes([sbox[b] for b in data])

def e5_mutation_layer(data: bytes) -> bytes:
    sbox = mutate_sbox()
    mutated = apply_mutated_sbox(data, sbox)
    return mutated, sbox
