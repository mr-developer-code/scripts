import tenseal as ts

context = ts.context(ts.SCHEME_TYPE.CKKS,
                    poly_modulus_degree = 16384,#8192 4096,
                    coeff_mod_bit_sizes = [60,40,40,60])

context.generate_galois_keys()
context.global_scale = 2**40
context.auto_rescale = True

#---------------------------------------------------------------------------------------