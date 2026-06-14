# Same as before.
# The cases are this:

# Do the MITM attack again, but play with "g". What happens with:
#
#    1. g = 1
#    2. g = p
#    3. g = p - 1
# Write attacks for each.


# 1. -> the shared key is always 1
# 2. -> the shared key is always 0

# 3. This is the most interesting. (p-1)**a mod p = 1 if a is even, p-1 if a is odd.
# The proof is simple: by the binomial theorem, every term containing p vanishes mod p,
# leaving only (-1)**a, which is 1 if a is even and -1 if a is odd. -1 mod p = p-1. qed.
# Given that I get (p-1)**(a*b), the shared key is p-1 iff a and b are both odd (i.e. a*b odd),
# and 1 otherwise.
