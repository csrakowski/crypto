#include "SHA1.h"

Note 1: All variables are unsigned 32 bits and wrap modulo 232 when calculating
Note 2: All constants in this pseudo code are in big endian. 
        Within each word, the most significant byte is stored in the leftmost byte position

Initialize variables:
h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0

Pre-processing:
append the bit '1' to the message
append 0 ≤ k < 512 bits '0', so that the resulting message length (in bits)
   is congruent to 448 ≡ −64 (mod 512)
append length of message (before pre-processing), in bits, as 64-bit big-endian integer

Process the message in successive 512-bit chunks:
break message into 512-bit chunks
for each chunk
    break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15

    Extend the sixteen 32-bit words into eighty 32-bit words:
    for i from 16 to 79
        w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1

    Initialize hash value for this chunk:
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    Main loop:
    [27]
    for i from 0 to 79
        if 0 ≤ i ≤ 19 then
            f = (b and c) or ((not b) and d)
            k = 0x5A827999
        else if 20 ≤ i ≤ 39
            f = b xor c xor d
            k = 0x6ED9EBA1
        else if 40 ≤ i ≤ 59
            f = (b and c) or (b and d) or (c and d) 
            k = 0x8F1BBCDC
        else if 60 ≤ i ≤ 79
            f = b xor c xor d
            k = 0xCA62C1D6

        temp = (a leftrotate 5) + f + e + k + w[i]
        e = d
        d = c
        c = b leftrotate 30
        b = a
        a = temp

    Add this chunk's hash to result so far:
    h0 = h0 + a
    h1 = h1 + b 
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e

Produce the final hash value (big-endian):
digest = hash = h0 append h1 append h2 append h3 append h4
The constant values used are chosen as nothing up my sleeve numbers: the four round constants k are 230 times the square roots of 2, 3, 5 and 10. The first four starting values for h0 through h3 are the same as the MD5 algorithm, and the fifth (for h4) is similar.
Instead of the formulation from the original FIPS PUB 180-1 shown, the following equivalent expressions may be used to compute f in the main loop above:
(0  ≤ i ≤ 19): f = d xor (b and (c xor d))                (alternative 1)
(0  ≤ i ≤ 19): f = (b and c) xor ((not b) and d)          (alternative 2)
(0  ≤ i ≤ 19): f = (b and c) + ((not b) and d)            (alternative 3)
(0  ≤ i ≤ 19): f = vec_sel(d, c, b)                       (alternative 4)
 
(40 ≤ i ≤ 59): f = (b and c) or (d and (b or c))          (alternative 1)
(40 ≤ i ≤ 59): f = (b and c) or (d and (b xor c))         (alternative 2)
(40 ≤ i ≤ 59): f = (b and c) + (d and (b xor c))          (alternative 3)
(40 ≤ i ≤ 59): f = (b and c) xor (b and d) xor (c and d)  (alternative 4)
Max Locktyukhin has also shown[28] that for the rounds 32–79 the computation of:
      w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
can be replaced with:
      w[i] = (w[i-6] xor w[i-16] xor w[i-28] xor w[i-32]) leftrotate 2
This transformation keeps all operands 64-bit aligned and, by removing the dependency of w[i] on w[i-3], allows efficient SIMD implementation with a vector length of 4 such as x86 SSE instructions.