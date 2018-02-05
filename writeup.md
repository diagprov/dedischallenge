
# Writeup

## Notes on a cryptographic level

I've seen the Schnorr public signature scheme as given in the Dedis library. 
Having written my own last time around, I decided to continue with a "standard" 
Schnorr signature scheme as given on [Schnorr Signatures, wikipedia][wiki-schnorr].
Point / message hashing uses the scheme

   Blake2b(P||M)

   [wiki-schnorr]: https://en.wikipedia.org/wiki/Schnorr_signature
