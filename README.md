# JCSha3
## Library enabling the usage of SHA-3 Message Digest algorithm on any JavaCard 

**_The work on this project has been discontinued. You can find newer (and substantially faster) versions of JCSha3 here:
https://github.com/MiragePV/OptimizedJCAlgs_**

This code was created by translating tiny_sha3 from C into JavaCard's simplified Java. Original code here: https://github.com/mjosaarinen/tiny_sha3, props to Markku-Juhani O. Saarinen

This code is completely open-source and available to use freely to anyone, licensed under MIT.

## Version History

1.0.0
First working version, almost literal translation from tiny_sha3. Very simple applet allowing the usage of one SHA-3 algorithm, no SHAKE implemented yet.

Speed: 27 seconds on CJ2A081 (I guess I'll have to work on that)
