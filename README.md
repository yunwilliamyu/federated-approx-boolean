This code is associated with the following manuscript: Alexander T. Leighton and Yun William Yu; "Secure federated Boolean count queries using fully-homomorphic cryptography". In submission. https://www.biorxiv.org/content/10.1101/2021.11.10.468090

# Requirements
 - Golang 1.21.1
 - Lattigo v4.0
 - Golang iter library
 - Python v3 (and "pip3 install mmh3 scikit-learn numpy")

Please go to https://go.dev/doc/install for Golang install requirements.

# Quick-start simulation
Once Golang and the necessary Python libraries are installed, clone this Git repo and run the following:
```
python3 generate_samples.py [num_parties] [num_conditions] [num_buckets]
```
[num\_buckets] is only used for the initial LogLog sketch in the simulation, to determine the downsampling rate. That LogLog union-count query can also be done in a homomorphic encryption framework using the code at 
https://github.com/atleighton/rlwe-hll which is implemented in the alternate homomorphic encryption framework Palisade.

Note that generate\_samples.py will also run the full Boolean count query sampling in plaintext, so that we can later verify the results of running the same computation in ciphertext. It will also output a samples.txt which contains the bitvectors that the Go program will union and intersect in ciphertext.

We will then run the Go benchmarking program twice, once to get unions, and the other time to get intersections.
```
go run main.go u [num_parties] [num_conditions] [num_buckets] samples.txt
go run main.go i [num_parties] [num_conditions] [num_buckets] samples.txt
```
The respective outputs can be checked against the plaintext computation earlier.

Note that for prototyping purposes, num\_parties, num\_conditions, and num\_buckets should all be powers of 2.

# Acknowledgements
Code is heavily modified, but based off code at https://github.com/tuneinsight/lattigo/blob/master/examples/dbfv/psi/main.go, with modifications made by yunwilliamyu.
