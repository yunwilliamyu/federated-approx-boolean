#!/bin/bash


for num_parties in 2 4 8
do
    for num_buckets in 128 256 512
    do
        res_file=res-$num_parties-$num_buckets.txt
        python3 generate_samples.py $num_parties 4 $num_buckets > $res_file
        go run main.go u $num_parties 4 samples.txt &>> $res_file
        go run main.go i $num_parties 4 samples.txt &>> $res_file
    done
done
