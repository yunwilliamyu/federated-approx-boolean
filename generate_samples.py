#!/usr/bin/env python3

# Depends on modules mmh3 scikit-learn numpy
# i.e. pip3 install mmh3 scikit-learn numpy

# Data structure sizes
num_buckets = 512
num_bitvector = 2**15 
num_filled = int(num_bitvector**(2/3))
bitvector_sparsity = num_bitvector / num_filled  # the union should fill at most num_bitvector / bitvector_sparsity

rel_err = 3./2. * (1/num_bitvector)**(1./3.)

# Hospital simulation conditions
num_hospitals = 16
num_patients = 10**5 #(per condition)
overlap_factor = 2
seed = 50
intersection_size = 10000
num_conditions = 4

print("Num hospitals: ", num_hospitals)
print("Num conditions: ", num_conditions)

#======================================================================
# The simulation of data representing the hospitals and conditions    #
#======================================================================

import numpy as np
def generate_condition(num_hospitals, patients, overlap_factor, seed):
  num_patients = len(patients)
  prng = np.random.RandomState(seed)
  #A = prng.randint(0, 10**18, size=num_patients)
  A = patients
  H = []
  for _ in range(overlap_factor):
    A_copy = A.copy()
    prng.shuffle(A_copy)
    H.append(A_copy)
  H = np.vstack(H)
  H = H.reshape((num_hospitals,-1))
  return H

def generate_all_conditions(num_conditions, num_hospitals, num_patients, overlap_factor, seed, intersection_size):
  C = []
  prng = np.random.RandomState(seed)
  patients = prng.randint(0, 10**18, size=num_patients)
  A = generate_condition(num_hospitals, patients, overlap_factor, seed)
  c_shape = A.shape
  A = A.flatten()
  #C.append(A)
  for i in range(0,num_conditions):
    patients_B = prng.randint(0, 10**18, size=num_patients)
    patients_B[0:intersection_size] = patients[0:intersection_size]
    B = generate_condition(num_hospitals, patients_B, overlap_factor, seed+i)
    #B = B.flatten()
    #B[0:intersection_size] = A[0:intersection_size]
    #print(sum(B) - sum(A))
    #B = B.reshape(c_shape)
    #print(B.shape)
    B = B.reshape((1,) + B.shape)
    C.append(B)
  C = np.concatenate(C, axis=0)
  return C

import mmh3
def llsketch(patients, num_buckets):
  '''Generates a loglog sketch from a list of patients'''
  ans = (2**64 - 1) * np.ones(num_buckets)
  hashes = [mmh3.hash64(str(x), signed=False) for x in patients]
  for b, v in hashes:
    b = b % num_buckets
    if ans[b] > v:
      ans[b] = v

  ans = 64 - np.log2(ans).astype(np.int8)
  return ans

import math
from scipy.special import gamma
def estimate_from_llsketch(llsketch):
  N = sum(llsketch)
  num_buckets = len(llsketch)
  T_m = gamma(-1.0/num_buckets + 1)/(-1.0/num_buckets)
  frac = ((1 - (2**(1.0/num_buckets)))/math.log(2))
  a_m = (T_m * frac)**(-num_buckets)
  return a_m * num_buckets * 2**(N/num_buckets)

def sample_patients(patients, density, num_bitvector):
  '''patients should be a 1D numpy array'''
  hashes = [mmh3.hash64('x' + str(x), signed=False) for x in patients]
  ans = np.zeros(num_bitvector, dtype=np.uint8)
  for b, c in hashes:
    p = b / (2**64)
    c = c % num_bitvector
    if p < density:
      ans[c] = 1
  return ans

data = generate_all_conditions(num_conditions, num_hospitals, num_patients, overlap_factor, seed, intersection_size)

# Finding actual intersection of conditions
patient_array = []
for i in range(data.shape[0]):
  patients = set(data[i].flatten())
  #print(list(patients)[:100])
  patient_array.append(patients)
intersect = patient_array[0]
for i in range(1, len(patient_array)):
  intersect = patient_array[i] & intersect

print("Intersection size is {}".format(len(intersect)))

#print("Sanity check that the loglog sketching is working on just hospital 1, condition 1")
#print("Actual length {}".format(len(set(data[0][0].flatten()))))
#print("Estimated length {}".format(estimate_from_llsketch(llsketch(data[0][0], num_buckets))))

data_sketches = [[llsketch(data[i][j], num_buckets) for j in range(data.shape[1])] for i in range(data.shape[0])]
data_sketches = np.asarray(data_sketches)

#======================================================================
# Combining to form the union sketch would happen in the Palisade code#
#======================================================================
union_sketch = np.max(np.max(data_sketches, axis=1), axis=0)
estimated_union_cardinality = estimate_from_llsketch(union_sketch)
print("Estimated union cardinality {}".format(estimated_union_cardinality))



#======================================================================
# Given an estimated union cardinality, the subsampling of patients   #
# at each hospital then happens in plaintext again                    #
#======================================================================
density = num_bitvector / (bitvector_sparsity*estimated_union_cardinality)
if density > 1:
  density = 1
print("Sampling density {}".format(density))

sample = [[ sample_patients(data[i][j], density=density, num_bitvector=num_bitvector)  for j in range(data.shape[1])] for i in range(data.shape[0])]
sample = np.asarray(sample)

with open('samples.txt', 'w') as f:
    for j in range(sample.shape[1]):
        for i in range(sample.shape[0]):
            for k in range(sample.shape[2]):
                print(sample[i,j,k], end='', sep='', file=f)
            #print('', file=f)
        #print(file=f)

#======================================================================
# This will be the first step in the Lattigo ciphertext computations  #
#======================================================================
union_occupancy = np.sum(1-np.product(np.product(1-sample, axis=1), axis=0)) 
print("Actual union occupancy:", str(union_occupancy))

intersection_occupancy = np.sum(np.product(1-np.product(1-sample, axis=1), axis=0))
#intersection_size = expected_balls(num_bitvector, intersection_occupancy)
print("Intersection balls: ", intersection_occupancy)

percent_intersection = intersection_occupancy / union_occupancy
print("Percent intersection: ", percent_intersection)

finite_population_correction = np.sqrt(1 - intersection_occupancy / estimated_union_cardinality)
print("Finite population correction factor: ", finite_population_correction)

print("Final sizes: ", percent_intersection * estimated_union_cardinality)
print("Standard error: ", rel_err * estimated_union_cardinality * finite_population_correction)



