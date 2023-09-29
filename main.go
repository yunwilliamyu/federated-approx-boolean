// File originally forked from https://github.com/tuneinsight/lattigo/blob/master/examples/dbfv/psi/main.go on 2023-09-16 under Apache 2.0 liccense
// Modifications by yunwilliamyu also released under Apache 2.0 license

package main

import (
	"log"
	"os"
	"strconv"
	"sync"
	"time"
    "github.com/bradfitz/iter"
	//"fmt"
    //"bufio"
    "io/ioutil"
    //"strings"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/dbfv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

type party struct {
	sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey

	ckgShare    *drlwe.CKGShare
	rkgShareOne *drlwe.RKGShare
	rkgShareTwo *drlwe.RKGShare
	pcksShare   *drlwe.PCKSShare
    rtgShare    *drlwe.RTGShare

	input [][]uint64
}
type multTask struct {
	wg              *sync.WaitGroup
	op1             *rlwe.Ciphertext
	op2             *rlwe.Ciphertext
	res             *rlwe.Ciphertext
	elapsedmultTask time.Duration
}

var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedRTGCloud time.Duration
var elapsedRTGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration

func main() {
	// For more details about the PSI example see
	//     Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)

	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2 arg3
    // arg1: either "union" or "intersection"
	// arg2: number of parties
	// arg3: number of conditions
    // arg4: filename of sample text file in 0/1 textfile format

    compute_union := true // Default compute union
    if len(os.Args[1:]) >= 1 {
        if string(os.Args[1][0]) == "i" {compute_union = false }
    }

	// Largest for n=8192: 512 parties
	N := 8 // Default number of parties
	var err error
	if len(os.Args[1:]) >= 2 {
		N, err = strconv.Atoi(os.Args[2])
		check(err)
	}

	NConditions := 1 // Default number conditions
	if len(os.Args[1:]) >= 3 {
		NConditions, err = strconv.Atoi(os.Args[3])
		check(err)
	}

    sample_fn := "" // Default is empty string
    if len(os.Args[1:]) >= 4 {
        sample_fn = os.Args[4]
    }


	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	paramsDef := bfv.PN15QP827pq
	paramsDef.T = 65537
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	crs, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	encoder := bfv.NewEncoder(params)

	// Target private and public keys
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, N)

	// Inputs & expected result
    expRes := 0
    if sample_fn == "" {
        expRes = genInputs(params, P, NConditions)
    } else {
        expRes = readInputs(params, P, NConditions, sample_fn)
    }
    _ = expRes

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation
	rlk := rkgphase(params, crs, P)

    // 3) Collective rotation keys generation
    rtk := rtkphase(params, crs, P)

	l.Printf("\tdone (cloud: %s, party: %s)\n",
		elapsedRKGCloud, elapsedRKGParty)
	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud+elapsedRTGCloud, elapsedRKGParty+elapsedCKGParty+elapsedRTGParty)

	encInputs_party_first := encPhase(params, P, pk, encoder, NConditions)

    // Ciphertext of all ones
    onesCt := onesVec(params, pk, encoder)

    // Switch inner/outer loops of encInputs
    // Before: Party -> Condition -> Vector
    // After:  Condition -> Party -> Vector
    encInputs_condition_first := make([][]*rlwe.Ciphertext, NConditions)
    for i := range(encInputs_condition_first) {
        encInputs_condition_first[i] = make([]*rlwe.Ciphertext, len(P))
        for j := range encInputs_condition_first[i] {
            encInputs_condition_first[i][j] = encInputs_party_first[j][i]
        }
    }
    encInputs := encInputs_condition_first

	encRes := evalPhase(params, NConditions, encInputs, rlk, rtk, onesCt, compute_union)

	encOut := pcksPhase(params, tpk, encRes, P)

	// Decrypt the result with the target secret key
	l.Println("> Result:")
	decryptor := bfv.NewDecryptor(params, tsk)
	ptres := bfv.NewPlaintext(params, params.MaxLevel())
	elapsedDecParty := runTimed(func() {
		decryptor.Decrypt(encOut, ptres)
	})
    _ = elapsedDecParty

	// Check the result
	res := encoder.DecodeUintNew(ptres)
    ans := int(res[0])
    //l.Printf("\t%v\n", res[:16])
    l.Printf("\t%v\n", ans)
	//l.Printf("\t%v\n", len(res))
    //if expRes != ans {
        //l.Printf("\t%v\n", expRes)
        //l.Println("\tincorrect")
        //return
    //}
	//l.Println("\tcorrect")
	//l.Printf("> Finished (total cloud: %s, total party: %s)\n",
	//	elapsedCKGCloud+elapsedRKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud,
	//	elapsedCKGParty+elapsedRKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)

}

func encPhase(params bfv.Parameters, P []*party, pk *rlwe.PublicKey, encoder bfv.Encoder, NConditions int) (encInputs [][]*rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputs = make([][]*rlwe.Ciphertext, len(P))
	for i := range encInputs {
        encInputs[i] = make([]*rlwe.Ciphertext, NConditions)
        for j := range encInputs[i] {
            encInputs[i][j] = bfv.NewCiphertext(params, 1, params.MaxLevel())
        }
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase")
	encryptor := bfv.NewEncryptor(params, pk)

	pt := bfv.NewPlaintext(params, params.MaxLevel())
	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
            for j, pi_i := range pi.input {
                encoder.Encode(pi_i, pt)
                encryptor.Encrypt(pt, encInputs[i][j])
            }
		}
	}, len(P))

	elapsedEncryptCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	return
}

func onesVec(params bfv.Parameters, pk *rlwe.PublicKey, encoder bfv.Encoder) (onesCt *rlwe.Ciphertext) {
    // Generate a ones ciphertext vector for addition

	ones_pt := bfv.NewPlaintext(params, params.MaxLevel())
    onesCt = bfv.NewCiphertext(params, 1, params.MaxLevel())
    ones_input := make([]uint64, params.N())
    for i := range ones_input {
        ones_input[i] = 1
    }
    encoder.Encode(ones_input, ones_pt)
	encryptor := bfv.NewEncryptor(params, pk)
    encryptor.Encrypt(ones_pt, onesCt)
    return
}

func evalPhase(params bfv.Parameters, NConditions int, encInputs [][]*rlwe.Ciphertext, rlk *rlwe.RelinearizationKey, rtk *rlwe.RotationKeySet, onesCt *rlwe.Ciphertext, compute_union bool) (encRes *rlwe.Ciphertext) {
    l := log.New(os.Stderr, "", 0)


    l.Println("> Eval Phase")
    l.Println("NConditions: ", NConditions)
    evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rtk})

    conditions := make([]*rlwe.Ciphertext, 0)

    elapsedEvalCloud := time.Duration(0)
    for p := range iter.N(NConditions) {
        l.Println("> > unioning each condition: ", p)
        encLvls := make([][]*rlwe.Ciphertext, 0)
        encLvls = append(encLvls, encInputs[p])
        for nLvl := len(encInputs[p]) / 2; nLvl > 0; nLvl = nLvl >> 1 {
            encLvl := make([]*rlwe.Ciphertext, nLvl)
            for i := range encLvl {
                encLvl[i] = bfv.NewCiphertext(params, 2, params.MaxLevel())
            }
            encLvls = append(encLvls, encLvl)
        }
        conditions = append(conditions, encLvls[len(encLvls)-1][0])
        l.Println("Current len conditions: ", len(conditions))

        workCt := make([]*rlwe.Ciphertext, 2)
        workCt[0] = bfv.NewCiphertext(params, 1, params.MaxLevel())
        workCt[1] = bfv.NewCiphertext(params, 1, params.MaxLevel())
        elapsedEvalCloud += runTimed(func() {
            for i, lvl := range encLvls[:len(encLvls)-1] {
                nextLvl := encLvls[i+1]
                l.Println("\tlevel", i, len(lvl), "->", len(nextLvl))
                for j, nextLvlCt := range nextLvl {
                    evaluator.Neg(lvl[2*j], workCt[0])
                    evaluator.Neg(lvl[2*j+1], workCt[1])
                    evaluator.Add(onesCt, workCt[0], workCt[0])
                    evaluator.Add(onesCt, workCt[1], workCt[1])
                    //evaluator.Relinearize(workCt[0], workCt[0])
                    //evaluator.Relinearize(workCt[1], workCt[1])
                    evaluator.Mul(workCt[0], workCt[1], nextLvlCt)
                    evaluator.Relinearize(nextLvlCt, nextLvlCt)
                    evaluator.Neg(nextLvlCt, nextLvlCt)
                    evaluator.Add(onesCt, nextLvlCt, nextLvlCt)
                }
            }
        })
    }

    if compute_union {
        l.Println("> > unioning all conditions: ")
    } else {
        l.Println("> > intersecting all conditions: ")
    }
    encLvls := make([][]*rlwe.Ciphertext, 0)
    encLvls = append(encLvls, conditions)
    for nLvl := len(conditions) / 2; nLvl > 0; nLvl = nLvl >> 1 {
        encLvl := make([]*rlwe.Ciphertext, nLvl)
        for i := range encLvl {
            encLvl[i] = bfv.NewCiphertext(params, 2, params.MaxLevel())
        }
        encLvls = append(encLvls, encLvl)
    }
    encRes = encLvls[len(encLvls)-1][0]
    workCt := make([]*rlwe.Ciphertext, 2)
    workCt[0] = bfv.NewCiphertext(params, 1, params.MaxLevel())
    workCt[1] = bfv.NewCiphertext(params, 1, params.MaxLevel())
    elapsedEvalCloud += runTimed(func() {
        for i, lvl := range encLvls[:len(encLvls)-1] {
            nextLvl := encLvls[i+1]
            l.Println("\tlevel", i, len(lvl), "->", len(nextLvl))
            for j, nextLvlCt := range nextLvl {
                if compute_union {
                    evaluator.Neg(lvl[2*j], workCt[0])
                    evaluator.Neg(lvl[2*j+1], workCt[1])
                    evaluator.Add(onesCt, workCt[0], workCt[0])
                    evaluator.Add(onesCt, workCt[1], workCt[1])
                    //evaluator.Relinearize(workCt[0], workCt[0])
                    //evaluator.Relinearize(workCt[1], workCt[1])
                    evaluator.Mul(workCt[0], workCt[1], nextLvlCt)
                    evaluator.Relinearize(nextLvlCt, nextLvlCt)
                    evaluator.Neg(nextLvlCt, nextLvlCt)
                    evaluator.Add(onesCt, nextLvlCt, nextLvlCt)
                } else {
                    //workCt[0] = lvl[2*j]
                    //workCt[1] = lvl[2*j+1]
                    evaluator.Mul(lvl[2*j], lvl[2*j+1], nextLvlCt)
                    evaluator.Relinearize(nextLvlCt, nextLvlCt)
                }
            }
        }
    })
	//evaluator.Neg(encRes, encRes)
    //evaluator.Add(onesCt, encRes, encRes)
    //_ = onesCt
    //evaluator.InnerSum(encRes, encRes)
    evaluator.InnerSum(encRes, encRes)

	elapsedEvalParty = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n",
		elapsedEvalCloud, elapsedEvalParty)
	return
}

func genparties(params bfv.Parameters, N int) []*party {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)
	for i := range P {
		pi := &party{}
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()

		P[i] = pi
	}

	return P
}

func readInputs(params bfv.Parameters, P []*party, NConditions int, filename string) (expRes int) {
    size_vector := params.N()
    expRes = 0

    filebuffer, err := ioutil.ReadFile(filename)
    if err != nil {
        os.Exit(1)
    }
    inputdata := string(filebuffer)
    i_buf := 0
	for _, pi := range P {
		pi.input = make([][]uint64, NConditions)
        for i := range pi.input {
            pi.input[i] = make([]uint64, size_vector)
            for j := range pi.input[i] {
                if i_buf<len(inputdata) {
                    if string(inputdata[i_buf]) == "1" {
                        pi.input[i][j] = 1
                    } else if string(inputdata[i_buf]) == "0" {
                        pi.input[i][j] = 0
                    } else {
                        os.Exit(5)
                    }
                } else {
                    os.Exit(1)
                }
                i_buf++
            }
        }
	}
	return
}

func genInputs(params bfv.Parameters, P []*party, NConditions int) (expRes int) {
    size_vector := params.N()
    expRes = 0

	for _, pi := range P {
		pi.input = make([][]uint64, NConditions)
        for i := range pi.input {
            pi.input[i] = make([]uint64, size_vector)
            for j := range pi.input[i] {
                if utils.RandFloat64(0, 1) > 0.3 || i == 4 {
                    pi.input[i][j] = 1
                }
            }
        }
	}
	return
}

func pcksPhase(params bfv.Parameters, tpk *rlwe.PublicKey, encRes *rlwe.Ciphertext, P []*party) (encOut *rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Collective key switching from the collective secret key to
	// the target public key

	pcks := dbfv.NewPCKSProtocol(params, 3.19)

	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShare(params.MaxLevel())
	}

	l.Println("> PCKS Phase")
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P {
			pcks.GenShare(pi.sk, tpk, encRes, pi.pcksShare)
		}
	}, len(P))

	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	encOut = bfv.NewCiphertext(params, 1, params.MaxLevel())
	elapsedPCKSCloud = runTimed(func() {
		for _, pi := range P {
			pcks.AggregateShares(pi.pcksShare, pcksCombined, pcksCombined)
		}
		pcks.KeySwitch(encRes, pcksCombined, encOut)

	})
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	return
}

func rkgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RKG Phase")

	rkg := dbfv.NewRKGProtocol(params) // Relineariation key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}

	crp := rkg.SampleCRP(crs)

	elapsedRKGParty = runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
		}
	}, len(P))

	elapsedRKGCloud = runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShares(pi.rkgShareOne, rkgCombined1, rkgCombined1)
		}
	})

	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
		}
	}, len(P))

	rlk := rlwe.NewRelinearizationKey(params.Parameters, 1)
	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShares(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
		}
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	return rlk
}

func ckgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	l.Println("> CKG Phase")

	ckg := dbfv.NewCKGProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShare()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	crp := ckg.SampleCRP(crs)

	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P))

	pk := rlwe.NewPublicKey(params.Parameters)

	elapsedCKGCloud = runTimed(func() {
		for _, pi := range P {
			ckg.AggregateShares(pi.ckgShare, ckgCombined, ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}

func rtkphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RotationKeySet {

	l := log.New(os.Stderr, "", 0)

	l.Println("> RTG Phase")

	rtg := dbfv.NewRTGProtocol(params) // Rotation keys generation

	for _, pi := range P {
		pi.rtgShare = rtg.AllocateShare()
	}

	galEls := params.GaloisElementsForRowInnerSum()
	rotKeySet := rlwe.NewRotationKeySet(params.Parameters, galEls)

	for _, galEl := range galEls {

		rtgShareCombined := rtg.AllocateShare()

		crp := rtg.SampleCRP(crs)

		elapsedRTGParty += runTimedParty(func() {
			for _, pi := range P {
				rtg.GenShare(pi.sk, galEl, crp, pi.rtgShare)
			}
		}, len(P))

		elapsedRTGCloud += runTimed(func() {
			for _, pi := range P {
				rtg.AggregateShares(pi.rtgShare, rtgShareCombined, rtgShareCombined)
			}
			rtg.GenRotationKey(rtgShareCombined, crp, rotKeySet.Keys[galEl])
		})
	}
	l.Printf("\tdone (cloud: %s, party %s)\n", elapsedRTGCloud, elapsedRTGParty)

	return rotKeySet
}
