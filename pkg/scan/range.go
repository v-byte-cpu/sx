package scan

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
)

var errRangeSize = errors.New("invalid range size")

// We will pick the first cyclic group from this list that is
// larger than the range size
var cyclicGroups = []struct {
	// Prime number for (Z/pZ)* multiplicative group
	P int64
	// Cyclic group generator
	G int64
	// Number coprime with P-1
	N int64
}{
	{
		P: 3, // 2^1 + 1
		G: 2,
		N: 1,
	},
	{
		P: 5, // 2^2 + 1
		G: 2,
		N: 1,
	},
	{
		P: 11, // 2^3 + 3
		G: 2,
		N: 3,
	},
	{
		P: 17, // 2^4 + 1
		G: 3,
		N: 3,
	},
	{
		P: 37, // 2^5 + 5
		G: 2,
		N: 5,
	},
	{
		P: 67, // 2^6 + 3
		G: 2,
		N: 5,
	},
	{
		P: 131, // 2^7 + 3
		G: 2,
		N: 3,
	},
	{
		P: 257, // 2^8 + 1
		G: 3,
		N: 3,
	},
	{
		P: 523, // 2^9 + 11
		G: 2,
		N: 5,
	},
	{
		P: 1031, // 2^10 + 7
		G: 21,
		N: 3,
	},
	{
		P: 2053, // 2^11 + 5
		G: 2,
		N: 5,
	},
	{
		P: 4099, // 2^12 + 3
		G: 2,
		N: 5,
	},
	{
		P: 8219, // 2^13 + 27
		G: 2,
		N: 3,
	},
	{
		P: 16421, // 2^14 + 37
		G: 2,
		N: 3,
	},
	{
		P: 32771, // 2^15 + 3
		G: 2,
		N: 3,
	},
	{
		P: 65539, // 2^16 + 3
		G: 2,
		N: 5,
	},
	{
		P: 131101, // 2^17 + 29
		G: 17,
		N: 7,
	},
	{
		P: 262147, // 2^18 + 3
		G: 2,
		N: 5,
	},
	{
		P: 524309, // 2^19 + 21
		G: 2,
		N: 3,
	},
	{
		P: 1048589, // 2^20 + 13
		G: 2,
		N: 3,
	},
	{
		P: 2097211, // 2^21 + 59
		G: 2,
		N: 7,
	},
	{
		P: 4194371, // 2^22 + 67
		G: 2,
		N: 3,
	},
	{
		P: 8388619, // 2^23 + 11
		G: 2,
		N: 5,
	},
	{
		P: 16777259, // 2^24 + 43
		G: 2,
		N: 5,
	},
	{
		P: 33554467, // 2^25 + 35
		G: 2,
		N: 5,
	},
	{
		P: 67108933, // 2^26 + 69
		G: 2,
		N: 5,
	},
	{
		P: 134217773, // 2^27 + 45
		G: 2,
		N: 5,
	},
	{
		P: 268435459, // 2^28 + 3
		G: 2,
		N: 5,
	},
	{
		P: 536871019, // 2^29 + 107
		G: 2,
		N: 5,
	},
	{
		P: 1073741827, // 2^30 + 3
		G: 2,
		N: 5,
	},
	{
		P: 2147483659, // 2^31 + 11
		G: 2,
		N: 5,
	},
	{
		P: 4294967357, // 2^32 + 61
		G: 2,
		N: 5,
	},
}

// newRangeIterator creates a pseudo-random iterator for
// integer range [1..n]. Each integer is traversed exactly once.
func newRangeIterator(n int64) (*rangeIterator, error) {
	// Here we apply cyclic groups
	// (Z/pZ)* is a multiplicative group if p is a prime number
	// also (Z/pZ)* is a cyclic group, to understand this fact I recommend to read
	// "When Is the Multiplicative Group Modulo n Cyclic?" paper by Aryeh Zax
	if n <= 0 {
		return nil, errRangeSize
	}

	// find first cyclic group that is larger than n
	idx := sort.Search(len(cyclicGroups), func(i int) bool {
		return cyclicGroups[i].P > n
	})
	if idx == len(cyclicGroups) {
		return nil, errRangeSize
	}
	cyclic := cyclicGroups[idx]
	P, G, N := big.NewInt(cyclic.P), big.NewInt(cyclic.G), big.NewInt(cyclic.N)

	// first of all, we apply group theory facts for cyclic groups:
	// 1. Let T be a finite cyclic group of order n. Let G be a generator. Let r be an
	// integer != 0, and relatively prime to n.  Then (G ** r) is also a generator of T.
	// 2. Fermat's little theorem:
	// if p is a prime number then for any integer a: (a ** (p-1)) mod p = 1.
	// See Chapter 2, Exercise 17 on page 26 and Theorem 4.3 (Lagrange's theorem)
	// in the "Undergraduate Algebra" Third Edition by Serge Lang

	// number of elements of (Z/pZ)* is equal to P-1
	// randM is a random integer
	randM := big.NewInt(rand.Int63())
	one := big.NewInt(1)
	randM.Add(randM, one)
	// if N is coprime with P-1 => (N ** randM) is coprime with P-1
	// by Fermat's little theorem: (G ** M) mod P = (G ** (M mod (P-1))) mod P for any integer M
	// prepare new group generator:
	// G - generator, (N ** randM) is coprime with group order => G = (G ** (N ** randM)) mod P is also a generator
	N.Exp(N, randM, big.NewInt(cyclic.P-1))
	G.Exp(G, N, P)

	// select a random element from which to start the iteration: randI = (G ** randM) mod P
	randM.SetInt64(rand.Int63()).Add(randM, one)
	randI := big.NewInt(0).Exp(G, randM, P)

	it := &rangeIterator{P: P, G: G,
		rangeLimit: big.NewInt(n),
		I:          big.NewInt(0).Set(randI),
		startI:     big.NewInt(0).Set(randI),
	}

	// find a first number I <= n from which to start the iteration
	if !it.Next() && n > 1 {
		return nil, fmt.Errorf("invalid cyclic group: P = %+v G = %+v N = %+v startI = %+v",
			P, G, N, it.startI)
	}
	it.startI.Set(it.I)
	return it, nil
}

type rangeIterator struct {
	// Prime number for (Z/pZ)* multiplicative group
	P *big.Int
	// Cyclic group generator
	G *big.Int
	// Current number
	I *big.Int
	// the number at which the iteration starts
	startI *big.Int

	// right boundary of the range
	rangeLimit *big.Int
	stop       bool
}

func (it *rangeIterator) Next() bool {
	if it.stop {
		return false
	}
	for {
		// I = (I * G) mod P
		it.I.Mul(it.I, it.G)
		it.I.Mod(it.I, it.P)
		if it.I.Cmp(it.startI) == 0 {
			it.stop = true
			return false
		}
		// if i <= rangeLimit
		if it.I.Cmp(it.rangeLimit) < 1 {
			return true
		}
	}
}

func (it *rangeIterator) Int() *big.Int {
	return it.I
}
