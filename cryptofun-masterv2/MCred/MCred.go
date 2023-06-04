package MCred

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/arnaucube/go-snark/bn128"
	"math/big"
)

//const bits = 1024

// MCred is the data structure of the BN128 pairing curve
type MCred struct {
	Bn bn128.Bn128
}
type CAKeys struct {
	PrivK_x *big.Int
	PrivK_y []*big.Int
	PubK_X  [3][2]*big.Int
	PubK_Y  [][3][2]*big.Int
}
type TraceKeys struct {
	PrivK *big.Int
	PubK  [3][2]*big.Int
}
type Record struct {
	R  [3]*big.Int
	S1 [][3][2]*big.Int
	S2 [][3][2]*big.Int
}

// NewMCred generates a new BLS scheme
func NewMCred() (MCred, error) {
	bn, err := bn128.NewBn128()
	if err != nil {
		return MCred{}, err
	}
	mCred := MCred{}
	mCred.Bn = bn
	return mCred, nil
}

// IssueKeyGen generate a key pair of issuer
func (mCred MCred) IssueKeyGen(alpha []*big.Int) (CAKeys, error) {
	var err error
	var PrivK *big.Int
	k := CAKeys{}
	k.PrivK_x, err = rand.Int(rand.Reader, mCred.Bn.Q)
	for i := 0; i < len(alpha); i++ {
		PrivK, err = rand.Int(rand.Reader, mCred.Bn.Q)
		k.PrivK_y = append(k.PrivK_y, PrivK)
	}
	if err != nil {
		return CAKeys{}, err
	}
	// pubK = pk * G
	k.PubK_X = mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, k.PrivK_x)
	for i := 0; i < len(alpha); i++ {
		k.PubK_Y = append(k.PubK_Y, mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, k.PrivK_y[i]))
	}
	return k, nil
}

// TraceKeyGen generate a key pair of issuer
func (mCred MCred) TraceKeyGen() (TraceKeys, error) {
	var err error
	z := TraceKeys{}
	z.PrivK, err = rand.Int(rand.Reader, mCred.Bn.Q)
	if err != nil {
		return TraceKeys{}, err
	}
	// pubK = pk * G
	z.PubK = mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, z.PrivK)
	return z, nil
}

// HashtoG1 hashes a message m
func (mCred MCred) HashtoG1(m []byte) [3]*big.Int {
	h := sha256.New()
	h.Write(m)
	hash := h.Sum(nil)
	r := new(big.Int).SetBytes(hash)
	// get point over the curve
	point := mCred.Bn.G1.MulScalar(mCred.Bn.G1.G, r)
	return point
}

// request
func (mCred MCred) request(id []byte, z TraceKeys, alpha []*big.Int) ([][3][2]*big.Int, [][3][2]*big.Int, [][3]*big.Int,
	[3]*big.Int, *big.Int, [][3]*big.Int, []*big.Int, *big.Int, []*big.Int, []*big.Int, [][3][2]*big.Int, [][3][2]*big.Int,
	*big.Int, []*big.Int) {
	h := mCred.HashtoG1(id)
	ri, err := rand.Int(rand.Reader, mCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid random")
	}
	R := mCred.Bn.G1.MulScalar(h, ri)
	//fmt.Println("R:", R)
	var h_1 [][3]*big.Int
	for i := 0; i < len(alpha); i++ {
		h_1 = append(h_1, mCred.Bn.G1.MulScalar(R, alpha[i]))
	}
	c, a, s := mCred.proof_zkpok(h_1, R, alpha)
	var t []*big.Int
	var S1 [][3][2]*big.Int
	var S2 [][3][2]*big.Int
	for i := 0; i < len(alpha); i++ {
		ran_t, err := rand.Int(rand.Reader, mCred.Bn.Q)
		if err != nil {
			panic("an error occured: invaid random")
		}
		t = append(t, ran_t)
		S1 = append(S1, mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, t[i]))
		S2 = append(S2, mCred.Bn.G2.Add(mCred.Bn.G2.MulScalar(z.PubK, ran_t), mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, alpha[i])))
	}
	//fmt.Println("to:", t[0])
	proof_c, proof_s1, proof_s2, proof_b, proof_d := mCred.prove_commitment(z.PubK, S1, S2, alpha, t)
	return S1, S2, h_1, R, c, a, s, proof_c, proof_s1, proof_s2, proof_b, proof_d, ri, t
}

// proof_zkpok
func (mCred MCred) proof_zkpok(h_1 [][3]*big.Int, R [3]*big.Int, alpha []*big.Int) (*big.Int, [][3]*big.Int, []*big.Int) {
	var r []*big.Int
	var a [][3]*big.Int
	for i := 0; i < len(alpha); i++ {
		ri1, err := rand.Int(rand.Reader, mCred.Bn.Q)
		if err != nil {
			panic("an error occured: invaid random")
		}
		r = append(r, ri1)
		a = append(a, mCred.Bn.G1.MulScalar(R, r[i]))
	}
	//create the challenge
	g1Points := a
	for i := 0; i < len(h_1); i++ {
		g1Points = append(g1Points, h_1[i])
	}

	c := mCred.to_challenge(g1Points, nil, nil)
	var s []*big.Int
	for i := 0; i < len(alpha); i++ {
		s = append(s, new(big.Int).Add(r[i], new(big.Int).Mul(c, alpha[i])))
		//s = append(s, mCred.Bn.Fq1.Add(r[i], mCred.Bn.Fq1.Mul(c, alpha[i])))
	}
	return c, a, s
}

func (mCred MCred) to_challenge(g1Points [][3]*big.Int, g2Points [][3][2]*big.Int, IntPoints []*big.Int) *big.Int {
	h := sha256.New()
	if g1Points != nil {
		for i := 0; i < len(g1Points); i++ {
			for j := 0; j < len(g1Points[i]); j++ {
				h.Write(g1Points[i][j].Bytes())
			}
		}
	}
	if g2Points != nil {
		for i := 0; i < len(g2Points); i++ {
			for j := 0; j < len(g2Points[i]); j++ {
				for k := 0; k < len(g2Points[i][j]); k++ {
					h.Write(g2Points[i][j][k].Bytes())
				}
			}
		}
	}
	if IntPoints != nil {
		for i := 0; i < len(IntPoints); i++ {
			h.Write(IntPoints[i].Bytes())
		}
	}
	hash := h.Sum(nil)
	r := new(big.Int).SetBytes(hash)
	return r
}

func (mCred MCred) to_Bytes(g1Points [][3]*big.Int, g2Points [][3][2]*big.Int, IntPoints []*big.Int) []byte {
	var buffer bytes.Buffer
	if g1Points != nil {
		for i := 0; i < len(g1Points); i++ {
			for j := 0; j < len(g1Points[i]); j++ {
				buffer.Write(g1Points[i][j].Bytes())
			}
		}
	}

	if g2Points != nil {
		for i := 0; i < len(g2Points); i++ {
			for j := 0; j < len(g2Points[i]); j++ {
				for k := 0; k < len(g2Points[i][j]); k++ {
					buffer.Write(g2Points[i][j][k].Bytes())
				}
			}
		}
	}
	if IntPoints != nil {
		for i := 0; i < len(IntPoints); i++ {
			buffer.Write(IntPoints[i].Bytes())
		}
	}
	h := buffer.Bytes()
	return h
}

func (mCred MCred) prove_commitment(PubK [3][2]*big.Int, S1 [][3][2]*big.Int, S2 [][3][2]*big.Int, alpha []*big.Int, t []*big.Int) (*big.Int, []*big.Int, []*big.Int, [][3][2]*big.Int, [][3][2]*big.Int) {
	var u1, u2 []*big.Int
	var b, d [][3][2]*big.Int
	for i := 0; i < len(alpha); i++ {
		ran_1, err := rand.Int(rand.Reader, mCred.Bn.Q)
		ran_2, err := rand.Int(rand.Reader, mCred.Bn.Q)
		if err != nil {
			panic("an error occured: invaid random")
		}
		u1 = append(u1, ran_1)
		u2 = append(u2, ran_2)
		b = append(b, mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, ran_1))
		d = append(d, mCred.Bn.G2.Add(mCred.Bn.G2.MulScalar(PubK, ran_1), mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, ran_2)))
	}
	//fmt.Println("u1 0", u1[0])
	//fmt.Println("b0", b[0])
	//create the challenge
	g2Points := S1
	for i := 0; i < len(S2); i++ {
		g2Points = append(g2Points, S2[i])
		g2Points = append(g2Points, b[i])
		g2Points = append(g2Points, d[i])
	}
	c := mCred.to_challenge(nil, g2Points, nil)
	var s1 []*big.Int
	var s2 []*big.Int
	for i := 0; i < len(alpha); i++ {
		//s1 = append(s1, new(big.Int).Mod(new(big.Int).Add(u1[i], new(big.Int).Mod(new(big.Int).Mul(c, t[i]), mCred.Bn.Q)), mCred.Bn.Q))
		s1 = append(s1, new(big.Int).Add(u1[i], new(big.Int).Mul(c, t[i])))
		s2 = append(s2, new(big.Int).Add(u2[i], new(big.Int).Mul(c, alpha[i])))

	}
	//fmt.Println("t 0", t[0])
	//fmt.Println("S1 0", mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, t[0]))
	//fmt.Println("equal S:", mCred.Bn.G2.Equal(S1[0], mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, t[0])))
	////fmt.Println("g2^s1:", mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, s1[0]))
	//fmt.Println("!!!!!!S1[0]*C :", mCred.Bn.G2.MulScalar(S1[0], c))
	//testct := new(big.Int).Mul(t[0], c)
	//fmt.Println("!!!!!G2^C*T :", mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, testct))
	//fmt.Println("equal :", mCred.Bn.G2.Equal(mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, testct), mCred.Bn.G2.MulScalar(S1[0], c)))
	return c, s1, s2, b, d
}

// issue blindly sign a message
func (mCred MCred) issue(ca CAKeys, S1 [][3][2]*big.Int, S2 [][3][2]*big.Int, PubK [3][2]*big.Int, proof_c *big.Int, proof_s1 []*big.Int, proof_s2 []*big.Int, proof_b [][3][2]*big.Int,
	proof_d [][3][2]*big.Int, c *big.Int, a [][3]*big.Int, s []*big.Int, h_1 [][3]*big.Int, R [3]*big.Int, t []*big.Int) [3]*big.Int {
	if !mCred.verify_proofalpha(c, a, s, h_1, R) {
		panic("an error occured: invaid proofalpha")
	}
	if !mCred.verify_commitment(PubK, S1, S2, proof_c, proof_s1, proof_s2, proof_b, proof_d, t) {
		panic("an error occured: invaid commitment")
	}
	sigma := mCred.Bn.G1.MulScalar(R, ca.PrivK_x)
	for i := 0; i < len(h_1); i++ {
		sigma = mCred.Bn.G1.Add(sigma, mCred.Bn.G1.MulScalar(h_1[i], ca.PrivK_y[i]))
	}
	return sigma
}

func (mCred MCred) verify_proofalpha(c *big.Int, a [][3]*big.Int, s []*big.Int, h_1 [][3]*big.Int, R [3]*big.Int) bool {
	for i := 0; i < len(s); i++ {
		if !mCred.Bn.G1.Equal(mCred.Bn.G1.MulScalar(R, s[i]), mCred.Bn.G1.Add(a[i], mCred.Bn.G1.MulScalar(h_1[i], c))) {
			return false
		}
	}
	//fmt.Println("proof_d verifiedalpha:")
	g1Points := a
	for i := 0; i < len(h_1); i++ {
		g1Points = append(g1Points, h_1[i])
	}
	cTest := mCred.to_challenge(g1Points, nil, nil)
	if c.Cmp(cTest) != 0 {
		return false
	}
	return true
}

func (mCred MCred) verify_commitment(PubK [3][2]*big.Int, S1 [][3][2]*big.Int, S2 [][3][2]*big.Int, proof_c *big.Int, proof_s1 []*big.Int, proof_s2 []*big.Int, proof_b [][3][2]*big.Int,
	proof_d [][3][2]*big.Int, t []*big.Int) bool {
	var left, right [3][2]*big.Int
	for i := 0; i < len(S1); i++ {
		if !mCred.Bn.G2.Equal(proof_b[i], mCred.Bn.G2.Sub(mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, proof_s1[i]), mCred.Bn.G2.MulScalar(S1[i], proof_c))) {
			return false
		}
		left = mCred.Bn.G2.Add(mCred.Bn.G2.MulScalar(PubK, proof_s1[i]), mCred.Bn.G2.MulScalar(mCred.Bn.G2.G, proof_s2[i]))
		right = mCred.Bn.G2.MulScalar(S2[i], proof_c)
		if !mCred.Bn.G2.Equal(proof_d[i], mCred.Bn.G2.Sub(left, right)) {
			//fmt.Println("proof_d verified:")
			return false
		}
	}
	g2Points := S1
	for i := 0; i < len(S2); i++ {
		g2Points = append(g2Points, S2[i])
		g2Points = append(g2Points, proof_b[i])
		g2Points = append(g2Points, proof_d[i])
	}
	if proof_c.Cmp(mCred.to_challenge(nil, g2Points, nil)) != 0 {
		return false
	}
	return true
}

// Verify credential
func (mCred MCred) Vericred(id []byte, R [3]*big.Int, sigg [3]*big.Int, alpha []*big.Int, ri *big.Int, ca CAKeys) [3]*big.Int {
	h := mCred.HashtoG1(id)
	var riInv *big.Int
	riInv = mCred.Bn.Fq1.Inverse(ri)
	fmt.Println("inversexy:", mCred.Bn.G1.Equal(h, mCred.Bn.G1.MulScalar(h, mCred.Bn.Fq1.Mul(riInv, ri))))
	//var Ri [3]*big.Int
	//fmt.Println("inversehri:", mCred.Bn.G1.MulScalar(h, ri))
	//fmt.Println("inverseR:", R)
	//Ri = mCred.Bn.G1.MulScalar(h, mCred.Bn.Fq1.Mul(riInv, ri))
	//fmt.Println("inverseRi:", Ri)
	//fmt.Println("inversemache:", mCred.Bn.G1.Equal(h, Ri))
	//sigg = mCred.Bn.G1.MulScalar(sigg, riInv)
	var XY [3][2]*big.Int
	XY = ca.PubK_X
	for i := 0; i < len(alpha); i++ {
		XY = mCred.Bn.G2.Add(XY, mCred.Bn.G2.MulScalar(ca.PubK_Y[i], alpha[i]))
	}

	pairRi, err := mCred.Bn.Pairing(R, XY)
	pairdg2, err := mCred.Bn.Pairing(sigg, mCred.Bn.G2.G)
	if err != nil {
		panic("an error occured: invaid random")
	}
	fmt.Println("equalRIdg2", mCred.Bn.Fq12.Equal(pairRi, pairdg2))
	return sigg
}

// Randomize
func (mCred MCred) randAggr(h [3]*big.Int, sigg [3]*big.Int) ([3]*big.Int, [3]*big.Int) {
	r, err := rand.Int(rand.Reader, mCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid Randomize")
	}
	h = mCred.Bn.G1.MulScalar(h, r)
	sigg = mCred.Bn.G1.MulScalar(sigg, r)
	return h, sigg
}

func (mCred MCred) CredAggr(id []byte, cred [][3]*big.Int, ri *big.Int) ([3]*big.Int, [3]*big.Int) {
	h := mCred.HashtoG1(id)
	var riInv *big.Int
	var Asigg [3]*big.Int
	riInv = mCred.Bn.Fq1.Inverse(ri)
	//fmt.Println("inversexy:", mCred.Bn.G1.Equal(h, mCred.Bn.G1.MulScalar(h, mCred.Bn.Fq1.Mul(riInv, ri))))
	//fmt.Println("inverriinv:", mCred.Bn.Fq1.Mul(riInv, ri))
	Asigg = cred[0]
	for i := 1; i < len(cred); i++ {
		if i == 0 {
			Asigg = mCred.Bn.G1.MulScalar(cred[i], riInv)
		} else {
			Asigg = mCred.Bn.G1.Add(Asigg, cred[i])
		}
	}
	R := mCred.Bn.G1.MulScalar(h, ri)
	return R, Asigg
}

func (mCred MCred) CredShow(h [3]*big.Int, Asigg [3]*big.Int, alpha []*big.Int, cas []CAKeys, k int64) ([3]*big.Int, [3]*big.Int, [3]*big.Int, *big.Int, []*big.Int, [3]*big.Int, [2][3][2]*big.Int) {

	c, d := mCred.randAggr(h, Asigg)
	/*
		aggrPubkX := cas[0].PubK_X
		for i := 1; i < len(cas); i++ {
			aggrPubkX = mCred.Bn.G2.Add(aggrPubkX, cas[i].PubK_X)
		}
		//Y
		var aggrPubkY [][3][2]*big.Int
		for i := 0; i < len(cas[0].PubK_Y); i++ {
			aggrPubkY = append(aggrPubkY, cas[0].PubK_Y[i])
		}

		for i := 0; i < len(cas[0].PubK_Y); i++ {
			for j := 1; j < len(cas); j++ {
				aggrPubkY[i] = mCred.Bn.G2.Add(aggrPubkY[i], cas[j].PubK_Y[i])
			}
		}

		//--------//

		//--------//

		CYX := mCred.Bn.G2.MulScalar(aggrPubkY[0], alpha[0])
		CY1 := mCred.Bn.G2.MulScalar(aggrPubkY[k], alpha[k])
		for i := 1; i < int(k); i++ {
			CYX = mCred.Bn.G2.Add(CYX, mCred.Bn.G2.MulScalar(aggrPubkY[i], alpha[i]))
		}

		for i := int(k) + 1; i < len(alpha); i++ {
			CY1 = mCred.Bn.G2.Add(CY1, mCred.Bn.G2.MulScalar(aggrPubkY[i], alpha[i]))
		}
		//--
		paircxy, err := mCred.Bn.Pairing(c, mCred.Bn.G2.Add(aggrPubkX, mCred.Bn.G2.Add(CY1, CYX)))
		pairdg2, err := mCred.Bn.Pairing(d, mCred.Bn.G2.G)
		if err != nil {
			panic("an error occured: invaid random")
		}
		fmt.Println("equalcxy", mCred.Bn.Fq12.Equal(paircxy, pairdg2))
	*/

	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [][3]*big.Int
	for i := 0; i < len(alpha); i++ {
		f = append(f, mCred.HashtoG1(new(big.Int).Add(mCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes()))
	}
	F := mCred.Bn.G1.MulScalar(f[0], alpha[0])
	for i := 1; i < len(alpha); i++ {
		F = mCred.Bn.G1.Add(F, mCred.Bn.G1.MulScalar(f[i], alpha[i]))
	}
	c1, s1, a, a2 := mCred.proveShow(cas, c, d, alpha, F, f, k)
	return c, d, F, c1, s1, a, a2
}

func (mCred MCred) proveShow(cas []CAKeys, c [3]*big.Int, d [3]*big.Int, alpha []*big.Int, F [3]*big.Int, f [][3]*big.Int, k int64) (*big.Int, []*big.Int, [3]*big.Int, [2][3][2]*big.Int) {
	var rsk []*big.Int
	var a [3]*big.Int
	var b [3][2]*big.Int
	//var pubb [3][2]*big.Int

	for i := 0; i < int(k); i++ {
		ri, err := rand.Int(rand.Reader, mCred.Bn.Q)
		if err != nil {
			panic("an error occured: invaid random")
		}
		rsk = append(rsk, ri)
	}
	/*if i == 0 {
		a = mCred.Bn.G1.MulScalar(f[i], rsk[i])
		b = mCred.Bn.G2.MulScalar(cas[0].PubK_Y[i], rsk[i])
	} else {
		a = mCred.Bn.G1.Add(a, mCred.Bn.G1.MulScalar(f[i], rsk[i]))
		b = mCred.Bn.G2.Add(b, mCred.Bn.G2.MulScalar(cas[0].PubK_Y[i], rsk[i]))
	}*/

	a = mCred.Bn.G1.MulScalar(f[0], rsk[0])
	b = mCred.Bn.G2.MulScalar(cas[0].PubK_Y[0], rsk[0])
	for i := 1; i < int(k); i++ {
		a = mCred.Bn.G1.Add(a, mCred.Bn.G1.MulScalar(f[i], rsk[i]))
		b = mCred.Bn.G2.Add(b, mCred.Bn.G2.MulScalar(cas[0].PubK_Y[i], rsk[i]))
	}
	/*
		pubb = cas[0].PubK_Y[0]
		for j := 0; j < len(cas); j++ {
			for i := 0; i < int(k); i++ {
				pubb = mCred.Bn.G2.Add(pubb, cas[j].PubK_Y[i])
			}
		}
		pubb = mCred.Bn.G2.Sub(pubb, cas[0].PubK_Y[0])
	*/
	/*}
	a = mCred.Bn.G1.MulScalar(f[0], rsk[0])
	 = mCred.Bn.G2.MulScalar(cas[0].PubK_Y[0], rsk[0])
	for i := 1; i < int(k); i++ {
		a = mCred.Bn.G1.Add(a, mCred.Bn.G1.MulScalar(f[i], rsk[i]))
		b = mCred.Bn.G2.Add(b, mCred.Bn.G2.MulScalar(cas[0].PubK_Y[i], rsk[i]))
	}*/

	for i := 1; i < len(cas); i++ {
		for j := 0; j < int(k); j++ {
			b = mCred.Bn.G2.Add(b, mCred.Bn.G2.MulScalar(cas[i].PubK_Y[j], rsk[j]))
		}
	}
	a2, err := mCred.Bn.Pairing(c, b)

	if err != nil {
		panic("an error occured: invaid random")
	}
	g1Points := f
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	//       ---------//g1Points = append(g1Points, F)
	g1Points = append(g1Points, a)
	var g2Points [][3][2]*big.Int
	g2Points = append(g2Points, a2[0])
	g2Points = append(g2Points, a2[1])
	//fmt.Println("!!!! g1Points", g1Points)
	//fmt.Println("!!!! g2Points", g2Points)
	c1 := mCred.to_challenge(g1Points, g2Points, nil)
	var s1 []*big.Int
	for i := 0; i < int(k); i++ {
		s1 = append(s1, new(big.Int).Add(rsk[i], new(big.Int).Mul(c1, alpha[i])))
		//s1 = append(s1, mCred.Bn.Fq1.Add(rsk[i], mCred.Bn.Fq1.Mul(c1, alpha[i])))
	}

	return c1, s1, a, a2
}

func (mCred MCred) credVerify(cas []CAKeys, c [3]*big.Int, d [3]*big.Int, F [3]*big.Int, c1 *big.Int, s1 []*big.Int, a [3]*big.Int, alpha []*big.Int, k int64, a2 [2][3][2]*big.Int) bool {
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [][3]*big.Int
	var F1 [3]*big.Int
	var fi [3]*big.Int
	var Ffi1 [3]*big.Int
	var abc [3]*big.Int

	for i := 0; i < len(alpha); i++ {
		f = append(f, mCred.HashtoG1(new(big.Int).Add(mCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes()))
	}
	F1 = mCred.Bn.G1.MulScalar(f[0], s1[0])
	for i := 1; i < int(k); i++ {
		F1 = mCred.Bn.G1.Add(F1, mCred.Bn.G1.MulScalar(f[i], s1[i]))
	}
	fi = mCred.Bn.G1.MulScalar(f[k], alpha[k])
	for i := int(k) + 1; i < len(alpha); i++ {
		fi = mCred.Bn.G1.Add(fi, mCred.Bn.G1.MulScalar(f[i], alpha[i]))
	}
	Ffi1 = mCred.Bn.G1.Sub(F, fi)
	abc = mCred.Bn.G1.MulScalar(Ffi1, c1)

	ab := mCred.Bn.G1.Sub(F1, abc)

	//fmt.Println("a==b", ab)
	//fmt.Println("a==b", mCred.Bn.G1.Equal(ab, a))
	//fmt.Println("a==b", a)
	//	############################
	//var aggrPubkX [][3][2]*big.Int
	// aggregated publickey
	// X
	aggrPubkX := cas[0].PubK_X
	for i := 1; i < len(cas); i++ {
		aggrPubkX = mCred.Bn.G2.Add(aggrPubkX, cas[i].PubK_X)
	}
	//Y
	var aggrPubkY [][3][2]*big.Int
	for i := 0; i < len(cas[0].PubK_Y); i++ {
		aggrPubkY = append(aggrPubkY, cas[0].PubK_Y[i])
	}

	for i := 0; i < len(cas[0].PubK_Y); i++ {
		for j := 1; j < len(cas); j++ {
			aggrPubkY[i] = mCred.Bn.G2.Add(aggrPubkY[i], cas[j].PubK_Y[i])
		}
	}

	CY := mCred.Bn.G2.MulScalar(aggrPubkY[0], s1[0])
	//CYX := mCred.Bn.G2.MulScalar(aggrPubkY[0], alpha[0])
	CY1 := mCred.Bn.G2.MulScalar(aggrPubkY[k], alpha[k])
	for i := 1; i < int(k); i++ {
		CY = mCred.Bn.G2.Add(CY, mCred.Bn.G2.MulScalar(aggrPubkY[i], s1[i]))
		//CYX = mCred.Bn.G2.Add(CYX, mCred.Bn.G2.MulScalar(aggrPubkY[i], alpha[i]))
	}

	for i := int(k) + 1; i < len(alpha); i++ {
		CY1 = mCred.Bn.G2.Add(CY1, mCred.Bn.G2.MulScalar(aggrPubkY[i], alpha[i]))
	}
	//--
	//paircxy, err := mCred.Bn.Pairing(c, mCred.Bn.G2.Add(aggrPubkX, mCred.Bn.G2.Add(CY1, CYX)))
	//pairdg2, err := mCred.Bn.Pairing(d, mCred.Bn.G2.G)
	//pairxy1, err := mCred.Bn.Pairing(c, mCred.Bn.G2.Add(aggrPubkX, CY1))
	//pairyalpha, err := mCred.Bn.Pairing(c, CYX)
	//paircxyy := mCred.Bn.Fq12.Mul(pairxy1, pairyalpha)
	//fmt.Println("equalpaircxyy=pairdg2", mCred.Bn.Fq12.Equal(paircxyy, pairdg2))

	//pairdiv := mCred.Bn.Fq12.Div(pairdg2, pairxy1)
	//fmt.Println("equalcxy1", mCred.Bn.Fq12.Equal(pairdiv, pairyalpha))
	//pairdivx := mCred.Bn.Fq12.MulScalar(pairdiv, c1)
	//fmt.Println("pairdivx", pairdivx)
	//pairxyy1 := mCred.Bn.Fq12.MulScalar(pairyalpha, c1)
	//fmt.Println("pairxyy1", pairxyy1)
	//fmt.Println("equalcxy", mCred.Bn.Fq12.Equal(paircxy, pairdg2))
	//fmt.Println("equalcxyZ", mCred.Bn.Fq12.Equal(pairdivx, pairxyy1))

	//pairXC, err := mCred.Bn.Pairing(c, mCred.Bn.G2.MulScalar(CYX, c1))
	//pairSYC, err := mCred.Bn.Pairing(c, CY)
	//if err != nil {
	//	panic("an error occured: invaid random")
	//}
	//pairRcb := mCred.Bn.Fq12.Div(pairSYC, pairXC)
	//T2 := pairRcb
	//fmt.Println("equal", mCred.Bn.Fq12.Equal(T2, a2))

	//-----------//
	//var XYC [3][2]*big.Int
	//XYC := mCred.Bn.G2.Add(aggrPubkX, CY1)
	//XYC = mCred.Bn.G2.MulScalar(XYC, c1)
	//var YSX [3][2]*big.Int

	//YSX := mCred.Bn.G2.Add(CY, XYC)
	//pairB1, err := mCred.Bn.Pairing(c, YSX)
	//var dc [3]*big.Int
	//dc := mCred.Bn.G1.MulScalar(d, c1)
	//pairU, err := mCred.Bn.Pairing(dc, mCred.Bn.G2.G)
	//if err != nil {
	//	panic("an error occured: invaid random")
	//}
	//pairR := mCred.Bn.Fq12.Div(pairB1, pairU)
	//T1 := pairR

	//fmt.Println("equal123", mCred.Bn.Fq12.Equal(T1, a2))

	pairB1, err := mCred.Bn.Pairing(mCred.Bn.G1.MulScalar(c, c1), mCred.Bn.G2.Add(aggrPubkX, CY1))
	//pairB2, err := mCred.Bn.Pairing(c, CY1)
	pairU, err := mCred.Bn.Pairing(mCred.Bn.G1.MulScalar(d, c1), mCred.Bn.G2.G)
	pairL, err := mCred.Bn.Pairing(c, CY)
	//pairXC, err := mCred.Bn.Pairing(c, mCred.Bn.G2.MulScalar(CYX, c1))
	if err != nil {
		panic("an error occured: invaid random")
	}
	//pairB := mCred.Bn.Fq12.Mul(pairB1, pairB2)
	pairR := mCred.Bn.Fq12.Div(pairU, pairB1)
	//pairB3 := mCred.Bn.Fq12.MulScalar(pairR, c1)
	//paircys := mCred.Bn.Fq12.Div(pairL, a2)
	//fmt.Println("equal1", paircys)
	//fmt.Println("equal12", mCred.Bn.Fq12.Equal(pairR, pairXC))
	//T1 := mCred.Bn.Fq12.Mul(a2, pairR)
	T2 := mCred.Bn.Fq12.Div(pairL, pairR)
	//fmt.Println("equal1234", mCred.Bn.Fq12.Equal(T1, pairL))
	//fmt.Println("equal12345", mCred.Bn.Fq12.Equal(T2, a2))

	g1Points = f
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	//g1Points = append(g1Points, F)
	g1Points = append(g1Points, a)
	var g2Points [][3][2]*big.Int
	g2Points = append(g2Points, T2[0])
	g2Points = append(g2Points, T2[1])
	if c1.Cmp(mCred.to_challenge(g1Points, g2Points, nil)) != 0 {
		//fmt.Println("g1Points", g1Points)
		//fmt.Println("g2Points", g2Points)
		//fmt.Println("a==ab", mCred.Bn.G1.Equal(a, ab))
		//fmt.Println("equal", mCred.Bn.Fq12.Equal(T2, a2))
		return false
	} else if !mCred.Bn.G1.Equal(a, ab) {
		//fmt.Println("ab test")
		return false
	} else {
		return true
	}
}
func (mCred MCred) Trace(c [3]*big.Int, d [3]*big.Int, F [3]*big.Int, L []Record, tsk *big.Int, k int64, n int) ([3]*big.Int, [][3][2]*big.Int) {
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [][3]*big.Int
	for i := 0; i < n; i++ {
		f = append(f, mCred.HashtoG1(new(big.Int).Add(mCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes()))
	}
	var E [][3][2]*big.Int
	for i := 0; i < n; i++ {
		E = append(E, mCred.Bn.G2.Sub(L[0].S2[i], mCred.Bn.G2.MulScalar(L[0].S1[i], tsk)))
	}
	verifyPairL, err := mCred.Bn.Pairing(f[0], E[0])
	if err != nil {
		panic("an error occured: invaid random")
	}
	for i := 1; i < n; i++ {
		verifyPair, err := mCred.Bn.Pairing(f[i], E[i])
		if err != nil {
			panic("an error occured: invaid random")
		}
		verifyPairL = mCred.Bn.Fq12.Mul(verifyPairL, verifyPair)
	}
	verifyPairR, err := mCred.Bn.Pairing(F, mCred.Bn.G2.G)
	if err != nil {
		panic("an error occured: invaid random")
	}
	if !mCred.Bn.Fq12.Equal(verifyPairL, verifyPairR) {
		panic("an error occured: invaid trace")
	} else {
		return L[0].R, E
	}
}

func (mCred MCred) Judge(cas []CAKeys, c [3]*big.Int, d [3]*big.Int, F [3]*big.Int, c1 *big.Int, s1 []*big.Int, a [3]*big.Int, alpha []*big.Int, k int64, a2 [2][3][2]*big.Int, R [3]*big.Int, E [][3][2]*big.Int) bool {
	n := len(alpha)
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [][3]*big.Int
	for i := 0; i < n; i++ {
		f = append(f, mCred.HashtoG1(new(big.Int).Add(mCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes()))
	}
	verified := mCred.credVerify(cas, c, d, F, c1, s1, a, alpha, k, a2)
	if !verified {
		panic("an error occured: invaid judge")
		return false
	}
	verifyPairL, err := mCred.Bn.Pairing(f[0], E[0])
	if err != nil {
		panic("an error occured: invaid random")
	}
	for i := 1; i < n; i++ {
		verifyPair, err := mCred.Bn.Pairing(f[i], E[i])
		if err != nil {
			panic("an error occured: invaid random")
		}
		verifyPairL = mCred.Bn.Fq12.Mul(verifyPairL, verifyPair)
	}
	verifyPairR, err := mCred.Bn.Pairing(F, mCred.Bn.G2.G)
	if err != nil {
		panic("an error occured: invaid random")
	}
	if !mCred.Bn.Fq12.Equal(verifyPairL, verifyPairR) {
		panic("an error occured: invaid trace")
		return false
	}
	return true
}
