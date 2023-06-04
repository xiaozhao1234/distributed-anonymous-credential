package Dcred

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/arnaucube/go-snark/bn128"
	"math/big"
)

//const bits = 1024

// Dcred is the data structure of the BN128 pairing curve
type Dcred struct {
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
	S1 [3][2]*big.Int
	S2 [3][2]*big.Int
}

// NewMCred generates a new BLS scheme
func NewDcred() (Dcred, error) {
	bn, err := bn128.NewBn128()
	if err != nil {
		return Dcred{}, err
	}
	DCred := Dcred{}
	DCred.Bn = bn
	return DCred, nil
}

// IssueKeyGen generate a key pair of issuer
func (DCred Dcred) IssueKeyGen(alpha []*big.Int) (CAKeys, error) {
	var err error
	var PrivK *big.Int
	k := CAKeys{}
	k.PrivK_x, err = rand.Int(rand.Reader, DCred.Bn.Q)
	for i := 0; i < len(alpha); i++ {
		PrivK, err = rand.Int(rand.Reader, DCred.Bn.Q)
		k.PrivK_y = append(k.PrivK_y, PrivK)
	}
	if err != nil {
		return CAKeys{}, err
	}
	// pubK = pk * G
	k.PubK_X = DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, k.PrivK_x)
	for i := 0; i < len(alpha); i++ {
		k.PubK_Y = append(k.PubK_Y, DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, k.PrivK_y[i]))
	}
	return k, nil
}

// TraceKeyGen generate a key pair of issuer
func (DCred Dcred) TraceKeyGen() (TraceKeys, error) {
	var err error
	z := TraceKeys{}
	z.PrivK, err = rand.Int(rand.Reader, DCred.Bn.Q)
	if err != nil {
		return TraceKeys{}, err
	}
	// pubK = pk * G
	z.PubK = DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, z.PrivK)
	return z, nil
}

// HashtoG1 hashes a message m
func (DCred Dcred) HashtoG1(m []byte) [3]*big.Int {
	h := sha256.New()
	h.Write(m)
	hash := h.Sum(nil)
	r := new(big.Int).SetBytes(hash)
	// get point over the curve
	point := DCred.Bn.G1.MulScalar(DCred.Bn.G1.G, r)
	return point
}

// request
func (DCred Dcred) request(id []byte, z TraceKeys, alpha []*big.Int) ([3][2]*big.Int, [3][2]*big.Int, [][3]*big.Int,
	[3]*big.Int, *big.Int, [][3]*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, [3][2]*big.Int, [3][2]*big.Int,
	*big.Int, *big.Int) {
	h := DCred.HashtoG1(id)
	ri, err := rand.Int(rand.Reader, DCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid random")
	}
	R := DCred.Bn.G1.MulScalar(h, ri)
	//fmt.Println("R:", R)
	var h_1 [][3]*big.Int
	for i := 0; i < len(alpha); i++ {
		h_1 = append(h_1, DCred.Bn.G1.MulScalar(R, alpha[i]))
	}
	c, a, s := DCred.proof_zkpok(h_1, R, alpha)
	var t *big.Int
	var S1 [3][2]*big.Int
	var S2 [3][2]*big.Int
	//for i := 0; i < len(alpha); i++ {
	t, err = rand.Int(rand.Reader, DCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid random")
	}
	//t = append(t, ran_t)
	// S2 = append(S2, LCred.Bn.G2.Add(LCred.Bn.G2.MulScalar(z.PubK, ran_t), LCred.Bn.G2.MulScalar(LCred.Bn.G2.G, alpha[i])))
	//}
	//fmt.Println("to:", t[0])
	S1 = DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, t)
	S2 = DCred.Bn.G2.Add(DCred.Bn.G2.MulScalar(z.PubK, t), DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, alpha[len(alpha)-1]))
	proof_c, proof_s1, proof_s2, proof_b, proof_d := DCred.prove_commitment(z.PubK, S1, S2, alpha, t)
	return S1, S2, h_1, R, c, a, s, proof_c, proof_s1, proof_s2, proof_b, proof_d, ri, t
}

// proof_zkpok
func (DCred Dcred) proof_zkpok(h_1 [][3]*big.Int, R [3]*big.Int, alpha []*big.Int) (*big.Int, [][3]*big.Int, *big.Int) {
	var ri1 *big.Int
	var a [][3]*big.Int
	//for i := 0; i < len(alpha); i++ {
	ri1, err := rand.Int(rand.Reader, DCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid random")
	}
	//}
	//create the challenge
	a = append(a, DCred.Bn.G1.MulScalar(R, ri1))
	c := DCred.to_challenge(a, nil, nil)
	var s *big.Int
	//for i := 0; i < len(alpha); i++ {
	s = new(big.Int).Add(ri1, new(big.Int).Mul(c, alpha[len(alpha)-1]))
	//s = append(s, mCred.Bn.Fq1.Add(r[i], mCred.Bn.Fq1.Mul(c, alpha[i])))
	//}
	return c, a, s
}

func (DCred Dcred) to_challenge(g1Points [][3]*big.Int, g2Points [][3][2]*big.Int, IntPoints []*big.Int) *big.Int {
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

func (DCred Dcred) to_Bytes(g1Points [][3]*big.Int, g2Points [][3][2]*big.Int, IntPoints []*big.Int) []byte {
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

func (DCred Dcred) prove_commitment(PubK [3][2]*big.Int, S1 [3][2]*big.Int, S2 [3][2]*big.Int, alpha []*big.Int, t *big.Int) (*big.Int, *big.Int, *big.Int, [3][2]*big.Int, [3][2]*big.Int) {
	var u1, u2 *big.Int
	var b, d [3][2]*big.Int
	//for i := 0; i < len(alpha); i++ {
	u1, err := rand.Int(rand.Reader, DCred.Bn.Q)
	u2, err = rand.Int(rand.Reader, DCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid random")
	}

	//create the challenge
	b = DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, u1)
	d = DCred.Bn.G2.Add(DCred.Bn.G2.MulScalar(PubK, u1), DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, u2))
	var g2Points [][3][2]*big.Int
	g2Points = append(g2Points, S1)
	for i := 0; i < len(S2); i++ {
		g2Points = append(g2Points, S2)
		g2Points = append(g2Points, b)
		g2Points = append(g2Points, d)
	}
	c := DCred.to_challenge(nil, g2Points, nil)
	var s1 *big.Int
	var s2 *big.Int
	//for i := 0; i < len(alpha); i++ {
	//s1 = append(s1, new(big.Int).Mod(new(big.Int).Add(u1[i], new(big.Int).Mod(new(big.Int).Mul(c, t[i]), mCred.Bn.Q)), mCred.Bn.Q))

	s1 = new(big.Int).Add(u1, new(big.Int).Mul(c, t))
	s2 = new(big.Int).Add(u2, new(big.Int).Mul(c, alpha[len(alpha)-1]))
	//}
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
func (DCred Dcred) issue(ca CAKeys, S1 [3][2]*big.Int, S2 [3][2]*big.Int, PubK [3][2]*big.Int, proof_c *big.Int, proof_s1 *big.Int, proof_s2 *big.Int, proof_b [3][2]*big.Int,
	proof_d [3][2]*big.Int, c *big.Int, a [][3]*big.Int, s *big.Int, h_1 [][3]*big.Int, R [3]*big.Int, t *big.Int) [3]*big.Int {
	if !DCred.verify_proofalpha(c, a, s, h_1, R) {
		panic("an error occured: invaid proofalpha")
	}
	if !DCred.verify_commitment(PubK, S1, S2, proof_c, proof_s1, proof_s2, proof_b, proof_d, t) {
		panic("an error occured: invaid commitment")
	}
	sigma := DCred.Bn.G1.MulScalar(R, ca.PrivK_x)
	for i := 0; i < len(h_1); i++ {
		sigma = DCred.Bn.G1.Add(sigma, DCred.Bn.G1.MulScalar(h_1[i], ca.PrivK_y[i]))
	}
	return sigma
}

func (DCred Dcred) verify_proofalpha(c *big.Int, a [][3]*big.Int, s *big.Int, h_1 [][3]*big.Int, R [3]*big.Int) bool {

	if !DCred.Bn.G1.Equal(DCred.Bn.G1.MulScalar(R, s), DCred.Bn.G1.Add(a[0], DCred.Bn.G1.MulScalar(h_1[len(h_1)-1], c))) {
		return false
	}

	//fmt.Println("proof_d verifiedalpha:")
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, a[0])

	cTest := DCred.to_challenge(g1Points, nil, nil)
	if c.Cmp(cTest) != 0 {
		return false
	}
	return true
}

func (DCred Dcred) verify_commitment(PubK [3][2]*big.Int, S1 [3][2]*big.Int, S2 [3][2]*big.Int, proof_c *big.Int, proof_s1 *big.Int, proof_s2 *big.Int, proof_b [3][2]*big.Int,
	proof_d [3][2]*big.Int, t *big.Int) bool {
	var left, right [3][2]*big.Int
	//for i := 0; i < len(S1); i++ {
	if !DCred.Bn.G2.Equal(proof_b, DCred.Bn.G2.Sub(DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, proof_s1), DCred.Bn.G2.MulScalar(S1, proof_c))) {
		return false
	}
	left = DCred.Bn.G2.Add(DCred.Bn.G2.MulScalar(PubK, proof_s1), DCred.Bn.G2.MulScalar(DCred.Bn.G2.G, proof_s2))
	right = DCred.Bn.G2.MulScalar(S2, proof_c)
	if !DCred.Bn.G2.Equal(proof_d, DCred.Bn.G2.Sub(left, right)) {
		//fmt.Println("proof_d verified:")
		return false
	}
	//}
	var g2Points [][3][2]*big.Int
	g2Points = append(g2Points, S1)
	for i := 0; i < len(S2); i++ {
		g2Points = append(g2Points, S2)
		g2Points = append(g2Points, proof_b)
		g2Points = append(g2Points, proof_d)
	}
	if proof_c.Cmp(DCred.to_challenge(nil, g2Points, nil)) != 0 {
		return false
	}
	return true
}

// Verify credential
func (DCred Dcred) Vericred(id []byte, R [3]*big.Int, sigg [3]*big.Int, alpha []*big.Int, ri *big.Int, ca CAKeys) [3]*big.Int {
	h := DCred.HashtoG1(id)
	var riInv *big.Int
	riInv = DCred.Bn.Fq1.Inverse(ri)
	fmt.Println("inversexy:", DCred.Bn.G1.Equal(h, DCred.Bn.G1.MulScalar(h, DCred.Bn.Fq1.Mul(riInv, ri))))

	var XY [3][2]*big.Int
	XY = ca.PubK_X
	for i := 0; i < len(alpha); i++ {
		XY = DCred.Bn.G2.Add(XY, DCred.Bn.G2.MulScalar(ca.PubK_Y[i], alpha[i]))
	}

	pairRi, err := DCred.Bn.Pairing(R, XY)
	pairdg2, err := DCred.Bn.Pairing(sigg, DCred.Bn.G2.G)
	if err != nil {
		panic("an error occured: invaid random")
	}
	fmt.Println("equalRIdg2", DCred.Bn.Fq12.Equal(pairRi, pairdg2))
	return sigg
}

// Randomize
func (DCred Dcred) randAggr(h [3]*big.Int, sigg [3]*big.Int) ([3]*big.Int, [3]*big.Int) {
	r, err := rand.Int(rand.Reader, DCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid Randomize")
	}
	h = DCred.Bn.G1.MulScalar(h, r)
	sigg = DCred.Bn.G1.MulScalar(sigg, r)
	return h, sigg
}

func (DCred Dcred) CredAggr(id []byte, cred [][3]*big.Int, ri *big.Int) ([3]*big.Int, [3]*big.Int) {
	h := DCred.HashtoG1(id)
	var riInv *big.Int
	var Asigg [3]*big.Int
	riInv = DCred.Bn.Fq1.Inverse(ri)
	//fmt.Println("inversexy:", mCred.Bn.G1.Equal(h, mCred.Bn.G1.MulScalar(h, mCred.Bn.Fq1.Mul(riInv, ri))))
	//fmt.Println("inverriinv:", mCred.Bn.Fq1.Mul(riInv, ri))
	Asigg = cred[0]
	for i := 1; i < len(cred); i++ {
		if i == 0 {
			Asigg = DCred.Bn.G1.MulScalar(cred[i], riInv)
		} else {
			Asigg = DCred.Bn.G1.Add(Asigg, cred[i])
		}
	}
	R := DCred.Bn.G1.MulScalar(h, ri)
	return R, Asigg
}

func (DCred Dcred) CredShow(h [3]*big.Int, Asigg [3]*big.Int, alpha []*big.Int, cas []CAKeys, k int64) ([3]*big.Int, [3]*big.Int, [3]*big.Int, *big.Int, *big.Int, [3]*big.Int, [2][3][2]*big.Int) {

	c, d := DCred.randAggr(h, Asigg)
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [3]*big.Int
	//for i := 0; i < len(alpha); i++ {
	f = DCred.HashtoG1(new(big.Int).Add(DCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes())
	//}
	F := DCred.Bn.G1.MulScalar(f, alpha[len(alpha)-1])
	//for i := 1; i < len(alpha); i++ {
	//	F = LCred.Bn.G1.Add(F, LCred.Bn.G1.MulScalar(f[i], alpha[i]))
	//}
	c1, s1, a, a2 := DCred.proveShow(cas, c, d, alpha, F, f, k)
	return c, d, F, c1, s1, a, a2
}

func (DCred Dcred) proveShow(cas []CAKeys, c [3]*big.Int, d [3]*big.Int, alpha []*big.Int, F [3]*big.Int, f [3]*big.Int, k int64) (*big.Int, *big.Int, [3]*big.Int, [2][3][2]*big.Int) {
	var rsk *big.Int
	var a [3]*big.Int
	var b [3][2]*big.Int
	//var pubb [3][2]*big.Int

	//for i := 0; i < int(k); i++ {
	rsk, err := rand.Int(rand.Reader, DCred.Bn.Q)
	if err != nil {
		panic("an error occured: invaid random")
	}
	//	rsk = append(rsk, ri)

	a = DCred.Bn.G1.MulScalar(f, rsk)
	b = DCred.Bn.G2.MulScalar(cas[0].PubK_Y[len(alpha)-1], rsk)

	for i := 1; i < len(cas); i++ {
		//for j := 0; j < int(k); j++ {
		b = DCred.Bn.G2.Add(b, DCred.Bn.G2.MulScalar(cas[i].PubK_Y[len(alpha)-1], rsk))
		//}
	}
	a2, err := DCred.Bn.Pairing(c, b)

	if err != nil {
		panic("an error occured: invaid random")
	}
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, f)
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	//       ---------//g1Points = append(g1Points, F)
	g1Points = append(g1Points, a)
	var g2Points [][3][2]*big.Int
	g2Points = append(g2Points, a2[0])
	g2Points = append(g2Points, a2[1])
	//fmt.Println("!!!! g1Points", g1Points)
	//fmt.Println("!!!! g2Points", g2Points)
	c1 := DCred.to_challenge(g1Points, g2Points, nil)
	var s1 *big.Int
	//for i := 0; i < int(k); i++ {
	s1 = new(big.Int).Add(rsk, new(big.Int).Mul(c1, alpha[len(alpha)-1]))
	//s1 = append(s1, mCred.Bn.Fq1.Add(rsk[i], mCred.Bn.Fq1.Mul(c1, alpha[i])))
	//}

	return c1, s1, a, a2
}

func (DCred Dcred) credVerify(cas []CAKeys, c [3]*big.Int, d [3]*big.Int, F [3]*big.Int, c1 *big.Int, s1 *big.Int, a [3]*big.Int, alpha []*big.Int, k int64, a2 [2][3][2]*big.Int) bool {
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [3]*big.Int
	//var F1 [3]*big.Int
	//var fi [3]*big.Int
	//var Ffi1 [3]*big.Int
	var abc [3]*big.Int

	//for i := 0; i < len(alpha); i++ {
	f = DCred.HashtoG1(new(big.Int).Add(DCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes())
	//}
	F1 := DCred.Bn.G1.MulScalar(f, s1)
	//for i := 1; i < int(k); i++ {
	//	F1 = LCred.Bn.G1.Add(F1, LCred.Bn.G1.MulScalar(f[i], s1[i]))
	//}
	//fi = LCred.Bn.G1.MulScalar(f, alpha[len(alpha)-1])
	//for i := int(k) + 1; i < len(alpha); i++ {
	//	fi = LCred.Bn.G1.Add(fi, LCred.Bn.G1.MulScalar(f[i], alpha[i]))
	//}
	//Ffi1 = LCred.Bn.G1.Sub(F, fi)
	abc = DCred.Bn.G1.MulScalar(F, c1)

	ab := DCred.Bn.G1.Sub(F1, abc)

	aggrPubkX := cas[0].PubK_X
	for i := 1; i < len(cas); i++ {
		aggrPubkX = DCred.Bn.G2.Add(aggrPubkX, cas[i].PubK_X)
	}

	var aggrPubkY [][3][2]*big.Int
	for i := 0; i < len(cas[0].PubK_Y); i++ {
		aggrPubkY = append(aggrPubkY, cas[0].PubK_Y[i])
	}

	for i := 0; i < len(cas[0].PubK_Y); i++ {
		for j := 1; j < len(cas); j++ {
			aggrPubkY[i] = DCred.Bn.G2.Add(aggrPubkY[i], cas[j].PubK_Y[i])
		}
	}

	CY := DCred.Bn.G2.MulScalar(aggrPubkY[len(alpha)-1], s1)
	//CYX := mCred.Bn.G2.MulScalar(aggrPubkY[0], alpha[0])
	//CY1 := DCred.Bn.G2.MulScalar(aggrPubkY[0], alpha[0])

	//for i := 1; i < (len(alpha) - 1); i++ {
	//	CY1 = DCred.Bn.G2.Add(CY1, DCred.Bn.G2.MulScalar(aggrPubkY[i], alpha[i]))
	//}

	pairB1, err := DCred.Bn.Pairing(DCred.Bn.G1.MulScalar(c, c1), aggrPubkX)
	//pairB2, err := mCred.Bn.Pairing(c, CY1)
	pairU, err := DCred.Bn.Pairing(DCred.Bn.G1.MulScalar(d, c1), DCred.Bn.G2.G)
	pairL, err := DCred.Bn.Pairing(c, CY)
	//pairXC, err := mCred.Bn.Pairing(c, mCred.Bn.G2.MulScalar(CYX, c1))
	if err != nil {
		panic("an error occured: invaid random")
	}
	//pairB := mCred.Bn.Fq12.Mul(pairB1, pairB2)
	pairR := DCred.Bn.Fq12.Div(pairU, pairB1)
	//pairB3 := mCred.Bn.Fq12.MulScalar(pairR, c1)
	//paircys := mCred.Bn.Fq12.Div(pairL, a2)
	//fmt.Println("equal1", paircys)
	//fmt.Println("equal12", mCred.Bn.Fq12.Equal(pairR, pairXC))
	//T1 := mCred.Bn.Fq12.Mul(a2, pairR)
	T2 := DCred.Bn.Fq12.Div(pairL, pairR)
	//fmt.Println("equal1234", mCred.Bn.Fq12.Equal(T1, pairL))
	//fmt.Println("equal12345", mCred.Bn.Fq12.Equal(T2, a2))
	var g1points [][3]*big.Int
	g1points = append(g1points, f)
	g1points = append(g1points, c)
	g1points = append(g1points, d)
	//g1Points = append(g1Points, F)
	g1points = append(g1points, a)
	var g2Points [][3][2]*big.Int
	g2Points = append(g2Points, T2[0])
	g2Points = append(g2Points, T2[1])
	fmt.Println("equal1234", DCred.Bn.Fq12.Equal(a2, T2))

	if c1.Cmp(DCred.to_challenge(g1points, g2Points, nil)) != 0 {
		//fmt.Println("g1Points", g1Points)
		//fmt.Println("g2Points", g2Points)
		//fmt.Println("a==ab", mCred.Bn.G1.Equal(a, ab))
		//fmt.Println("equal1234", LCred.Bn.Fq12.Equal(a2, T2))
		return false
	} else if !DCred.Bn.G1.Equal(a, ab) {
		//fmt.Println("ab test")
		return false
	} else {
		return true
	}
}
func (DCred Dcred) Trace(c [3]*big.Int, d [3]*big.Int, F [3]*big.Int, L []Record, tsk *big.Int, k int64, n int) ([3]*big.Int, [3][2]*big.Int) {
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [3]*big.Int
	f = DCred.HashtoG1(new(big.Int).Add(DCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes())

	var E [3][2]*big.Int
	E = DCred.Bn.G2.Sub(L[0].S2, DCred.Bn.G2.MulScalar(L[0].S1, tsk))
	//}
	verifyPairL, err := DCred.Bn.Pairing(f, E)
	if err != nil {
		panic("an error occured: invaid random")
	}

	verifyPairR, err := DCred.Bn.Pairing(F, DCred.Bn.G2.G)
	if err != nil {
		panic("an error occured: invaid random")
	}
	if !DCred.Bn.Fq12.Equal(verifyPairL, verifyPairR) {
		panic("an error occured: invaid trace")
	} else {
		return L[0].R, E
	}
}

func (DCred Dcred) Judge(cas []CAKeys, c [3]*big.Int, d [3]*big.Int, F [3]*big.Int, c1 *big.Int, s1 *big.Int, a [3]*big.Int, alpha []*big.Int, k int64, a2 [2][3][2]*big.Int, R [3]*big.Int, E [3][2]*big.Int) bool {
	//n := len(alpha)
	var g1Points [][3]*big.Int
	g1Points = append(g1Points, c)
	g1Points = append(g1Points, d)
	var f [3]*big.Int
	f = DCred.HashtoG1(new(big.Int).Add(DCred.to_challenge(g1Points, nil, nil), new(big.Int).SetInt64(k)).Bytes())

	verified := DCred.credVerify(cas, c, d, F, c1, s1, a, alpha, k, a2)
	if !verified {
		panic("an error occured: invaid judge")
		return false
	}
	verifyPairL, err := DCred.Bn.Pairing(f, E)
	if err != nil {
		panic("an error occured: invaid random")
	}

	verifyPairR, err := DCred.Bn.Pairing(F, DCred.Bn.G2.G)
	if err != nil {
		panic("an error occured: invaid random")
	}
	if !DCred.Bn.Fq12.Equal(verifyPairL, verifyPairR) {
		panic("an error occured: invaid trace")
		return false
	}
	return true
}
