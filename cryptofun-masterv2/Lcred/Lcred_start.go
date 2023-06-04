package Lcred

import (
	"crypto/rand"
	"github.com/arnaucube/cryptofun/utils"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"
)

func LcredTest() {
	LCred, err := NewLcred()
	if err != nil {
		return
	}
	f, err := os.OpenFile("./Lcred/log.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModePerm)
	if err != nil {
		return
	}
	defer func() {
		f.Close()
	}()

	log.SetOutput(f)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	for canumber := 1; canumber <= 22; canumber++ {
		for attrnumber := 2; attrnumber <= 10; attrnumber++ {
			log.Println("---------------------ca------------:", canumber)
			log.Println("---------------------attr----------:", attrnumber)

			//# m CA number
			m := canumber
			//# n attr number
			n := attrnumber
			//# attr show
			var k = int64(n)
			var alpha []*big.Int
			for i := 0; i < n; i++ {
				ranAlpha, err := rand.Int(rand.Reader, LCred.Bn.Q)
				if err != nil {
					return
				}
				alpha = append(alpha, ranAlpha)
			}
			sum := int64(0)
			var cas []CAKeys
			var PubK_Xs [][3][2]*big.Int
			var PubK_Ys [][][3][2]*big.Int
			for i := 0; i < m; i++ {
				start := time.Now().UnixMicro()
				ca, err := LCred.IssueKeyGen(alpha)
				end := time.Now().UnixMicro()
				//fmt.Println("IssueKeyGen(us)", end-start)
				sum = sum + end - start
				if err != nil {
					return
				}
				cas = append(cas, ca)
				PubK_Xs = append(PubK_Xs, cas[i].PubK_X)
				PubK_Ys = append(PubK_Ys, cas[i].PubK_Y)
			}
			//fmt.Println("----------------------IssueKeyGen----------------")
			log.Println("sumIssueKeyGen(us)", sum)
			log.Println("avgIssueKeyGen(us)", sum/int64(m))
			var g2Points [][3][2]*big.Int
			g2Points = append(g2Points, cas[0].PubK_X)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-caKey.txt", LCred.to_Bytes(nil, g2Points, nil), false)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-caKey.txt", LCred.to_Bytes(nil, cas[0].PubK_Y, nil), true)
			start := time.Now().UnixMicro()
			z, err := LCred.TraceKeyGen()
			end := time.Now().UnixMicro()
			log.Println("TraceKeyGen(us)", end-start)
			if err != nil {
				return
			}
			g2Points = nil
			g2Points = append(g2Points, z.PubK)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-traceKey.txt", LCred.to_Bytes(nil, g2Points, nil), false)

			id := []byte("message0")
			start = time.Now().UnixMicro()
			S1, S2, h_1, R, c, a, s, proof_c, proof_s1, proof_s2, proof_b, proof_d, ri, tT := LCred.request(id, z, alpha)
			end = time.Now().UnixMicro()
			log.Println("request(us)", end-start)
			g2Points = nil
			g2Points = append(g2Points, S1, S2, proof_b, proof_d)
			var g1Points [][3]*big.Int
			g1Points = append(g1Points, R)
			var intPoints []*big.Int
			intPoints = append(intPoints, c, s, proof_c, proof_s1, proof_s2)

			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-request.txt", LCred.to_Bytes(g1Points, g2Points, intPoints), false)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-request.txt", LCred.to_Bytes(h_1, nil, nil), true)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-request.txt", LCred.to_Bytes(a, nil, nil), true)

			//b, err = json.Marshal(ri)
			//utils.FileWrite("./request.txt", string(b), true)
			//b, err = json.Marshal(tT)
			//utils.FileWrite("./request.txt", string(b), true)
			sum = int64(0)
			var sigmas [][3]*big.Int
			var ListL []Record
			var hh [][3]*big.Int
			//var sig [][3]*big.Int
			for i := 0; i < m; i++ {
				start = time.Now().UnixMicro()
				sigmas = append(sigmas, LCred.issue(cas[i], S1, S2, z.PubK, proof_c, proof_s1, proof_s2, proof_b, proof_d, c, a, s, h_1, R, tT))
				end = time.Now().UnixMicro()
				//fmt.Println("issue(us)", end-start)
				sum = sum + end - start
				hh = append(hh, LCred.Vericred(id, R, sigmas[i], alpha, ri, cas[i]))
			}
			//fmt.Println("----------------------issue----------------")
			log.Println("sumIssue(us)", sum)
			log.Println("AvgIssue(us)", sum/int64(m))
			g1Points = nil
			g1Points = append(g1Points, sigmas[0])
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-issue.txt", LCred.to_Bytes(g1Points, nil, nil), false)

			record := Record{}
			record.R = R
			record.S1 = S1
			record.S2 = S2
			ListL = append(ListL, record)
			start = time.Now().UnixMicro()
			h, Asigg := LCred.CredAggr(id, sigmas, ri)
			end = time.Now().UnixMicro()
			log.Println("CredAggr(us)", end-start)
			g1Points = nil
			g1Points = append(g1Points, h, Asigg)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-credAggr.txt", LCred.to_Bytes(g1Points, nil, nil), false)

			start = time.Now().UnixMicro()
			credC, credD, credF, credC1, credS1, credA, credA2 := LCred.CredShow(h, Asigg, alpha, cas, k)
			//fmt.Println("credential test:", credA2)
			end = time.Now().UnixMicro()
			log.Println("CredShow(us)", end-start)
			g2Points = nil
			g2Points = append(g2Points, credA2[0], credA2[1])
			g1Points = nil
			g1Points = append(g1Points, credC, credD, credF, credA)
			intPoints = nil
			intPoints = append(intPoints, credC1, credS1)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-CredShow.txt", LCred.to_Bytes(g1Points, g2Points, intPoints), false)

			start = time.Now().UnixMicro()
			verified := LCred.credVerify(cas, credC, credD, credF, credC1, credS1, credA, alpha, k, credA2)
			end = time.Now().UnixMicro()
			log.Println("credVerify(us)", end-start)
			//fmt.Println("credential verified:", verified)
			if verified != true {
				return
			}
			start = time.Now().UnixMicro()
			L_R, L_E := LCred.Trace(credC, credD, credF, ListL, z.PrivK, k, n)
			end = time.Now().UnixMicro()
			log.Println("Trace(us)", end-start)
			g2Points = nil
			g2Points = append(g2Points, L_E)
			g1Points = nil
			g1Points = append(g1Points, L_R)
			utils.FileWriteBytes("./Lcred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-Trace.txt", LCred.to_Bytes(g1Points, g2Points, nil), false)
			start = time.Now().UnixMicro()
			judged := LCred.Judge(cas, credC, credD, credF, credC1, credS1, credA, alpha, k, credA2, L_R, L_E)
			end = time.Now().UnixMicro()
			log.Println("Judge(us)", end-start)
			//fmt.Println("judge verified:", judged)
			if judged != true {
				return
			}
		}
	}

}
