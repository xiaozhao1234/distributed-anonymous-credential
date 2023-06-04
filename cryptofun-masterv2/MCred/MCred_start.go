package MCred

import (
	"crypto/rand"
	"github.com/arnaucube/cryptofun/utils"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"
)

func MCredTest() {
	mCred, err := NewMCred()
	if err != nil {
		return
	}
	f, err := os.OpenFile("./MCred/log.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModePerm)
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
			for disclosure := 1; disclosure < attrnumber; disclosure++ {
				log.Println("---------------------ca-------------------:", canumber)
				log.Println("---------------------attr-----------------:", attrnumber)
				log.Println("---------------------disclosure-----------:", disclosure)

				//# m CA number
				m := canumber
				//# n attr number
				n := attrnumber
				//# attr show
				var k = int64(disclosure)
				var alpha []*big.Int
				for i := 0; i < n; i++ {
					ranAlpha, err := rand.Int(rand.Reader, mCred.Bn.Q)
					if err != nil {
						return
					}
					alpha = append(alpha, ranAlpha)
				}
				var cas []CAKeys
				var PubK_Xs [][3][2]*big.Int
				var PubK_Ys [][][3][2]*big.Int
				sum := int64(0)
				for i := 0; i < m; i++ {
					start := time.Now().UnixMicro()
					ca, err := mCred.IssueKeyGen(alpha)
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
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-caKey.txt", mCred.to_Bytes(nil, g2Points, nil), false)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-caKey.txt", mCred.to_Bytes(nil, cas[0].PubK_Y, nil), true)
				start := time.Now().UnixMicro()
				z, err := mCred.TraceKeyGen()
				end := time.Now().UnixMicro()
				log.Println("TraceKeyGen(us)", end-start)
				if err != nil {
					return
				}
				g2Points = nil
				g2Points = append(g2Points, z.PubK)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-traceKey.txt", mCred.to_Bytes(nil, g2Points, nil), false)
				id := []byte("message0")
				start = time.Now().UnixMicro()
				S1, S2, h_1, R, c, a, s, proof_c, proof_s1, proof_s2, proof_b, proof_d, ri, tT := mCred.request(id, z, alpha)
				end = time.Now().UnixMicro()
				log.Println("request(us)", end-start)

				var g1Points [][3]*big.Int
				g1Points = append(g1Points, R)
				var intPoints []*big.Int
				intPoints = append(intPoints, c, proof_c)

				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-request.txt", mCred.to_Bytes(g1Points, S1, intPoints), false)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-request.txt", mCred.to_Bytes(h_1, S2, s), true)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-request.txt", mCred.to_Bytes(a, proof_b, proof_s1), true)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-request.txt", mCred.to_Bytes(nil, proof_d, proof_s2), true)
				//b, err = json.Marshal(ri)
				//utils.FileWrite("./request.txt", string(b), true)
				//b, err = json.Marshal(tT)
				//utils.FileWrite("./request.txt", string(b), true)

				var sigmas [][3]*big.Int
				var ListL []Record
				var hh [][3]*big.Int
				//var sig [][3]*big.Int
				sum = int64(0)
				for i := 0; i < m; i++ {
					start = time.Now().UnixMicro()
					sigmas = append(sigmas, mCred.issue(cas[i], S1, S2, z.PubK, proof_c, proof_s1, proof_s2, proof_b, proof_d, c, a, s, h_1, R, tT))
					end = time.Now().UnixMicro()
					//fmt.Println("issue(us)", end-start)
					sum = sum + end - start
					hh = append(hh, mCred.Vericred(id, R, sigmas[i], alpha, ri, cas[i]))
				}
				//fmt.Println("----------------------issue----------------")
				log.Println("sumIssue(us)", sum)
				log.Println("AvgIssue(us)", sum/int64(m))
				g1Points = nil
				g1Points = append(g1Points, sigmas[0])
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-issue.txt", mCred.to_Bytes(g1Points, nil, nil), false)
				record := Record{}
				record.R = R
				record.S1 = S1
				record.S2 = S2
				ListL = append(ListL, record)
				start = time.Now().UnixMicro()
				h, Asigg := mCred.CredAggr(id, sigmas, ri)
				end = time.Now().UnixMicro()
				log.Println("CredAggr(us)", end-start)

				g1Points = nil
				g1Points = append(g1Points, h, Asigg)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-credAggr.txt", mCred.to_Bytes(g1Points, nil, nil), false)

				start = time.Now().UnixMicro()
				credC, credD, credF, credC1, credS1, credA, credA2 := mCred.CredShow(h, Asigg, alpha, cas, k)
				end = time.Now().UnixMicro()
				log.Println("CredShow(us)", end-start)
				g2Points = nil
				g2Points = append(g2Points, credA2[0], credA2[1])
				g1Points = nil
				g1Points = append(g1Points, credC, credD, credF, credA)
				intPoints = nil
				intPoints = append(intPoints, credC1)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-CredShow.txt", mCred.to_Bytes(g1Points, g2Points, intPoints), false)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-CredShow.txt", mCred.to_Bytes(nil, nil, credS1), true)

				//fmt.Println("credential test:", credA2)
				start = time.Now().UnixMicro()
				verified := mCred.credVerify(cas, credC, credD, credF, credC1, credS1, credA, alpha, k, credA2)
				end = time.Now().UnixMicro()
				log.Println("credVerify(us)", end-start)
				//fmt.Println("credential verified:", verified)
				if verified != true {
					return
				}
				start = time.Now().UnixMicro()
				L_R, L_E := mCred.Trace(credC, credD, credF, ListL, z.PrivK, k, n)
				end = time.Now().UnixMicro()
				log.Println("Trace(us)", end-start)

				g1Points = nil
				g1Points = append(g1Points, L_R)
				utils.FileWriteBytes("./MCred/"+strconv.Itoa(canumber)+"-"+strconv.Itoa(attrnumber)+"-"+strconv.Itoa(disclosure)+"-Trace.txt", mCred.to_Bytes(g1Points, L_E, nil), false)

				start = time.Now().UnixMicro()
				judged := mCred.Judge(cas, credC, credD, credF, credC1, credS1, credA, alpha, k, credA2, L_R, L_E)
				end = time.Now().UnixMicro()
				log.Println("Judge(us)", end-start)
				//fmt.Println("judge verified:", judged)
				if judged != true {
					return
				}
			}
		}
	}
}
