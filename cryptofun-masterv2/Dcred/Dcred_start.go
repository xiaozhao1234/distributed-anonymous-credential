package Dcred

import (
	"crypto/rand"
	"github.com/arnaucube/cryptofun/utils"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"
)

func DcredTest() {

	DCred, err := NewDcred()
	if err != nil {
		return
	}
	f, err := os.OpenFile("./Dcred/log.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModePerm)
	if err != nil {
		return
	}
	defer func() {
		f.Close()
	}()

	log.SetOutput(f)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	for j := 1; j <= 22; j++ {
		log.Println("---------------------ca------------------:", j)

		//# m CA number
		m := j
		//# n attr number
		n := 1
		//# attr show
		var k = int64(8)
		var alpha []*big.Int
		for i := 0; i < n; i++ {
			ranAlpha, err := rand.Int(rand.Reader, DCred.Bn.Q)
			if err != nil {
				return
			}
			alpha = append(alpha, ranAlpha)
		}

		var cas []CAKeys
		//var PubK_Xs [][3][2]*big.Int
		//var PubK_Ys [][][3][2]*big.Int
		sum := int64(0)
		for i := 0; i < m; i++ {
			start := time.Now().UnixMicro()
			ca, err := DCred.IssueKeyGen(alpha)
			end := time.Now().UnixMicro()
			//fmt.Println("IssueKeyGen(us)", end-start)
			sum = sum + end - start
			if err != nil {
				return
			}
			cas = append(cas, ca)
			//PubK_Xs = append(PubK_Xs, cas[i].PubK_X)
			//PubK_Ys = append(PubK_Ys, cas[i].PubK_Y)
		}
		//fmt.Println("----------------------IssueKeyGen----------------")
		log.Println("sumIssueKeyGen(us)", sum)
		log.Println("avgIssueKeyGen(us)", sum/int64(m))
		var g2Points [][3][2]*big.Int
		g2Points = append(g2Points, cas[0].PubK_X)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-caKey.txt", DCred.to_Bytes(nil, g2Points, nil), false)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-caKey.txt", DCred.to_Bytes(nil, cas[0].PubK_Y, nil), true)
		start := time.Now().UnixMicro()
		z, err := DCred.TraceKeyGen()
		end := time.Now().UnixMicro()
		log.Println("TraceKeyGen(us)", end-start)
		if err != nil {
			return
		}
		g2Points = nil
		g2Points = append(g2Points, z.PubK)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-traceKey.txt", DCred.to_Bytes(nil, g2Points, nil), false)
		id := []byte("message0")
		start = time.Now().UnixMicro()
		S1, S2, h_1, R, c, a, s, proof_c, proof_s1, proof_s2, proof_b, proof_d, ri, tT := DCred.request(id, z, alpha)
		end = time.Now().UnixMicro()
		log.Println("request(us)", end-start)

		g2Points = nil
		g2Points = append(g2Points, S1, S2, proof_b, proof_d)
		var g1Points [][3]*big.Int
		g1Points = append(g1Points, R)
		var intPoints []*big.Int
		intPoints = append(intPoints, c, s, proof_c, proof_s1, proof_s2)

		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-request.txt", DCred.to_Bytes(g1Points, g2Points, intPoints), false)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-request.txt", DCred.to_Bytes(h_1, nil, nil), true)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-request.txt", DCred.to_Bytes(a, nil, nil), true)

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
			sigmas = append(sigmas, DCred.issue(cas[i], S1, S2, z.PubK, proof_c, proof_s1, proof_s2, proof_b, proof_d, c, a, s, h_1, R, tT))
			end = time.Now().UnixMicro()
			//fmt.Println("issue(us)", end-start)
			sum = sum + end - start
			hh = append(hh, DCred.Vericred(id, R, sigmas[i], alpha, ri, cas[i]))
		}
		//log.Println("----------------------issue----------------")
		log.Println("sumIssue(us)", sum)
		log.Println("AvgIssue(us)", sum/int64(m))

		g1Points = nil
		g1Points = append(g1Points, sigmas[0])
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-issue.txt", DCred.to_Bytes(g1Points, nil, nil), false)
		record := Record{}
		record.R = R
		record.S1 = S1
		record.S2 = S2
		ListL = append(ListL, record)
		start = time.Now().UnixMicro()
		h, Asigg := DCred.CredAggr(id, sigmas, ri)
		end = time.Now().UnixMicro()
		log.Println("CredAggr(us)", end-start)

		g1Points = nil
		g1Points = append(g1Points, h, Asigg)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-credAggr.txt", DCred.to_Bytes(g1Points, nil, nil), false)

		start = time.Now().UnixMicro()
		credC, credD, credF, credC1, credS1, credA, credA2 := DCred.CredShow(h, Asigg, alpha, cas, k)
		//fmt.Println("credential test:", credA2)
		end = time.Now().UnixMicro()
		log.Println("CredShow(us)", end-start)

		g2Points = nil
		g2Points = append(g2Points, credA2[0], credA2[1])
		g1Points = nil
		g1Points = append(g1Points, credC, credD, credF, credA)
		intPoints = nil
		intPoints = append(intPoints, credC1, credS1)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-CredShow.txt", DCred.to_Bytes(g1Points, g2Points, intPoints), false)

		start = time.Now().UnixMicro()
		verified := DCred.credVerify(cas, credC, credD, credF, credC1, credS1, credA, alpha, k, credA2)
		end = time.Now().UnixMicro()
		log.Println("credVerify(us)", end-start)
		//fmt.Println("credential verified:", verified)
		if verified != true {
			return
		}
		start = time.Now().UnixMicro()
		L_R, L_E := DCred.Trace(credC, credD, credF, ListL, z.PrivK, k, n)
		end = time.Now().UnixMicro()
		log.Println("Trace(us)", end-start)

		g2Points = nil
		g2Points = append(g2Points, L_E)
		g1Points = nil
		g1Points = append(g1Points, L_R)
		utils.FileWriteBytes("./Dcred/"+strconv.Itoa(m)+"-Trace.txt", DCred.to_Bytes(g1Points, g2Points, nil), false)

		start = time.Now().UnixMicro()
		judged := DCred.Judge(cas, credC, credD, credF, credC1, credS1, credA, alpha, k, credA2, L_R, L_E)
		end = time.Now().UnixMicro()
		log.Println("Judge(us)", end-start)
		//fmt.Println("judge verified:", judged)
		if judged != true {
			return
		}
	}

}
