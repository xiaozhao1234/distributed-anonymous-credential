# cryptofun [![Go Report Card](https://goreportcard.com/badge/github.com/arnaucube/cryptofun)](https://goreportcard.com/report/github.com/arnaucube/cryptofun) [![Build Status](https://travis-ci.org/arnaucube/cryptofun.svg?branch=master)](https://travis-ci.org/arnaucube/cryptofun)

The distributed anonymous credential scheme

Our scheme is based on the open-source project [https://goreportcard.com/report/github.com/arnaucube/cryptofun]

Implements pairing groups are based on the Barreto-Naehrig curve in python and the BLS-128 curve in golang for implementation, respectively with ubuntu

The Waterbear BFT System project [https://github.com/fififish/waterbear]

Crypto algorithms from scratch. Academic purposes only.

- [Dcred]
- [MCred]
- [Lcred]
- [ECC ElGamal](#ecc-elgamal)
- [Bn128 pairing](#bn128)
- [BLS signature](#bls)

---




## ECC ElGamal
- https://en.wikipedia.org/wiki/ElGamal_encryption

- [x] ECC ElGamal key generation
- [x] ECC ElGamal Encrypton
- [x] ECC ElGamal Decryption


#### Usage
- NewEG, Encryption, Decryption
```go
// define new elliptic curve
ec := ecc.NewEC(big.NewInt(int64(1)), big.NewInt(int64(18)), big.NewInt(int64(19)))

// define new point
g := ecc.Point{big.NewInt(int64(7)), big.NewInt(int64(11))}

// define new ElGamal crypto system with the elliptic curve and the point
eg, err := NewEG(ec, g)
if err!=nil {
	fmt.Println(err)
}

// define privK&pubK over the elliptic curve
privK := big.NewInt(int64(5))
pubK, err := eg.PubK(privK)
if err!=nil {
	fmt.Println(err)
}

// define point to encrypt
m := ecc.Point{big.NewInt(int64(11)), big.NewInt(int64(12))}

// encrypt
c, err := eg.Encrypt(m, pubK, big.NewInt(int64(15)))
if err!=nil {
	fmt.Println(err)
}

// decrypt
d, err := eg.Decrypt(c, privK)
if err!=nil {
	fmt.Println(err)
}

// check that decryption is correct
if !m.Equal(d) {
	fmt.Println("decrypted not equal to original")
}





## Bn128
Implementation of the bn128 pairing.
Code moved to https://github.com/arnaucube/go-snark/tree/master/bn128


## BLS
Boneh–Lynn–Shacham (BLS) signature scheme implemented in Go.
https://en.wikipedia.org/wiki/Boneh%E2%80%93Lynn%E2%80%93Shacham

This package uses the BN128 Go implementation from https://github.com/arnaucube/go-snark/tree/master/bn128

### Usage
```go
bls, err := NewKeys()
assert.Nil(t, err)

fmt.Println("privK:", bls.PrivK)
fmt.Println("pubK:", bls.PubK)

m := []byte("test")
sig := bls.Sign(m)
fmt.Println("signature:", sig)

verified := bls.Verify(m, sig, bls.PubK)
assert.True(t, verified)

/* out:
privK: 28151522174243194157727175362620544050084772361374505986857263387912025505082855947281432752362814690196305655335201716186584298643231993241609823412370437094839017595372164876997343464950463323765646363122343203470911131219733598647659483557447955173651057370197665461325593653581904430885385707255151472097067657072671643359241937143381958053903725229458882818033464163487351806079175441316235756460455300637131488613568714712448336232283394011955460567718918055245116200622473324300828876609569556897836255866438665750954410544846238847540023603735360532628141508114304504053826700874403280496870140784630677100277
pubK: [528167154220154970470523315181365784447502116458960328551053767278433374201 18282159022449399855128689249640771309991127595389457870089153259100566421596 19728585501269572907574045312283749798205079570296187960832716959652451330253]
signature: [[12832528436266902887734423636380781315321578271441494003771296275495461508593 6964131770814642748778827029569297554111206304527781019989920684169107205085] [6508357389516441729339280841134358160957092583050390612877406497974519092306 12073245715182483402311045895787625736998570529454024932833669602347318770866] [13520730275909614846121720877644124261162513989808465368770765804305866618385 19571107788574492009101590535904131414163790958090376021518899789800327786039]]
verified: true
*/
```


---

To run all tests:
```
go test ./... -v
```
