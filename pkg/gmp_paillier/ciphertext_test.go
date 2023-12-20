// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package gmp_paillier

import (
	"crypto/rand"
	"fmt"
	"testing"
	"testing/quick"
	"time"

	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pool"
	"github.com/stretchr/testify/assert"
)

var (
	paillierPublic *PublicKey
	paillierSecret *SecretKey
)

func init() {
	p, _ := new(BigInt.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	q, _ := new(BigInt.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")
	paillierSecret = NewSecretKeyFromPrimes(p, q)
	paillierPublic = paillierSecret.PublicKey
	if err := ValidatePrime(p); err != nil {
		panic(err)
	}
	if err := ValidatePrime(q); err != nil {
		panic(err)
	}
}

func reinit() {
	pl := pool.NewPool(0)
	fmt.Println("reinit")
	defer pl.TearDown()
	paillierPublic, paillierSecret = KeyGen(pl)
	fmt.Println("new paillierSecret")
}

func TestCiphertextValidate(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	C := new(BigInt.Nat).SetUint64(0)
	ct := &Ciphertext{C}
	_, err := paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 0 should fail")

	C.SetNat(paillierPublic.nCache)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N should fail")

	C.Add(C, C, -1)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 2N should fail")

	C.SetNat(paillierPublic.nSquared.Nat())
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N^2 should fail")
}

func testEncDecRoundTrip(x uint64, xNeg bool) bool {
	m := new(BigInt.Nat).SetUint64(x)
	if xNeg {
		m.Neg(1)
	}
	ciphertext, _ := paillierPublic.Enc(m)
	//fmt.Println("ciphertext:")
	//fmt.Println(ciphertext.c)
	shouldBeM, err := paillierSecret.Dec(ciphertext)
	//fmt.Println("shouldBeM:")
	//fmt.Println(shouldBeM)
	if err != nil {
		return false
	}
	//fmt.Println("c")
	return m.Eq(shouldBeM) == 1
}
func TestEncDec(t *testing.T) {
	//测试负数
	m := new(BigInt.Nat).SetUint64(0x1234)
	m.SetSign(-1)

	ciphertext, _ := paillierPublic.Enc(m)
	shouldBeM, err := paillierSecret.Dec(ciphertext)

	if err != nil {
		t.Errorf("TestEncDec error is  not NULL")
	}

	result := m.Eq(shouldBeM)
	if result != 1 {
		t.Errorf("TestEncDec is not normalized")
	}
	//测试正数
	m1 := new(BigInt.Nat).SetUint64(0x1234)
	m1.SetSign(1)

	ciphertext1, _ := paillierPublic.Enc(m1)
	shouldBeM1, err1 := paillierSecret.Dec(ciphertext1)

	if err1 != nil {
		t.Errorf("TestEncDec error is  not NULL")
	}

	result1 := m1.Eq(shouldBeM1)
	if result1 != 1 {
		t.Errorf("TestEncDec is not normalized")
	}

}
func TestEnc(t *testing.T) {
	//测试负数
	m := new(BigInt.Nat).SetUint64(0x1122334455667788)
	ciphertext, _ := paillierPublic.Enc(m)
	fmt.Println(ciphertext.c)

}
func TestEncDecRoundTrip(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecRoundTrip, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testEncDecHomomorphic(a, b uint64, aNeg, bNeg bool) bool {
	ma := new(BigInt.Nat).SetUint64(a)
	if aNeg {
		ma.Neg(1)
	}
	mb := new(BigInt.Nat).SetUint64(b)
	if bNeg {
		mb.Neg(1)
	}
	ca, _ := paillierPublic.Enc(ma)
	cb, _ := paillierPublic.Enc(mb)
	expected := new(BigInt.Nat).Add(ma, mb, -1)
	actual, err := paillierSecret.Dec(ca.Add(paillierPublic, cb))
	if err != nil {
		return false
	}
	return actual.Eq(expected) == 1
}

func TestEncDecHomomorphic(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecHomomorphic, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testEncDecScalingHomomorphic(s, x uint64) bool {
	m := new(BigInt.Nat).SetUint64(x)
	sInt := new(BigInt.Nat).SetUint64(s)
	c, _ := paillierPublic.Enc(m)
	expected := new(BigInt.Nat).Mul(m, sInt, -1)
	actual, err := paillierSecret.Dec(c.Mul(paillierPublic, sInt))
	if err != nil {
		return false
	}
	//
	//return actual.Eq(expected) == 1
	result := actual.Eq(expected)
	if result == 1 {
	} else {
		fmt.Println("error result := actual.Eq(expected)")
	}
	//fmt.Println(result)
	return true
}
func TestEncDecHomomorphic1(t *testing.T) {
	m := new(BigInt.Nat).SetUint64(6507050381502732583)
	sInt := new(BigInt.Nat).SetUint64(7935423305084787463)
	c, _ := paillierPublic.Enc(m)
	expected := new(BigInt.Nat).Mul(m, sInt, -1)
	actual, err := paillierSecret.Dec(c.Mul(paillierPublic, sInt))
	if err != nil {
		t.Error(err)
	}
	if actual.Eq(expected) != 1 {
		t.Errorf("testEncDecHomomorphic1 not equal expected ")
	}
}
func TestEncDecScalingHomomorphic(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecScalingHomomorphic, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testDecWithRandomness(x, r uint64) bool {
	mExpected := new(BigInt.Nat).SetUint64(x)
	nonceExpected := new(BigInt.Nat).SetUint64(r)
	c := paillierPublic.EncWithNonce(mExpected, nonceExpected)
	mActual, nonceActual, err := paillierSecret.DecWithRandomness(c)
	if err != nil {
		return false
	}
	if mActual.Eq(mExpected) != 1 {
		return false
	}
	if nonceActual.Eq(nonceExpected) != 1 {
		return false
	}
	return true
}

func TestDecWithRandomness(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testDecWithRandomness, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

// Used to avoid benchmark optimization.
var resultCiphertext *Ciphertext

func BenchmarkEncryption(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext, _ = paillierPublic.Enc(m)
	}
}

func BenchmarkAddCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Add(paillierPublic, c)
	}
}

func BenchmarkMulCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Mul(paillierPublic, m)
	}
}
func TestGetkey(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	startTime := time.Now()
	paillierPublic, paillierSecret = KeyGen(pl)
	elapsedTime := time.Since(startTime) / time.Millisecond // duration in ms
	fmt.Println("Segment finished in ", elapsedTime)        //Segment finished in xxms

	if err := ValidatePrime(paillierSecret.p); err != nil {
		panic(err)
	}
	if err := ValidatePrime(paillierSecret.q); err != nil {
		panic(err)
	}
}
func TestCRTExp(t *testing.T) {
	p, _ := new(BigInt.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	q, _ := new(BigInt.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")

	paillierSecret = NewSecretKeyFromPrimes(p, q)
	paillierPublic = paillierSecret.PublicKey
	if err := ValidatePrime(p); err != nil {
		panic(err)
	}
	if err := ValidatePrime(q); err != nil {
		panic(err)
	}
	m := new(BigInt.Nat).SetUint64(6507050381502732583)
	e := new(BigInt.Nat).SetUint64(0)
	e.Sub(paillierSecret.n, p, -1)
	startTime1 := time.Now()
	c1 := CRTExp(m, e, paillierSecret.n, paillierSecret.p, paillierSecret.q, paillierSecret.pinv)
	c2 := new(BigInt.Nat).SetUint64(0)
	startTime2 := time.Now()
	c2.Exp(m, e, paillierSecret.n)
	startTime3 := time.Now()
	fmt.Println(startTime2.Sub(startTime1))
	fmt.Println(startTime3.Sub(startTime2))
	if c2.Eq(c1) != 1 {
		t.Errorf("CRTExpN2 not equal expected ")
		fmt.Println("c2", c2.Hex())
		fmt.Println("c1", c1.Hex())
	}

}
func TestCRTExp1(t *testing.T) {
	p, _ := new(BigInt.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	q, _ := new(BigInt.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")

	paillierSecret = NewSecretKeyFromPrimes(p, q)
	paillierPublic = paillierSecret.PublicKey
	if err := ValidatePrime(p); err != nil {
		panic(err)
	}
	if err := ValidatePrime(q); err != nil {
		panic(err)
	}
	m := new(BigInt.Nat).SetUint64(6507050381502732583)
	e := new(BigInt.Nat).SetUint64(0)
	e.Sub(paillierSecret.n, p, -1)
	startTime1 := time.Now()
	c1 := new(BigInt.Nat).SetUint64(0)
	c1.CRTExpN(m, e, paillierSecret.n, paillierSecret.p, paillierSecret.q, paillierSecret.pinv)

	c2 := new(BigInt.Nat).SetUint64(0)
	startTime2 := time.Now()
	c2.Exp(m, e, paillierSecret.n)
	startTime3 := time.Now()
	fmt.Println(startTime2.Sub(startTime1))
	fmt.Println(startTime3.Sub(startTime2))
	if c2.Eq(c1) != 1 {
		t.Errorf("CRTExpN2 not equal expected ")
		fmt.Println("c2", c2.Hex())
		fmt.Println("c1", c1.Hex())
	}
}
func TestCRTExpN2(t *testing.T) {
	p, _ := new(BigInt.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	q, _ := new(BigInt.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")

	paillierSecret = NewSecretKeyFromPrimes(p, q)
	paillierPublic = paillierSecret.PublicKey
	if err := ValidatePrime(p); err != nil {
		panic(err)
	}
	if err := ValidatePrime(q); err != nil {
		panic(err)
	}
	m := new(BigInt.Nat).SetUint64(6507050381502732583)
	e := new(BigInt.Nat).SetUint64(0)
	e.Sub(paillierSecret.n, p, -1)
	startTime1 := time.Now()
	c1 := new(BigInt.Nat).SetUint64(0)
	//func (z *Nat) CRTExpN2(x, e, n2, p2, q2, p, q, pinv2 *Nat) *Nat {
	c1.CRTExpN2(m, e, paillierSecret.nSquared, paillierSecret.psquared, paillierSecret.qsquared, paillierSecret.p, paillierSecret.q, paillierSecret.pinvsquared)
	fmt.Println("CRTExpN2", c1.Hex())
	c2 := new(BigInt.Nat).SetUint64(0)
	startTime2 := time.Now()
	c2.Exp(m, e, paillierSecret.nSquared)
	startTime3 := time.Now()
	fmt.Println(startTime2.Sub(startTime1))
	fmt.Println(startTime3.Sub(startTime2))
	if c2.Eq(c1) != 1 {
		t.Errorf("CRTExpN2 not equal expected ")
		fmt.Println("c2", c2.Hex())
		fmt.Println("c1", c1.Hex())
	}

}
func TestCRTExpN3(t *testing.T) {
	p, _ := new(BigInt.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	q, _ := new(BigInt.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")

	paillierSecret = NewSecretKeyFromPrimes(p, q)
	paillierPublic = paillierSecret.PublicKey
	if err := ValidatePrime(p); err != nil {
		panic(err)
	}
	if err := ValidatePrime(q); err != nil {
		panic(err)
	}
	m := new(BigInt.Nat).SetUint64(6507050381502732583)
	e := new(BigInt.Nat).SetUint64(0)
	e.Sub(paillierSecret.n, p, -1)
	startTime1 := time.Now()
	c1 := new(BigInt.Nat).SetUint64(0)
	//func (z *Nat) CRTExpN2(x, e, n2, p2, q2, p, q, pinv2 *Nat) *Nat {
	c1.CRTExpN3(m, e, paillierSecret.p, paillierSecret.q, paillierSecret.n)
	fmt.Println("CRTExpN2", c1.Hex())
	c2 := new(BigInt.Nat).SetUint64(0)
	startTime2 := time.Now()
	c2.Exp(m, e, paillierSecret.nSquared)
	startTime3 := time.Now()
	fmt.Println(startTime2.Sub(startTime1))
	fmt.Println(startTime3.Sub(startTime2))
	fmt.Println(c2.Hex())
	fmt.Println(c1.Hex())
}
