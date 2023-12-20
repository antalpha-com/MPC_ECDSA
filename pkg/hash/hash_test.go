package hash

import (
	"crypto/rand"
	"math/big"
	"testing"

	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"

	"MPC_ECDSA/pkg/BigInt"
	"github.com/stretchr/testify/assert"
)

func TestHash_WriteAny(t *testing.T) {
	var err error

	testFunc := func(vs ...interface{}) error {
		h := New()
		for _, v := range vs {
			err = h.WriteAny(v)
			if err != nil {
				return err
			}
		}
		return nil
	}
	b := big.NewInt(35)
	i := new(BigInt.Nat).SetBig(b)
	n := new(BigInt.Nat).SetBig(b)
	m := new(BigInt.Nat).SetBytes(b.Bytes())

	assert.NoError(t, testFunc(i, n, m))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{})))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{}).ActOnBase()))
	assert.NoError(t, testFunc([]byte{1, 4, 6}))
}
