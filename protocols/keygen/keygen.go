//Package keygen implements the key generation phase of ECDSA

package keygen

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/protocol"
	"MPC_ECDSA/protocols/config"
	"crypto/rand"
	log "github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// Rounds represents the number of rounds
const Rounds round.Number = 5

// Start returns a function that starts the key generation protocol session.
// The function takes in the round information, a resource pool, a configuration, and a flag indicating whether to use a mnemonic.
// The returned function is responsible for initializing and returning the appropriate round session based on the provided parameters.
func Start(info round.Info, pl *pool.Pool, c *config.Config, useMnemonic bool) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		var helper *round.Helper
		//Creates a Helper for the session using the round.NewSession function
		if c == nil {
			//If no configuration is provided(c==nil), it means that keys need to be generated
			helper, err = round.NewSession(info, sessionID, pl)
		} else {
			//If a configuration is provided(c!=nil), it means that the keys need to be refreshed
			helper, err = round.NewSession(info, sessionID, pl, c)
		}
		if err != nil {
			log.Errorf("keygen: %v", err)
			return nil, err
		}

		group := helper.Group()
		//Refresh keys with configuration
		if c != nil {
			PublicSharesECDSA := make(map[party.ID]curve.Point, len(c.Public))
			for id, public := range c.Public {
				PublicSharesECDSA[id] = public.ECDSA
			}
			return &round1{
				Helper:                    helper,
				PreviousSecretECDSA:       c.ECDSA,           //secret ECDSA key  F(x_i)
				PreviousPublicSharesECDSA: PublicSharesECDSA, //公钥 私钥乘以基点
				PreviousChainKey:          c.ChainKey,
				VSSSecret:                 polynomial.NewPolynomial(group, helper.Threshold(), group.NewScalar()), // fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
			}, nil
		} else { // Generate keys without configuration
			var VSSConstant curve.Scalar
			if useMnemonic {
				// Generate a 256-bit random value based on the mnemonic
				VSSConstant = generateMnemonic(group)
			} else {
				// Generate a random 256-bit constant value
				VSSConstant = sample.Scalar(rand.Reader, group)
			}
			// Generate a local polynomial f_i(x) with degree t，where the polynomial is the Shamir secret sharing polynomial
			VSSSecret := polynomial.NewPolynomial(group, helper.Threshold(), VSSConstant)
			//Return a pointer to a round1 struct
			return &round1{
				Helper:    helper,    //The Helper field stores the helper object that provides essential functionality and information for the protocol execution.
				VSSSecret: VSSSecret, // The VSSSecret field stores a polynomial object that plays a crucial role in the protocol
			}, nil
		}
	}
}

// generateMnemonic generates a mnemonic phrase, which is used for memorization or user-friendly seeds.
// It follows the BIP-39 standard for mnemonic generation.
func generateMnemonic(group curve.Curve) curve.Scalar {

	// Generate a mnemonic for memorization or user-friendly seeds
	//Generate a random entropy of 256 bits using the bip39.NewEntropy function.
	entropy, _ := bip39.NewEntropy(256)
	//Convert the entropy into a mnemonic phrase using the bip39.NewMnemonic function.
	mnemonic, _ := bip39.NewMnemonic(entropy)

	//Generate a seed from the mnemonic and an empty password using the bip39.NewSeed function.
	seed := bip39.NewSeed(mnemonic, "")
	//Create a master key from the seed using the bip32.NewMasterKey function.
	masterKey, _ := bip32.NewMasterKey(seed)
	//Creates a new BigInt.Nat instance n and sets its value by converting the byte slice masterKey.Key to a BigInt.Nat.
	n := new(BigInt.Nat).SetBytes(masterKey.Key)
	//Convert the master key to a scalar value suitable for the given curve group using the group.NewScalar function.
	//The resulting scalar value, representing the master key, is returned by the function.
	return group.NewScalar().SetNat(n)
}
