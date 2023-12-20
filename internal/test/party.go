package test

import (
	"MPC_ECDSA/pkg/party"
)

// PartyIDs returns a party.IDSlice (sorted) with IDs represented as simple strings.
func PartyIDs(n int) party.IDSlice {
	baseString := ""
	ids := make(party.IDSlice, n)
	for i := range ids {
		if i%26 == 0 && i > 0 {
			baseString += "a"
		}
		ids[i] = party.ID(baseString + string('a'+rune(i%26)))
	}
	return party.NewIDSlice(ids)
}
func ResharingPartyIDs(n int) party.IDSlice {
	baseString := ""
	ids := make(party.IDSlice, n)
	for i := range ids {
		if i%26 == 0 && i > 0 {
			baseString += "a"
		}
		ids[i] = party.ID(baseString + string('e'+rune(i%26)))
	}
	return party.NewIDSlice(ids)
}
