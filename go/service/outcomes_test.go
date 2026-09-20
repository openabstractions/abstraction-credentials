package service

import "testing"

func TestAuthorizationRefusalMappingsRejectUnknownWords(t *testing.T) {
	if storeRefusal("invented") != 0 || rotateRefusal("invented") != 0 || revokeRefusal("invented") != 0 || pageRefusal("invented") != 0 {
		t.Fatal("unknown authorization refusal mapped to a valid wire outcome")
	}
}
