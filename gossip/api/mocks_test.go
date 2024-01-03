package api

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMockSecurityAdvisor(t *testing.T) {
	msa := &MockSecurityAdvisor{
		Mock: mock.Mock{},
	}

	expectedPeerIdentity := PeerIdentity("abc")
	unexpectedPeerIdentity := PeerIdentity("def")
	orgIdentity := OrgIdentity("123")

	msa.On("OrgByPeerIdentity", expectedPeerIdentity).Return(orgIdentity)

	fn := func() {
		msa.OrgByPeerIdentity(unexpectedPeerIdentity)
	}

	require.Panics(t, fn)

	res := msa.OrgByPeerIdentity(expectedPeerIdentity)
	require.Equal(t, res, orgIdentity)
}
