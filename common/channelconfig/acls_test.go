package channelconfig

import (
	"testing"

	pbpeer "github.com/11090815/hyperchain/protos-go/peer"
	"github.com/stretchr/testify/require"
)

const (
	sampleAPI1Name      = "Foo"
	sampleAPI1PolicyRef = "foo"

	sampleAPI2Name      = "Bar"
	sampleAPI2PolicyRef = "/Channel/foo"
)

var sampleAPIsProvider = map[string]*pbpeer.APIResource{
	sampleAPI1Name: {PolicyRef: sampleAPI1PolicyRef},
	sampleAPI2Name: {PolicyRef: sampleAPI2PolicyRef},
}

func TestGreenAPIsPath(t *testing.T) {
	ap := newAPIsProvider(sampleAPIsProvider)
	require.NotNil(t, ap)

	require.Equal(t, "/Channel/Application/" + sampleAPI1PolicyRef, ap.PolicyRefForAPI(sampleAPI1Name))
	require.Equal(t, sampleAPI2PolicyRef, ap.PolicyRefForAPI(sampleAPI2Name))
	require.Empty(t, ap.PolicyRefForAPI("missing"))
}

func TestNilACLs(t *testing.T) {
	ccg := newAPIsProvider(nil)

	require.NotNil(t, ccg)
	require.NotNil(t, ccg.aclPolicyRefs)
	require.Empty(t, ccg.aclPolicyRefs)
}

func TestEmptyACLs(t *testing.T) {
	ccg := newAPIsProvider(map[string]*pbpeer.APIResource{})

	require.NotNil(t, ccg)
	require.NotNil(t, ccg.aclPolicyRefs)
	require.Empty(t, ccg.aclPolicyRefs)
}

func TestEmptyPolicyRef(t *testing.T) {
	ars := map[string]*pbpeer.APIResource{
		"unsetAPI": {PolicyRef: ""},
	}

	ccg := newAPIsProvider(ars)

	require.NotNil(t, ccg)
	require.NotNil(t, ccg.aclPolicyRefs)
	require.Empty(t, ccg.aclPolicyRefs)

	ars = map[string]*pbpeer.APIResource{
		"unsetAPI": {PolicyRef: ""},
		"setAPI":   {PolicyRef: sampleAPI2PolicyRef},
	}

	ccg = newAPIsProvider(ars)

	require.NotNil(t, ccg)
	require.NotNil(t, ccg.aclPolicyRefs)
	require.NotEmpty(t, ccg.aclPolicyRefs)
	require.NotContains(t, ccg.aclPolicyRefs, sampleAPI1Name)
}