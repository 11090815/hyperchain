package channelconfig

import pbpeer "github.com/11090815/hyperchain/protos-go/peer"

// aclsProvider 实现了 PolicyMapper 接口
type aclsProvider struct {
	aclPolicyRefs map[string]string
}

func newAPIsProvider(acls map[string]*pbpeer.APIResource) *aclsProvider {
	aclPolicyRefs := make(map[string]string)

	for key, acl := range acls {
		if acl.PolicyRef == "" {
			logger.Warnf("Policy reference for resource \"%s\" is specified, but empty, falling back to default.", key)
			continue
		}

		// 不明白是干什么的？
		if acl.PolicyRef[0] != '/' {
			aclPolicyRefs[key] = "/" + ChannelGroupKey + "/" + ApplicationGroupKey + "/" + acl.PolicyRef
		} else {
			aclPolicyRefs[key] = acl.PolicyRef
		}
	}

	return &aclsProvider{aclPolicyRefs: aclPolicyRefs}
}

func (ap *aclsProvider) PolicyRefForAPI(aclName string) string {
	return ap.aclPolicyRefs[aclName]
}
