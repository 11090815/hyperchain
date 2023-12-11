package policies

import (
	"github.com/11090815/hyperchain/common/hlogging"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
)

const (
	PathSeparator = "/"

	ChannelPrefix = "Channel"

	ApplicationPrefix = "Application"

	OrdererPrefix = "Orderer"

	ChannelApplicationReaders = PathSeparator + ChannelPrefix + PathSeparator + ApplicationPrefix + PathSeparator + "Readers"

	BlockValidation = PathSeparator + ChannelPrefix + PathSeparator + OrdererPrefix + PathSeparator + "BlockValidation"
)

var logger = hlogging.MustGetLogger("common.policies")

type PrincipalSet []*pbmsp.MSPPrincipal

type PrincipalSets []PrincipalSet

// ContainingOnly 以 principal 集合为某个超级集合的元素，遍历这个超级集合里的每个 principal 集合，更深入的，
// 继续遍历每个 principal 集合里的每个 principal，然后根据给定的谓词，对每个集合里的 principal 进行检查，如
// 果集合中的所有 principal 都能通过检查，就将该 principal 集合保留下来，放入到一个新实例化的超级集合中，最后
// 将该超级集合返回出来。
func (pss PrincipalSets) ContainingOnly(f func(*pbmsp.MSPPrincipal) bool) PrincipalSets {
	var res PrincipalSets
	for _, set := range pss {
		if !set.ContainingOnly(f) {
			continue
		}
		res = append(res, set)
	}
	return res
}

// ContainingOnly 遍历一遍 principal 集合，根据给定的谓词，对每个 principal 进行检查，如果有一个
// principal 检查不通过，则返回 false，否则返回 true。
func (ps PrincipalSet) ContainingOnly(f func(*pbmsp.MSPPrincipal) bool) bool {
	for _, principal := range ps {
		if !f(principal) {
			return false
		}
	}
	return true
}

// UniqueSet 遍历一遍 principal 集合，实例化一个 map，此 map 的 key 为 principal，value 是 int 类型
// 的数字，principal 集合中可能会存在重复的 principal，统计每个不一样的 principal 的个数，然后将统计出
// 来的个数填充到实例化出来的 map 里。
func (ps PrincipalSet) UniqueSet() map[*pbmsp.MSPPrincipal]int {
	type principal struct {
		cls int32
		p   string
	}
	histogram := make(map[principal]int)
	for _, p := range ps {
		key := principal{cls: int32(p.PrincipalClassification), p: string(p.Principal)}
		histogram[key]++
	}
	res := make(map[*pbmsp.MSPPrincipal]int)
	for principal, count := range histogram {
		res[&pbmsp.MSPPrincipal{PrincipalClassification: pbmsp.MSPPrincipal_Classification(principal.cls), Principal: []byte(principal.p)}] = count
	}

	return res
}
