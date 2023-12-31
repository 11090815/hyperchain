// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.24.4
// source: policies.proto

package pbcommon

import (
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Policy_PolicyType int32

const (
	Policy_UNKNOWN       Policy_PolicyType = 0
	Policy_SIGNATURE     Policy_PolicyType = 1
	Policy_MSP           Policy_PolicyType = 2
	Policy_IMPLICIT_META Policy_PolicyType = 3
)

// Enum value maps for Policy_PolicyType.
var (
	Policy_PolicyType_name = map[int32]string{
		0: "UNKNOWN",
		1: "SIGNATURE",
		2: "MSP",
		3: "IMPLICIT_META",
	}
	Policy_PolicyType_value = map[string]int32{
		"UNKNOWN":       0,
		"SIGNATURE":     1,
		"MSP":           2,
		"IMPLICIT_META": 3,
	}
)

func (x Policy_PolicyType) Enum() *Policy_PolicyType {
	p := new(Policy_PolicyType)
	*p = x
	return p
}

func (x Policy_PolicyType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Policy_PolicyType) Descriptor() protoreflect.EnumDescriptor {
	return file_policies_proto_enumTypes[0].Descriptor()
}

func (Policy_PolicyType) Type() protoreflect.EnumType {
	return &file_policies_proto_enumTypes[0]
}

func (x Policy_PolicyType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Policy_PolicyType.Descriptor instead.
func (Policy_PolicyType) EnumDescriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{0, 0}
}

type ImplicitMetaPolicy_Rule int32

const (
	ImplicitMetaPolicy_ANY      ImplicitMetaPolicy_Rule = 0 // 要求满足任意子策略，如果不存在子策略，则总是返回 true
	ImplicitMetaPolicy_ALL      ImplicitMetaPolicy_Rule = 1 // 要求满足所有子政策的要求
	ImplicitMetaPolicy_MAJORITY ImplicitMetaPolicy_Rule = 2 // 要求满足绝大多数（超过半数）次级政策的要求
)

// Enum value maps for ImplicitMetaPolicy_Rule.
var (
	ImplicitMetaPolicy_Rule_name = map[int32]string{
		0: "ANY",
		1: "ALL",
		2: "MAJORITY",
	}
	ImplicitMetaPolicy_Rule_value = map[string]int32{
		"ANY":      0,
		"ALL":      1,
		"MAJORITY": 2,
	}
)

func (x ImplicitMetaPolicy_Rule) Enum() *ImplicitMetaPolicy_Rule {
	p := new(ImplicitMetaPolicy_Rule)
	*p = x
	return p
}

func (x ImplicitMetaPolicy_Rule) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ImplicitMetaPolicy_Rule) Descriptor() protoreflect.EnumDescriptor {
	return file_policies_proto_enumTypes[1].Descriptor()
}

func (ImplicitMetaPolicy_Rule) Type() protoreflect.EnumType {
	return &file_policies_proto_enumTypes[1]
}

func (x ImplicitMetaPolicy_Rule) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ImplicitMetaPolicy_Rule.Descriptor instead.
func (ImplicitMetaPolicy_Rule) EnumDescriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{3, 0}
}

// Policy 表达了一个 orderer 可以评估的策略。
type Policy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type  int32  `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Policy) Reset() {
	*x = Policy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policies_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Policy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Policy) ProtoMessage() {}

func (x *Policy) ProtoReflect() protoreflect.Message {
	mi := &file_policies_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Policy.ProtoReflect.Descriptor instead.
func (*Policy) Descriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{0}
}

func (x *Policy) GetType() int32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *Policy) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

// SignaturePolicyEnvelope 封装了签名策略，并包含一个版本以备未来增强之用。
type SignaturePolicyEnvelope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version    int32                 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Rule       *SignaturePolicy      `protobuf:"bytes,2,opt,name=rule,proto3" json:"rule,omitempty"`
	Identities []*pbmsp.MSPPrincipal `protobuf:"bytes,3,rep,name=identities,proto3" json:"identities,omitempty"`
}

func (x *SignaturePolicyEnvelope) Reset() {
	*x = SignaturePolicyEnvelope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policies_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignaturePolicyEnvelope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignaturePolicyEnvelope) ProtoMessage() {}

func (x *SignaturePolicyEnvelope) ProtoReflect() protoreflect.Message {
	mi := &file_policies_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignaturePolicyEnvelope.ProtoReflect.Descriptor instead.
func (*SignaturePolicyEnvelope) Descriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{1}
}

func (x *SignaturePolicyEnvelope) GetVersion() int32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *SignaturePolicyEnvelope) GetRule() *SignaturePolicy {
	if x != nil {
		return x.Rule
	}
	return nil
}

func (x *SignaturePolicyEnvelope) GetIdentities() []*pbmsp.MSPPrincipal {
	if x != nil {
		return x.Identities
	}
	return nil
}

// SignaturePolicy 是一个递归消息结构，它定义了一个轻量级 DSL，用于描述比 "exactly this signature" 更复杂的策略。
// NOutOf 运算符足以表达 AND 和 OR，当然也可以表达 N 个以下 M 个策略中的 N 个。SignedBy 表示签名来自有效证书，该
// 证书由字节中指定的可信机构签署。 如果是自签证书，则是证书本身，如果是传统证书，则是 CA。
type SignaturePolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Type:
	//
	//	*SignaturePolicy_SignedBy
	//	*SignaturePolicy_NOutOf_
	Type isSignaturePolicy_Type `protobuf_oneof:"Type"`
}

func (x *SignaturePolicy) Reset() {
	*x = SignaturePolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policies_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignaturePolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignaturePolicy) ProtoMessage() {}

func (x *SignaturePolicy) ProtoReflect() protoreflect.Message {
	mi := &file_policies_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignaturePolicy.ProtoReflect.Descriptor instead.
func (*SignaturePolicy) Descriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{2}
}

func (m *SignaturePolicy) GetType() isSignaturePolicy_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (x *SignaturePolicy) GetSignedBy() int32 {
	if x, ok := x.GetType().(*SignaturePolicy_SignedBy); ok {
		return x.SignedBy
	}
	return 0
}

func (x *SignaturePolicy) GetNOutOf() *SignaturePolicy_NOutOf {
	if x, ok := x.GetType().(*SignaturePolicy_NOutOf_); ok {
		return x.NOutOf
	}
	return nil
}

type isSignaturePolicy_Type interface {
	isSignaturePolicy_Type()
}

type SignaturePolicy_SignedBy struct {
	SignedBy int32 `protobuf:"varint,1,opt,name=signed_by,json=signedBy,proto3,oneof"`
}

type SignaturePolicy_NOutOf_ struct {
	NOutOf *SignaturePolicy_NOutOf `protobuf:"bytes,2,opt,name=n_out_of,json=nOutOf,proto3,oneof"`
}

func (*SignaturePolicy_SignedBy) isSignaturePolicy_Type() {}

func (*SignaturePolicy_NOutOf_) isSignaturePolicy_Type() {}

// ImplicitMetaPolicy 是一种取决于配置层次性质的策略类型。它是隐式的，因为规则是根据子策略的数
// 量隐式生成的。说它是元策略，是因为它只取决于其他策略的结果。评估时，该策略会遍历所有直接子分组，
// 检索名称为 sub_policy 的策略，评估集合并应用该规则。例如，有 4 个子组，策略名称为 "foo"，
// ImplicitMetaPolicy 会检索每个子组，检索每个子组的策略 "foo"，对其进行评估，在 ANY 的情况下，
// 满足 1 个签名即可，ALL 需要 4 个签名，MAJORITY 需要 3 个签名。
type ImplicitMetaPolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SubPolicy string                  `protobuf:"bytes,1,opt,name=sub_policy,json=subPolicy,proto3" json:"sub_policy,omitempty"`
	Rule      ImplicitMetaPolicy_Rule `protobuf:"varint,2,opt,name=rule,proto3,enum=pbcommon.ImplicitMetaPolicy_Rule" json:"rule,omitempty"`
}

func (x *ImplicitMetaPolicy) Reset() {
	*x = ImplicitMetaPolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policies_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImplicitMetaPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImplicitMetaPolicy) ProtoMessage() {}

func (x *ImplicitMetaPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_policies_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImplicitMetaPolicy.ProtoReflect.Descriptor instead.
func (*ImplicitMetaPolicy) Descriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{3}
}

func (x *ImplicitMetaPolicy) GetSubPolicy() string {
	if x != nil {
		return x.SubPolicy
	}
	return ""
}

func (x *ImplicitMetaPolicy) GetRule() ImplicitMetaPolicy_Rule {
	if x != nil {
		return x.Rule
	}
	return ImplicitMetaPolicy_ANY
}

// ApplicationPolicy 捕获了在应用程序级别设置和评估的不同策略类型。
type ApplicationPolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Type:
	//
	//	*ApplicationPolicy_SignaturePolicyEnvelope
	//	*ApplicationPolicy_ChannelConfigPolicyReference
	Type isApplicationPolicy_Type `protobuf_oneof:"Type"`
}

func (x *ApplicationPolicy) Reset() {
	*x = ApplicationPolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policies_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ApplicationPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApplicationPolicy) ProtoMessage() {}

func (x *ApplicationPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_policies_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApplicationPolicy.ProtoReflect.Descriptor instead.
func (*ApplicationPolicy) Descriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{4}
}

func (m *ApplicationPolicy) GetType() isApplicationPolicy_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (x *ApplicationPolicy) GetSignaturePolicyEnvelope() *SignaturePolicyEnvelope {
	if x, ok := x.GetType().(*ApplicationPolicy_SignaturePolicyEnvelope); ok {
		return x.SignaturePolicyEnvelope
	}
	return nil
}

func (x *ApplicationPolicy) GetChannelConfigPolicyReference() string {
	if x, ok := x.GetType().(*ApplicationPolicy_ChannelConfigPolicyReference); ok {
		return x.ChannelConfigPolicyReference
	}
	return ""
}

type isApplicationPolicy_Type interface {
	isApplicationPolicy_Type()
}

type ApplicationPolicy_SignaturePolicyEnvelope struct {
	// 如果指定策略为 MSP principals 签名的组合（使用阈值门），则使用 SignaturePolicyEnvelope 类型。
	SignaturePolicyEnvelope *SignaturePolicyEnvelope `protobuf:"bytes,1,opt,name=signature_policy_envelope,json=signaturePolicyEnvelope,proto3,oneof"`
}

type ApplicationPolicy_ChannelConfigPolicyReference struct {
	// ChannelConfigPolicyReference 用于将策略指定为引用通道配置中定义的策略的字符串。
	ChannelConfigPolicyReference string `protobuf:"bytes,2,opt,name=channel_config_policy_reference,json=channelConfigPolicyReference,proto3,oneof"`
}

func (*ApplicationPolicy_SignaturePolicyEnvelope) isApplicationPolicy_Type() {}

func (*ApplicationPolicy_ChannelConfigPolicyReference) isApplicationPolicy_Type() {}

type SignaturePolicy_NOutOf struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	N     int32              `protobuf:"varint,1,opt,name=n,proto3" json:"n,omitempty"`
	Rules []*SignaturePolicy `protobuf:"bytes,2,rep,name=rules,proto3" json:"rules,omitempty"`
}

func (x *SignaturePolicy_NOutOf) Reset() {
	*x = SignaturePolicy_NOutOf{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policies_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignaturePolicy_NOutOf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignaturePolicy_NOutOf) ProtoMessage() {}

func (x *SignaturePolicy_NOutOf) ProtoReflect() protoreflect.Message {
	mi := &file_policies_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignaturePolicy_NOutOf.ProtoReflect.Descriptor instead.
func (*SignaturePolicy_NOutOf) Descriptor() ([]byte, []int) {
	return file_policies_proto_rawDescGZIP(), []int{2, 0}
}

func (x *SignaturePolicy_NOutOf) GetN() int32 {
	if x != nil {
		return x.N
	}
	return 0
}

func (x *SignaturePolicy_NOutOf) GetRules() []*SignaturePolicy {
	if x != nil {
		return x.Rules
	}
	return nil
}

var File_policies_proto protoreflect.FileDescriptor

var file_policies_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x08, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x1a, 0x40, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x31, 0x31, 0x30, 0x39, 0x30, 0x38, 0x31, 0x35, 0x2f,
	0x68, 0x79, 0x70, 0x65, 0x72, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x73, 0x2d, 0x67, 0x6f, 0x2f, 0x6d, 0x73, 0x70, 0x2f, 0x6d, 0x73, 0x70, 0x5f, 0x70, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x78, 0x0a, 0x06,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x22, 0x44, 0x0a, 0x0a, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b,
	0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x53,
	0x49, 0x47, 0x4e, 0x41, 0x54, 0x55, 0x52, 0x45, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x4d, 0x53,
	0x50, 0x10, 0x02, 0x12, 0x11, 0x0a, 0x0d, 0x49, 0x4d, 0x50, 0x4c, 0x49, 0x43, 0x49, 0x54, 0x5f,
	0x4d, 0x45, 0x54, 0x41, 0x10, 0x03, 0x22, 0x97, 0x01, 0x0a, 0x17, 0x53, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f,
	0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x2d, 0x0a, 0x04,
	0x72, 0x75, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x70, 0x62, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x04, 0x72, 0x75, 0x6c, 0x65, 0x12, 0x33, 0x0a, 0x0a, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x13, 0x2e, 0x70, 0x62, 0x6d, 0x73, 0x70, 0x2e, 0x4d, 0x53, 0x50, 0x50, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x52, 0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73,
	0x22, 0xbf, 0x01, 0x0a, 0x0f, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x12, 0x1d, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x62,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x48, 0x00, 0x52, 0x08, 0x73, 0x69, 0x67, 0x6e, 0x65,
	0x64, 0x42, 0x79, 0x12, 0x3c, 0x0a, 0x08, 0x6e, 0x5f, 0x6f, 0x75, 0x74, 0x5f, 0x6f, 0x66, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79,
	0x2e, 0x4e, 0x4f, 0x75, 0x74, 0x4f, 0x66, 0x48, 0x00, 0x52, 0x06, 0x6e, 0x4f, 0x75, 0x74, 0x4f,
	0x66, 0x1a, 0x47, 0x0a, 0x06, 0x4e, 0x4f, 0x75, 0x74, 0x4f, 0x66, 0x12, 0x0c, 0x0a, 0x01, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x01, 0x6e, 0x12, 0x2f, 0x0a, 0x05, 0x72, 0x75, 0x6c,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x70, 0x62, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x50, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x52, 0x05, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x42, 0x06, 0x0a, 0x04, 0x54, 0x79,
	0x70, 0x65, 0x22, 0x92, 0x01, 0x0a, 0x12, 0x49, 0x6d, 0x70, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x4d,
	0x65, 0x74, 0x61, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x75, 0x62,
	0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x73,
	0x75, 0x62, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x35, 0x0a, 0x04, 0x72, 0x75, 0x6c, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x21, 0x2e, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x49, 0x6d, 0x70, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x2e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x04, 0x72, 0x75, 0x6c, 0x65, 0x22,
	0x26, 0x0a, 0x04, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x07, 0x0a, 0x03, 0x41, 0x4e, 0x59, 0x10, 0x00,
	0x12, 0x07, 0x0a, 0x03, 0x41, 0x4c, 0x4c, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08, 0x4d, 0x41, 0x4a,
	0x4f, 0x52, 0x49, 0x54, 0x59, 0x10, 0x02, 0x22, 0xc5, 0x01, 0x0a, 0x11, 0x41, 0x70, 0x70, 0x6c,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x5f, 0x0a,
	0x19, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x5f, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x21, 0x2e, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x45, 0x6e, 0x76, 0x65, 0x6c,
	0x6f, 0x70, 0x65, 0x48, 0x00, 0x52, 0x17, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12, 0x47,
	0x0a, 0x1f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x1c, 0x63, 0x68, 0x61, 0x6e, 0x6e,
	0x65, 0x6c, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65,
	0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x42, 0x06, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x42,
	0x33, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x31, 0x31,
	0x30, 0x39, 0x30, 0x38, 0x31, 0x35, 0x2f, 0x68, 0x79, 0x70, 0x65, 0x72, 0x63, 0x68, 0x61, 0x69,
	0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2d, 0x67, 0x6f, 0x2f, 0x70, 0x62, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_policies_proto_rawDescOnce sync.Once
	file_policies_proto_rawDescData = file_policies_proto_rawDesc
)

func file_policies_proto_rawDescGZIP() []byte {
	file_policies_proto_rawDescOnce.Do(func() {
		file_policies_proto_rawDescData = protoimpl.X.CompressGZIP(file_policies_proto_rawDescData)
	})
	return file_policies_proto_rawDescData
}

var file_policies_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_policies_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_policies_proto_goTypes = []interface{}{
	(Policy_PolicyType)(0),          // 0: pbcommon.Policy.PolicyType
	(ImplicitMetaPolicy_Rule)(0),    // 1: pbcommon.ImplicitMetaPolicy.Rule
	(*Policy)(nil),                  // 2: pbcommon.Policy
	(*SignaturePolicyEnvelope)(nil), // 3: pbcommon.SignaturePolicyEnvelope
	(*SignaturePolicy)(nil),         // 4: pbcommon.SignaturePolicy
	(*ImplicitMetaPolicy)(nil),      // 5: pbcommon.ImplicitMetaPolicy
	(*ApplicationPolicy)(nil),       // 6: pbcommon.ApplicationPolicy
	(*SignaturePolicy_NOutOf)(nil),  // 7: pbcommon.SignaturePolicy.NOutOf
	(*pbmsp.MSPPrincipal)(nil),      // 8: pbmsp.MSPPrincipal
}
var file_policies_proto_depIdxs = []int32{
	4, // 0: pbcommon.SignaturePolicyEnvelope.rule:type_name -> pbcommon.SignaturePolicy
	8, // 1: pbcommon.SignaturePolicyEnvelope.identities:type_name -> pbmsp.MSPPrincipal
	7, // 2: pbcommon.SignaturePolicy.n_out_of:type_name -> pbcommon.SignaturePolicy.NOutOf
	1, // 3: pbcommon.ImplicitMetaPolicy.rule:type_name -> pbcommon.ImplicitMetaPolicy.Rule
	3, // 4: pbcommon.ApplicationPolicy.signature_policy_envelope:type_name -> pbcommon.SignaturePolicyEnvelope
	4, // 5: pbcommon.SignaturePolicy.NOutOf.rules:type_name -> pbcommon.SignaturePolicy
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_policies_proto_init() }
func file_policies_proto_init() {
	if File_policies_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_policies_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Policy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_policies_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignaturePolicyEnvelope); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_policies_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignaturePolicy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_policies_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImplicitMetaPolicy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_policies_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ApplicationPolicy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_policies_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignaturePolicy_NOutOf); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_policies_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*SignaturePolicy_SignedBy)(nil),
		(*SignaturePolicy_NOutOf_)(nil),
	}
	file_policies_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*ApplicationPolicy_SignaturePolicyEnvelope)(nil),
		(*ApplicationPolicy_ChannelConfigPolicyReference)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_policies_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_policies_proto_goTypes,
		DependencyIndexes: file_policies_proto_depIdxs,
		EnumInfos:         file_policies_proto_enumTypes,
		MessageInfos:      file_policies_proto_msgTypes,
	}.Build()
	File_policies_proto = out.File
	file_policies_proto_rawDesc = nil
	file_policies_proto_goTypes = nil
	file_policies_proto_depIdxs = nil
}
