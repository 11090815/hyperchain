// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.24.4
// source: configuration.proto

package pbcommon

import (
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

type HashAlgorithm struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 目前仅支持 SHA256。
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *HashAlgorithm) Reset() {
	*x = HashAlgorithm{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HashAlgorithm) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HashAlgorithm) ProtoMessage() {}

func (x *HashAlgorithm) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HashAlgorithm.ProtoReflect.Descriptor instead.
func (*HashAlgorithm) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{0}
}

func (x *HashAlgorithm) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type BlockDataHashStructure struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 宽度指定计算 BlockDataHash 时使用的 Merkle 树的宽度，以便复制平面散列，将此宽度设置为 MAX_UINT32
	Width uint32 `protobuf:"varint,1,opt,name=width,proto3" json:"width,omitempty"`
}

func (x *BlockDataHashStructure) Reset() {
	*x = BlockDataHashStructure{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BlockDataHashStructure) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlockDataHashStructure) ProtoMessage() {}

func (x *BlockDataHashStructure) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlockDataHashStructure.ProtoReflect.Descriptor instead.
func (*BlockDataHashStructure) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{1}
}

func (x *BlockDataHashStructure) GetWidth() uint32 {
	if x != nil {
		return x.Width
	}
	return 0
}

type OrdererAddress struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addresses []string `protobuf:"bytes,1,rep,name=addresses,proto3" json:"addresses,omitempty"`
}

func (x *OrdererAddress) Reset() {
	*x = OrdererAddress{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OrdererAddress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OrdererAddress) ProtoMessage() {}

func (x *OrdererAddress) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OrdererAddress.ProtoReflect.Descriptor instead.
func (*OrdererAddress) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{2}
}

func (x *OrdererAddress) GetAddresses() []string {
	if x != nil {
		return x.Addresses
	}
	return nil
}

// Consenter 代表一个共识节点
type Consenter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id   uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Host string `protobuf:"bytes,2,opt,name=host,proto3" json:"host,omitempty"`
	Port uint32 `protobuf:"varint,3,opt,name=port,proto3" json:"port,omitempty"`
	// MspId msp 的 id。
	MspId string `protobuf:"bytes,4,opt,name=msp_id,json=mspId,proto3" json:"msp_id,omitempty"`
	// Identity x509 证书的 ASN.1 DER PEM 格式的数据。
	Identity      []byte `protobuf:"bytes,5,opt,name=identity,proto3" json:"identity,omitempty"`
	ClientTlsCert []byte `protobuf:"bytes,6,opt,name=client_tls_cert,json=clientTlsCert,proto3" json:"client_tls_cert,omitempty"`
	ServerTlsCert []byte `protobuf:"bytes,7,opt,name=server_tls_cert,json=serverTlsCert,proto3" json:"server_tls_cert,omitempty"`
}

func (x *Consenter) Reset() {
	*x = Consenter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Consenter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Consenter) ProtoMessage() {}

func (x *Consenter) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Consenter.ProtoReflect.Descriptor instead.
func (*Consenter) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{3}
}

func (x *Consenter) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Consenter) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Consenter) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *Consenter) GetMspId() string {
	if x != nil {
		return x.MspId
	}
	return ""
}

func (x *Consenter) GetIdentity() []byte {
	if x != nil {
		return x.Identity
	}
	return nil
}

func (x *Consenter) GetClientTlsCert() []byte {
	if x != nil {
		return x.ClientTlsCert
	}
	return nil
}

func (x *Consenter) GetServerTlsCert() []byte {
	if x != nil {
		return x.ServerTlsCert
	}
	return nil
}

type Orderers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Consenters []*Consenter `protobuf:"bytes,1,rep,name=consenters,proto3" json:"consenters,omitempty"`
}

func (x *Orderers) Reset() {
	*x = Orderers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Orderers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Orderers) ProtoMessage() {}

func (x *Orderers) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Orderers.ProtoReflect.Descriptor instead.
func (*Orderers) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{4}
}

func (x *Orderers) GetConsenters() []*Consenter {
	if x != nil {
		return x.Consenters
	}
	return nil
}

// Consortium 表示创建通道的联盟上下文信息。
type Consortium struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *Consortium) Reset() {
	*x = Consortium{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Consortium) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Consortium) ProtoMessage() {}

func (x *Consortium) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Consortium.ProtoReflect.Descriptor instead.
func (*Consortium) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{5}
}

func (x *Consortium) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// 所具有的能力。
type Capabilities struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Capabilities map[string]*Capability `protobuf:"bytes,1,rep,name=capabilities,proto3" json:"capabilities,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"` // 能力名字 ==> 空结构体。
}

func (x *Capabilities) Reset() {
	*x = Capabilities{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Capabilities) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Capabilities) ProtoMessage() {}

func (x *Capabilities) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Capabilities.ProtoReflect.Descriptor instead.
func (*Capabilities) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{6}
}

func (x *Capabilities) GetCapabilities() map[string]*Capability {
	if x != nil {
		return x.Capabilities
	}
	return nil
}

// 是一个空的结构体。
type Capability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Capability) Reset() {
	*x = Capability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_configuration_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Capability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Capability) ProtoMessage() {}

func (x *Capability) ProtoReflect() protoreflect.Message {
	mi := &file_configuration_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Capability.ProtoReflect.Descriptor instead.
func (*Capability) Descriptor() ([]byte, []int) {
	return file_configuration_proto_rawDescGZIP(), []int{7}
}

var File_configuration_proto protoreflect.FileDescriptor

var file_configuration_proto_rawDesc = []byte{
	0x0a, 0x13, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x22,
	0x23, 0x0a, 0x0d, 0x48, 0x61, 0x73, 0x68, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x22, 0x2e, 0x0a, 0x16, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74,
	0x61, 0x48, 0x61, 0x73, 0x68, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x75, 0x72, 0x65, 0x12, 0x14,
	0x0a, 0x05, 0x77, 0x69, 0x64, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x77,
	0x69, 0x64, 0x74, 0x68, 0x22, 0x2e, 0x0a, 0x0e, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x65, 0x72, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x61, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x65, 0x73, 0x22, 0xc6, 0x01, 0x0a, 0x09, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x74,
	0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x6d, 0x73,
	0x70, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6d, 0x73, 0x70, 0x49,
	0x64, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x08, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x26, 0x0a,
	0x0f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x6c, 0x73, 0x5f, 0x63, 0x65, 0x72, 0x74,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x54, 0x6c,
	0x73, 0x43, 0x65, 0x72, 0x74, 0x12, 0x26, 0x0a, 0x0f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f,
	0x74, 0x6c, 0x73, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x54, 0x6c, 0x73, 0x43, 0x65, 0x72, 0x74, 0x22, 0x3f, 0x0a,
	0x08, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x65, 0x72, 0x73, 0x12, 0x33, 0x0a, 0x0a, 0x63, 0x6f, 0x6e,
	0x73, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e,
	0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x74,
	0x65, 0x72, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x73, 0x22, 0x20,
	0x0a, 0x0a, 0x43, 0x6f, 0x6e, 0x73, 0x6f, 0x72, 0x74, 0x69, 0x75, 0x6d, 0x12, 0x12, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x22, 0xb3, 0x01, 0x0a, 0x0c, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65,
	0x73, 0x12, 0x4c, 0x0a, 0x0c, 0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x2e,
	0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x0c, 0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x1a,
	0x55, 0x0a, 0x11, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2e, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x0c, 0x0a, 0x0a, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69,
	0x6c, 0x69, 0x74, 0x79, 0x42, 0x33, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x31, 0x31, 0x30, 0x39, 0x30, 0x38, 0x31, 0x35, 0x2f, 0x68, 0x79, 0x70, 0x65,
	0x72, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2d, 0x67, 0x6f,
	0x2f, 0x70, 0x62, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_configuration_proto_rawDescOnce sync.Once
	file_configuration_proto_rawDescData = file_configuration_proto_rawDesc
)

func file_configuration_proto_rawDescGZIP() []byte {
	file_configuration_proto_rawDescOnce.Do(func() {
		file_configuration_proto_rawDescData = protoimpl.X.CompressGZIP(file_configuration_proto_rawDescData)
	})
	return file_configuration_proto_rawDescData
}

var file_configuration_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_configuration_proto_goTypes = []interface{}{
	(*HashAlgorithm)(nil),          // 0: pbcommon.HashAlgorithm
	(*BlockDataHashStructure)(nil), // 1: pbcommon.BlockDataHashStructure
	(*OrdererAddress)(nil),         // 2: pbcommon.OrdererAddress
	(*Consenter)(nil),              // 3: pbcommon.Consenter
	(*Orderers)(nil),               // 4: pbcommon.Orderers
	(*Consortium)(nil),             // 5: pbcommon.Consortium
	(*Capabilities)(nil),           // 6: pbcommon.Capabilities
	(*Capability)(nil),             // 7: pbcommon.Capability
	nil,                            // 8: pbcommon.Capabilities.CapabilitiesEntry
}
var file_configuration_proto_depIdxs = []int32{
	3, // 0: pbcommon.Orderers.consenters:type_name -> pbcommon.Consenter
	8, // 1: pbcommon.Capabilities.capabilities:type_name -> pbcommon.Capabilities.CapabilitiesEntry
	7, // 2: pbcommon.Capabilities.CapabilitiesEntry.value:type_name -> pbcommon.Capability
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_configuration_proto_init() }
func file_configuration_proto_init() {
	if File_configuration_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_configuration_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HashAlgorithm); i {
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
		file_configuration_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BlockDataHashStructure); i {
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
		file_configuration_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OrdererAddress); i {
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
		file_configuration_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Consenter); i {
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
		file_configuration_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Orderers); i {
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
		file_configuration_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Consortium); i {
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
		file_configuration_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Capabilities); i {
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
		file_configuration_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Capability); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_configuration_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_configuration_proto_goTypes,
		DependencyIndexes: file_configuration_proto_depIdxs,
		MessageInfos:      file_configuration_proto_msgTypes,
	}.Build()
	File_configuration_proto = out.File
	file_configuration_proto_rawDesc = nil
	file_configuration_proto_goTypes = nil
	file_configuration_proto_depIdxs = nil
}
