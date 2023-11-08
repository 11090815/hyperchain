// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.24.4
// source: amcl.proto

package translator

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

// ECP is an elliptic curve point specified by its coordinates
// ECP corresponds to an element of the first group (G1)
type ECP struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	X []byte `protobuf:"bytes,1,opt,name=x,proto3" json:"x,omitempty"`
	Y []byte `protobuf:"bytes,2,opt,name=y,proto3" json:"y,omitempty"`
}

func (x *ECP) Reset() {
	*x = ECP{}
	if protoimpl.UnsafeEnabled {
		mi := &file_amcl_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECP) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECP) ProtoMessage() {}

func (x *ECP) ProtoReflect() protoreflect.Message {
	mi := &file_amcl_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECP.ProtoReflect.Descriptor instead.
func (*ECP) Descriptor() ([]byte, []int) {
	return file_amcl_proto_rawDescGZIP(), []int{0}
}

func (x *ECP) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *ECP) GetY() []byte {
	if x != nil {
		return x.Y
	}
	return nil
}

// ECP2 is an elliptic curve point specified by its coordinates
// ECP2 corresponds to an element of the second group (G2)
type ECP2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Xa []byte `protobuf:"bytes,1,opt,name=xa,proto3" json:"xa,omitempty"`
	Xb []byte `protobuf:"bytes,2,opt,name=xb,proto3" json:"xb,omitempty"`
	Ya []byte `protobuf:"bytes,3,opt,name=ya,proto3" json:"ya,omitempty"`
	Yb []byte `protobuf:"bytes,4,opt,name=yb,proto3" json:"yb,omitempty"`
}

func (x *ECP2) Reset() {
	*x = ECP2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_amcl_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECP2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECP2) ProtoMessage() {}

func (x *ECP2) ProtoReflect() protoreflect.Message {
	mi := &file_amcl_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECP2.ProtoReflect.Descriptor instead.
func (*ECP2) Descriptor() ([]byte, []int) {
	return file_amcl_proto_rawDescGZIP(), []int{1}
}

func (x *ECP2) GetXa() []byte {
	if x != nil {
		return x.Xa
	}
	return nil
}

func (x *ECP2) GetXb() []byte {
	if x != nil {
		return x.Xb
	}
	return nil
}

func (x *ECP2) GetYa() []byte {
	if x != nil {
		return x.Ya
	}
	return nil
}

func (x *ECP2) GetYb() []byte {
	if x != nil {
		return x.Yb
	}
	return nil
}

var File_amcl_proto protoreflect.FileDescriptor

var file_amcl_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x61, 0x6d, 0x63, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x6c, 0x61, 0x74, 0x6f, 0x72, 0x22, 0x21, 0x0a, 0x03, 0x45, 0x43, 0x50, 0x12,
	0x0c, 0x0a, 0x01, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x78, 0x12, 0x0c, 0x0a,
	0x01, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x79, 0x22, 0x46, 0x0a, 0x04, 0x45,
	0x43, 0x50, 0x32, 0x12, 0x0e, 0x0a, 0x02, 0x78, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x02, 0x78, 0x61, 0x12, 0x0e, 0x0a, 0x02, 0x78, 0x62, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x02, 0x78, 0x62, 0x12, 0x0e, 0x0a, 0x02, 0x79, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x02, 0x79, 0x61, 0x12, 0x0e, 0x0a, 0x02, 0x79, 0x62, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x02, 0x79, 0x62, 0x42, 0x41, 0x5a, 0x3f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x31, 0x31, 0x30, 0x39, 0x30, 0x38, 0x31, 0x35, 0x2f, 0x68, 0x79, 0x70, 0x65, 0x72,
	0x63, 0x68, 0x61, 0x69, 0x6e, 0x2f, 0x69, 0x64, 0x65, 0x6d, 0x69, 0x78, 0x2f, 0x73, 0x63, 0x68,
	0x65, 0x6d, 0x65, 0x73, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x74, 0x72, 0x61, 0x6e,
	0x73, 0x6c, 0x61, 0x74, 0x6f, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_amcl_proto_rawDescOnce sync.Once
	file_amcl_proto_rawDescData = file_amcl_proto_rawDesc
)

func file_amcl_proto_rawDescGZIP() []byte {
	file_amcl_proto_rawDescOnce.Do(func() {
		file_amcl_proto_rawDescData = protoimpl.X.CompressGZIP(file_amcl_proto_rawDescData)
	})
	return file_amcl_proto_rawDescData
}

var file_amcl_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_amcl_proto_goTypes = []interface{}{
	(*ECP)(nil),  // 0: translator.ECP
	(*ECP2)(nil), // 1: translator.ECP2
}
var file_amcl_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_amcl_proto_init() }
func file_amcl_proto_init() {
	if File_amcl_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_amcl_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECP); i {
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
		file_amcl_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECP2); i {
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
			RawDescriptor: file_amcl_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_amcl_proto_goTypes,
		DependencyIndexes: file_amcl_proto_depIdxs,
		MessageInfos:      file_amcl_proto_msgTypes,
	}.Build()
	File_amcl_proto = out.File
	file_amcl_proto_rawDesc = nil
	file_amcl_proto_goTypes = nil
	file_amcl_proto_depIdxs = nil
}