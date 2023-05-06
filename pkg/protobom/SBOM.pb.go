// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.19.6
// source: api/SBOM.proto

package protobom

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Node_NodeType int32

const (
	Node_PACKAGE Node_NodeType = 0
	Node_FILE    Node_NodeType = 1
)

// Enum value maps for Node_NodeType.
var (
	Node_NodeType_name = map[int32]string{
		0: "PACKAGE",
		1: "FILE",
	}
	Node_NodeType_value = map[string]int32{
		"PACKAGE": 0,
		"FILE":    1,
	}
)

func (x Node_NodeType) Enum() *Node_NodeType {
	p := new(Node_NodeType)
	*p = x
	return p
}

func (x Node_NodeType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Node_NodeType) Descriptor() protoreflect.EnumDescriptor {
	return file_api_SBOM_proto_enumTypes[0].Descriptor()
}

func (Node_NodeType) Type() protoreflect.EnumType {
	return &file_api_SBOM_proto_enumTypes[0]
}

func (x Node_NodeType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Node_NodeType.Descriptor instead.
func (Node_NodeType) EnumDescriptor() ([]byte, []int) {
	return file_api_SBOM_proto_rawDescGZIP(), []int{1, 0}
}

type SBOM struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id       string      `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Metadata []*Property `protobuf:"bytes,2,rep,name=metadata,proto3" json:"metadata,omitempty"`
	Nodes    []*Node     `protobuf:"bytes,3,rep,name=nodes,proto3" json:"nodes,omitempty"`
	Graph    []*Edge     `protobuf:"bytes,4,rep,name=graph,proto3" json:"graph,omitempty"`
}

func (x *SBOM) Reset() {
	*x = SBOM{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_SBOM_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SBOM) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SBOM) ProtoMessage() {}

func (x *SBOM) ProtoReflect() protoreflect.Message {
	mi := &file_api_SBOM_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SBOM.ProtoReflect.Descriptor instead.
func (*SBOM) Descriptor() ([]byte, []int) {
	return file_api_SBOM_proto_rawDescGZIP(), []int{0}
}

func (x *SBOM) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *SBOM) GetMetadata() []*Property {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *SBOM) GetNodes() []*Node {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *SBOM) GetGraph() []*Edge {
	if x != nil {
		return x.Graph
	}
	return nil
}

type Node struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id       string        `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Type     Node_NodeType `protobuf:"varint,2,opt,name=type,proto3,enum=puerco.protobom.Node_NodeType" json:"type,omitempty"`
	Metadata []*Property   `protobuf:"bytes,3,rep,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *Node) Reset() {
	*x = Node{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_SBOM_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Node) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Node) ProtoMessage() {}

func (x *Node) ProtoReflect() protoreflect.Message {
	mi := &file_api_SBOM_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Node.ProtoReflect.Descriptor instead.
func (*Node) Descriptor() ([]byte, []int) {
	return file_api_SBOM_proto_rawDescGZIP(), []int{1}
}

func (x *Node) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Node) GetType() Node_NodeType {
	if x != nil {
		return x.Type
	}
	return Node_PACKAGE
}

func (x *Node) GetMetadata() []*Property {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type Property struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name       string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value      string                 `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	Time       *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=time,proto3" json:"time,omitempty"`
	Properties []*Property            `protobuf:"bytes,4,rep,name=properties,proto3" json:"properties,omitempty"`
}

func (x *Property) Reset() {
	*x = Property{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_SBOM_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Property) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Property) ProtoMessage() {}

func (x *Property) ProtoReflect() protoreflect.Message {
	mi := &file_api_SBOM_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Property.ProtoReflect.Descriptor instead.
func (*Property) Descriptor() ([]byte, []int) {
	return file_api_SBOM_proto_rawDescGZIP(), []int{2}
}

func (x *Property) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Property) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Property) GetTime() *timestamppb.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

func (x *Property) GetProperties() []*Property {
	if x != nil {
		return x.Properties
	}
	return nil
}

type Edge struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type       string      `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	From       string      `protobuf:"bytes,2,opt,name=from,proto3" json:"from,omitempty"`
	To         []string    `protobuf:"bytes,3,rep,name=to,proto3" json:"to,omitempty"`
	Properties []*Property `protobuf:"bytes,4,rep,name=properties,proto3" json:"properties,omitempty"`
}

func (x *Edge) Reset() {
	*x = Edge{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_SBOM_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Edge) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Edge) ProtoMessage() {}

func (x *Edge) ProtoReflect() protoreflect.Message {
	mi := &file_api_SBOM_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Edge.ProtoReflect.Descriptor instead.
func (*Edge) Descriptor() ([]byte, []int) {
	return file_api_SBOM_proto_rawDescGZIP(), []int{3}
}

func (x *Edge) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Edge) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *Edge) GetTo() []string {
	if x != nil {
		return x.To
	}
	return nil
}

func (x *Edge) GetProperties() []*Property {
	if x != nil {
		return x.Properties
	}
	return nil
}

var File_api_SBOM_proto protoreflect.FileDescriptor

var file_api_SBOM_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x61, 0x70, 0x69, 0x2f, 0x53, 0x42, 0x4f, 0x4d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0f, 0x70, 0x75, 0x65, 0x72, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x6f,
	0x6d, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa7, 0x01, 0x0a, 0x04, 0x53, 0x42, 0x4f, 0x4d, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x35, 0x0a, 0x08, 0x6d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e,
	0x70, 0x75, 0x65, 0x72, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x6f, 0x6d, 0x2e,
	0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x12, 0x2b, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x15, 0x2e, 0x70, 0x75, 0x65, 0x72, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x6f, 0x6d, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12,
	0x2b, 0x0a, 0x05, 0x67, 0x72, 0x61, 0x70, 0x68, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15,
	0x2e, 0x70, 0x75, 0x65, 0x72, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x6f, 0x6d,
	0x2e, 0x45, 0x64, 0x67, 0x65, 0x52, 0x05, 0x67, 0x72, 0x61, 0x70, 0x68, 0x22, 0xa4, 0x01, 0x0a,
	0x04, 0x4e, 0x6f, 0x64, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x32, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x1e, 0x2e, 0x70, 0x75, 0x65, 0x72, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x6f, 0x6d, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x35, 0x0a, 0x08, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x70, 0x75,
	0x65, 0x72, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x6f, 0x6d, 0x2e, 0x50, 0x72,
	0x6f, 0x70, 0x65, 0x72, 0x74, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x22, 0x21, 0x0a, 0x08, 0x4e, 0x6f, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07,
	0x50, 0x41, 0x43, 0x4b, 0x41, 0x47, 0x45, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x46, 0x49, 0x4c,
	0x45, 0x10, 0x01, 0x22, 0x9f, 0x01, 0x0a, 0x08, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x79,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x2e, 0x0a, 0x04, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x39, 0x0a, 0x0a, 0x70, 0x72,
	0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19,
	0x2e, 0x70, 0x75, 0x65, 0x72, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x6f, 0x6d,
	0x2e, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x79, 0x52, 0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65,
	0x72, 0x74, 0x69, 0x65, 0x73, 0x22, 0x79, 0x0a, 0x04, 0x45, 0x64, 0x67, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x39, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74,
	0x69, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x70, 0x75, 0x65, 0x72,
	0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x6f, 0x6d, 0x2e, 0x50, 0x72, 0x6f, 0x70,
	0x65, 0x72, 0x74, 0x79, 0x52, 0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73,
	0x42, 0x0b, 0x5a, 0x09, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x6f, 0x6d, 0x2f, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_SBOM_proto_rawDescOnce sync.Once
	file_api_SBOM_proto_rawDescData = file_api_SBOM_proto_rawDesc
)

func file_api_SBOM_proto_rawDescGZIP() []byte {
	file_api_SBOM_proto_rawDescOnce.Do(func() {
		file_api_SBOM_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_SBOM_proto_rawDescData)
	})
	return file_api_SBOM_proto_rawDescData
}

var file_api_SBOM_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_SBOM_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_api_SBOM_proto_goTypes = []interface{}{
	(Node_NodeType)(0),            // 0: puerco.protobom.Node.NodeType
	(*SBOM)(nil),                  // 1: puerco.protobom.SBOM
	(*Node)(nil),                  // 2: puerco.protobom.Node
	(*Property)(nil),              // 3: puerco.protobom.Property
	(*Edge)(nil),                  // 4: puerco.protobom.Edge
	(*timestamppb.Timestamp)(nil), // 5: google.protobuf.Timestamp
}
var file_api_SBOM_proto_depIdxs = []int32{
	3, // 0: puerco.protobom.SBOM.metadata:type_name -> puerco.protobom.Property
	2, // 1: puerco.protobom.SBOM.nodes:type_name -> puerco.protobom.Node
	4, // 2: puerco.protobom.SBOM.graph:type_name -> puerco.protobom.Edge
	0, // 3: puerco.protobom.Node.type:type_name -> puerco.protobom.Node.NodeType
	3, // 4: puerco.protobom.Node.metadata:type_name -> puerco.protobom.Property
	5, // 5: puerco.protobom.Property.time:type_name -> google.protobuf.Timestamp
	3, // 6: puerco.protobom.Property.properties:type_name -> puerco.protobom.Property
	3, // 7: puerco.protobom.Edge.properties:type_name -> puerco.protobom.Property
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_api_SBOM_proto_init() }
func file_api_SBOM_proto_init() {
	if File_api_SBOM_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_SBOM_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SBOM); i {
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
		file_api_SBOM_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Node); i {
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
		file_api_SBOM_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Property); i {
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
		file_api_SBOM_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Edge); i {
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
			RawDescriptor: file_api_SBOM_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_SBOM_proto_goTypes,
		DependencyIndexes: file_api_SBOM_proto_depIdxs,
		EnumInfos:         file_api_SBOM_proto_enumTypes,
		MessageInfos:      file_api_SBOM_proto_msgTypes,
	}.Build()
	File_api_SBOM_proto = out.File
	file_api_SBOM_proto_rawDesc = nil
	file_api_SBOM_proto_goTypes = nil
	file_api_SBOM_proto_depIdxs = nil
}