// Code generated by protoc-gen-go. DO NOT EDIT.
// source: trillian_log_sequencer_api.proto

package trillian

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type SequenceRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SequenceRequest) Reset()         { *m = SequenceRequest{} }
func (m *SequenceRequest) String() string { return proto.CompactTextString(m) }
func (*SequenceRequest) ProtoMessage()    {}
func (*SequenceRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f32c68ea33658ef4, []int{0}
}

func (m *SequenceRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SequenceRequest.Unmarshal(m, b)
}
func (m *SequenceRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SequenceRequest.Marshal(b, m, deterministic)
}
func (m *SequenceRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SequenceRequest.Merge(m, src)
}
func (m *SequenceRequest) XXX_Size() int {
	return xxx_messageInfo_SequenceRequest.Size(m)
}
func (m *SequenceRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SequenceRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SequenceRequest proto.InternalMessageInfo

type SequenceResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SequenceResponse) Reset()         { *m = SequenceResponse{} }
func (m *SequenceResponse) String() string { return proto.CompactTextString(m) }
func (*SequenceResponse) ProtoMessage()    {}
func (*SequenceResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_f32c68ea33658ef4, []int{1}
}

func (m *SequenceResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SequenceResponse.Unmarshal(m, b)
}
func (m *SequenceResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SequenceResponse.Marshal(b, m, deterministic)
}
func (m *SequenceResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SequenceResponse.Merge(m, src)
}
func (m *SequenceResponse) XXX_Size() int {
	return xxx_messageInfo_SequenceResponse.Size(m)
}
func (m *SequenceResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SequenceResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SequenceResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*SequenceRequest)(nil), "trillian.SequenceRequest")
	proto.RegisterType((*SequenceResponse)(nil), "trillian.SequenceResponse")
}

func init() { proto.RegisterFile("trillian_log_sequencer_api.proto", fileDescriptor_f32c68ea33658ef4) }

var fileDescriptor_f32c68ea33658ef4 = []byte{
	// 174 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x28, 0x29, 0xca, 0xcc,
	0xc9, 0xc9, 0x4c, 0xcc, 0x8b, 0xcf, 0xc9, 0x4f, 0x8f, 0x2f, 0x4e, 0x2d, 0x2c, 0x4d, 0xcd, 0x4b,
	0x4e, 0x2d, 0x8a, 0x4f, 0x2c, 0xc8, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x80, 0xa9,
	0x50, 0x12, 0xe4, 0xe2, 0x0f, 0x86, 0x2a, 0x08, 0x02, 0xd1, 0xc5, 0x25, 0x4a, 0x42, 0x5c, 0x02,
	0x08, 0xa1, 0xe2, 0x82, 0xfc, 0xbc, 0xe2, 0x54, 0xa3, 0x10, 0x2e, 0x91, 0x10, 0xa8, 0x16, 0x9f,
	0xfc, 0x74, 0x98, 0x74, 0x91, 0x90, 0x0d, 0x17, 0xb3, 0x5f, 0x7e, 0x81, 0x90, 0xa4, 0x1e, 0xcc,
	0x40, 0x3d, 0x34, 0xd3, 0xa4, 0xa4, 0xb0, 0x49, 0x41, 0x4c, 0x75, 0x0a, 0xe7, 0x92, 0x4c, 0xce,
	0xcf, 0xd5, 0x4b, 0xcf, 0xcf, 0x4f, 0xcf, 0x49, 0x45, 0xa8, 0x03, 0xbb, 0xd1, 0x49, 0x06, 0x9b,
	0x85, 0x8e, 0x05, 0x99, 0x01, 0x20, 0xd9, 0x00, 0xc6, 0x28, 0xa9, 0xf4, 0xcc, 0x92, 0x8c, 0xd2,
	0x24, 0xbd, 0xe4, 0xfc, 0x5c, 0x7d, 0x88, 0x09, 0xfa, 0x30, 0x13, 0x92, 0xd8, 0xc0, 0x46, 0x18,
	0x03, 0x02, 0x00, 0x00, 0xff, 0xff, 0xcd, 0x5f, 0xd0, 0x69, 0x0a, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// TrillianLogSequencerClient is the client API for TrillianLogSequencer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TrillianLogSequencerClient interface {
	Nop(ctx context.Context, in *SequenceRequest, opts ...grpc.CallOption) (*SequenceResponse, error)
}

type trillianLogSequencerClient struct {
	cc *grpc.ClientConn
}

func NewTrillianLogSequencerClient(cc *grpc.ClientConn) TrillianLogSequencerClient {
	return &trillianLogSequencerClient{cc}
}

func (c *trillianLogSequencerClient) Nop(ctx context.Context, in *SequenceRequest, opts ...grpc.CallOption) (*SequenceResponse, error) {
	out := new(SequenceResponse)
	err := c.cc.Invoke(ctx, "/trillian.TrillianLogSequencer/Nop", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TrillianLogSequencerServer is the server API for TrillianLogSequencer service.
type TrillianLogSequencerServer interface {
	Nop(context.Context, *SequenceRequest) (*SequenceResponse, error)
}

// UnimplementedTrillianLogSequencerServer can be embedded to have forward compatible implementations.
type UnimplementedTrillianLogSequencerServer struct {
}

func (*UnimplementedTrillianLogSequencerServer) Nop(ctx context.Context, req *SequenceRequest) (*SequenceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Nop not implemented")
}

func RegisterTrillianLogSequencerServer(s *grpc.Server, srv TrillianLogSequencerServer) {
	s.RegisterService(&_TrillianLogSequencer_serviceDesc, srv)
}

func _TrillianLogSequencer_Nop_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SequenceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrillianLogSequencerServer).Nop(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trillian.TrillianLogSequencer/Nop",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrillianLogSequencerServer).Nop(ctx, req.(*SequenceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _TrillianLogSequencer_serviceDesc = grpc.ServiceDesc{
	ServiceName: "trillian.TrillianLogSequencer",
	HandlerType: (*TrillianLogSequencerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Nop",
			Handler:    _TrillianLogSequencer_Nop_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "trillian_log_sequencer_api.proto",
}
