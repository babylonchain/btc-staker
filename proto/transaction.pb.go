// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.6.1
// source: transaction.proto

package proto

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

type TransactionState int32

const (
	TransactionState_SENT_TO_BTC                   TransactionState = 0
	TransactionState_CONFIRMED_ON_BTC              TransactionState = 1
	TransactionState_SENT_TO_BABYLON               TransactionState = 2
	TransactionState_UNBONDING_STARTED             TransactionState = 3
	TransactionState_UNBONDING_SIGNATURES_RECEIVED TransactionState = 5
	TransactionState_UNBONDING_CONFIRMED_ON_BTC    TransactionState = 6
	TransactionState_SPENT_ON_BTC                  TransactionState = 7
)

// Enum value maps for TransactionState.
var (
	TransactionState_name = map[int32]string{
		0: "SENT_TO_BTC",
		1: "CONFIRMED_ON_BTC",
		2: "SENT_TO_BABYLON",
		3: "UNBONDING_STARTED",
		5: "UNBONDING_SIGNATURES_RECEIVED",
		6: "UNBONDING_CONFIRMED_ON_BTC",
		7: "SPENT_ON_BTC",
	}
	TransactionState_value = map[string]int32{
		"SENT_TO_BTC":                   0,
		"CONFIRMED_ON_BTC":              1,
		"SENT_TO_BABYLON":               2,
		"UNBONDING_STARTED":             3,
		"UNBONDING_SIGNATURES_RECEIVED": 5,
		"UNBONDING_CONFIRMED_ON_BTC":    6,
		"SPENT_ON_BTC":                  7,
	}
)

func (x TransactionState) Enum() *TransactionState {
	p := new(TransactionState)
	*p = x
	return p
}

func (x TransactionState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TransactionState) Descriptor() protoreflect.EnumDescriptor {
	return file_transaction_proto_enumTypes[0].Descriptor()
}

func (TransactionState) Type() protoreflect.EnumType {
	return &file_transaction_proto_enumTypes[0]
}

func (x TransactionState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use TransactionState.Descriptor instead.
func (TransactionState) EnumDescriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{0}
}

type WatchedTxData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SlashingTransaction    []byte `protobuf:"bytes,1,opt,name=slashing_transaction,json=slashingTransaction,proto3" json:"slashing_transaction,omitempty"`
	SlashingTransactionSig []byte `protobuf:"bytes,2,opt,name=slashing_transaction_sig,json=slashingTransactionSig,proto3" json:"slashing_transaction_sig,omitempty"`
	StakerBabylonPk        []byte `protobuf:"bytes,3,opt,name=staker_babylon_pk,json=stakerBabylonPk,proto3" json:"staker_babylon_pk,omitempty"`
}

func (x *WatchedTxData) Reset() {
	*x = WatchedTxData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transaction_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WatchedTxData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchedTxData) ProtoMessage() {}

func (x *WatchedTxData) ProtoReflect() protoreflect.Message {
	mi := &file_transaction_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchedTxData.ProtoReflect.Descriptor instead.
func (*WatchedTxData) Descriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{0}
}

func (x *WatchedTxData) GetSlashingTransaction() []byte {
	if x != nil {
		return x.SlashingTransaction
	}
	return nil
}

func (x *WatchedTxData) GetSlashingTransactionSig() []byte {
	if x != nil {
		return x.SlashingTransactionSig
	}
	return nil
}

func (x *WatchedTxData) GetStakerBabylonPk() []byte {
	if x != nil {
		return x.StakerBabylonPk
	}
	return nil
}

type UnbondingTxData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UnbondingTransaction             []byte `protobuf:"bytes,1,opt,name=unbonding_transaction,json=unbondingTransaction,proto3" json:"unbonding_transaction,omitempty"`
	UnbondingTransactionScript       []byte `protobuf:"bytes,2,opt,name=unbonding_transaction_script,json=unbondingTransactionScript,proto3" json:"unbonding_transaction_script,omitempty"`
	UnbondingTransactionValidatorSig []byte `protobuf:"bytes,3,opt,name=unbonding_transaction_validator_sig,json=unbondingTransactionValidatorSig,proto3" json:"unbonding_transaction_validator_sig,omitempty"`
	UnbondingTransactionJurySig      []byte `protobuf:"bytes,4,opt,name=unbonding_transaction_jury_sig,json=unbondingTransactionJurySig,proto3" json:"unbonding_transaction_jury_sig,omitempty"`
}

func (x *UnbondingTxData) Reset() {
	*x = UnbondingTxData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transaction_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnbondingTxData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnbondingTxData) ProtoMessage() {}

func (x *UnbondingTxData) ProtoReflect() protoreflect.Message {
	mi := &file_transaction_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnbondingTxData.ProtoReflect.Descriptor instead.
func (*UnbondingTxData) Descriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{1}
}

func (x *UnbondingTxData) GetUnbondingTransaction() []byte {
	if x != nil {
		return x.UnbondingTransaction
	}
	return nil
}

func (x *UnbondingTxData) GetUnbondingTransactionScript() []byte {
	if x != nil {
		return x.UnbondingTransactionScript
	}
	return nil
}

func (x *UnbondingTxData) GetUnbondingTransactionValidatorSig() []byte {
	if x != nil {
		return x.UnbondingTransactionValidatorSig
	}
	return nil
}

func (x *UnbondingTxData) GetUnbondingTransactionJurySig() []byte {
	if x != nil {
		return x.UnbondingTransactionJurySig
	}
	return nil
}

type TrackedTransaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StakingTransaction []byte           `protobuf:"bytes,1,opt,name=staking_transaction,json=stakingTransaction,proto3" json:"staking_transaction,omitempty"`
	StakingScript      []byte           `protobuf:"bytes,2,opt,name=staking_script,json=stakingScript,proto3" json:"staking_script,omitempty"`
	StakingOutputIdx   uint32           `protobuf:"varint,3,opt,name=staking_output_idx,json=stakingOutputIdx,proto3" json:"staking_output_idx,omitempty"`
	StakerAddress      string           `protobuf:"bytes,4,opt,name=staker_address,json=stakerAddress,proto3" json:"staker_address,omitempty"`
	BtcSigType         uint32           `protobuf:"varint,5,opt,name=btc_sig_type,json=btcSigType,proto3" json:"btc_sig_type,omitempty"`
	BabylonSigBtcPk    []byte           `protobuf:"bytes,6,opt,name=babylon_sig_btc_pk,json=babylonSigBtcPk,proto3" json:"babylon_sig_btc_pk,omitempty"`
	BtcSigBabylonSig   []byte           `protobuf:"bytes,7,opt,name=btc_sig_babylon_sig,json=btcSigBabylonSig,proto3" json:"btc_sig_babylon_sig,omitempty"`
	State              TransactionState `protobuf:"varint,8,opt,name=state,proto3,enum=proto.TransactionState" json:"state,omitempty"`
	Watched            bool             `protobuf:"varint,9,opt,name=watched,proto3" json:"watched,omitempty"`
}

func (x *TrackedTransaction) Reset() {
	*x = TrackedTransaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transaction_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TrackedTransaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TrackedTransaction) ProtoMessage() {}

func (x *TrackedTransaction) ProtoReflect() protoreflect.Message {
	mi := &file_transaction_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TrackedTransaction.ProtoReflect.Descriptor instead.
func (*TrackedTransaction) Descriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{2}
}

func (x *TrackedTransaction) GetStakingTransaction() []byte {
	if x != nil {
		return x.StakingTransaction
	}
	return nil
}

func (x *TrackedTransaction) GetStakingScript() []byte {
	if x != nil {
		return x.StakingScript
	}
	return nil
}

func (x *TrackedTransaction) GetStakingOutputIdx() uint32 {
	if x != nil {
		return x.StakingOutputIdx
	}
	return 0
}

func (x *TrackedTransaction) GetStakerAddress() string {
	if x != nil {
		return x.StakerAddress
	}
	return ""
}

func (x *TrackedTransaction) GetBtcSigType() uint32 {
	if x != nil {
		return x.BtcSigType
	}
	return 0
}

func (x *TrackedTransaction) GetBabylonSigBtcPk() []byte {
	if x != nil {
		return x.BabylonSigBtcPk
	}
	return nil
}

func (x *TrackedTransaction) GetBtcSigBabylonSig() []byte {
	if x != nil {
		return x.BtcSigBabylonSig
	}
	return nil
}

func (x *TrackedTransaction) GetState() TransactionState {
	if x != nil {
		return x.State
	}
	return TransactionState_SENT_TO_BTC
}

func (x *TrackedTransaction) GetWatched() bool {
	if x != nil {
		return x.Watched
	}
	return false
}

var File_transaction_proto protoreflect.FileDescriptor

var file_transaction_proto_rawDesc = []byte{
	0x0a, 0x11, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa8, 0x01, 0x0a, 0x0d, 0x57,
	0x61, 0x74, 0x63, 0x68, 0x65, 0x64, 0x54, 0x78, 0x44, 0x61, 0x74, 0x61, 0x12, 0x31, 0x0a, 0x14,
	0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x13, 0x73, 0x6c, 0x61, 0x73,
	0x68, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x38, 0x0a, 0x18, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61, 0x6e,
	0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x16, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x12, 0x2a, 0x0a, 0x11, 0x73, 0x74, 0x61,
	0x6b, 0x65, 0x72, 0x5f, 0x62, 0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x5f, 0x70, 0x6b, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x72, 0x42, 0x61, 0x62, 0x79,
	0x6c, 0x6f, 0x6e, 0x50, 0x6b, 0x22, 0x9c, 0x02, 0x0a, 0x0f, 0x55, 0x6e, 0x62, 0x6f, 0x6e, 0x64,
	0x69, 0x6e, 0x67, 0x54, 0x78, 0x44, 0x61, 0x74, 0x61, 0x12, 0x33, 0x0a, 0x15, 0x75, 0x6e, 0x62,
	0x6f, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x14, 0x75, 0x6e, 0x62, 0x6f, 0x6e, 0x64,
	0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x40,
	0x0a, 0x1c, 0x75, 0x6e, 0x62, 0x6f, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61, 0x6e,
	0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x1a, 0x75, 0x6e, 0x62, 0x6f, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x54,
	0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x12, 0x4d, 0x0a, 0x23, 0x75, 0x6e, 0x62, 0x6f, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x6f, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x20, 0x75,
	0x6e, 0x62, 0x6f, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x53, 0x69, 0x67, 0x12,
	0x43, 0x0a, 0x1e, 0x75, 0x6e, 0x62, 0x6f, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6a, 0x75, 0x72, 0x79, 0x5f, 0x73, 0x69,
	0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1b, 0x75, 0x6e, 0x62, 0x6f, 0x6e, 0x64, 0x69,
	0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4a, 0x75, 0x72,
	0x79, 0x53, 0x69, 0x67, 0x22, 0xec, 0x02, 0x0a, 0x12, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x65, 0x64,
	0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2f, 0x0a, 0x13, 0x73,
	0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e,
	0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x25, 0x0a, 0x0e,
	0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x53, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x12, 0x2c, 0x0a, 0x12, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x6f,
	0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x69, 0x64, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x10, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x49, 0x64,
	0x78, 0x12, 0x25, 0x0a, 0x0e, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x72, 0x5f, 0x61, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x73, 0x74, 0x61, 0x6b, 0x65,
	0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2b, 0x0a, 0x12, 0x62, 0x61, 0x62, 0x79,
	0x6c, 0x6f, 0x6e, 0x5f, 0x73, 0x69, 0x67, 0x5f, 0x62, 0x74, 0x63, 0x5f, 0x70, 0x6b, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x62, 0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x53, 0x69, 0x67,
	0x42, 0x74, 0x63, 0x50, 0x6b, 0x12, 0x33, 0x0a, 0x16, 0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x5f,
	0x73, 0x69, 0x67, 0x5f, 0x62, 0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x5f, 0x73, 0x69, 0x67, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x13, 0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x53, 0x69, 0x67,
	0x42, 0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x12, 0x2d, 0x0a, 0x05, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x77, 0x61, 0x74,
	0x63, 0x68, 0x65, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x77, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x64, 0x2a, 0xba, 0x01, 0x0a, 0x10, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x45, 0x4e, 0x54,
	0x5f, 0x54, 0x4f, 0x5f, 0x42, 0x54, 0x43, 0x10, 0x00, 0x12, 0x14, 0x0a, 0x10, 0x43, 0x4f, 0x4e,
	0x46, 0x49, 0x52, 0x4d, 0x45, 0x44, 0x5f, 0x4f, 0x4e, 0x5f, 0x42, 0x54, 0x43, 0x10, 0x01, 0x12,
	0x13, 0x0a, 0x0f, 0x53, 0x45, 0x4e, 0x54, 0x5f, 0x54, 0x4f, 0x5f, 0x42, 0x41, 0x42, 0x59, 0x4c,
	0x4f, 0x4e, 0x10, 0x02, 0x12, 0x15, 0x0a, 0x11, 0x55, 0x4e, 0x42, 0x4f, 0x4e, 0x44, 0x49, 0x4e,
	0x47, 0x5f, 0x53, 0x54, 0x41, 0x52, 0x54, 0x45, 0x44, 0x10, 0x03, 0x12, 0x21, 0x0a, 0x1d, 0x55,
	0x4e, 0x42, 0x4f, 0x4e, 0x44, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x49, 0x47, 0x4e, 0x41, 0x54, 0x55,
	0x52, 0x45, 0x53, 0x5f, 0x52, 0x45, 0x43, 0x45, 0x49, 0x56, 0x45, 0x44, 0x10, 0x05, 0x12, 0x1e,
	0x0a, 0x1a, 0x55, 0x4e, 0x42, 0x4f, 0x4e, 0x44, 0x49, 0x4e, 0x47, 0x5f, 0x43, 0x4f, 0x4e, 0x46,
	0x49, 0x52, 0x4d, 0x45, 0x44, 0x5f, 0x4f, 0x4e, 0x5f, 0x42, 0x54, 0x43, 0x10, 0x06, 0x12, 0x10,
	0x0a, 0x0c, 0x53, 0x50, 0x45, 0x4e, 0x54, 0x5f, 0x4f, 0x4e, 0x5f, 0x42, 0x54, 0x43, 0x10, 0x07,
	0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62,
	0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2f, 0x62, 0x74, 0x63, 0x2d,
	0x73, 0x74, 0x61, 0x6b, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
	0x6c, 0x6f, 0x6e, 0x50, 0x6b, 0x22, 0x88, 0x03, 0x0a, 0x12, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x65,
	0x64, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2f, 0x0a, 0x13,
	0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x73, 0x74, 0x61, 0x6b, 0x69,
	0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x25, 0x0a,
	0x0e, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x53, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x12, 0x2c, 0x0a, 0x12, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f,
	0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x69, 0x64, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x10, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x49,
	0x64, 0x78, 0x12, 0x25, 0x0a, 0x0e, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x72, 0x5f, 0x61, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x73, 0x74, 0x61, 0x6b,
	0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x20, 0x0a, 0x0c, 0x62, 0x74, 0x63,
	0x5f, 0x73, 0x69, 0x67, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0a, 0x62, 0x74, 0x63, 0x53, 0x69, 0x67, 0x54, 0x79, 0x70, 0x65, 0x12, 0x2b, 0x0a, 0x12, 0x62,
	0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x5f, 0x73, 0x69, 0x67, 0x5f, 0x62, 0x74, 0x63, 0x5f, 0x70,
	0x6b, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x62, 0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e,
	0x53, 0x69, 0x67, 0x42, 0x74, 0x63, 0x50, 0x6b, 0x12, 0x2d, 0x0a, 0x13, 0x62, 0x74, 0x63, 0x5f,
	0x73, 0x69, 0x67, 0x5f, 0x62, 0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x5f, 0x73, 0x69, 0x67, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x62, 0x74, 0x63, 0x53, 0x69, 0x67, 0x42, 0x61, 0x62,
	0x79, 0x6c, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x12, 0x2d, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54,
	0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52,
	0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x77, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x77, 0x61, 0x74, 0x63, 0x68, 0x65, 0x64,
	0x2a, 0x9a, 0x01, 0x0a, 0x10, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x45, 0x4e,
	0x54, 0x5f, 0x54, 0x4f, 0x5f, 0x42, 0x54, 0x43, 0x10, 0x00, 0x12, 0x14, 0x0a, 0x10, 0x43, 0x4f,
	0x4e, 0x46, 0x49, 0x52, 0x4d, 0x45, 0x44, 0x5f, 0x4f, 0x4e, 0x5f, 0x42, 0x54, 0x43, 0x10, 0x01,
	0x12, 0x13, 0x0a, 0x0f, 0x53, 0x45, 0x4e, 0x54, 0x5f, 0x54, 0x4f, 0x5f, 0x42, 0x41, 0x42, 0x59,
	0x4c, 0x4f, 0x4e, 0x10, 0x02, 0x12, 0x15, 0x0a, 0x11, 0x55, 0x4e, 0x42, 0x4f, 0x4e, 0x44, 0x49,
	0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x52, 0x54, 0x45, 0x44, 0x10, 0x03, 0x12, 0x21, 0x0a, 0x1d,
	0x55, 0x4e, 0x42, 0x4f, 0x4e, 0x44, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x49, 0x47, 0x4e, 0x41, 0x54,
	0x55, 0x52, 0x45, 0x53, 0x5f, 0x52, 0x45, 0x43, 0x45, 0x49, 0x56, 0x45, 0x44, 0x10, 0x05, 0x12,
	0x10, 0x0a, 0x0c, 0x53, 0x50, 0x45, 0x4e, 0x54, 0x5f, 0x4f, 0x4e, 0x5f, 0x42, 0x54, 0x43, 0x10,
	0x06, 0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x62, 0x61, 0x62, 0x79, 0x6c, 0x6f, 0x6e, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2f, 0x62, 0x74, 0x63,
	0x2d, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transaction_proto_rawDescOnce sync.Once
	file_transaction_proto_rawDescData = file_transaction_proto_rawDesc
)

func file_transaction_proto_rawDescGZIP() []byte {
	file_transaction_proto_rawDescOnce.Do(func() {
		file_transaction_proto_rawDescData = protoimpl.X.CompressGZIP(file_transaction_proto_rawDescData)
	})
	return file_transaction_proto_rawDescData
}

var file_transaction_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_transaction_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_transaction_proto_goTypes = []interface{}{
	(TransactionState)(0),      // 0: proto.TransactionState
	(*WatchedTxData)(nil),      // 1: proto.WatchedTxData
	(*UnbondingTxData)(nil),    // 2: proto.UnbondingTxData
	(*TrackedTransaction)(nil), // 3: proto.TrackedTransaction
}
var file_transaction_proto_depIdxs = []int32{
	0, // 0: proto.TrackedTransaction.state:type_name -> proto.TransactionState
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_transaction_proto_init() }
func file_transaction_proto_init() {
	if File_transaction_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transaction_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WatchedTxData); i {
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
		file_transaction_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UnbondingTxData); i {
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
		file_transaction_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TrackedTransaction); i {
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
			RawDescriptor: file_transaction_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transaction_proto_goTypes,
		DependencyIndexes: file_transaction_proto_depIdxs,
		EnumInfos:         file_transaction_proto_enumTypes,
		MessageInfos:      file_transaction_proto_msgTypes,
	}.Build()
	File_transaction_proto = out.File
	file_transaction_proto_rawDesc = nil
	file_transaction_proto_goTypes = nil
	file_transaction_proto_depIdxs = nil
}
