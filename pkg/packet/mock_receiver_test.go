// Code generated by MockGen. DO NOT EDIT.
// Source: receiver.go

// Package packet is a generated GoMock package.
package packet

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	gopacket "github.com/google/gopacket"
)

// MockProcessor is a mock of Processor interface.
type MockProcessor struct {
	ctrl     *gomock.Controller
	recorder *MockProcessorMockRecorder
}

// MockProcessorMockRecorder is the mock recorder for MockProcessor.
type MockProcessorMockRecorder struct {
	mock *MockProcessor
}

// NewMockProcessor creates a new mock instance.
func NewMockProcessor(ctrl *gomock.Controller) *MockProcessor {
	mock := &MockProcessor{ctrl: ctrl}
	mock.recorder = &MockProcessorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProcessor) EXPECT() *MockProcessorMockRecorder {
	return m.recorder
}

// ProcessPacketData mocks base method.
func (m *MockProcessor) ProcessPacketData(data []byte, ci *gopacket.CaptureInfo) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProcessPacketData", data, ci)
	ret0, _ := ret[0].(error)
	return ret0
}

// ProcessPacketData indicates an expected call of ProcessPacketData.
func (mr *MockProcessorMockRecorder) ProcessPacketData(data, ci interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProcessPacketData", reflect.TypeOf((*MockProcessor)(nil).ProcessPacketData), data, ci)
}

// MockReader is a mock of Reader interface.
type MockReader struct {
	ctrl     *gomock.Controller
	recorder *MockReaderMockRecorder
}

// MockReaderMockRecorder is the mock recorder for MockReader.
type MockReaderMockRecorder struct {
	mock *MockReader
}

// NewMockReader creates a new mock instance.
func NewMockReader(ctrl *gomock.Controller) *MockReader {
	mock := &MockReader{ctrl: ctrl}
	mock.recorder = &MockReaderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReader) EXPECT() *MockReaderMockRecorder {
	return m.recorder
}

// ReadPacketData mocks base method.
func (m *MockReader) ReadPacketData() ([]byte, *gopacket.CaptureInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadPacketData")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(*gopacket.CaptureInfo)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ReadPacketData indicates an expected call of ReadPacketData.
func (mr *MockReaderMockRecorder) ReadPacketData() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadPacketData", reflect.TypeOf((*MockReader)(nil).ReadPacketData))
}

// MockReceiver is a mock of Receiver interface.
type MockReceiver struct {
	ctrl     *gomock.Controller
	recorder *MockReceiverMockRecorder
}

// MockReceiverMockRecorder is the mock recorder for MockReceiver.
type MockReceiverMockRecorder struct {
	mock *MockReceiver
}

// NewMockReceiver creates a new mock instance.
func NewMockReceiver(ctrl *gomock.Controller) *MockReceiver {
	mock := &MockReceiver{ctrl: ctrl}
	mock.recorder = &MockReceiverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReceiver) EXPECT() *MockReceiverMockRecorder {
	return m.recorder
}

// ReceivePackets mocks base method.
func (m *MockReceiver) ReceivePackets(ctx context.Context) <-chan error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReceivePackets", ctx)
	ret0, _ := ret[0].(<-chan error)
	return ret0
}

// ReceivePackets indicates an expected call of ReceivePackets.
func (mr *MockReceiverMockRecorder) ReceivePackets(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReceivePackets", reflect.TypeOf((*MockReceiver)(nil).ReceivePackets), ctx)
}
