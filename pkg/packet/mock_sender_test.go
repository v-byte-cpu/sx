// Code generated by MockGen. DO NOT EDIT.
// Source: sender.go

// Package packet is a generated GoMock package.
package packet

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockSender is a mock of Sender interface.
type MockSender struct {
	ctrl     *gomock.Controller
	recorder *MockSenderMockRecorder
}

// MockSenderMockRecorder is the mock recorder for MockSender.
type MockSenderMockRecorder struct {
	mock *MockSender
}

// NewMockSender creates a new mock instance.
func NewMockSender(ctrl *gomock.Controller) *MockSender {
	mock := &MockSender{ctrl: ctrl}
	mock.recorder = &MockSenderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSender) EXPECT() *MockSenderMockRecorder {
	return m.recorder
}

// SendPackets mocks base method.
func (m *MockSender) SendPackets(ctx context.Context, in <-chan *BufferData) (<-chan interface{}, <-chan error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendPackets", ctx, in)
	ret0, _ := ret[0].(<-chan interface{})
	ret1, _ := ret[1].(<-chan error)
	return ret0, ret1
}

// SendPackets indicates an expected call of SendPackets.
func (mr *MockSenderMockRecorder) SendPackets(ctx, in interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendPackets", reflect.TypeOf((*MockSender)(nil).SendPackets), ctx, in)
}

// MockWriter is a mock of Writer interface.
type MockWriter struct {
	ctrl     *gomock.Controller
	recorder *MockWriterMockRecorder
}

// MockWriterMockRecorder is the mock recorder for MockWriter.
type MockWriterMockRecorder struct {
	mock *MockWriter
}

// NewMockWriter creates a new mock instance.
func NewMockWriter(ctrl *gomock.Controller) *MockWriter {
	mock := &MockWriter{ctrl: ctrl}
	mock.recorder = &MockWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWriter) EXPECT() *MockWriterMockRecorder {
	return m.recorder
}

// WritePacketData mocks base method.
func (m *MockWriter) WritePacketData(pkt []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WritePacketData", pkt)
	ret0, _ := ret[0].(error)
	return ret0
}

// WritePacketData indicates an expected call of WritePacketData.
func (mr *MockWriterMockRecorder) WritePacketData(pkt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WritePacketData", reflect.TypeOf((*MockWriter)(nil).WritePacketData), pkt)
}
