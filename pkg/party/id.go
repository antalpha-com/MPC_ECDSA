package party

import (
	"errors"
	"io"

	"MPC_ECDSA/pkg/math/curve"

	"MPC_ECDSA/pkg/BigInt"
	"github.com/fxamacker/cbor/v2"
)

// ID party
type ID string

// Scalar 返回ID转化的标量
func (id ID) Scalar(group curve.Curve) curve.Scalar {
	return group.NewScalar().SetNat(new(BigInt.Nat).SetBytes([]byte(id)))
}

// WriteTo makes ID implement the io.WriterTo interface.
// 实现io.WriterTo接口，把ID写入w
func (id ID) WriteTo(w io.Writer) (int64, error) {
	if id == "" {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write([]byte(id))
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (ID) Domain() string {
	return "ID"
}

// PointMap is a map from party ID's to points, to be easy to marshal.
//
// 从ID到曲线上的点的map
type PointMap struct {
	group  curve.Curve
	Points map[ID]curve.Point
}

// NewPointMap creates a PointMap from a map of points.
func NewPointMap(points map[ID]curve.Point) *PointMap {
	var group curve.Curve
	for _, v := range points {
		group = v.Curve()
		break
	}
	return &PointMap{group: group, Points: points}
}

// EmptyPointMap creates an empty PointMap with a fixed group, ready to be unmarshalled.
// 创建空的PointMap，在unmarshall之前调用
func EmptyPointMap(group curve.Curve) *PointMap {
	return &PointMap{group: group}
}

// MarshalBinary 把点Marshal为[]byte
func (m *PointMap) MarshalBinary() ([]byte, error) {
	pointBytes := make(map[ID]cbor.RawMessage, len(m.Points))
	var err error
	for k, v := range m.Points {
		pointBytes[k], err = cbor.Marshal(v)
		if err != nil {
			return nil, err
		}
	}
	return cbor.Marshal(pointBytes)
}

// UnmarshalBinary 从[]byte Unmarshal为Point
func (m *PointMap) UnmarshalBinary(data []byte) error {
	if m.group == nil {
		return errors.New("PointMap.UnmarshalBinary called without setting a group")
	}
	pointBytes := make(map[ID]cbor.RawMessage)
	if err := cbor.Unmarshal(data, &pointBytes); err != nil {
		return err
	}
	m.Points = make(map[ID]curve.Point, len(pointBytes))
	for k, v := range pointBytes {
		point := m.group.NewPoint()
		if err := cbor.Unmarshal(v, point); err != nil {
			return err
		}
		m.Points[k] = point
	}
	return nil
}
