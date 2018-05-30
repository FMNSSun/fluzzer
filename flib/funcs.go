package flib

import "math/rand"
import "reflect"

func RndUint32(v reflect.Value) error {
	v.SetUint(uint64(rand.Uint32()))
	return nil
}

func RndUint64(v reflect.Value) error {
	v.SetUint(uint64(rand.Uint64()))
	return nil
}
