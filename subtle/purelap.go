//go:build purego

package subtle

import "reflect"

func AnyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		reflect.ValueOf(&x[0]).Pointer() <= reflect.ValueOf(&y[len(y)-1]).Pointer() &&
		reflect.ValueOf(&y[0]).Pointer() <= reflect.ValueOf(&x[len(x)-1]).Pointer()
}

func InexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return AnyOverlap(x, y)
}
