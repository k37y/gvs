package main

import (
	"fmt"
	"reflect"
)

func useReflection() {
	v := reflect.ValueOf(fmt.Println)
	v.Call([]reflect.Value{reflect.ValueOf("hello")})
}
