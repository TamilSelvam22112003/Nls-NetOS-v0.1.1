package dataplane

import "fmt"
func InnerMTU(pathMTU int)(int,error) {
	if pathMTU<=OuterOverhead{return 0,fmt.Errorf("path MTU %d too small",pathMTU)}
	mtu:=pathMTU-OuterOverhead
	if mtu<1280{return 0,fmt.Errorf("path MTU %d cannot carry minimum IPv6 inner MTU",pathMTU)}
	if mtu>DefaultInnerMTU { mtu=DefaultInnerMTU }
	return mtu,nil
}
func MSSClamp(pathMTU int)(ipv4,ipv6 int,err error) {
	mtu,err:=InnerMTU(pathMTU);if err!=nil{return 0,0,err}
	return mtu-40,mtu-60,nil
}
