//go:build !linux

// Package sysx 放与操作系统有关的小工具。
package sysx

// DiskFreeGB 返回路径所在磁盘的剩余空间（GB）；查不到时返回 -1。
func DiskFreeGB(path string) float64 { return -1 }
