//go:build linux

// Package sysx 放与操作系统有关的小工具。
package sysx

import "syscall"

// DiskFreeGB 返回路径所在磁盘的剩余空间（GB）；查不到时返回 -1。
func DiskFreeGB(path string) float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return -1
	}
	return float64(st.Bavail) * float64(st.Bsize) / (1 << 30)
}
