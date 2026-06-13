package utils

import (
	"sync"
	"testing"
)

// TestNewBufferPool 测试创建缓冲区池
func TestNewBufferPool(t *testing.T) {
	pool := NewBufferPool()
	if pool == nil {
		t.Fatal("NewBufferPool() 返回 nil")
	}
}

// TestNewBufferPoolWithSize 测试创建指定大小的缓冲区池
func TestNewBufferPoolWithSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"小缓冲区", 1024},
		{"中等缓冲区", 4096},
		{"大缓冲区", 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewBufferPoolWithSize(tt.size)
			if pool == nil {
				t.Fatal("NewBufferPoolWithSize() 返回 nil")
			}
		})
	}
}

// TestGetBuffer 测试获取缓冲区
func TestGetBuffer(t *testing.T) {
	pool := NewBufferPool()

	tests := []struct {
		name string
		size int
	}{
		{"小缓冲区", 1024},
		{"中等缓冲区", 4096},
		{"大缓冲区", 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := pool.GetBuffer(tt.size)
			if buf == nil {
				t.Fatal("GetBuffer() 返回 nil")
			}
			if len(buf) != 0 {
				t.Errorf("GetBuffer() 返回的缓冲区长度应为 0，实际为 %d", len(buf))
			}
			if cap(buf) < tt.size {
				t.Errorf("GetBuffer() 返回的缓冲区容量应至少为 %d，实际为 %d", tt.size, cap(buf))
			}
		})
	}
}

// TestPutBuffer 测试归还缓冲区
func TestPutBuffer(t *testing.T) {
	pool := NewBufferPool()

	// 获取缓冲区
	buf := pool.GetBuffer(1024)
	if buf == nil {
		t.Fatal("GetBuffer() 返回 nil")
	}

	// 写入一些数据
	buf = append(buf, []byte("test data")...)
	if len(buf) == 0 {
		t.Fatal("写入数据后缓冲区长度为 0")
	}

	// 归还缓冲区
	pool.PutBuffer(buf)

	// 再次获取缓冲区，应该被重置
	buf2 := pool.GetBuffer(1024)
	if buf2 == nil {
		t.Fatal("GetBuffer() 返回 nil")
	}
	if len(buf2) != 0 {
		t.Errorf("PutBuffer 后再次获取的缓冲区长度应为 0，实际为 %d", len(buf2))
	}
}

// TestPutBufferNil 测试归还 nil 缓冲区
func TestPutBufferNil(t *testing.T) {
	pool := NewBufferPool()
	// 应该不会 panic
	pool.PutBuffer(nil)
}

// TestBufferPoolConcurrent 测试并发使用缓冲区池
func TestBufferPoolConcurrent(t *testing.T) {
	pool := NewBufferPool()
	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				buf := pool.GetBuffer(1024)
				if buf == nil {
					t.Error("GetBuffer() 返回 nil")
					return
				}
				if len(buf) != 0 {
					t.Errorf("GetBuffer() 返回的缓冲区长度应为 0，实际为 %d", len(buf))
					return
				}
				// 模拟使用缓冲区
				buf = append(buf, []byte("test data")...)
				pool.PutBuffer(buf)
			}
		}()
	}

	wg.Wait()
}

// TestGetBufferDefault 测试获取默认大小的缓冲区
func TestGetBufferDefault(t *testing.T) {
	pool := NewBufferPool()
	buf := pool.GetBufferDefault()
	if buf == nil {
		t.Fatal("GetBufferDefault() 返回 nil")
	}
	if len(buf) != 0 {
		t.Errorf("GetBufferDefault() 返回的缓冲区长度应为 0，实际为 %d", len(buf))
	}
	if cap(buf) < 4096 {
		t.Errorf("GetBufferDefault() 返回的缓冲区容量应至少为 4096，实际为 %d", cap(buf))
	}
}

// TestGlobalBufferPool 测试全局缓冲区池
func TestGlobalBufferPool(t *testing.T) {
	buf := GetGlobalBuffer(1024)
	if buf == nil {
		t.Fatal("GetGlobalBuffer() 返回 nil")
	}
	if len(buf) != 0 {
		t.Errorf("GetGlobalBuffer() 返回的缓冲区长度应为 0，实际为 %d", len(buf))
	}

	// 归还缓冲区
	PutGlobalBuffer(buf)

	// 再次获取
	buf2 := GetGlobalBuffer(1024)
	if buf2 == nil {
		t.Fatal("GetGlobalBuffer() 返回 nil")
	}
	if len(buf2) != 0 {
		t.Errorf("PutGlobalBuffer 后再次获取的缓冲区长度应为 0，实际为 %d", len(buf2))
	}
}

// TestParseChunkSize 测试解析缓冲区大小
func TestParseChunkSize(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  int
		wantError bool
	}{
		// 有效的格式
		{"字节", "1024B", 1024, false},
		{"字节无单位", "1024", 1024, false},
		{"KB", "64KB", 64 * 1024, false},
		{"KB小写", "64kb", 64 * 1024, false},
		{"KB带空格", "64 KB", 64 * 1024, false},
		{"MB", "1MB", 1 * 1024 * 1024, false},
		{"MB小写", "1mb", 1 * 1024 * 1024, false},
		{"MB带空格", "1 MB", 1 * 1024 * 1024, false},
		{"GB", "1GB", 1 * 1024 * 1024 * 1024, false},
		{"GB小写", "1gb", 1 * 1024 * 1024 * 1024, false},
		{"GB带空格", "1 GB", 1 * 1024 * 1024 * 1024, false},
		{"小数KB", "1.5KB", int(1.5 * 1024), false},
		{"小数MB", "2.5MB", int(2.5 * 1024 * 1024), false},

		// 无效的格式
		{"空字符串", "", 0, true},
		{"无效格式", "abc", 0, true},
		{"无效单位", "64TB", 0, true},
		{"负数", "-1KB", 0, true},
		{"零", "0KB", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseChunkSize(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("ParseChunkSize(%q) 期望返回错误，但没有", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseChunkSize(%q) 返回错误: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseChunkSize(%q) = %d, 期望 %d", tt.input, result, tt.expected)
				}
			}
		})
	}
}

// TestFormatChunkSize 测试格式化缓冲区大小
func TestFormatChunkSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int
		expected string
	}{
		{"字节", 512, "512B"},
		{"KB", 1024, "1.00KB"},
		{"KB小数", 1536, "1.50KB"},
		{"MB", 1024 * 1024, "1.00MB"},
		{"MB小数", int(1.5 * 1024 * 1024), "1.50MB"},
		{"GB", 1024 * 1024 * 1024, "1.00GB"},
		{"GB小数", int(1.5 * 1024 * 1024 * 1024), "1.50GB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatChunkSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("FormatChunkSize(%d) = %s, 期望 %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

// TestValidateChunkSize 测试验证缓冲区大小
func TestValidateChunkSize(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		wantError bool
	}{
		{"太小", 512, true},
		{"最小值", 1024, false},
		{"有效值", 64 * 1024, false},
		{"最大值", 100 * 1024 * 1024, false},
		{"太大", 200 * 1024 * 1024, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChunkSize(tt.size)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateChunkSize(%d) 期望返回错误，但没有", tt.size)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateChunkSize(%d) 返回错误: %v", tt.size, err)
				}
			}
		})
	}
}

// TestBufferPoolReuse 测试缓冲区复用
func TestBufferPoolReuse(t *testing.T) {
	pool := NewBufferPool()

	// 获取缓冲区
	buf1 := pool.GetBuffer(1024)
	buf1 = append(buf1, []byte("test data 1")...)

	// 归还缓冲区
	pool.PutBuffer(buf1)

	// 再次获取缓冲区
	buf2 := pool.GetBuffer(1024)

	// 检查缓冲区是否被重置
	if len(buf2) != 0 {
		t.Errorf("复用的缓冲区长度应为 0，实际为 %d", len(buf2))
	}

	// 检查缓冲区容量是否足够
	if cap(buf2) < 1024 {
		t.Errorf("复用的缓冲区容量应至少为 1024，实际为 %d", cap(buf2))
	}
}

// BenchmarkGetBuffer 基准测试获取缓冲区
func BenchmarkGetBuffer(b *testing.B) {
	pool := NewBufferPool()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.GetBuffer(1024)
		pool.PutBuffer(buf)
	}
}

// BenchmarkGetBufferParallel 并行基准测试获取缓冲区
func BenchmarkGetBufferParallel(b *testing.B) {
	pool := NewBufferPool()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.GetBuffer(1024)
			pool.PutBuffer(buf)
		}
	})
}

// BenchmarkParseChunkSize 基准测试解析缓冲区大小
func BenchmarkParseChunkSize(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseChunkSize("64KB")
	}
}