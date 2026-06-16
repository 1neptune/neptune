# Neptune - 安全删除功能 - 实现计划

## [x] Task 1: 创建安全删除工具模块（权限检测）
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 实现操作系统检测函数
  - 实现管理员/root权限检测函数
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: 检测操作系统类型函数返回正确值
  - `programmatic` TR-1.2: 权限检测函数返回正确值

## [x] Task 2: 实现Windows安全删除模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 删除指定卷的VSS副本
  - 禁用启动修复
  - 停用VSS服务
  - 禁用系统还原
  - 禁用WinRE
- **Acceptance Criteria Addressed**: AC-3, AC-4, AC-5, AC-6, AC-7
- **Test Requirements**:
  - `programmatic` TR-2.1: Windows模块正确调用相关命令
  - `human-judgment` TR-2.2: 输出详细执行信息

## [x] Task 3: 实现Linux安全删除模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 删除LVM快照
  - 删除btrfs快照
  - 删除ZFS快照
  - 停止备份服务
- **Acceptance Criteria Addressed**: AC-8, AC-9
- **Test Requirements**:
  - `programmatic` TR-3.1: Linux模块正确调用相关命令
  - `human-judgment` TR-3.2: 输出详细执行信息

## [x] Task 4: 实现macOS安全删除模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 删除TimeMachine备份
  - 停止backupd服务
  - 清除本地快照
  - 禁用Spotlight
- **Acceptance Criteria Addressed**: AC-10, AC-11, AC-12, AC-13
- **Test Requirements**:
  - `programmatic` TR-4.1: macOS模块正确调用相关命令
  - `human-judgment` TR-4.2: 输出详细执行信息

## [x] Task 5: 更新加密命令集成安全删除
- **Priority**: P0
- **Depends On**: Task 2, Task 3, Task 4
- **Description**: 
  - 修改encrypt.go，在删除源文件后调用完整的安全删除功能
- **Acceptance Criteria Addressed**: AC-14, AC-15
- **Test Requirements**:
  - `programmatic` TR-5.1: 加密命令正确触发安全删除
  - `human-judgment` TR-5.2: 错误处理逻辑正确

## [x] Task 6: 更新解密命令集成安全删除
- **Priority**: P0
- **Depends On**: Task 2, Task 3, Task 4
- **Description**: 
  - 修改decrypt.go，在删除源文件后调用完整的安全删除功能
- **Acceptance Criteria Addressed**: AC-14, AC-15
- **Test Requirements**:
  - `programmatic` TR-6.1: 解密命令正确触发安全删除
  - `human-judgment` TR-6.2: 错误处理逻辑正确

## [x] Task 7: 测试与验证
- **Priority**: P1
- **Depends On**: Task 1-6
- **Description**: 
  - 验证构建成功
  - 验证单元测试通过
- **Acceptance Criteria Addressed**: AC-1-15
- **Test Requirements**:
  - `programmatic` TR-7.1: 构建成功
  - `programmatic` TR-7.2: 所有单元测试通过
- **Acceptance Criteria Addressed**: AC-3, AC-4, AC-5, AC-6, AC-7
- **Test Requirements**:
  - `programmatic` TR-2.1: Windows模块正确调用相关命令
  - `human-judgment` TR-2.2: 输出详细执行信息

## [ ] Task 3: 实现Linux安全删除模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 删除LVM快照
  - 删除btrfs快照
  - 删除ZFS快照
  - 停止备份服务
- **Acceptance Criteria Addressed**: AC-8, AC-9
- **Test Requirements**:
  - `programmatic` TR-3.1: Linux模块正确调用相关命令
  - `human-judgment` TR-3.2: 输出详细执行信息

## [ ] Task 4: 实现macOS安全删除模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 删除TimeMachine备份
  - 停止backupd服务
  - 清除本地快照
  - 禁用Spotlight
- **Acceptance Criteria Addressed**: AC-10, AC-11, AC-12, AC-13
- **Test Requirements**:
  - `programmatic` TR-4.1: macOS模块正确调用相关命令
  - `human-judgment` TR-4.2: 输出详细执行信息

## [ ] Task 5: 更新加密命令集成安全删除
- **Priority**: P0
- **Depends On**: Task 2, Task 3, Task 4
- **Description**: 
  - 修改encrypt.go，在删除源文件后调用完整的安全删除功能
- **Acceptance Criteria Addressed**: AC-14, AC-15
- **Test Requirements**:
  - `programmatic` TR-5.1: 加密命令正确触发安全删除
  - `human-judgment` TR-5.2: 错误处理逻辑正确

## [ ] Task 6: 更新解密命令集成安全删除
- **Priority**: P0
- **Depends On**: Task 2, Task 3, Task 4
- **Description**: 
  - 修改decrypt.go，在删除源文件后调用完整的安全删除功能
- **Acceptance Criteria Addressed**: AC-14, AC-15
- **Test Requirements**:
  - `programmatic` TR-6.1: 解密命令正确触发安全删除
  - `human-judgment` TR-6.2: 错误处理逻辑正确

## [ ] Task 7: 测试与验证
- **Priority**: P1
- **Depends On**: Task 1-6
- **Description**: 
  - 验证构建成功
  - 验证单元测试通过
- **Acceptance Criteria Addressed**: AC-1-15
- **Test Requirements**:
  - `programmatic` TR-7.1: 构建成功
  - `programmatic` TR-7.2: 所有单元测试通过