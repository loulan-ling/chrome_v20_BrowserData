# chrome_v20_BrowserData

## Chrome v20 版本数据解密获取脚本

本项目是一个数据解密获取脚本，主要用于提取 Chrome 浏览器 v20 版本中的敏感数据，包括 cookies、密码、下载记录和浏览历史。该脚本基于runassu的[chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption)解密脚本进行了修改和扩展。

### 功能
- **导出数据**：将提取到的 Cookies、密码、下载记录和浏览历史导出为 CSV 文件，方便用户查看和管理。

### 使用说明
1. **环境要求**：
   - 请确保在 Windows 系统上运行该脚本，并且 Chrome 浏览器 v20 版本已安装。

2. **运行脚本**：
   - 以管理员权限运行该脚本以确保可以访问 Chrome 数据文件。

3. **输出文件**：
   - 数据将以 CSV 格式保存在 `result` 目录中，目录会自动创建。

### 注意事项
- 本工具仅供安全学习与交流之用，严禁用于任何非法行为，相关后果由用户自行承担。
