# 贡献指南

感谢你的贡献！为保证维护效率，请按下面方式提交：

**提交 Issue**
- 描述问题现象、期望行为与实际行为
- 提供复现步骤与日志片段（注意打码）
- 标注运行环境（Python 版本、系统、运行方式）

**提交 PR**
- 一个 PR 只做一件事
- 保持现有代码风格（尽量避免大规模格式化）
- 确保本地测试通过：

```bash
/Library/Frameworks/Python.framework/Versions/3.8/bin/python3 -m unittest discover -s tests
```

**安全与隐私**
- 不要提交任何敏感信息（账号、密码、API Key、日志等）
