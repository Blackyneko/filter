# filter

个人使用的公开代理规则仓库，提供可直接订阅的 Loon 与 Shadowrocket 规则。仓库只保存分流规则，不保存节点、代理订阅、Cookie、Token 或其他凭据。

## 稳定订阅地址

以下根目录地址为兼容入口，文件名和 Raw URL 保持稳定：

- [AI.list](https://raw.githubusercontent.com/Blackyneko/filter/main/AI.list)
- [Apple-AI.list](https://raw.githubusercontent.com/Blackyneko/filter/main/Apple-AI.list)
- [Binance.list](https://raw.githubusercontent.com/Blackyneko/filter/main/Binance.list)
- [talkatone.list](https://raw.githubusercontent.com/Blackyneko/filter/main/talkatone.list)

客户端专用输出位于：

- `rules/loon/`
- `rules/shadowrocket/`

专用输出由仓库脚本从固定清单生成，并分别按目标客户端校验。策略组名称由客户端配置决定，规则文件本身不包含节点或订阅信息。

## 更新模型

- 仅 `sources.json` 中明确列出的 HTTPS 地址可以被下载。
- 上游内容只作为文本处理，绝不执行上游脚本或代码。
- 下载结果会经过格式、规则数量、异常缩减和隐私检查。
- 所有来源全部通过后才会更新文件；失败时保留上一版正常内容。
- 定时同步只创建候选更新分支和 Pull Request，不直接更新 `main`。
- 定时任务每周一 04:17 UTC（北京时间 12:17）运行，也可在 Actions 页面手动触发。

本地检查：

```sh
python3 -m unittest discover -s tests
python3 scripts/validate_rules.py
python3 scripts/privacy_scan.py
python3 scripts/sync_rules.py --check
```

来源、署名和许可证见 [SOURCES.md](SOURCES.md)，安全边界见 [SECURITY.md](SECURITY.md)。
