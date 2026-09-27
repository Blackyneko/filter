# Security Policy

## 仓库边界

本仓库只能包含公开分流规则、来源元数据、生成脚本和自动化配置。禁止提交：

- `ss://`、`ssr://`、`vmess://`、`vless://`、`trojan://`、`tuic://`、`hysteria://` 等节点链接
- 代理订阅 URL、订阅 Token、API Key、Bearer Token、Cookie 或 Authorization 内容
- 私钥、证书私密材料和密码
- 普通个人邮箱或其他不必要的个人信息

GitHub noreply 邮箱和明确记录的公开项目联系信息可以出现在 Git 历史或来源说明中。

## 自动同步边界

- 只允许访问 `sources.json` 内的固定 HTTPS 文本地址。
- 禁止执行、导入或解释任何上游代码。
- 必须限制下载大小、连接时间、重定向目的地和允许的主机。
- 必须拒绝 HTML 错误页、非法规则、异常缩减和隐私扫描结果。
- 所有候选文件先写入临时目录；全部通过后才能替换工作区文件。
- GitHub Actions 只创建待人工审阅的 Pull Request，不自动合并到 `main`。

## 报告问题

若发现公开文件含凭据或个人信息，请立即停止使用相关 URL，并通过 GitHub Security Advisory 私下报告。不要在公开 Issue 中粘贴秘密值。
