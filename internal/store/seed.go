package store

import (
	"time"

	"github.com/google/uuid"
)

// SeedFreeResources removes legacy placeholder rows and idempotently inserts
// the real seed resources by name.
func (s *Store) SeedFreeResources() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM free_resources WHERE name IN (?, ?)`, "GPU Cloud", "Storage Cloud"); err != nil {
		return err
	}

	now := time.Now().Unix()
	resources := []FreeResourceRecord{
		{
			Name:      "Google Colab 免费 T4",
			Category:  "云电脑",
			Status:    "正常",
			ExpiresAt: 0,
			Quota:     "免费 T4 15GB/会话",
			Note:      "Tesla T4 15GB；CUDA 13.0；torch 2.14.1+cu130；ComfyUI + SD 1.5 已装，512×512 测试图成功；运行时临时，断开清空，存 Drive；账号 0394wxm@gmail.com；实测 2026-11-14 16:50",
			Link:      "https://colab.research.google.com/drive/1w5nS7Aem952hHW_Iq2-apqEjj0ktwXqo",
		},
		{
			Name:      "Simular Box main",
			Category:  "云电脑",
			Status:    "正常",
			ExpiresAt: expiryAtUTC("2026-11-26"),
			Quota:     "Box Free；1,000 credits/天",
			Note:      "2 核 / 3.8 GiB / 20 GB 盘（官方基线 4 核 / 7.7 GB / 40 GB，实测缩水）；Ubuntu 24.04.5 芝加哥；无 SSH；闲置会睡，连接唤醒；Hermes 在上面；不放重要数据；复查 2026-11-14 17:10 （到期日为约数）",
			Link:      "https://box.simular.ai",
		},
		{
			Name:      "InstaBox muse-sandbox",
			Category:  "云电脑",
			Status:    "正常",
			ExpiresAt: 0,
			Quota:     "$0；4 核 8G；100 GB 出站/月",
			Note:      "4 核 / 7.8 GB；根盘 16 GB + /data 20 GB；Debian 13；root + Docker；30 分钟闲置自动暂停；单次最长 120 分钟→480 分钟；无独立入站 IPv4；免费政策随时可变；验证 2026-11-14 17:19",
			Link:      "https://instabox.sh",
		},
		{
			Name:      "Cloady Xray（美西 USW1）",
			Category:  "节点",
			Status:    "正常",
			ExpiresAt: 0,
			Quota:     "$0；每月 10 GB",
			Note:      "VLESS + WS + TLS 443；0.25 核 / 256 MB；免费档总计 ≤0.5 核 / 1 GB / 5 GB SSD；闲置 7 天暂停，控制台重启恢复；部署验证 2026-11-14 17:29；链接只放控制台，绝不放节点地址/UUID",
			Link:      "https://cloady.com",
		},
		{
			Name:      "Kaggle 免费 GPU",
			Category:  "Tokens·API",
			Status:    "已停用",
			ExpiresAt: expiryAtUTC("2026-11-19"),
			Quota:     "$100/月，剩约 10%",
			Note:      "账号 Gupta180；草稿 notebook281064c66b 保留；手机验证未完成，GPU 与 Internet 锁住；2026-11-14 决定停用，Colab 覆盖 GPU",
			Link:      "https://www.kaggle.com/settings",
		},
		{
			Name:      "Railway",
			Category:  "Tokens·API",
			Status:    "已停用",
			ExpiresAt: 0,
			Quota:     "无长期免费档",
			Note:      "仅 30 天一次性 $5 试用，已过期（0 天）；未建项目、未升级、未输支付信息；2026-11-14 决定跳过",
			Link:      "https://railway.com",
		},
		{
			Name:      "家里 PVE 主机",
			Category:  "自有设备",
			Status:    "正常",
			ExpiresAt: 0,
			Quota:     "自有硬件",
			Note:      "AMD 5700G 无头；16 GB；1 TB SSD；Proxmox VE；国内家里，拟 24 小时开；用途未定；记录 2026-11-01",
			Link:      "",
		},
		{
			Name:      "RackNerd VPS",
			Category:  "自有设备",
			Status:    "正常",
			ExpiresAt: 0,
			Quota:     "$20 包年",
			Note:      "1 核 Xeon Gold 6252 / 961 MB / 19 GB；204.152.200.224；Hysteria2 主力节点；近空载，可再加 2–3 个 20–50 MB 轻服务；国内直连超时、海外均通",
			Link:      "",
		},
		{
			Name:      "魔搭 × AMD MI300X 100 小时",
			Category:  "云电脑",
			Status:    "待续",
			ExpiresAt: 0,
			Quota:     "100 小时新人权益",
			Note:      "实测 GPU 为 Radeon PRO W7900D 48GB（DID 0x744b），非 MI300X；1 GPU / 16 核 / 55GB；实例动不动超时关机，2026-11-15 暂时跳过",
			Link:      "https://developer.amd.com.cn/radeon/",
		},
		{
			Name:      "LXI.be 免费主机",
			Category:  "域名主机",
			Status:    "待领",
			ExpiresAt: 0,
			Quota:     "€0 永久；5GB；无限流量",
			Note:      "免费档有 SSH（panel.lxi.be:2222，密码登录）；只需邮箱验证；验证链接一次性",
			Link:      "https://lxi.be/",
		},
		{
			Name:      "Jantit VPN Singapore 3",
			Category:  "节点",
			Status:    "待续",
			ExpiresAt: expiryAtUTC("2026-11-16"),
			Quota:     "7 天换号",
			Note:      "VLESS Reality；每 7 天换号，提醒已设",
			Link:      "https://www.vpnjantit.com/",
		},
		{
			Name:      "Notion 教育计划",
			Category:  "账号权益",
			Status:    "正常",
			ExpiresAt: expiryAtUTC("2027-11-15"),
			Quota:     "免费（教育计划）",
			Note:      "2026-11-15 已续；一年一次靠邮件提醒；到期日为约数",
			Link:      "",
		},
		{
			Name:      "Vercel AI Gateway",
			Category:  "Tokens·API",
			Status:    "待续",
			ExpiresAt: expiryAtUTC("2026-12-01"),
			Quota:     "$5/月已耗尽",
			Note:      "Kimi K2.7、Gemini 2.5 Flash 已停；12 月 1 日刷新",
			Link:      "https://vercel.com/dashboard",
		},
		{
			Name:      "超算互联网 1 亿 Token",
			Category:  "Tokens·API",
			Status:    "待领",
			ExpiresAt: expiryAtUTC("2026-11-30"),
			Quota:     "一次性 1 亿，仅客户端内",
			Note:      "需手机号实名；进不了网关",
			Link:      "https://www.scnet.cn/",
		},
		{
			Name:      "Coarena $5/天",
			Category:  "Tokens·API",
			Status:    "待领",
			ExpiresAt: 0,
			Quota:     "每天 $5",
			Note:      "提示词与回复会被存下并可能授权进数据集；不适合真实工作与隐私内容",
			Link:      "https://coarena.ai/",
		},
		{
			Name:      "Numes 免费额度",
			Category:  "Tokens·API",
			Status:    "待领",
			ExpiresAt: 0,
			Quota:     "新号免费额度（金额未写）",
			Note:      "$0 端点未验证是否真零扣费",
			Link:      "https://numes.ai/",
		},
		{
			Name:      "zkVerify Agent Games",
			Category:  "Tokens·API",
			Status:    "待领",
			ExpiresAt: expiryAtUTC("2026-11-21"),
			Quota:     "奖池 40 万 VFY",
			Note:      "须自建 AI agent＋公开端点参赛；期望值低",
			Link:      "https://agentgames.zkverify.io/",
		},
	}

	for _, resource := range resources {
		var exists int
		err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM free_resources WHERE name = ?)`, resource.Name).Scan(&exists)
		if err != nil {
			return err
		}
		if exists != 0 {
			continue
		}

		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		resource.ID = id.String()
		resource.CreatedAt = now
		resource.UpdatedAt = now
		_, err = tx.Exec(
			`INSERT INTO free_resources (id, name, category, status, expires_at, quota, note, link, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			resource.ID, resource.Name, resource.Category, resource.Status, resource.ExpiresAt, resource.Quota, resource.Note, resource.Link, resource.CreatedAt, resource.UpdatedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func expiryAtUTC(date string) int64 {
	parsed, err := time.ParseInLocation("2006-01-02", date, time.UTC)
	if err != nil {
		return 0
	}
	return parsed.Unix()
}
