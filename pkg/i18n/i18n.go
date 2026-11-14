package i18n

import (
	"os"
	"strings"
)

type Language string

const (
	LangZH Language = "zh" // 中文
	LangEN Language = "en" // 英文
)

var currentLang Language

func init() {
	currentLang = detectLanguage()
}

// detectLanguage
func detectLanguage() Language {
	// 检查环境变量，优先级: LANG > LC_ALL > LC_MESSAGES > LANGUAGE
	for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"} {
		if lang := os.Getenv(env); lang != "" {
			lang = strings.ToLower(lang)
			if strings.HasPrefix(lang, "zh") {
				return LangZH
			}
			if strings.HasPrefix(lang, "en") {
				return LangEN
			}
		}
	}
	// 默认英文
	return LangEN
}

// GetLanguage 获取当前语言
func GetLanguage() Language {
	return currentLang
}

// SetLanguage 设置语言
func SetLanguage(lang Language) {
	currentLang = lang
}

// IsChinese 是否中文
func IsChinese() bool {
	return currentLang == LangZH
}
