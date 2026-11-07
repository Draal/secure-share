package config

import (
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/FinalLevel/go-i18n/i18n"
	"github.com/FinalLevel/go-i18n/i18n/language"
)

type Language struct {
	Code     string // go-i18n tag: "en-us"
	Short    string // "en"
	Prefix   string // URL prefix: "" for English, "/ru", "/uk"
	Name     string // endonym for the language switcher
	OGLocale string // Open Graph locale: "en_US"
	Banner   string // "this page is available in your language", in that language
	RTL      bool   // right-to-left writing direction
}

type Config struct {
	Root        string
	UseMinified bool
	UseHashing  bool
	MaxFileSize int64
	Languages   []Language
	assets      map[string]string // "css/site.css" -> "/assets/css/site.1a2b3c4d.css"
}

// calcAssetCrc32 returns the public URL of a file under Root: the minified
// version when there is one and UseMinified is on, with the crc32 of the
// content in the name when UseHashing is on.
func (c *Config) calcAssetCrc32(p string) (string, error) {
	if c.UseMinified {
		if ext := path.Ext(p); ext != "" {
			minified := fmt.Sprintf("%s.min%s", strings.TrimSuffix(p, ext), ext)
			if _, err := os.Stat(c.Root + minified); err == nil {
				p = minified
			}
		}
	}
	content, err := os.ReadFile(c.Root + p)
	if err != nil {
		return "", err
	}
	if c.UseHashing {
		if ext := path.Ext(p); ext != "" {
			p = fmt.Sprintf("%s.%x%s", strings.TrimSuffix(p, ext), crc32.ChecksumIEEE(content), ext)
		}
	}
	return p, nil
}

// calcAssetsCrc32 computes URLs for every file under public/assets, except
// minified copies, gzipped copies and licenses.
func (c *Config) calcAssetsCrc32() error {
	c.assets = make(map[string]string)
	root := c.Root + "/assets"
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if strings.Contains(name, ".min.") || path.Ext(name) == ".gz" || path.Ext(name) == ".txt" {
			return nil
		}
		url, err := c.calcAssetCrc32("/assets/" + name)
		c.assets[name] = url
		return err
	})
}

// GetAssetUrl returns the public URL of an asset by its path under
// public/assets, e.g. "css/site.css".
func (c *Config) GetAssetUrl(name string) string {
	return c.assets[name]
}

// These translations currently use simple strings, not plural forms.
func init() {
	language.Add(&language.Language{Tag: "ka", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "kk", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "uz", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "fil", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "ur", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "fa", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "bn", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "vi", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "hi", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "he", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "ro", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "sk", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "no", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "hr", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "sr", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "id", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "ms", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "be", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "el", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "sl", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "mk", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "fi", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "ja", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "ko", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "hu", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "az", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "sq", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "et", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "lv", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "lt", PluralSpec: language.Parse("en")[0].PluralSpec})
	language.Add(&language.Language{Tag: "th", PluralSpec: language.Parse("en")[0].PluralSpec})
}

func (c *Config) loadTranslationFiles() error {
	c.Languages = []Language{
		{Code: "en-us", Short: "en", Prefix: "", Name: "English", OGLocale: "en_US", Banner: "This page is available in English"},
		{Code: "ru-ru", Short: "ru", Prefix: "/ru", Name: "Русский", OGLocale: "ru_RU", Banner: "Эта страница есть на русском"},
		{Code: "uk-uk", Short: "uk", Prefix: "/uk", Name: "Українська", OGLocale: "uk_UA", Banner: "Ця сторінка є українською"},
		{Code: "ar-sa", Short: "ar", Prefix: "/ar", Name: "العربية", OGLocale: "ar_SA", Banner: "هذه الصفحة متاحة باللغة العربية", RTL: true},
		{Code: "he-il", Short: "he", Prefix: "/he", Name: "עברית", OGLocale: "he_IL", Banner: "הדף הזה זמין בעברית", RTL: true},
		{Code: "de-de", Short: "de", Prefix: "/de", Name: "Deutsch", OGLocale: "de_DE", Banner: "Diese Seite ist auf Deutsch verfügbar"},
		{Code: "fr-fr", Short: "fr", Prefix: "/fr", Name: "Français", OGLocale: "fr_FR", Banner: "Cette page est disponible en français"},
		{Code: "es-es", Short: "es", Prefix: "/es", Name: "Español", OGLocale: "es_ES", Banner: "Esta página está disponible en español"},
		{Code: "pt-br", Short: "pt", Prefix: "/pt", Name: "Português", OGLocale: "pt_BR", Banner: "Esta página está disponível em português"},
		{Code: "it-it", Short: "it", Prefix: "/it", Name: "Italiano", OGLocale: "it_IT", Banner: "Questa pagina è disponibile in italiano"},
		{Code: "nl-nl", Short: "nl", Prefix: "/nl", Name: "Nederlands", OGLocale: "nl_NL", Banner: "Deze pagina is beschikbaar in het Nederlands"},
		{Code: "pl-pl", Short: "pl", Prefix: "/pl", Name: "Polski", OGLocale: "pl_PL", Banner: "Ta strona jest dostępna po polsku"},
		{Code: "tr-tr", Short: "tr", Prefix: "/tr", Name: "Türkçe", OGLocale: "tr_TR", Banner: "Bu sayfa Türkçe olarak kullanılabilir"},
		{Code: "cs-cz", Short: "cs", Prefix: "/cs", Name: "Čeština", OGLocale: "cs_CZ", Banner: "Tato stránka je dostupná v češtině"},
		{Code: "ro-ro", Short: "ro", Prefix: "/ro", Name: "Română", OGLocale: "ro_RO", Banner: "Această pagină este disponibilă în română"},
		{Code: "bg-bg", Short: "bg", Prefix: "/bg", Name: "Български", OGLocale: "bg_BG", Banner: "Тази страница е достъпна на български"},
		{Code: "sk-sk", Short: "sk", Prefix: "/sk", Name: "Slovenčina", OGLocale: "sk_SK", Banner: "Táto stránka je dostupná v slovenčine"},
		{Code: "sv-se", Short: "sv", Prefix: "/sv", Name: "Svenska", OGLocale: "sv_SE", Banner: "Den här sidan finns på svenska"},
		{Code: "da-dk", Short: "da", Prefix: "/da", Name: "Dansk", OGLocale: "da_DK", Banner: "Denne side findes på dansk"},
		{Code: "no-no", Short: "no", Prefix: "/no", Name: "Norsk", OGLocale: "nb_NO", Banner: "Denne siden finnes på norsk"},
		{Code: "hr-hr", Short: "hr", Prefix: "/hr", Name: "Hrvatski", OGLocale: "hr_HR", Banner: "Ova stranica dostupna je na hrvatskom"},
		{Code: "sr-rs", Short: "sr", Prefix: "/sr", Name: "Srpski", OGLocale: "sr_RS", Banner: "Ova stranica je dostupna na srpskom"},
		{Code: "id-id", Short: "id", Prefix: "/id", Name: "Bahasa Indonesia", OGLocale: "id_ID", Banner: "Halaman ini tersedia dalam bahasa Indonesia"},
		{Code: "ms-my", Short: "ms", Prefix: "/ms", Name: "Bahasa Melayu", OGLocale: "ms_MY", Banner: "Halaman ini tersedia dalam bahasa Melayu"},
		{Code: "be-by", Short: "be", Prefix: "/be", Name: "Беларуская", OGLocale: "be_BY", Banner: "Гэта старонка даступная па-беларуску"},
		{Code: "el-gr", Short: "el", Prefix: "/el", Name: "Ελληνικά", OGLocale: "el_GR", Banner: "Αυτή η σελίδα είναι διαθέσιμη στα ελληνικά"},
		{Code: "sl-si", Short: "sl", Prefix: "/sl", Name: "Slovenščina", OGLocale: "sl_SI", Banner: "Ta stran je na voljo v slovenščini"},
		{Code: "mk-mk", Short: "mk", Prefix: "/mk", Name: "Македонски", OGLocale: "mk_MK", Banner: "Оваа страница е достапна на македонски"},
		{Code: "fi-fi", Short: "fi", Prefix: "/fi", Name: "Suomi", OGLocale: "fi_FI", Banner: "Tämä sivu on saatavilla suomeksi"},
		{Code: "ja-jp", Short: "ja", Prefix: "/ja", Name: "日本語", OGLocale: "ja_JP", Banner: "このページは日本語で利用できます"},
		{Code: "ko-kr", Short: "ko", Prefix: "/ko", Name: "한국어", OGLocale: "ko_KR", Banner: "이 페이지는 한국어로 제공됩니다"},
		{Code: "hu-hu", Short: "hu", Prefix: "/hu", Name: "Magyar", OGLocale: "hu_HU", Banner: "Ez az oldal magyarul is elérhető"},
		{Code: "az-az", Short: "az", Prefix: "/az", Name: "Azərbaycan dili", OGLocale: "az_AZ", Banner: "Bu səhifə Azərbaycan dilində mövcuddur"},
		{Code: "sq-al", Short: "sq", Prefix: "/sq", Name: "Shqip", OGLocale: "sq_AL", Banner: "Kjo faqe është e disponueshme në shqip"},
		{Code: "et-ee", Short: "et", Prefix: "/et", Name: "Eesti keel", OGLocale: "et_EE", Banner: "See leht on saadaval eesti keeles"},
		{Code: "lv-lv", Short: "lv", Prefix: "/lv", Name: "Latviešu valoda", OGLocale: "lv_LV", Banner: "Šī lapa ir pieejama latviešu valodā"},
		{Code: "lt-lt", Short: "lt", Prefix: "/lt", Name: "Lietuvių kalba", OGLocale: "lt_LT", Banner: "Šis puslapis pasiekiamas lietuvių kalba"},
		{Code: "th-th", Short: "th", Prefix: "/th", Name: "ภาษาไทย", OGLocale: "th_TH", Banner: "หน้านี้มีให้บริการเป็นภาษาไทย"},
		{Code: "hi-in", Short: "hi", Prefix: "/hi", Name: "हिन्दी", OGLocale: "hi_IN", Banner: "यह पृष्ठ हिन्दी में उपलब्ध है"},
		{Code: "vi-vn", Short: "vi", Prefix: "/vi", Name: "Tiếng Việt", OGLocale: "vi_VN", Banner: "Trang này có bằng tiếng Việt"},
		{Code: "bn-bd", Short: "bn", Prefix: "/bn", Name: "বাংলা", OGLocale: "bn_BD", Banner: "এই পৃষ্ঠাটি বাংলায় পাওয়া যায়"},
		{Code: "fa-ir", Short: "fa", Prefix: "/fa", Name: "فارسی", OGLocale: "fa_IR", Banner: "این صفحه به فارسی در دسترس است", RTL: true},
		{Code: "ur-pk", Short: "ur", Prefix: "/ur", Name: "اردو", OGLocale: "ur_PK", Banner: "یہ صفحہ اردو میں دستیاب ہے", RTL: true},
		{Code: "fil-ph", Short: "fil", Prefix: "/fil", Name: "Filipino", OGLocale: "fil_PH", Banner: "Available ang pahinang ito sa Filipino"},
		{Code: "uz-uz", Short: "uz", Prefix: "/uz", Name: "O‘zbekcha", OGLocale: "uz_UZ", Banner: "Bu sahifa o‘zbek tilida mavjud"},
		{Code: "kk-kz", Short: "kk", Prefix: "/kk", Name: "Қазақша", OGLocale: "kk_KZ", Banner: "Бұл бет қазақ тілінде қолжетімді"},
		{Code: "ka-ge", Short: "ka", Prefix: "/ka", Name: "ქართული", OGLocale: "ka_GE", Banner: "ეს გვერდი ხელმისაწვდომია ქართულად"},
	}
	for _, l := range c.Languages {
		if err := i18n.LoadTranslationFile(fmt.Sprintf("translation/%s.all.json", l.Code)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) GetLanguageByCode(code string) Language {
	for _, l := range c.Languages {
		if l.Code == code {
			return l
		}
	}
	return Language{}
}

// LanguageByShort finds a language by its primary code ("ru" or "fil").
func (c *Config) LanguageByShort(short string) (Language, bool) {
	if short == "nb" {
		short = "no"
	}
	for _, l := range c.Languages {
		if l.Short == short {
			return l, true
		}
	}
	return Language{}, false
}

const (
	LangEnglish = "en-us"
)

// T returns the translate function for a language tag.
func (c *Config) T(code string) i18n.TranslateFunc {
	t, _, _ := i18n.Tfunc(code, LangEnglish)
	return t
}

// MaxFileSizeString formats the upload limit for UI texts: "5 MB".
func (c *Config) MaxFileSizeString() string {
	if mb := c.MaxFileSize / (1024 * 1024); mb > 0 {
		return fmt.Sprintf("%d MB", mb)
	}
	return fmt.Sprintf("%d KB", c.MaxFileSize/1024)
}

func OpenFromEnv() (*Config, error) {
	config := Config{
		Root:        "./public",
		UseMinified: os.Getenv("USE_MINIFIED") != "",
		UseHashing:  os.Getenv("USE_HASHING") != "",
		MaxFileSize: 5 * 1024 * 1024,
	}
	if maxFileSize, _ := strconv.ParseInt(os.Getenv("MAX_FILE_SIZE"), 10, 64); maxFileSize > 0 {
		config.MaxFileSize = maxFileSize
	}
	if err := config.calcAssetsCrc32(); err != nil {
		return nil, fmt.Errorf("Couldn't calculate crc32: %s", err.Error())
	}
	if err := config.loadTranslationFiles(); err != nil {
		return nil, fmt.Errorf("Couldn't load translation files: %s", err.Error())
	}
	return &config, nil
}
