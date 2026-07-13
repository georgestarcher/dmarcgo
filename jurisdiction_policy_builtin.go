package dmarcgo

import "time"

var builtinUSExportControlJurisdictionPolicy = mustBuiltinJurisdictionRiskPolicy()

// BuiltinJurisdictionRiskPolicy returns a versioned, offline snapshot of U.S.
// export-control-inspired jurisdiction context. It is review context only, not
// legal advice, sanctions screening, actor attribution, or a malicious verdict.
func BuiltinJurisdictionRiskPolicy() JurisdictionRiskPolicy {
	return builtinUSExportControlJurisdictionPolicy
}

func mustBuiltinJurisdictionRiskPolicy() JurisdictionRiskPolicy {
	asOf := time.Date(2026, time.July, 8, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2027, time.January, 8, 0, 0, 0, 0, time.UTC)
	policy, err := NormalizeJurisdictionRiskPolicy(JurisdictionRiskPolicyConfig{
		ID:          "us_export_control_inspired",
		Version:     "2026-07-08",
		Name:        "U.S. export-control-inspired jurisdiction context",
		Description: "Curated review context derived from Country Groups D and E in Supplement No. 1 to 15 CFR Part 740; it is not a cyber-threat, actor, intent, nationality, sanctions, or legal classification.",
		EffectiveAt: asOf,
		AsOf:        asOf,
		ExpiresAt:   &expiresAt,
		Sources: []JurisdictionRiskPolicySource{
			{Title: "BIS Country Guidance", URI: "https://www.bis.gov/licensing/country-guidance"},
			{Title: "15 CFR Part 740, Supplement No. 1 - Country Groups", URI: "https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-740/appendix-Supplement%20No.%201%20to%20Part%20740"},
		},
		Entries:                     builtinJurisdictionPolicyEntries(),
		MaxReviewPriorityAdjustment: 10,
	})
	if err != nil {
		panic(err)
	}
	return policy
}

func builtinJurisdictionPolicyEntries() []JurisdictionRiskPolicyEntry {
	return []JurisdictionRiskPolicyEntry{
		builtinJurisdictionPolicyEntry("AE", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("AF", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("AM", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("AZ", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("BH", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("BY", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("CD", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("CF", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("CN", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("CU", JurisdictionRiskTierEmbargo, 10, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD5, JurisdictionCategoryBISCountryGroupE2),
		builtinJurisdictionPolicyEntry("EG", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("ER", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("GE", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("HT", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("IL", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("IQ", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("IR", JurisdictionRiskTierEmbargo, 10, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5, JurisdictionCategoryBISCountryGroupE1),
		builtinJurisdictionPolicyEntry("JO", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("KG", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("KH", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1),
		builtinJurisdictionPolicyEntry("KP", JurisdictionRiskTierEmbargo, 10, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5, JurisdictionCategoryBISCountryGroupE1),
		builtinJurisdictionPolicyEntry("KW", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("KZ", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("LA", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1),
		builtinJurisdictionPolicyEntry("LB", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("LY", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("MD", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("MM", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("MN", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("MO", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("NI", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("OM", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("PK", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("QA", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("RU", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("SA", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("SD", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("SO", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("SS", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("SY", JurisdictionRiskTierEmbargo, 10, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5, JurisdictionCategoryBISCountryGroupE1),
		builtinJurisdictionPolicyEntry("TJ", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("TM", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("TW", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("UZ", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("VE", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD2, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4, JurisdictionCategoryBISCountryGroupD5),
		builtinJurisdictionPolicyEntry("VN", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3),
		builtinJurisdictionPolicyEntry("YE", JurisdictionRiskTierExportControl, 3, JurisdictionCategoryBISCountryGroupD1, JurisdictionCategoryBISCountryGroupD3, JurisdictionCategoryBISCountryGroupD4),
		builtinJurisdictionPolicyEntry("ZW", JurisdictionRiskTierArmsEmbargo, 6, JurisdictionCategoryBISCountryGroupD5),
	}
}

func builtinJurisdictionPolicyEntry(country string, tier JurisdictionRiskTier, adjustment int, categories ...JurisdictionCategoryCode) JurisdictionRiskPolicyEntry {
	reasons := make([]JurisdictionReasonCode, 0, len(categories))
	for _, category := range categories {
		reasons = append(reasons, builtinJurisdictionReason(category))
	}
	return JurisdictionRiskPolicyEntry{
		CountryCode: country, Tier: tier, Categories: categories, Reasons: reasons,
		ReviewPriorityAdjustment: adjustment,
	}
}

func builtinJurisdictionReason(category JurisdictionCategoryCode) JurisdictionReasonCode {
	switch category {
	case JurisdictionCategoryBISCountryGroupD1:
		return JurisdictionReasonNationalSecurity
	case JurisdictionCategoryBISCountryGroupD2:
		return JurisdictionReasonNuclear
	case JurisdictionCategoryBISCountryGroupD3:
		return JurisdictionReasonChemicalBiological
	case JurisdictionCategoryBISCountryGroupD4:
		return JurisdictionReasonMissileTechnology
	case JurisdictionCategoryBISCountryGroupD5:
		return JurisdictionReasonUSArmsEmbargo
	case JurisdictionCategoryBISCountryGroupE1:
		return JurisdictionReasonTerrorismSupportingCountries
	case JurisdictionCategoryBISCountryGroupE2:
		return JurisdictionReasonUnilateralEmbargo
	default:
		panic("unsupported built-in jurisdiction category")
	}
}
