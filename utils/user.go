package utils

func StringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
