package domain

type SheetData struct {
	Values [][]interface{}
}

type RuleField struct {
	Field         string   `json:"field"`
	ParameterType string   `json:"parameterType"`
	Operators     []string `json:"operators"`
}

var TypeToOperators = map[string][]string{
	"numérico":   {"=", "!=", ">", "<", ">=", "<="},
	"moneda":     {"=", "!=", ">", "<", ">=", "<="},
	"porcentaje": {"=", "!=", ">", "<", ">=", "<="},
	"fecha":      {"=", "!=", ">", "<", ">=", "<="},
	"booleano":   {"=", "!="},
	"texto":      {"=", "!=", "contiene", "no contiene"},
	"categoría":  {"=", "!=", "está en", "no está en"},
}
