// Copyright 2023 SphereEx Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package distsql

import (
	"fmt"
	"strings"
)

type EncrytionRule struct {
	// ifNotExist
	IfNotExist bool
	// rulename
	// Name string
	// encryptionDefinition
	EncryptionDefinitions []EncryptDefinition
}

func (r *EncrytionRule) ToDistSQL() string {
	var stmt string
	createVerb := "CREATE"
	// alterVerb := "ALTER"
	// deleteVerb := "DELETE"
	ruleType := "ENCRYPT RULE"

	stmt = fmt.Sprintf("%s %s ", createVerb, ruleType)

	if r.IfNotExist {
		stmt = fmt.Sprintf("%s IF NOT EXISTS ", stmt)
	}

	for _, e := range r.EncryptionDefinitions {
		stmt = fmt.Sprintf("%s %s,", stmt, e.ToDistSQL())
	}
	stmt = strings.TrimSuffix(stmt, ",")
	stmt = fmt.Sprintf("%s;", stmt)

	return stmt
}

type EncryptDefinition struct {
	// name
	Name string
	// columns
	Columns []Column
	// queryWithCipherColumn
	QueryWithCipherColumn bool
}

func (r *EncryptDefinition) ToDistSQL() string {
	var stmt string
	stmt = fmt.Sprintf("%s ", r.Name)
	stmt = fmt.Sprintf("%s (COLUMNS ", stmt)

	for _, c := range r.Columns {
		stmt = fmt.Sprintf("%s (%s),", stmt, c.ToDistSQL())
	}
	stmt = strings.TrimSuffix(stmt, ",")
	stmt = fmt.Sprintf("%s)", stmt)

	if r.QueryWithCipherColumn {
		stmt = fmt.Sprintf("%s, QUERY_ WITH_CIPHER_COLUMN=true", stmt)
	} else {
		stmt = fmt.Sprintf("%s, QUERY_ WITH_CIPHER_COLUMN=false", stmt)
	}
	stmt = fmt.Sprintf("%s)", stmt)
	return stmt
}

type Column struct {
	// columnName
	Name string
	// plainColumnName
	Plain string
	// cipherColumnName
	Cipher string
	// assistedQueryColumnName
	AssistedQueryColumn string
	// likeQueryColumnName
	LikeQueryColumn string
	// encryptAlgorithmDefinition
	EncryptionAlgorithm *EncryptionAlgorithmType
	// assistedQueryAlgorithmDefinition
	AssistedQueryAlgorithm *AssistedQueryAlgorithmType
	// likeQueryAlgorithmDefinition
	LikeQueryAlgorithm *LikeQueryAlgorithmType
}

type EncryptionAlgorithmType struct {
	AlgorithmType
}
type AssistedQueryAlgorithmType struct {
	AlgorithmType
}
type LikeQueryAlgorithmType struct {
	AlgorithmType
}

type AlgorithmType struct {
	Name       string
	Properties Properties
}

type Properties map[string]string

func (r *Column) ToDistSQL() string {
	var stmt string
	stmt = fmt.Sprintf("NAME=%s ", r.Name)

	if len(r.Plain) != 0 {
		stmt = fmt.Sprintf("%s, PLAIN=%s ", stmt, r.Plain)
	}
	if len(r.Cipher) != 0 {
		stmt = fmt.Sprintf("%s, CIPHER=%s ", stmt, r.Cipher)
	}
	if len(r.AssistedQueryColumn) != 0 {
		stmt = fmt.Sprintf("%s, ASSISTED_QUERY_COLUMN=%s ", stmt, r.AssistedQueryColumn)
	}
	if len(r.LikeQueryColumn) != 0 {
		stmt = fmt.Sprintf("%s, LIKE_QUERY_COLUMN=%s ", stmt, r.LikeQueryColumn)
	}

	if r.EncryptionAlgorithm != nil {
		stmt = fmt.Sprintf("%s, %s,", stmt, r.EncryptionAlgorithm.ToDistSQL())
	}
	if r.AssistedQueryAlgorithm != nil {
		stmt = fmt.Sprintf("%s, %s,", stmt, r.AssistedQueryAlgorithm.ToDistSQL())
	}
	if r.LikeQueryAlgorithm != nil {
		stmt = fmt.Sprintf("%s, %s,", stmt, r.LikeQueryAlgorithm.ToDistSQL())
	}
	stmt = strings.TrimSuffix(stmt, ",")

	return stmt
}

func (r *EncryptionAlgorithmType) ToDistSQL() string {
	return fmt.Sprintf("ENCRYPT_ALGORITHM(%s)", r.AlgorithmType.ToDistSQL())
}

func (r *AssistedQueryAlgorithmType) ToDistSQL() string {
	return fmt.Sprintf("ASSISTED_QUERY_ALGORITHM(%s)", r.AlgorithmType.ToDistSQL())
}

func (r *LikeQueryAlgorithmType) ToDistSQL() string {
	return fmt.Sprintf("LIKE_QUERY_ALGORITHM(%s)", r.AlgorithmType.ToDistSQL())
}

func (r *AlgorithmType) ToDistSQL() string {
	var stmt string
	if len(r.Properties) == 0 {
		stmt = fmt.Sprintf("NAME='%s'", r.Name)
	} else {
		for k, v := range r.Properties {
			if len(stmt) != 0 {
				stmt = fmt.Sprintf("%s, '%s'='%s',", stmt, k, v)
			} else {
				stmt = fmt.Sprintf("'%s'='%s',", k, v)
			}
		}
		stmt = strings.TrimSuffix(stmt, ",")
		stmt = fmt.Sprintf("NAME=%s, PROPERTIES(%s)", r.Name, stmt)
	}

	return fmt.Sprintf("TYPE(%s)", stmt)
}
