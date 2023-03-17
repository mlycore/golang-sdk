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

package encryption

import (
	"testing"
)

func Test_CreateEncryptRule(t *testing.T) {
	r := CreateEncryptRule{
		EncryptRule{
			IfNotExist: true,
			EncryptDefinitions: []EncryptDefinition{
				{
					Name: "t_encrypt",
					Columns: []Column{
						{
							Name:   "user_id",
							Plain:  "user_plain",
							Cipher: "user_cipher",
							EncryptionAlgorithm: &EncryptionAlgorithmType{
								AlgorithmType: AlgorithmType{
									Name: "AES",
									Properties: map[string]string{
										"aes-key-value": "123456abc",
									},
								},
							},
						},
						{
							Name:   "order_id",
							Cipher: "order_cipher",
							EncryptionAlgorithm: &EncryptionAlgorithmType{
								AlgorithmType: AlgorithmType{
									Name: "MD5",
								},
							},
						},
					},
					QueryWithCipherColumn: true,
				},
				{
					Name: "t_encrypt_2",
					Columns: []Column{
						{
							Name:   "user_id",
							Plain:  "user_plain",
							Cipher: "user_cipher",
							EncryptionAlgorithm: &EncryptionAlgorithmType{
								AlgorithmType: AlgorithmType{
									Name: "AES",
									Properties: map[string]string{
										"aes-key-value": "123456abc",
									},
								},
							},
						},
						{
							Name:   "order_id",
							Cipher: "order_cipher",
							EncryptionAlgorithm: &EncryptionAlgorithmType{
								AlgorithmType: AlgorithmType{
									Name: "MD5",
								},
							},
						},
					},
					QueryWithCipherColumn: false,
				},
			},
		},
	}

	t.Logf("%s\n", r.ToDistSQL())
}

func Test_EncryptRule(t *testing.T) {
	r := EncryptRule{
		IfNotExist: false,
		EncryptDefinitions: []EncryptDefinition{
			{
				Name: "t_encrypt",
				Columns: []Column{
					{
						Name:   "user_id",
						Plain:  "user_plain",
						Cipher: "user_cipher",
						EncryptionAlgorithm: &EncryptionAlgorithmType{
							AlgorithmType: AlgorithmType{
								Name: "AES",
								Properties: map[string]string{
									"aes-key-value": "123456abc",
								},
							},
						},
					},
					{
						Name:   "order_id",
						Cipher: "order_cipher",
						EncryptionAlgorithm: &EncryptionAlgorithmType{
							AlgorithmType: AlgorithmType{
								Name: "MD5",
							},
						},
					},
				},
				QueryWithCipherColumn: true,
			},
			{
				Name: "t_encrypt_2",
				Columns: []Column{
					{
						Name:   "user_id",
						Plain:  "user_plain",
						Cipher: "user_cipher",
						EncryptionAlgorithm: &EncryptionAlgorithmType{
							AlgorithmType: AlgorithmType{
								Name: "AES",
								Properties: map[string]string{
									"aes-key-value": "123456abc",
								},
							},
						},
					},
					{
						Name:   "order_id",
						Cipher: "order_cipher",
						EncryptionAlgorithm: &EncryptionAlgorithmType{
							AlgorithmType: AlgorithmType{
								Name: "MD5",
							},
						},
					},
				},
				QueryWithCipherColumn: false,
			},
		},
	}

	t.Logf("%s\n", r.ToDistSQL())

}

func Test_AlgorithmTypeToDistSQL(t *testing.T) {
	algo := &AlgorithmType{
		Name: "MD5",
		Properties: map[string]string{
			"aes-key-value": "123456abc",
		},
	}

	t.Logf("%s\n", algo.ToDistSQL())
}

func Test_ColumnToDistSQL(t *testing.T) {
	col := &Column{
		Name:   "user_id",
		Plain:  "user_plain",
		Cipher: "user_cipher",
		EncryptionAlgorithm: &EncryptionAlgorithmType{
			AlgorithmType: AlgorithmType{
				Name: "AES",
				Properties: map[string]string{
					"aes-key-value": "123456abc",
				},
			},
		},
	}

	t.Logf("%s\n", col.ToDistSQL())
}

func Test_EncryptDefinitionToDistSQL(t *testing.T) {
	e := &EncryptDefinition{
		Name: "t_encrypt",
		Columns: []Column{
			{
				Name:   "user_id",
				Plain:  "user_plain",
				Cipher: "user_cipher",
				EncryptionAlgorithm: &EncryptionAlgorithmType{
					AlgorithmType: AlgorithmType{
						Name: "AES",
						Properties: map[string]string{
							"aes-key-value": "123456abc",
						},
					},
				},
			},
			{
				Name:   "order_id",
				Cipher: "order_cipher",
				EncryptionAlgorithm: &EncryptionAlgorithmType{
					AlgorithmType: AlgorithmType{
						Name: "MD5",
					},
				},
			},
		},
		QueryWithCipherColumn: true,
	}

	t.Logf("%s\n", e.ToDistSQL())
}

func Test_DropEncryptRule(t *testing.T) {
	e := &DropEncryptRule{
		EncryptRule: EncryptRule{
			IfExsits: true,
			EncryptDefinitions: EncryptDefinitionList{
				{
					Name: "t_encrypt",
				},
				{
					Name: "t_encrypt_2",
				},
			},
		},
	}

	t.Logf("%s\n", e.ToDistSQL())
}
