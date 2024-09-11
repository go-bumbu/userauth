package staticusers

import (
	"encoding/json"
	"fmt"
	"github.com/go-bumbu/userauth"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)

// ensure the interface is fulfilled
var _ userauth.UserStore = &Users{}

type User struct {
	Id      string `yaml:"id" json:"id"`           // user Identifying string: e.g. name or email
	HashPw  string `yaml:"pw" json:"pw"`           // hashed passwd in one of the supported algorithms
	Enabled bool   `yaml:"enabled" json:"enabled"` // flag if user is enabled
}

// TODO: add option to allow plaintext passwords in files,
// and in consequence hash on init

type Users struct {
	Users []User `yaml:"users"`
}

func (stu *Users) GetUser(userId string) (userauth.User, error) {
	for _, u := range stu.Users {
		if userId == u.Id {
			return userauth.User{
				Id:      u.Id,
				HashPw:  u.HashPw,
				Enabled: u.Enabled,
			}, nil
		}
	}
	return userauth.User{}, userauth.NotFoundErr{}
}

// TODO remove
//func (stu *Users) CanLogin(user string, plainPw string) bool {
//	for _, u := range stu.Users {
//		if user == u.Id {
//			if !u.Enabled {
//				return false
//			}
//			access, err := userauth.CheckPass(plainPw, u.HashPw)
//			if err != nil {
//				return false
//			}
//			return access
//		}
//	}
//	return false
//}

// FromFile loads a file containing user information and returns static user
// possible files are json, yaml and htpasswd
func FromFile(file string) (*Users, error) {
	fType := fileType(file)

	switch fType {
	case ExtYaml, ExtYml:
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return yamlBytes(b)
	case ExtJson:
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return jsonBytes(b)
	default:
		return nil, fmt.Errorf("unsupported file format")
	}

}

// unmarshal a yaml containing users into a list of users
func yamlBytes(in []byte) (*Users, error) {
	data := Users{}
	err := yaml.Unmarshal(in, &data)
	if err != nil {
		return nil, err
	}
	return &data, err
}

// unmarshal a json containing users into a list of users
func jsonBytes(in []byte) (*Users, error) {
	data := Users{}
	err := json.Unmarshal(in, &data)
	if err != nil {
		return nil, err
	}
	return &data, err
}

const (
	ExtYaml = "YAML"
	ExtYml  = "YML"
	ExtJson = "JSON"
)

func fileType(fpath string) string {
	filename := filepath.Base(fpath)
	extension := strings.TrimPrefix(filepath.Ext(filename), ".")
	extension = strings.ToUpper(extension)
	switch extension {
	case ExtYaml:
		return ExtYaml
	case ExtJson:
		return ExtJson
	default:
		return ""
	}
}
