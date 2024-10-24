package dbusers

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// DbManager is an opinionated user manager that stores the information on a gorm database
type DbManager struct {
	db               *gorm.DB
	bcryptDifficulty int // exposed as parameter for make tests faster
}

type ManagerOpts struct {
	BcryptDifficulty int
}

// NewDbManager creates an instance of user manager
func NewDbManager(db *gorm.DB, opts ManagerOpts) (*DbManager, error) {

	// Migrate the schema
	err := db.AutoMigrate(&userModel{})
	if err != nil {
		return nil, err
	}

	return &DbManager{
		db:               db,
		bcryptDifficulty: opts.BcryptDifficulty, // set the cost of the difficulty
	}, nil
}

// userModel is the database representation of the user
type userModel struct {
	gorm.Model
	Email   string `gorm:"uniqueIndex"`
	Name    string
	Pw      string
	Enabled bool
	// last login
	// login location
}

type User struct {
	Name    string `yaml:"name"`
	Email   string `yaml:"email"`
	Pw      string `yaml:"pw"` // or hashed passwd
	Enabled bool   `yaml:"enabled"`
}

func (mng DbManager) Create(id string, pw string) error {
	usr := User{
		Email: id,
		Pw:    pw,
	}
	return mng.CreateUser(usr)
}

func (mng DbManager) CreateUser(usr User) error {

	if usr.Email == "" {
		// todo add email structure verifications
		return errors.New("email cannot be empty")
	}

	if usr.Pw == "" {
		// todo pw length and complexity verification
		return errors.New("password cannot be empty")
	}

	// generate bcrypt hashed password
	hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(usr.Pw), mng.bcryptDifficulty)
	if err != nil {
		return err
	}

	usrModel := userModel{
		Name:    usr.Name,
		Email:   usr.Email,
		Pw:      string(hashedPasswd),
		Enabled: usr.Enabled,
	}

	mng.db.Create(&usrModel)
	return nil
}

// AllowLogin checks if the user provided password is correct for login
// if no error is returned login is successful
func (mng DbManager) AllowLogin(user string, providedPass string) bool {

	var usr userModel

	// todo avoid record not found to be printed
	err := mng.db.First(&usr, "email = ?", user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Handle record not found error...
		return false
	}

	//if result.RowsAffected == 0 {
	//	return false
	//}

	// todo, does this use a salt?
	err = bcrypt.CompareHashAndPassword([]byte(usr.Pw), []byte(providedPass))
	return err == nil

}

//// GenJwtToken generates a signed jwt token
//func GenJwtToken() (string, error) {
//
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
//		"foo": "bar",
//		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
//	})
//
//	hmacSampleSecret := []byte("secret")
//	return token.SignedString(hmacSampleSecret)
//
//}

// use jwt to create a session ?
// login to create a session directly
// - interface session storage ( db, memory etc)
