package main

import (
	"database/sql"
	"sync"
	"time"
)

type User struct {
	ID           int
	Login        string
	PasswordHash string
	Salt         string

	LastLogin *LastLogin
	lock      sync.RWMutex

	// NOTE: atomicパッケージを用いた場合、LastLoginを直接書き換えることが出来ない。
	//       unsafe.Pointerを型変換して使用する必要があるが、その場合テンプレートのレンダリングが不便になる。
	//       このような理由から、LastLoginの更新はlockを使った実装にした。
	//LastLoginPtr unsafe.Pointer
}

type LastLogin struct {
	Login     string
	IP        string
	CreatedAt time.Time
}

type CreateLoginLogArgs struct {
	CreateAt  time.Time
	UserId    sql.NullInt64
	Login     string
	IP        string
	Successed int
}

func (u *User) getLastLogin() *LastLogin {
	u.lock.RLock()
	defer u.lock.RUnlock()
	return u.LastLogin
}
