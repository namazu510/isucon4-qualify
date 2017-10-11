package main

import (
	"database/sql"
	"errors"
	"github.com/cornelk/hashmap"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	// 初期状態だと、ユーザIDは約5500、アクセス元IPは約1万6千。
	// コリジョンの発生確率を下げるため、それぞれ10倍の空間を予約しておく。
	UserMapSize = 2000000 * 10
	IPMapSize   = 16000 * 10
	InitTimeout = 58 * time.Second
)

var (
	ErrBannedIP      = errors.New("Banned IP")
	ErrLockedUser    = errors.New("Locked user")
	ErrUserNotFound  = errors.New("Not found user")
	ErrWrongPassword = errors.New("Wrong password")

	// 初期状態だと、ユーザIDは約5500、アクセス元IPは約1万6千。
	// コリジョンの発生確率を下げるため、それぞれ10倍の空間を予約しておく。
	bannedIPMap   = hashmap.New(IPMapSize)
	bannedUserMap = hashmap.New(UserMapSize)

	bannedIPLock   = new(sync.RWMutex)
	bannedUserLock = new(sync.RWMutex)

	userMap = map[string]*User{}
)

func createLoginLog(succeeded bool, remoteAddr, login string, user *User) error {
	succ := 0
	if succeeded {
		succ = 1
	}

	var userId sql.NullInt64
	if user != nil {
		userId.Int64 = int64(user.ID)
		userId.Valid = true
	}

	_, err := db.Exec(
		"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
			"VALUES (?,?,?,?,?)",
		time.Now(), userId, login, remoteAddr, succ,
	)

	return err
}

func isLockedUser(user *User) (bool, error) {
	if user == nil {
		return false, nil
	}

	bannedUserLock.Lock()
	p, exists := bannedUserMap.Get(strconv.Itoa(user.ID))
	if !exists {
		bannedUserLock.Unlock()
		return false, nil
	}

	counter := (*int64)(p)
	c := int(atomic.LoadInt64(counter))
	res := UserLockThreshold <= c
	bannedUserLock.Unlock()
	return res, nil
}

func isBannedIP(ip string) (bool, error) {
	bannedIPLock.Lock()
	p, exists := bannedIPMap.GetStringKey(ip)
	if !exists {
		bannedIPLock.Unlock()
		return false, nil
	}

	counter := (*int64)(p)
	c := int(atomic.LoadInt64(counter))
	res := IPBanThreshold <= int(c)
	bannedIPLock.Unlock()
	return res, nil
}

func attemptLogin(req *http.Request) (*User, error) {
	succeeded := false
	loginName := req.PostFormValue("login")
	password := req.PostFormValue("password")
	user, ok := userMap[loginName]
	if !ok {
		user = &User{}
		rows, _ := db.Query("SELECT id, login, password_hash, salt from users WHERE login = ?", loginName)
		defer rows.Close()
		if rows.Next() {
			rows.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)
			userMap[loginName] = user
		} else {
			// do nothing
			user = nil
		}
	}

	remoteAddr := req.RemoteAddr
	if xForwardedFor := req.Header.Get("X-Forwarded-For"); len(xForwardedFor) > 0 {
		remoteAddr = xForwardedFor
	}

	defer func() {
		createLoginLog(succeeded, remoteAddr, loginName, user)

		var defaultValue int64 = 0
		var userFailures, ipFailures *int64

		bannedIPLock.Lock()
		p2, _ := bannedIPMap.GetOrInsert(remoteAddr, unsafe.Pointer(&defaultValue))
		ipFailures = (*int64)(p2)
		if succeeded {
			for !atomic.CompareAndSwapInt64(ipFailures, atomic.LoadInt64(ipFailures), 0) {
			}
		} else {
			atomic.AddInt64(ipFailures, 1)
		}
		bannedIPLock.Unlock()

		if user == nil {
			return
		}

		bannedUserLock.Lock()
		p1, _ := bannedUserMap.GetOrInsert(strconv.Itoa(user.ID), unsafe.Pointer(&defaultValue))
		userFailures = (*int64)(p1)
		if succeeded {
			for !atomic.CompareAndSwapInt64(userFailures, atomic.LoadInt64(userFailures), 0) {
			}
			for !atomic.CompareAndSwapInt64(ipFailures, atomic.LoadInt64(ipFailures), 0) {
			}
		} else {
			atomic.AddInt64(userFailures, 1)
			atomic.AddInt64(ipFailures, 1)
		}
		bannedUserLock.Unlock()
	}()

	if banned, _ := isBannedIP(remoteAddr); banned {
		return nil, ErrBannedIP
	}

	if locked, _ := isLockedUser(user); locked {
		return nil, ErrLockedUser
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.PasswordHash != calcPassHash(password, user.Salt) {
		return nil, ErrWrongPassword
	}

	succeeded = true
	return user, nil
}

func getCurrentUser(userId interface{}) *User {
	user := &User{}
	row := db.QueryRow(
		"SELECT id, login, password_hash, salt FROM users WHERE id = ?",
		userId,
	)
	err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	if err != nil {
		return nil
	}

	return user
}

func bannedIPs() []string {
	ips := []string{}

	rows, err := db.Query(
		"SELECT ip FROM "+
			"(SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) "+
			"AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?",
		IPBanThreshold,
	)

	if err != nil {
		return ips
	}

	defer rows.Close()
	for rows.Next() {
		var ip string

		if err := rows.Scan(&ip); err != nil {
			return ips
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return ips
	}

	rowsB, err := db.Query(
		"SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip",
	)

	if err != nil {
		return ips
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var ip string
		var lastLoginId int

		if err := rows.Scan(&ip, &lastLoginId); err != nil {
			return ips
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id",
			ip, lastLoginId,
		).Scan(&count)

		if err != nil {
			return ips
		}

		if IPBanThreshold <= count {
			ips = append(ips, ip)
		}
	}
	if err := rowsB.Err(); err != nil {
		return ips
	}

	return ips
}

func lockedUsers() []string {
	userIds := []string{}

	rows, err := db.Query(
		"SELECT user_id, login FROM "+
			"(SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) "+
			"AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?",
		UserLockThreshold,
	)

	if err != nil {
		return userIds
	}

	defer rows.Close()
	for rows.Next() {
		var userId int
		var login string

		if err := rows.Scan(&userId, &login); err != nil {
			return userIds
		}
		userIds = append(userIds, login)
	}
	if err := rows.Err(); err != nil {
		return userIds
	}

	rowsB, err := db.Query(
		"SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id",
	)

	if err != nil {
		return userIds
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var userId int
		var login string
		var lastLoginId int

		if err := rowsB.Scan(&userId, &login, &lastLoginId); err != nil {
			return userIds
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id",
			userId, lastLoginId,
		).Scan(&count)

		if err != nil {
			return userIds
		}

		if UserLockThreshold <= count {
			userIds = append(userIds, login)
		}
	}
	if err := rowsB.Err(); err != nil {
		return userIds
	}

	return userIds
}

func warmCache(timeout time.Time) {
	rows, _ := db.Query(
		"SELECT id, ip , succeeded FROM login_log ORDER BY id ASC",
	)
	for rows.Next() {
		var ip string
		var id int64
		var succeeded bool
		rows.Scan(&id, &ip, &succeeded)

		var defaultValue int64 = 0
		var userFailures, ipFailures *int64

		p1, _ := bannedUserMap.GetOrInsert(strconv.FormatInt(id, 10), unsafe.Pointer(&defaultValue))
		userFailures = (*int64)(p1)
		p2, _ := bannedIPMap.GetOrInsert(ip, unsafe.Pointer(&defaultValue))
		ipFailures = (*int64)(p2)

		if succeeded {
			for !atomic.CompareAndSwapInt64(userFailures, atomic.LoadInt64(userFailures), 0) {
			}
			for !atomic.CompareAndSwapInt64(ipFailures, atomic.LoadInt64(ipFailures), 0) {
			}
		} else {
			atomic.AddInt64(userFailures, 1)
			atomic.AddInt64(ipFailures, 1)
		}

		if time.Now().After(timeout) {
			return
		}
	}
}
