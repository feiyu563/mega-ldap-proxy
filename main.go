package main

import (
	"errors"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/astaxie/beego/orm"
	"github.com/go-ldap/ldap/v3"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"
)

func init() {
	db_driver := beego.AppConfig.String("INIT::db_driver")
	switch db_driver {
	case "sqlite3":
		// 检查数据库文件
		Db_name := "./db/Authorization.db"
		//os.Create(Db_name)
		// 注册驱动（“sqlite3” 属于默认注册，此处代码可省略）
		orm.RegisterDriver("db_driver", orm.DRSqlite)
		// 注册默认数据库
		orm.RegisterDataBase("default", "sqlite3", Db_name, 10)
	case "mysql":
		orm.RegisterDriver("mysql", orm.DRMySQL)
		orm.RegisterDataBase("default", "mysql", beego.AppConfig.String("INIT::db_user")+":"+beego.AppConfig.String("INIT::db_password")+"@tcp("+beego.AppConfig.String("INIT::db_host")+":"+beego.AppConfig.String("INIT::db_port")+")/"+beego.AppConfig.String("INIT::db_name")+"?charset=utf8mb4")
	case "postgres":
		orm.RegisterDriver("postgres", orm.DRPostgres)
		orm.RegisterDataBase("default", "postgres", "user="+beego.AppConfig.String("INIT::db_user")+" password="+beego.AppConfig.String("INIT::db_password")+" dbname="+beego.AppConfig.String("INIT::db_name")+" host="+beego.AppConfig.String("INIT::db_host")+" port="+beego.AppConfig.String("INIT::db_port")+" sslmode=disable")
	default:
		// 检查数据库文件
		Db_name := "./db/Authorization.db"
		//os.Create(Db_name)
		// 注册驱动（“sqlite3” 属于默认注册，此处代码可省略）
		orm.RegisterDriver("db_driver", orm.DRSqlite)
		// 注册默认数据库
		orm.RegisterDataBase("default", "sqlite3", Db_name, 10)
	}
	// 注册模型
	orm.RegisterModel(new(Authorization))
	orm.RunSyncdb("default", false, true)
}

func main() {
	version:="v1.0.0"
	logtype := beego.AppConfig.String("INIT::logtype")
	if logtype == "console" {
		logs.SetLogger(logtype)
	} else if logtype == "file" {
		logpath := beego.AppConfig.String("INIT::logpath")
		logs.SetLogger(logtype, `{"filename":"`+logpath+`"}`)
	}
	//代理转发目标
	http.HandleFunc("/", ProxyToBackend)
	//ldap登录
	http.HandleFunc("/ldaplogin", LdapLogin)
	http.HandleFunc("/ldapadmin", LdapAdmin)
	http.HandleFunc("/ldapadmindel", LdapAdminDel)
	//定义静态资源
	fsh := http.FileServer(http.Dir("proxystatic"))
	http.Handle("/proxystatic/", http.StripPrefix("/proxystatic/", fsh))

	logs.Info("[ "+time.Now().Format("2006/01/02 15:04:05")+" ] Start Proxy "+version+" On 0.0.0.0:"+beego.AppConfig.String("INIT::port"))
	http.ListenAndServe(":"+beego.AppConfig.String("INIT::port"), nil)
}
//登录
func LdapLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, _ := template.ParseFiles("views/login.html")
		t.Execute(w, nil)
	} else {
		//获取用户名和密码信息
		username:=r.FormValue("username")
		password:=r.FormValue("password")
		//判断用户名密码是否正确
		IsLogin,_:=LdapAuth(username,password)
		if IsLogin  {
			ck,_:=r.Cookie("olduri")
			olduri:=ck.Value
			maxage:= int(time.Hour * 24 / time.Second)
			cookiename := &http.Cookie{Name: "username",Value: username, MaxAge:maxage}
			cookiepass := &http.Cookie{Name: "password",Value: password, MaxAge:maxage}
			cookieuri := &http.Cookie{Name: "olduri",Value: "", MaxAge:maxage}
			http.SetCookie(w, cookiename)
			http.SetCookie(w, cookiepass)
			http.SetCookie(w, cookieuri)
			if olduri=="" {
				http.Redirect(w,r,"/",302)
			} else {
				http.Redirect(w,r,olduri,302)
			}
			return
		} else {
			var errmsg interface{}
			errmsg="用户名或密码错误，请重新输入！"
			t, _ := template.ParseFiles("views/login.html")
			t.Execute(w, errmsg)
			return
		}
	}

}
//管理员
func LdapAdmin(w http.ResponseWriter, r *http.Request) {
	IsLogin,_:=LdapAuthCheck(r)
	if !IsLogin {
		http.Redirect(w,r,"/ldaplogin",302)
		return
	}

	//检查是否是admin用户
	ck,err:=r.Cookie("username")
	if err!=nil {
		http.Redirect(w,r,"/ldaplogin",302)
		return
	}
	username:=ck.Value
	if IsNotAdmin(username) {
		//w.Write([]byte("你不是管理员，禁止操作!"))
		//return
		var errmsg interface{}
		errmsg="你不是管理员，禁止操作!"
		t, _ := template.ParseFiles("views/login.html")
		t.Execute(w, errmsg)
		return
	}
	if r.Method == "GET" {
		t, _ := template.ParseFiles("views/admin.html")

		Template, err := GetAllUserAuths()
		if err != nil {
			logs.Error(err)
		}
		t.Execute(w,  Template)

	} else {
		//获取表单信息
		user := r.FormValue("user")
		group := r.FormValue("group")
		auth := r.FormValue("auth")
		err:=AddUserAuth(user, group, auth)
		if err!=nil {
			logs.Error("添加用户权限失败：",err.Error())
		}
		http.Redirect(w,r,"/ldapadmin",302)
	}
}

func LdapAdminDel(w http.ResponseWriter, r *http.Request) {
	IsLogin,_:=LdapAuthCheck(r)
	if !IsLogin {
		http.Redirect(w,r,"/ldaplogin",302)
		return
	}
	//检查是否是admin用户
	ck,err:=r.Cookie("username")
	if err!=nil {
		http.Redirect(w,r,"/ldaplogin",302)
		return
	}
	username:=ck.Value
	if IsNotAdmin(username) {
		//w.Write([]byte("你不是管理员，禁止操作!"))
		//return
		var errmsg interface{}
		errmsg="你不是管理员，禁止操作!"
		t, _ := template.ParseFiles("views/login.html")
		t.Execute(w, errmsg)
		return
	}
	Del_id, _ := strconv.Atoi(r.FormValue("id"))
	err = DelUserAuth(Del_id)
	if err != nil {
		logs.Error("删除权限条目失败：",err)
	}
	http.Redirect(w,r,"/ldapadmin",302)
}
//IsNotAdmin
func IsNotAdmin(username string) bool {
	AdminUsers:=strings.Split(beego.AppConfig.String("INIT::adminuser"), ",")
	for _,Admin :=range AdminUsers {
		if username==Admin {
			return false
		}
	}
	return true
}
//代理开始处理请求
func ProxyToBackend(w http.ResponseWriter, r *http.Request) {
	//判断用户是否登录过
	IsLogin,Auths:=LdapAuthCheck(r)
	if  !IsLogin {
		maxage:= int(time.Hour * 24 / time.Second)
		cookieuri := &http.Cookie{Name: "olduri",Value: r.RequestURI, MaxAge:maxage}
		http.SetCookie(w, cookieuri)
		http.Redirect(w,r,"/ldaplogin",302)
		return
	}
	if Auths==nil {
		//w.Write([]byte("你没有权限访问，请联系管理员授权!"))
		//return
		var errmsg interface{}
		errmsg="你没有权限访问，请联系管理员（"+beego.AppConfig.String("INIT::adminuser")+"）授权访问！"
		t, _ := template.ParseFiles("views/login.html")
		t.Execute(w, errmsg)
		return
	}
	//打印用户访问的页面
	ck,_:=r.Cookie("username")
	username:=ck.Value
	logs.Info("[ "+time.Now().Format("2006/01/02 15:04:05")+" ] 用户：",username,"访问了URL：",r.RequestURI)

	client := &http.Client{}
	var resp  = &http.Response{}

	req, err := http.NewRequest(r.Method,beego.AppConfig.String("INIT::backend_url")+r.RequestURI,r.Body)
	req.Header=r.Header
	resp, err = client.Do(req)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer req.Body.Close()
	//处理返回
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil && err != io.EOF {
		http.NotFound(w, r)
		return
	}
	for i, j := range resp.Header {
		for _, k := range j {
			w.Header().Add(i, k)
		}
	}
	for _, c := range resp.Cookies() {
		w.Header().Add("Set-Cookie", c.Raw)
	}
	_, ok := resp.Header["Content-Length"]
	if !ok && resp.ContentLength > 0 {
		w.Header().Add("Content-Length", fmt.Sprint(resp.ContentLength))
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(data)
}

//LDAP相关
//检查cookie是否为登录状态
func LdapAuthCheck(r *http.Request) (IsLogin bool,authorization *Authorization) {
	ck,err:=r.Cookie("username")
	if err!=nil {
		return false,nil
	}
	username:=ck.Value
	ck,err=r.Cookie("password")
	if err!=nil {
		return false,nil
	}
	password:=ck.Value
	return LdapAuth(username,password)
}

func LdapAuth(user,passwd string) (IsLogin bool,authorization *Authorization)  {
	//连接ldap
	conn, err := ldap.Dial("tcp", beego.AppConfig.String("LDAP::ldap_url")+":"+beego.AppConfig.String("LDAP::ldap_port"))
	if err != nil {
		logs.Error("连接ldap:",err)
		return false,nil
	}
	defer conn.Close()
	//登录ldap
	err = conn.Bind(beego.AppConfig.String("LDAP::ldap_login"), beego.AppConfig.String("LDAP::ldap_password"))
	if err != nil {
		logs.Error("登录ldap:",err)
		return false,nil
	}
	//查询
	filter:="(&(objectClass=person)(uid="+user+"))"
	searchRequest := ldap.NewSearchRequest(
		beego.AppConfig.String("LDAP::ldap_basedn"),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn","ou"},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		logs.Error("查询:",err)
		return false,nil
	}

	//查询结果
	if len(sr.Entries) != 1 {
		logs.Error("查询结果: search 0 entry")
		return false,nil
	}
	//验证登录
	userDN := sr.Entries[0].DN
	err = conn.Bind(userDN, passwd)
	if err != nil {
		logs.Error("验证登录:bind password error: %v\n", err)
		return false,nil
	}else {
		logs.Info("验证登录: 用户: ",user,"组: ",sr.Entries[0].GetAttributeValue("ou"),"恭喜登录成功")
		return true,LdapAuthorization(user)
	}
}

//授权,返回可以访问的Url
func LdapAuthorization(user string) *Authorization  {
	UserAuth,err:=GetUserAuth(user)
	if err!=nil {
		logs.Error("尝试查找用户权限信息失败：",err.Error())
		return nil
	}
	return UserAuth
}

// 分类
type Authorization struct {
	Id      int		`orm:"pk;auto"`
	User 	string 	`orm:"index"`
	Group  	string
	Auth 	string
	Tpl     string 	`orm:"type(text)"`
	Created time.Time	`orm:"auto_now"`
}

func GetAllUserAuths() ([]*Authorization, error) {
	o := orm.NewOrm()
	Tpl_all := make([]*Authorization, 0)
	qs := o.QueryTable("Authorization")
	_, err := qs.All(&Tpl_all)
	return Tpl_all, err
}

func GetUserAuth(user string) (*Authorization, error) {
	o := orm.NewOrm()
	tpl_one := new(Authorization)
	qs := o.QueryTable("Authorization")
	err := qs.Filter("user", user).One(tpl_one)
	if err != nil {
		return tpl_one, err
	}
	return tpl_one, err
}

func DelUserAuth(id int) error {
	o := orm.NewOrm()
	tpl_one := &Authorization{Id: id}
	_, err := o.Delete(tpl_one)
	return err
}

func AddUserAuth(user, group, auth string) error {
	o := orm.NewOrm()
	qs := o.QueryTable("Authorization")
	bExist := qs.Filter("user", user).Exist()
	var err error
	if bExist {
		err = errors.New("已经存在！")
		return err
	}
	Template_table := &Authorization{
		User: 	user,
		Group: group,
		Auth:     auth,
	}
	// 插入数据
	_, err = o.Insert(Template_table)
	return err
}

func UpdateUserAuth(id int, user, group, tpl string) error {
	o := orm.NewOrm()
	tpl_update := &Authorization{Id: id}
	err := o.Read(tpl_update)
	if err == nil {
		tpl_update.Id = id
		tpl_update.User = user
		tpl_update.Group = group
		tpl_update.Tpl = tpl
		tpl_update.Created = time.Now()
		_, err := o.Update(tpl_update)
		return err
	}
	return err
}
