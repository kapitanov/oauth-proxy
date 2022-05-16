package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var (
	ClientID     = ReadEnv("GH_CLIENT_ID", "")
	ClientSecret = ReadEnv("GH_CLIENT_SECRET", "")
	BackendURL   = strings.TrimSuffix(ReadEnv("BACKEND_URL", ""), "/")
	ListenAddr   = ReadEnv("LISTEN_ADDR", "0.0.0.0:8080")
	ServerURL    = ReadEnv("PUBLIC_URL", "")
	RedirectURL  = fmt.Sprintf("%s/_/login", ReadEnv("PUBLIC_URL", ""))
	ValidUsers   = GenerateUsers(ReadEnv("GH_USERS", ""))
)

var (
	reverseProxy *httputil.ReverseProxy
)

func ReadEnv(key, val string) string {
	s := os.Getenv(key)
	if s == "" {
		s = val
	}

	if s == "" {
		panic(fmt.Sprintf("missing env variable %s", key))
	}

	return s
}

func GenerateUsers(s string) map[string]struct{} {
	m := make(map[string]struct{})

	strs := strings.FieldsFunc(s, func(c rune) bool {
		return c == ' ' || c == ',' || c == ';'
	})
	for _, str := range strs {
		str = strings.TrimSpace(str)
		if str != "" {
			m[str] = struct{}{}
		}
	}

	return m
}

func main() {
	backendURL, err := url.Parse(BackendURL)
	if err != nil {
		panic(err)
	}

	reverseProxy = httputil.NewSingleHostReverseProxy(backendURL)
	log.Printf("backend url: %v", backendURL)

	mux := http.NewServeMux()

	mux.HandleFunc("/_/login", LoginHandler)
	mux.HandleFunc("/", ContentHandler)

	log.Printf("listening on %v", ListenAddr)
	err = http.ListenAndServe(ListenAddr, mux)
	if err != nil {
		panic(err)
	}
}

type GithubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

func CheckAccessToken(accessToken string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return false, err
	}

	req.Header = http.Header{
		"Authorization": []string{fmt.Sprintf("token %s", accessToken)},
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("unable to get user info: %d", resp.StatusCode)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var user GithubUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		return false, err
	}

	if _, exists := ValidUsers[strings.ToLower(user.Login)]; !exists {
		log.Printf("user %v has no access to this site", user.Login)
		return false, nil
	}

	return true, nil
}

func RedeemCode(code string) (string, error) {
	resp, err := http.PostForm("https://github.com/login/oauth/access_token", url.Values{
		"client_id":     []string{ClientID},
		"client_secret": []string{ClientSecret},
		"code":          []string{code},
		"redirect_uri":  []string{RedirectURL},
	})
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("unable to get access token: %d", resp.StatusCode)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", err
	}

	if !values.Has("access_token") {
		return "", fmt.Errorf("missing access token in response")
	}

	return values.Get("access_token"), nil
}

const (
	AccessTokenCookie = "access_token"
)

func ContentHandler(w http.ResponseWriter, req *http.Request) {
	cookie, _ := req.Cookie(AccessTokenCookie)
	if cookie == nil {
		RenderLoginPage(w, req)
		return
	}

	ok, err := CheckAccessToken(cookie.Value)
	if err != nil {
		log.Printf("unable to check access: %v", err)

		cookie := &http.Cookie{
			Name:   AccessTokenCookie,
			Value:  "",
			Secure: true,
			Path:   "/",
			MaxAge: -1,
		}
		w.Header().Add("Set-Cookie", cookie.String())

		model := &ErrorPageModel{
			Code:        "internal error",
			Description: "",
		}
		RenderTemplatePage(w, req, http.StatusBadRequest, "error.html", model)
		return
	}

	if !ok {
		cookie := &http.Cookie{
			Name:   AccessTokenCookie,
			Value:  "",
			Secure: true,
			Path:   "/",
			MaxAge: -1,
		}
		w.Header().Add("Set-Cookie", cookie.String())

		model := &ErrorPageModel{
			Code:        "Forbidden",
			Description: "You don't have an access to this page",
		}
		RenderTemplatePage(w, req, http.StatusForbidden, "error.html", model)
		return
	}

	reverseProxy.ServeHTTP(w, req)
}

func LoginHandler(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	if query.Has("error") {
		query := req.URL.Query()
		model := &ErrorPageModel{
			Code:        query.Get("error"),
			Description: query.Get("error_description"),
			ErrorURL:    query.Get("error_uri"),
		}
		RenderTemplatePage(w, req, http.StatusBadRequest, "error.html", model)
		return
	}

	if !query.Has("code") {
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusFound)
		return
	}

	accessToken, err := RedeemCode(query.Get("code"))
	if err != nil {
		log.Printf("unable to redeem code: %v", err)

		model := &ErrorPageModel{
			Code:        "unable to get access",
			Description: "",
		}
		RenderTemplatePage(w, req, http.StatusBadRequest, "error.html", model)
		return
	}

	redirectTo := query.Get("redirect_to")
	if redirectTo == "" {
		redirectTo = "/"
	}

	cookie := &http.Cookie{
		Name:   AccessTokenCookie,
		Value:  accessToken,
		Secure: true,
		Path:   "/",
	}

	w.Header().Set("Location", redirectTo)
	w.Header().Add("Set-Cookie", cookie.String())
	w.WriteHeader(http.StatusFound)
}

type LoginPageModel struct {
	RedirectURL string
}

func RenderLoginPage(w http.ResponseWriter, req *http.Request) {
	u := fmt.Sprintf("%s%s", ServerURL, req.URL.Path)
	u = fmt.Sprintf("%s?redirect_to=%s", RedirectURL, url.QueryEscape(u))
	u = fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s&scope=%s",
		"https://github.com/login/oauth/authorize",
		url.QueryEscape(ClientID),
		url.QueryEscape(u),
		url.QueryEscape("read:user"))
	model := &LoginPageModel{
		RedirectURL: u,
	}
	RenderTemplatePage(w, req, http.StatusUnauthorized, "login.html", model)
}

type ErrorPageModel struct {
	Code        string
	Description string
	ErrorURL    string
}

func RenderTemplatePage(w http.ResponseWriter, r *http.Request, status int, name string, model interface{}) {
	t, err := template.ParseFiles(filepath.Join(".", "www", name))
	if err != nil {
		log.Printf("unable to load template '%s': %v", name, err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = t.Execute(w, model)
	if err != nil {
		log.Printf("unable to render template '%s': %v", name, err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
}
