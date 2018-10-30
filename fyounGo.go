
package main

import (
	"./proto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ConfigJson struct {
	LoginURL string `json:"login_url"`
	QrParams string `json:"qr_params"`
	PwdParams string `json:"pwd_params"`
	OlineParams string `json:"oline_params"`
	StatusParams string `json:"status_params"`
	KickParams string `json:"kick_params"`
	Host string `json:"host"`
	Path []string `json:"path"`
	Header struct {
		UserAgent string `json:"User-Agent"`
		Accept string `json:"Accept"`
		ContentType string `json:"Content-Type"`
		AppSign string `json:"App-Sign"`
		Authorization string `json:"Authorization"`
	} `json:"header"`
	Params struct {
		Mobile string `json:"mobile"`
		Password string `json:"password"`
		Cv string `json:"cv"`
		ServerDid string `json:"server_did"`
		Pubc int `json:"pubc"`
		Vv int `json:"vv"`
		Mm string `json:"mm"`
		Sv string `json:"sv"`
		Imsi string `json:"imsi"`
		Model string `json:"model"`
		Rl string `json:"rl"`
		Did string `json:"did"`
		Version string `json:"version"`
		Type int `json:"type"`
		Time int `json:"time"`
		Sign string `json:"sign"`
		SysVersion int `json:"sysVersion"`
		Mscgip string `json:"mscgip"`
		Wlanuserip string `json:"wlanuserip"`
		Mac string `json:"mac"`
		Netmask string `json:"netmask"`
		Gateway string `json:"gateway"`
		Bssid string `json:"bssid"`
		Routerip string `json:"routerip"`
		Wlanusermac string `json:"wlanusermac"`
		Userlocation string `json:"userlocation"`
	} `json:"params"`
	Userid string `json:"userid"`
	AppSign64 string `json:"appSign64"`
	UnsignStr string `json:"unsign_str"`
}

type RequestResult struct {
	Status   string `json:"status"`
	Response string `json:"response"`
	Time int64 `json:"time"`
}

const HOST = "https://wifi.loocha.cn"

var PATH = [5]string{
	"/wifi/v3/qrcode", "/wifi/v3/pwd", "/wifi/v3/login", "/wifi/v3/status", "/wifi/v3/kickoff"}

var KEY string //解密密钥
var REQUEST_TIME int64
var CONFIG *ConfigJson

func main() {
	//account := flag.String("a", "", "The `account(phone number)` of ChinaTelecom(required!).")
	//passwd := flag.String("p", "", "The `password` of '掌上大学'(required!).")
	name := flag.String("n", "plus", "The `device name`.")

	flag.Parse() //解析输入的参数

	dat, errf := ioutil.ReadFile("config.json")
	if errf != nil {
		println(errf)
		exit()
	}
	myc = newClient(10);

	CONFIG = &ConfigJson{}
	errj := json.Unmarshal(dat, CONFIG)

	if errj != nil {
		println(errj)
		exit()
	}

	initial()

	if CONFIG.Userid == "" {
		//if (*account == "" || *passwd == "") {
		//	print("The -a [account] and the -p [password] must be set!\nUsing -h to see more.")
		//	exit()
		//}
		println("account: ", CONFIG.Params.Mobile, ", password: ",CONFIG.Params.Password, ", device name: ", *name)
		initial_first(CONFIG.Params.Mobile,CONFIG.Params.Password)

	}
	if (*name != "") {
		CONFIG.Params.Model = *name
	}
	for i := 0; i < len(PATH); i++ {
		PATH[i] = "/" + CONFIG.Userid + PATH[i]
	}
	//f,_ := json.Marshal(CONFIG)
	//ioutil.WriteFile("config.json",f,os.ModeAppend)

	for{
		if(!test_network()) {
			online();
		}
		time.Sleep(time.Duration(10)*time.Second)
	}

}

func do_request(urlstring string, ipath int) (*RequestResult,error){

	var ipath_ string
	if ipath == 0 || ipath == 2 {
		ipath_ = "POST"
	} else if ipath == 4 {
		ipath_= "DELETE"
	} else {
		ipath_= "GET"
	}

	req, err := http.NewRequest(ipath_, encode(urlstring), nil)
	req.Header.Add("User-Agent", CONFIG.Header.UserAgent)
	req.Header.Add("Accept", CONFIG.Header.Accept)
	req.Header.Add("Content-Type", CONFIG.Header.ContentType)
	req.Header.Add("App-Sign", CONFIG.Header.AppSign)
	req.Header.Add("Authorization", CONFIG.Header.Authorization)

	response, err := myc.Do(req)
	if err != nil {
		println(err)
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			println(err)
			return nil, err
		}
		datar,_ := DecryptDES_ECB(body,[]byte(KEY))
	    //println(string(datar))

		requestResult := &RequestResult{}
		errj2 := json.Unmarshal([]byte(datar), requestResult)
		if errj2 != nil {
			println(err)
			return nil,errj2
		}
		return requestResult, nil
	}
	return nil, nil
}

func get_sign(ipath int)(string){
	t :=  time.Now().UnixNano() / 1000000
	tts := strconv.FormatInt(t,10)
	REQUEST_TIME = t
	sub_appsign := get_sub_appsign(t)
	KEY = sub_appsign[0:8]

	var ttype int;
	if ipath == 3{
		ttype = 7
	}else if ipath == 4{
		ttype = 11
	}else{
		ttype = 4
	}
	spath := PATH[ipath]
	//{p[cv]}&mobile={p[mobile]}&model={p[model]}&path={path}&server_did={p[server_did]}&time={time}&type={type}{sub_app_sign}
	s := "app=" + CONFIG.Params.Cv + "&mobile=" + CONFIG.Params.Mobile + "&model=" + CONFIG.Params.Model + "&path=" + spath + "&server_did=" + CONFIG.Params.ServerDid + "&time=" + tts + "&type=" + strconv.Itoa(ttype) + sub_appsign
	//println(s)
	return md5f(s)
}

func get_sub_appsign(tt int64)(string){
	tts := strconv.FormatInt(tt,10)
	nums1,_ := strconv.Atoi(tts[3:7])
	nums2,_ := strconv.Atoi(tts[7:12])
	start := int(nums1 % 668)
	length := int(nums2 / 668)
	if length <= 7{
		length = 8
	}
	if (start + length) >= 668{
		start = 668 - length
	}
	s := CONFIG.AppSign64[start:start + length]
	return s
}

//初始化账号密码
func initial_first(mobile string,pwd string){
	generate_did()

	encodeString := base64.StdEncoding.EncodeToString([]byte(mobile + ":" + pwd))
	CONFIG.Header.Authorization = "Basic " + encodeString

	s,_ :=login();
	CONFIG.Userid = s
	println("user id：" + s)

}

func test_network()(bool){
	u := encode("http://test.f-young.cn/")
	req, _ := http.NewRequest("GET", u, nil)
	rep, _ := newClient(10).Do(req)
	defer rep.Body.Close()

	if rep.StatusCode == 302 {
		return true
	}
	return false
}
var myc *http.Client

func initial() (err error) {
	u := encode("http://pre.f-young.cn/js/conf.js")
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	rep, err := newClient(0).Do(req)
	if err != nil {
		return  err
	}
	if rep.StatusCode != 200 {
		return  errors.New("Not the Telecom campus network.")
	}else{
		defer rep.Body.Close()
		body, err := ioutil.ReadAll(rep.Body)
		if err != nil {
			return err
		}

		r,err:=regexp.Compile("LoochaCollege-(.+).apk") //(?:LoochaCollege-).*(?:-)
		if err!=nil{
			return err
		}
		version:=r.FindString(string(body))
		println("最新版本：" + version + "，当前版本：" + CONFIG.Params.Cv)
	}

	u = encode("http://test.f-young.cn/")
	req, err = http.NewRequest("GET", u, nil)
	if err != nil {
		return  err
	}
	defer rep.Body.Close()
	rep, err = http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return  err
	}
	defer rep.Body.Close()

	if rep.StatusCode == 302 {
		content := rep.Header.Get("Location")

		argString := strings.Split(content, "?")
		args := strings.SplitN(argString[1], "&", -1)
		for _, param := range args {
			if strings.Contains(param, "wlanuserip") {
				CONFIG.Params.Wlanuserip = strings.Split(param, "=")[1]
			}
			if strings.Contains(param, "mscgip") {
				CONFIG.Params.Mscgip = strings.Split(param, "=")[1]
			}
			if strings.Contains(param, "wlanusermac") {
				CONFIG.Params.Wlanusermac = strings.Split(param, "=")[1]
			}
			if strings.Contains(param, "userlocation") {
				CONFIG.Params.Userlocation = strings.Split(param, "=")[1]
			}
		}
		return nil
	}
	if rep.StatusCode == 200 {
		return  nil
	}

	return errors.New("Failed to detect net state!")
}

func login() (string,error) {
	//  "login_url": "https://cps.loocha.cn:9607/anony/login?1={p[cv]}&server_did={p[server_did]}&pubc=0&vv={p[vv]}&mm={p[model]}&sv={p[sv]}&imsi={p[imsi]}&rl={p[rl]}&version={p[version]}&auto=1&model={p[model]}",
	strr := "https://cps.loocha.cn:9607/anony/login?1=" + CONFIG.Params.Cv + "&server_did=" + CONFIG.Params.ServerDid + "&pubc=0&vv=" + strconv.Itoa(CONFIG.Params.Vv) + "&mm=" + CONFIG.Params.Model+ "&sv=" + CONFIG.Params.Sv + "&imsi=" + CONFIG.Params.Imsi + "&rl=" + CONFIG.Params.Rl + "&version=" + CONFIG.Params.Version + "&auto=1&model=" + CONFIG.Params.Model
	u := encode(strr)
	request, err := http.NewRequest("GET", u, nil)

	if err != nil {
		return "", err
	}
	request.Header.Add("User-Agent", CONFIG.Header.UserAgent)
	request.Header.Add("Accept", CONFIG.Header.Accept)
	request.Header.Add("Content-Type", CONFIG.Header.ContentType)
	request.Header.Add("App-Sign", CONFIG.Header.AppSign)
	request.Header.Add("Authorization", CONFIG.Header.Authorization)
	response, err := myc.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return "", err
		}

		// protobuf解析
		var loginResult cmessage.User;
		err = proto.Unmarshal(body, &loginResult)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(loginResult.Id,10),nil
		if loginResult.Status != 0 {
			return "", errors.New("Failed to resolve user info![0].")
		}
	}
	return "", errors.New("Failed to resolve user info![1].")
}

//生成随机的server_did 和did，无实际意义
//:return: did和server_did的字典类型
func generate_did(){
	t := float64(time.Now().UnixNano()) / 1000000000
	ram_str1 := md5f(strconv.FormatFloat(t, 'f', -1, 64))
	ram_str1 = strings.ToLower(ram_str1)
	ram_str2 := ram_str1[0:16]
	sdid := ram_str1[0:8] + "-" + ram_str1[8:12] + "-" + ram_str1[12:16] + "-" + ram_str1[16:20] + "-" + ram_str1[20:]
	ram_num := RandInt64(10000000,99999999)
	imie := "35362607" + strconv.FormatInt(ram_num,10)
	did := imie + "_null_" + ram_str2 + "_null_"
	CONFIG.Params.ServerDid = sdid
    CONFIG.Params.Did = did
    println("serverdid:"+ sdid + "||did:" + did)
}

func online() {
	qrcode := getQrCode()
	println("QRCode:" + qrcode)
	passwd := getPasswd()
	println("Password:" + passwd)

	//1={p[cv]}&server_did={p[server_did]}&pubc=0&vv={p[vv]}&mm={p[model]}&imsi=none&rl={p[rl]}&did={p[did]}&qrcode={qrcode}&code={pwd}&time={time}&sysVersion=1&sign={sign}",
	md5 := get_sign(2)
	str := HOST + PATH[2] + "?l=" + CONFIG.Params.Cv + "&server_did=" + CONFIG.Params.ServerDid + "&pubc=0&vv=" + strconv.Itoa(CONFIG.Params.Vv) + "&mm=" +  CONFIG.Params.Model + "&imsi=none&rl=" + CONFIG.Params.Rl + "&did=" + CONFIG.Params.Did + "&qrcode=" + qrcode + "&code=" + passwd + "&time=" + strconv.FormatInt(REQUEST_TIME,10)  + "&sysVersion=1&sign=" + md5
	u,err := do_request(str,2)
	println(str)
	if err != nil {
		println(err)
	}
	println(u.Response)
}

func getPasswd() (string) {
	//"pwd_params": "1={p[cv]}&server_did={p[server_did]}&pubc=0&vv={p[vv]}&mm={p[model]}&imsi=none&rl={p[rl]}&did={p[did]}&type=4&wwan=0&wanip={p[wlanuserip]}&time={time}&sign={sign}&sysVersion=1",
	md5 := get_sign(1)
	u,err := do_request(HOST +  PATH[1] + "?1="+ CONFIG.Params.Cv + "&server_did=" + CONFIG.Params.ServerDid + "&pubc=0&vv=" + strconv.Itoa(CONFIG.Params.Vv) + "&mm="+ CONFIG.Params.Model + "&imsi=none&rl=" + CONFIG.Params.Rl + "&did=" + CONFIG.Params.Did + "&type=4&wwan=0&wanip=" + CONFIG.Params.Wlanuserip + "&time=" + strconv.FormatInt(REQUEST_TIME,10) + "&sign=" + md5 + "&sysVersion=1",1)
	if err != nil {
		println(err)
		return ""
	}
	return u.Response
}

func getQrCode() (string) {
	//"qr_params": "1={p[cv]}&server_did={p[server_did]}&pubc=0&vv={p[vv]}&mm={p[model]}&sv={p[sv]}&imsi={p[imsi]}&rl={p[rl]}&did={p[did]}&type=4&time={time}&sign={sign}&sysVersion=1&brasip={p[mscgip]}&ulanip={p[wlanuserip]}&wlanip={p[wlanuserip]}&ssid=%40f-Young&mac={p[mac]}&netmask={p[netmask]}&gateway={p[gateway]}&bssid={p[bssid]}&routerIp={p[routerip]}",
	md5 := get_sign(0)
	url := HOST + PATH[0] + "?1="+ CONFIG.Params.Cv +"&server_did=" + CONFIG.Params.ServerDid + "&pubc=0&vv=" + strconv.Itoa(CONFIG.Params.Vv) + "&mm=" + CONFIG.Params.Model + "&sv=" + CONFIG.Params.Sv + "&imsi=" + CONFIG.Params.Imsi + "&rl=" + CONFIG.Params.Rl + "&did=" + CONFIG.Params.Did +"&type=4&time="+ strconv.FormatInt(REQUEST_TIME,10) + "&sign=" + md5  + "&sysVersion=1&brasip=" + CONFIG.Params.Mscgip +"&ulanip=" + CONFIG.Params.Wlanuserip  +"&wlanip=" + CONFIG.Params.Wlanuserip + "&ssid=%40f-Young&mac=" + CONFIG.Params.Mac + "&netmask=" + CONFIG.Params.Netmask + "&gateway=" + CONFIG.Params.Gateway + "&bssid=" + CONFIG.Params.Bssid + "&routerIp=" + CONFIG.Params.Routerip

	u,err := do_request(url, 0)

	if err != nil {
		println(err)
		return ""
	}
	return u.Response
}
