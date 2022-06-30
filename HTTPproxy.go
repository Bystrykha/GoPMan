package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var HTTPHeaders = map[string]string{"User-Agent":"", "Date":"", "ContentType":"",
	"ProxyConnection":"", "Accept":"", "Referer":"", "AcceptEncoding":"", "AcceptLanguage":""}
var payloadFlag = ""

func modifyCatalog(){
	fmt.Println("change http headers? [y/n]")
	var flag string
	fmt.Scanf("%s\n", &flag)
	if flag == "y"{
		for k := range HTTPHeaders{
			fmt.Print(k, " : ")
			var headerValue string
			fmt.Scanf("%s\n", &headerValue)
			HTTPHeaders[k] = headerValue
			fmt.Print("\n")
		}
	}
	fmt.Println("change payload? [y/n]")
	fmt.Scanf("%s\n", &payloadFlag)
}

type proxy struct {
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (p *proxy) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	log.Println(req.RemoteAddr, " ", req.Method, " ", req.URL)
	a := req.Header
	for k, v := range a{
		fmt.Println(k, ":", v)
	}

	for k, v := range HTTPHeaders{
		if v != "" {
			req.Header.Set(k, v)
		}
	}

	//req.Header.Set("User-Agent", "Golang_Spider_Bot/3.0")

	if payloadFlag == "y"{
		file, err := os.Open("payload.txt")
		if err != nil{
			os.Exit(0)
		}
		req.Body = ioutil.NopCloser(bufio.NewReader(file))
	}

	client := &http.Client{}
	req.RequestURI = ""
	resp, _ := client.Do(req)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	io.Copy(wr, resp.Body)
}

func main(){
	modifyCatalog()
	address := "127.0.0.1:8080"
	handler := &proxy{}

	log.Println("Starting proxy server on", address)
	if err := http.ListenAndServe(address, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
