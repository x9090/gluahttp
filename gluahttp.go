package gluahttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/yuin/gopher-lua"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type httpModule struct {
	do func(req *http.Request) (*http.Response, error)
}

type empty struct{}

// Global variables for the target passed by VulnScan engine
var HostName string
var PortNum int

func NewHttpModule(client *http.Client, hostName string, portNum int) *httpModule {
	HostName = hostName
	PortNum = portNum
	return NewHttpModuleWithDo(client.Do)
}

func NewHttpModuleWithDo(do func(req *http.Request) (*http.Response, error)) *httpModule {
	return &httpModule{
		do: do,
	}
}

func (h *httpModule) Loader(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get":           h.get,
		"delete":        h.delete,
		"head":          h.head,
		"patch":         h.patch,
		"post":          h.post,
		"put":           h.put,
		"request":       h.request,
		"request_batch": h.requestBatch,
	})
	registerHttpResponseType(mod, L)
	L.Push(mod)
	return 1
}

func (h *httpModule) get(L *lua.LState) int {
	return h.doRequestAndPush(L, "get", L.ToString(1), L.ToTable(2))
}

func (h *httpModule) delete(L *lua.LState) int {
	return h.doRequestAndPush(L, "delete", L.ToString(1), L.ToTable(2))
}

func (h *httpModule) head(L *lua.LState) int {
	return h.doRequestAndPush(L, "head", L.ToString(1), L.ToTable(2))
}

func (h *httpModule) patch(L *lua.LState) int {
	return h.doRequestAndPush(L, "patch", L.ToString(1), L.ToTable(2))
}

func (h *httpModule) post(L *lua.LState) int {
	return h.doRequestAndPush(L, "post", L.ToString(1), L.ToTable(2))
}

func (h *httpModule) put(L *lua.LState) int {
	return h.doRequestAndPush(L, "put", L.ToString(1), L.ToTable(2))
}

func (h *httpModule) request(L *lua.LState) int {
	return h.doRequestAndPush(L, L.ToString(1), L.ToString(2), L.ToTable(3))
}

func (h *httpModule) requestBatch(L *lua.LState) int {
	requests := L.ToTable(1)
	amountRequests := requests.Len()

	errs := make([]error, amountRequests)
	responses := make([]*lua.LUserData, amountRequests)
	sem := make(chan empty, amountRequests)

	i := 0

	requests.ForEach(func(_ lua.LValue, value lua.LValue) {
		requestTable := toTable(value)

		if requestTable != nil {
			method := requestTable.RawGet(lua.LNumber(1)).String()
			url := requestTable.RawGet(lua.LNumber(2)).String()
			options := toTable(requestTable.RawGet(lua.LNumber(3)))

			go func(i int, L *lua.LState, method string, url string, options *lua.LTable) {
				response, err := h.doRequest(L, method, url, options)

				if err == nil {
					errs[i] = nil
					responses[i] = response
				} else {
					errs[i] = err
					responses[i] = nil
				}

				sem <- empty{}
			}(i, L, method, url, options)
		} else {
			errs[i] = errors.New("Request must be a table")
			responses[i] = nil
			sem <- empty{}
		}

		i = i + 1
	})

	for i = 0; i < amountRequests; i++ {
		<-sem
	}

	hasErrors := false
	errorsTable := L.NewTable()
	responsesTable := L.NewTable()
	for i = 0; i < amountRequests; i++ {
		if errs[i] == nil {
			responsesTable.Append(responses[i])
			errorsTable.Append(lua.LNil)
		} else {
			responsesTable.Append(lua.LNil)
			errorsTable.Append(lua.LString(fmt.Sprintf("%s", errs[i])))
			hasErrors = true
		}
	}

	if hasErrors {
		L.Push(responsesTable)
		L.Push(errorsTable)
		return 2
	} else {
		L.Push(responsesTable)
		return 1
	}
}
func randomBoundary(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (h *httpModule) doRequest(L *lua.LState, method string, url string, options *lua.LTable) (*lua.LUserData, error) {
	req, err := http.NewRequest(strings.ToUpper(method), url, nil)
	if err != nil {
		return nil, err
	}

	if ctx := L.Context(); ctx != nil {
		req = req.WithContext(ctx)
	}

	if options != nil {
		if reqCookies, ok := options.RawGet(lua.LString("cookies")).(*lua.LTable); ok {
			reqCookies.ForEach(func(key lua.LValue, value lua.LValue) {
				req.AddCookie(&http.Cookie{Name: key.String(), Value: value.String()})
			})
		}

		switch reqQuery := options.RawGet(lua.LString("query")).(type) {
		case lua.LString:
			req.URL.RawQuery = reqQuery.String()
		}

		body := options.RawGet(lua.LString("body"))
		if _, ok := body.(lua.LString); !ok {
			// "form" is deprecated.
			body = options.RawGet(lua.LString("form"))
			// Only set the Content-Type to application/x-www-form-urlencoded
			// when someone uses "form", not for "body".
			if _, ok := body.(lua.LString); ok {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}

		// Multipart encoding
		if files, ok := options.RawGet(lua.LString("files")).(*lua.LTable); ok {
			boundary, _ := randomBoundary(16)
			startBoundary := "--" + boundary + "\r\n"
			lastBoundary := "--" + boundary + "--\r\n"
			var disposBody []string
			files.ForEach(func(fileKey lua.LValue, fileValue lua.LValue) {
				//fmt.Println(fileKey, fileValue)

				if fileValue.Type() == lua.LTTable {
					formData := ""
					filenameData := ""
					toTable(fileValue).ForEach(func(vk lua.LValue, dataVal lua.LValue) {
						//fmt.Println(vk, dataVal)
						switch vk.(lua.LNumber) {
						case 1:
							filenameData = fmt.Sprintf(" filename=\"%s\"", dataVal.String())
						case 2:
							if len(filenameData) > 0 {
								formData = fmt.Sprintf("%s\r\n\r\n%s\r\n", filenameData, dataVal.String())
							} else {
								formData = fmt.Sprintf("\r\n\r\n%s\r\n", dataVal.String())
							}

						}
					})
					disposBody = append(disposBody, fmt.Sprintf("%sContent-Disposition: form-data; name=\"%s\";%s", startBoundary, fileKey.String(), formData))
				} else if fileValue.Type() == lua.LTString {
					disposBody = append(disposBody, fmt.Sprintf("%sContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n\r\n%s\r\n", startBoundary, fileKey.String(), fileKey.String(), fileValue.String()))
				}
			})
			// Setting last boundary
			body = lua.LString(strings.Join(disposBody, "") + lastBoundary)
			req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
		}

		switch reqBody := body.(type) {
		case lua.LString:
			body := reqBody.String()
			//fmt.Printf("body:\n%s", body)
			req.ContentLength = int64(len(body))
			req.Body = ioutil.NopCloser(strings.NewReader(body))
		}

		reqTimeout := options.RawGet(lua.LString("timeout"))
		if reqTimeout != lua.LNil {
			duration := time.Duration(0)
			switch reqTimeout.(type) {
			case lua.LNumber:
				duration = time.Second * time.Duration(int(reqTimeout.(lua.LNumber)))
			case lua.LString:
				duration, err = time.ParseDuration(string(reqTimeout.(lua.LString)))
				if err != nil {
					return nil, err
				}
			}
			ctx, cancel := context.WithTimeout(req.Context(), duration)
			req = req.WithContext(ctx)
			defer cancel()
		}

		// Set these last. That way the code above doesn't overwrite them.
		if reqHeaders, ok := options.RawGet(lua.LString("headers")).(*lua.LTable); ok {
			reqHeaders.ForEach(func(key lua.LValue, value lua.LValue) {
				req.Header.Set(key.String(), value.String())
			})
		}
	}

	res, err := h.do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	return newHttpResponse(res, &body, len(body), L), nil
}

func buildTargetBaseURL(hostName string, portNum int) string {
	url := hostName

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		switch portNum {
		case 80:
			url = fmt.Sprintf("http://%s", url)

		case 443:
			url = fmt.Sprintf("https://%s", url)

		default:
			fmt.Println("Unrecognized port, using default HTTPS with specified port number\n")
			url = fmt.Sprintf("https://%s:%d", url, portNum)
		}
	} else if portNum != 80 && portNum != 443 {
		url = fmt.Sprintf("%s:%d", hostName, portNum)
	}
	return url
}

//func (h *httpModule) doRequestAndPush(L *lua.LState, method string, url string, options *lua.LTable) int {
func (h *httpModule) doRequestAndPush(L *lua.LState, method string, path string, options *lua.LTable) int {
	baseURL := buildTargetBaseURL(HostName, PortNum)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := baseURL + path
	//fmt.Printf("Making request using URL: %s\n", url)
	response, err := h.doRequest(L, method, url, options)

	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("%s", err)))
		return 2
	}

	L.Push(response)
	return 1
}

func toTable(v lua.LValue) *lua.LTable {
	if lv, ok := v.(*lua.LTable); ok {
		return lv
	}
	return nil
}
