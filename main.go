package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxRetries = 1
)

type MetaAI struct {
	session                *http.Client
	accessToken            string
	fbEmail                string
	fbPassword             string
	proxy                  map[string]string
	isAuthed               bool
	cookies                map[string]string
	externalConversationID string
	offlineThreadingID     string
}

type Payload struct {
	Message                    map[string]interface{} `json:"message"`
	ExternalConversationID     string                 `json:"externalConversationId"`
	OfflineThreadingID         string                 `json:"offlineThreadingId"`
	SuggestedPromptIndex       interface{}            `json:"suggestedPromptIndex"`
	FlashVideoRecapInput       map[string]interface{} `json:"flashVideoRecapInput"`
	FlashPreviewInput          interface{}            `json:"flashPreviewInput"`
	PromptPrefix               interface{}            `json:"promptPrefix"`
	Entrypoint                 string                 `json:"entrypoint"`
	IcebreakerType             string                 `json:"icebreaker_type"`
	RelayInternalAbraDebug     bool                   `json:"__relay_internal__pv__AbraDebugDevOnlyrelayprovider"`
	RelayInternalWebPixelRatio int                    `json:"__relay_internal__pv__WebPixelRatiorelayprovider"`
}

func NewMetaAI(fbEmail, fbPassword string, proxy map[string]string) (*MetaAI, error) {
	meta := &MetaAI{
		session:    &http.Client{},
		fbEmail:    fbEmail,
		fbPassword: fbPassword,
		proxy:      proxy,
		isAuthed:   fbPassword != "" && fbEmail != "",
	}

	if meta.proxy != nil && !meta.checkProxy("") {
		return nil, fmt.Errorf("unable to connect to proxy. please check your proxy settings")
	}

	cookies, err := meta.getCookies()
	if err != nil {
		return nil, err
	}
	meta.cookies = cookies
	return meta, nil
}

func (m *MetaAI) checkProxy(testURL string) bool {
	testURL = "https://api.ipify.org/?format=json"
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	resp, err := m.session.Do(req)
	if err != nil {
		return false
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		m.session.Transport = &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://%s", m.proxy["http"]))
			},
		}
		return true
	}
	return false
}

func extractValue(responseText string, startStr string, endStr string) string {
	startIdx := strings.Index(responseText, startStr)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(startStr)
	endIdx := strings.Index(responseText[startIdx:], endStr)
	if endIdx == -1 {
		return ""
	}
	return responseText[startIdx : startIdx+endIdx]
}
func (m *MetaAI) getAccessToken() (string, error) {
	if m.accessToken != "" {
		return m.accessToken, nil
	}

	URL := "https://www.meta.ai/api/graphql/"
	payload := url.Values{}
	payload.Add("lsd", m.cookies["lsd"])
	payload.Add("fb_api_caller_class", "RelayModern")
	payload.Add("fb_api_req_friendly_name", "useAbraAcceptTOSForTempUserMutation")
	payload.Add("variables", "{\"dob\": \"1970-01-01\", \"icebreaker_type\": \"TEXT\", \"__relay_internal__pv__WebPixelRatiorelayprovider\": 1}")
	payload.Add("server_timestamps", "true")
	payload.Add("doc_id", "7604648749596940")

	req, err := http.NewRequest("POST", URL, bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("cookie", fmt.Sprintf("_js_datr=%s; abra_csrf=%s; datr=%s;", m.cookies["_js_datr"], m.cookies["abra_csrf"], m.cookies["datr"]))
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("x-fb-friendly-name", "useAbraAcceptTOSForTempUserMutation")
	req.Header.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

	resp, err := m.session.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	var authJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&authJSON); err != nil {
		return "", fmt.Errorf("unable to receive a valid response from Meta AI. this is likely due to your region being blocked. try manually accessing https://www.meta.ai/ to confirm: %w", err)
	}

	m.accessToken = authJSON["data"].(map[string]interface{})["xab_abra_accept_terms_of_service"].(map[string]interface{})["new_temp_user_auth"].(map[string]interface{})["access_token"].(string)
	return m.accessToken, nil
}

func (m *MetaAI) prompt(message string, stream bool, attempts int, newConversation bool) (interface{}, error) {
	if !m.isAuthed {
		token, err := m.getAccessToken()
		if err != nil {
			return nil, err
		}
		m.accessToken = token
	}

	if m.externalConversationID == "" || newConversation {
		m.externalConversationID = uuid.New().String()
	}

	variables := map[string]interface{}{
		"message":                map[string]string{"sensitive_string_value": message},
		"externalConversationId": m.externalConversationID,
		"offlineThreadingId":     generateOfflineThreadingID(),
		"suggestedPromptIndex":   nil,
		"flashVideoRecapInput":   map[string][]string{"images": {}},
		"flashPreviewInput":      nil,
		"promptPrefix":           nil,
		"entrypoint":             "ABRA__CHAT__TEXT",
		"icebreaker_type":        "TEXT",
		"__relay_internal__pv__AbraDebugDevOnlyrelayprovider": false,
		"__relay_internal__pv__WebPixelRatiorelayprovider":    1,
	}

	variablesJSON, err := json.Marshal(variables)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal variables: %w", err)
	}

	payload := url.Values{}
	payload.Set("fb_api_caller_class", "RelayModern")
	payload.Set("fb_api_req_friendly_name", "useAbraSendMessageMutation")
	payload.Set("variables", string(variablesJSON))
	payload.Set("server_timestamps", "true")
	payload.Set("doc_id", "7783822248314888")

	if m.isAuthed {
		payload.Set("fb_dtsg", m.cookies["fb_dtsg"])
	} else {
		payload.Set("access_token", m.accessToken)
	}

	client := &http.Client{}
	if m.proxy["http"] != "" {
		client.Transport = &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://%s", m.proxy["http"]))
			},
		}
	}

	req, err := http.NewRequest("POST", "https://graph.meta.ai/graphql?locale=user", bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-fb-friendly-name", "useAbraSendMessageMutation")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

	if m.isAuthed {
		req.Header.Set("Cookie", fmt.Sprintf("datr=%s", m.cookies["datr"]))
	}

	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	for k, _ := range m.cookies {
		if k == "datr" {
			req.AddCookie(&http.Cookie{Name: k, Value: m.cookies[k]})
		}
	}
	resp, err := m.session.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lastStreamedResponse, err := m.extractLastResponse(string(body))
	if err != nil {
		return m.retry(message, stream, attempts)
	}

	extractedData, err := m.extractData(lastStreamedResponse)
	if err != nil {
		return m.retry(message, stream, attempts)
	}
	return extractedData, nil
}

func (m *MetaAI) retry(message string, stream bool, attempts int) (interface{}, error) {
	if attempts >= maxRetries {
		log.Printf("unable to obtain a valid response from Meta AI. retrying... attempt %d/%d", attempts+1, maxRetries)
		time.Sleep(3 * time.Second)
		return m.prompt(message, stream, attempts+1, false)
	}
	return nil, fmt.Errorf("unable to obtain a valid response from Meta AI. try again later")
}

func (m *MetaAI) extractLastResponse(response string) (map[string]interface{}, error) {
	var lastStreamedResponse map[string]interface{}
	var lastResp string
	lastResponse := strings.Split(response, "\n")
	if len(lastResponse) > 0 {
		lastResp = lastResponse[len(lastResponse)-1]
	}
	line := lastResp
	var jsonLine map[string]interface{}
	if err := json.Unmarshal([]byte(line), &jsonLine); err != nil {
		return nil, err
	}

	botResponseMessage, ok := jsonLine["data"].(map[string]interface{})["node"].(map[string]interface{})["bot_response_message"].(map[string]interface{})

	chatID, ok := botResponseMessage["id"].(string)
	if ok {
		parts := strings.Split(chatID, "_")
		m.externalConversationID = parts[0]
		m.offlineThreadingID = parts[1]
	}

	streamingState, ok := botResponseMessage["streaming_state"].(string)
	if ok && streamingState == "OVERALL_DONE" {
		lastStreamedResponse = jsonLine
	}
	if lastStreamedResponse == nil {
		return nil, fmt.Errorf("no valid last streamed response found")
	}
	return lastStreamedResponse, nil
}

func (m *MetaAI) extractData(jsonLine map[string]interface{}) (map[string]interface{}, error) {
	if jsonLine["data"] == nil || jsonLine["data"].(map[string]interface{})["node"] == nil {
		return nil, fmt.Errorf("invalid JSON line")
	}
	botResponseMessage, ok := jsonLine["data"].(map[string]interface{})["node"].(map[string]interface{})["bot_response_message"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid bot response message in JSON line")
	}

	response := formatResponse(jsonLine)
	if response == "" {
		return nil, fmt.Errorf("invalid response in bot response message")
	}
	_, ok = botResponseMessage["fetch_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid fetch ID in bot response message")
	}

	//sources, err := m.fetchSources(fetchID)
	//if err != nil {
	//	return nil, err
	//}

	return map[string]interface{}{
		"message": response,
		"sources": []map[string]interface{}{},
	}, nil
}

func (m *MetaAI) getCookies() (map[string]string, error) {
	m.session = &http.Client{}
	respSession, err := m.session.Get("https://www.meta.ai/")
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(respSession.Body)

	responseText := string(body)

	cookies := map[string]string{
		"_js_datr": extractValue(responseText, `_js_datr":{"value":"`, `",`),
		"datr":     extractValue(responseText, `datr":{"value":"`, `",`),
		"lsd":      extractValue(responseText, `"LSD",[],{"token":"`, `"}`),
		"fb_dtsg":  extractValue(responseText, `DTSGInitData",[],{"token":"`, `"`),
	}

	if len(respSession.Cookies()) > 0 {
		cookies["abra_sess"] = m.cookies["abra_sess"]
	} else {
		cookies["abra_csrf"] = extractValue(responseText, `abra_csrf":{"value":"`, `",`)
	}
	m.cookies = cookies
	time.Sleep(1 * time.Second)

	return cookies, nil
}

func (m *MetaAI) fetchSources(fetchID string) ([]map[string]interface{}, error) {
	URL := "https://graph.meta.ai/graphql?locale=user"
	var payload url.Values
	payload.Add("access_token", m.accessToken)
	payload.Add("fb_api_caller_class", "RelayModern")
	payload.Add("fb_api_req_friendly_name", "AbraSearchPluginDialogQuery")
	payload.Add("variables", "{\"abraMessageFetchID\":\""+fetchID+"\"}")
	payload.Add("server_timestamps", "true")
	payload.Add("doc_id", "6946734308765963")
	req, err := http.NewRequest("POST", URL, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("authority", "graph.meta.ai")
	req.Header.Set("accept-language", "en-US,en;q=0.9,fr-FR;q=0.8,fr;q=0.7")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("cookie", fmt.Sprintf("dpr=2; abra_csrf=%s; datr=%s; ps_n=1; ps_l=1", m.cookies["abra_csrf"], m.cookies["datr"]))
	req.Header.Set("x-fb-friendly-name", "AbraSearchPluginDialogQuery")

	resp, err := m.session.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var respJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respJSON); err != nil {
		return nil, err
	}

	message, ok := respJSON["data"].(map[string]interface{})["message"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid message in response JSON")
	}

	searchResults, ok := message["searchResults"].(map[string]interface{})
	if !ok || searchResults == nil {
		return nil, fmt.Errorf("no search results found in response JSON")
	}

	references, ok := searchResults["references"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid references in search results")
	}

	var sources []map[string]interface{}
	for _, ref := range references {
		refMap, ok := ref.(map[string]interface {
		})
		if !ok {
			continue
		}
		sources = append(sources, map[string]interface{}{
			"source": refMap["source"],
			"link":   refMap["link"],
		})
	}
	return sources, nil
}

func getFBSession(email, password string) (map[string]string, error) {
	// Implement Facebook session retrieval logic here
	return map[string]string{
		"abra_sess": "abra_session_token",
	}, nil
}

func formatResponse(resp map[string]interface{}) string {
	// Implement response formatting logic here
	if resp["data"] == nil || resp["data"].(map[string]interface{})["node"] == nil {
		return ""
	}
	botResponseMessage, ok := resp["data"].(map[string]interface{})["node"].(map[string]interface{})["bot_response_message"].(map[string]interface{})
	if !ok {
		return ""
	}
	botResponseMessage, ok = botResponseMessage["composed_text"].(map[string]interface{})
	if !ok {
		return ""
	}
	content := botResponseMessage["content"].([]interface{})
	text := content[0].(map[string]interface{})
	if text["text"] == nil {
		return ""
	}
	return text["text"].(string)
}

func generateOfflineThreadingID() string {
	// Maximum value for a 64-bit integer in Go
	const maxInt uint64 = (1 << 64) - 1
	const mask22Bits uint64 = (1 << 22) - 1

	// Get the current timestamp in milliseconds
	getCurrentTimestamp := func() uint64 {
		return uint64(time.Now().UnixNano() / int64(time.Millisecond))
	}

	// Generate a random 64-bit integer
	getRandom64bitInt := func() uint64 {
		return rand.Uint64()
	}

	// Combine timestamp and random value
	combineAndMask := func(timestamp, randomValue uint64) uint64 {
		shiftedTimestamp := timestamp << 22
		maskedRandom := randomValue & mask22Bits
		return (shiftedTimestamp | maskedRandom) & maxInt
	}

	timestamp := getCurrentTimestamp()
	randomValue := getRandom64bitInt()
	threadingID := combineAndMask(timestamp, randomValue)

	return strconv.FormatUint(threadingID, 10)
}

func main() {
	meta, err := NewMetaAI("", "", nil)
	if err != nil {
		log.Fatalf("error creating MetaAI instance: %v", err)
	}

	resp, err := meta.prompt("What is the weather of Mumbai today", false, 0, false)
	if err != nil {
		log.Fatalf("error getting response: %v", err)
	}

	fmt.Printf("Response: %v\n", resp)
}
