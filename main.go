package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxRetries = 3
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

func (m *MetaAI) getAccessToken() (string, error) {
	if m.accessToken != "" {
		return m.accessToken, nil
	}

	URL := "https://www.meta.ai/api/graphql/"
	payload := url.Values{}
	payload.Add("access_token", m.cookies["fb_dtsg"])
	payload.Add("fb_api_caller_class", "RelayModern")
	payload.Add("fb_api_req_friendly_name", "useAbraLoginMutation")
	payload.Add("variables", "{\"email\":\""+m.fbEmail+"\",\"password\":\""+m.fbPassword+"\",\"__relay_internal__pv__WebPixelRatiorelayprovider\":1}")
	payload.Add("server_timestamps", "true")
	payload.Add("doc_id", "7604648749596940")

	req, err := http.NewRequest("POST", URL, strings.NewReader(payload.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("cookie", fmt.Sprintf("_js_datr=%s; abra_csrf=%s; datr=%s;", m.cookies["_js_datr"], m.cookies["abra_csrf"], m.cookies["datr"]))
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("x-fb-friendly-name", "useAbraAcceptTOSForTempUserMutation")

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
	time.Sleep(1 * time.Second) // Meta needs to register cookies on their side
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
		m.externalConversationID = generateOfflineThreadingID()
	}

	payload := url.Values{
		"fb_api_caller_class":      {"RelayModern"},
		"fb_api_req_friendly_name": {"useAbraSendMessageMutation"},
		"variables":                {"{\"message\":{\"sensitive_string_value\":\"" + message + "\"},\"externalConversationId\":\"" + m.externalConversationID + "\",\"offlineThreadingId\":\"" + generateOfflineThreadingID() + "\",\"suggestedPromptIndex\":null,\"flashVideoRecapInput\":{\"images\":[]},\"flashPreviewInput\":null,\"promptPrefix\":null,\"entrypoint\":\"ABRA__CHAT__TEXT\",\"icebreaker_type\":\"TEXT\",\"__relay_internal__pv__AbraDebugDevOnlyrelayprovider\":false,\"__relay_internal__pv__WebPixelRatiorelayprovider\":1}"},
		"server_timestamps":        {"true"},
		"doc_id":                   {"7783822248314888"},
	}

	if m.isAuthed {
		payload.Set("fb_dtsg", m.cookies["fb_dtsg"])
		m.session = &http.Client{}
		m.session.Transport = &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://%s", m.proxy["http"]))
			},
		}
	} else {
		payload.Set("access_token", m.accessToken)
		m.session.Transport = nil
	}

	req, err := http.NewRequest("POST", "https://www.meta.ai/api/graphql/", strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("x-fb-friendly-name", "useAbraSendMessageMutation")
	if m.isAuthed {
		req.Header.Set("cookie", fmt.Sprintf("abra_sess=%s", m.cookies["abra_sess"]))
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
	if attempts <= maxRetries {
		log.Printf("unable to obtain a valid response from Meta AI. retrying... attempt %d/%d", attempts+1, maxRetries)
		time.Sleep(3 * time.Second)
		return m.prompt(message, stream, attempts+1, false)
	}
	return nil, fmt.Errorf("unable to obtain a valid response from Meta AI. try again later")
}

func (m *MetaAI) extractLastResponse(response string) (map[string]interface{}, error) {
	var lastStreamedResponse map[string]interface{}
	for _, line := range strings.Split(response, "\n") {
		var jsonLine map[string]interface{}
		if err := json.Unmarshal([]byte(line), &jsonLine); err != nil {
			continue
		}

		botResponseMessage, ok := jsonLine["data"].(map[string]interface{})["node"].(map[string]interface{})["bot_response_message"].(map[string]interface{})
		if !ok {
			continue
		}

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
	}
	if lastStreamedResponse == nil {
		return nil, fmt.Errorf("no valid last streamed response found")
	}
	return lastStreamedResponse, nil
}

func (m *MetaAI) extractData(jsonLine map[string]interface{}) (map[string]interface{}, error) {
	botResponseMessage, ok := jsonLine["data"].(map[string]interface{})["node"].(map[string]interface{})["bot_response_message"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid bot response message in JSON line")
	}

	response := formatResponse(jsonLine)
	fetchID, ok := botResponseMessage["fetch_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid fetch ID in bot response message")
	}

	sources, err := m.fetchSources(fetchID)
	if err != nil {
		return nil, err
	}

	medias, err := m.extractMedia(botResponseMessage)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"message": response,
		"sources": sources,
		"media":   medias,
	}, nil
}

func (m *MetaAI) extractMedia(jsonLine map[string]interface{}) ([]map[string]interface{}, error) {
	var medias []map[string]interface{}
	imagineCard, ok := jsonLine["imagine_card"].(map[string]interface{})
	if !ok {
		return medias, nil
	}

	session, ok := imagineCard["session"].(map[string]interface{})
	if !ok {
		return medias, nil
	}

	mediaSets, ok := session["media_sets"].([]interface{})
	if !ok {
		return medias, nil
	}

	for _, mediaSet := range mediaSets {
		imagineMedia, ok := mediaSet.(map[string]interface{})["imagine_media"].([]interface{})
		if !ok {
			continue
		}

		for _, media := range imagineMedia {
			mediaMap, ok := media.(map[string]interface{})
			if !ok {
				continue
			}

			medias = append(medias, map[string]interface{}{
				"url":    mediaMap["uri"],
				"type":   mediaMap["media_type"],
				"prompt": mediaMap["prompt"],
			})
		}
	}
	return medias, nil
}

func (m *MetaAI) getCookies() (map[string]string, error) {
	resp, err := http.Get("https://www.meta.ai/")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cookies := map[string]string{
		"_js_datr": extractValue(string(body), `_js_datr":{"value":"`, `",`),
		"datr":     extractValue(string(body), `datr":{"value":"`, `",`),
		"lsd":      extractValue(string(body), `"LSD",[],{"token":"`, `"}`),
		"fb_dtsg":  extractValue(string(body), `DTSGInitData",[],{"token":"`, `"`),
	}

	if m.fbEmail != "" && m.fbPassword != "" {
		fbSession, err := getFBSession(m.fbEmail, m.fbPassword)
		if err != nil {
			return nil, err
		}
		cookies["abra_sess"] = fbSession["abra_sess"]
	} else {
		cookies["abra_csrf"] = extractValue(string(body), `abra_csrf":{"value":"`, `",`)
	}

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
	botResponseMessage, ok := resp["data"].(map[string]interface{})["node"].(map[string]interface{})["bot_response_message"].(map[string]interface{})
	if !ok {
		return ""
	}
	return botResponseMessage["text"].(string)
}

func generateOfflineThreadingID() string {
	// Implement offline threading ID generation logic here
	return uuid.NewString()
}

func extractValue(text, start, end string) string {
	startIndex := strings.Index(text, start)
	if startIndex == -1 {
		return ""
	}
	startIndex += len(start)
	endIndex := strings.Index(text[startIndex:], end)
	if endIndex == -1 {
		return ""
	}
	return text[startIndex : startIndex+endIndex]
}

func main() {
	meta, err := NewMetaAI("", "", nil)
	if err != nil {
		log.Fatalf("error creating MetaAI instance: %v", err)
	}

	resp, err := meta.prompt("What was the Warriors score last game?", false, 0, false)
	if err != nil {
		log.Fatalf("error getting response: %v", err)
	}

	fmt.Printf("Response: %v\n", resp)
}
