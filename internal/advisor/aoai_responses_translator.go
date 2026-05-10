package advisor

import (
	"encoding/json"
	"fmt"
)

// aoaiResponsesTranslator speaks Azure OpenAI's Responses API
// (https://learn.microsoft.com/en-us/azure/ai-services/openai/reference#responses).
// This is the modern unified API surface that supersedes
// chat-completions for many use cases — selected when the operator's
// llm.endpoint contains `/openai/responses`.
//
// Key differences from chat-completions:
//   * URL has no `/deployments/<dep>` segment; `model` in the request
//     body is the load-bearing field that picks the model.
//   * Body uses `input` (array of input items) instead of `messages`.
//   * Tool definitions are flatter: {type:"function", name, parameters}
//     instead of nested {type:"function", function:{...}}.
//   * Tool choice is {type:"function", name} instead of nested form.
//   * Response uses `output` (array of output items) instead of
//     `choices[].message`. Function calls show up as items with
//     type=`function_call`, carrying `name` and `arguments` (string).
//
// Auth: api-key (same as chat-completions). The Responses API does
// not require a separate api-version negotiation header beyond the
// query string the operator sets.
type aoaiResponsesTranslator struct{}

const aoaiResponsesMaxOutputTokens = 1024

func (aoaiResponsesTranslator) Name() string { return "aoai" }

type aoaiRespInputItem struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aoaiRespToolDef struct {
	Type        string         `json:"type"` // "function"
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type aoaiRespToolChoice struct {
	Type string `json:"type"` // "function"
	Name string `json:"name"`
}

type aoaiRespRequest struct {
	Model           string              `json:"model"`
	Input           []aoaiRespInputItem `json:"input"`
	MaxOutputTokens int                 `json:"max_output_tokens,omitempty"`
	Tools           []aoaiRespToolDef   `json:"tools,omitempty"`
	ToolChoice      *aoaiRespToolChoice `json:"tool_choice,omitempty"`
}

func (aoaiResponsesTranslator) BuildRequest(in Input, model, apiKey string) ([]byte, map[string]string, error) {
	if model == "" {
		return nil, nil, fmt.Errorf("aoai responses: llm.model is required (the Responses API URL has no deployment path; the body's model field picks the model)")
	}
	serialized, err := json.Marshal(in)
	if err != nil {
		return nil, nil, fmt.Errorf("aoai responses: marshal input: %w", err)
	}
	items := []aoaiRespInputItem{
		{Role: "system", Content: composeSystemPrompt(in.Mode, in.Directives)},
		{Role: "user", Content: userPrompt(serialized)},
	}
	req := aoaiRespRequest{
		Model:           model,
		Input:           items,
		MaxOutputTokens: aoaiResponsesMaxOutputTokens,
		Tools: []aoaiRespToolDef{{
			Type:        "function",
			Name:        toolName,
			Description: toolDescription,
			Parameters:  decisionSchema(),
		}},
		ToolChoice: &aoaiRespToolChoice{
			Type: "function",
			Name: toolName,
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("aoai responses: marshal request: %w", err)
	}
	hdr := map[string]string{"Content-Type": "application/json"}
	if apiKey != "" {
		hdr["api-key"] = apiKey
	}
	return body, hdr, nil
}

type aoaiRespContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type aoaiRespOutputItem struct {
	Type      string                 `json:"type"`
	ID        string                 `json:"id,omitempty"`
	Role      string                 `json:"role,omitempty"`
	Content   []aoaiRespContentBlock `json:"content,omitempty"`
	Name      string                 `json:"name,omitempty"`
	Arguments string                 `json:"arguments,omitempty"`
	CallID    string                 `json:"call_id,omitempty"`
	Status    string                 `json:"status,omitempty"`
}

type aoaiRespResponse struct {
	ID     string               `json:"id"`
	Object string               `json:"object"`
	Status string               `json:"status"`
	Output []aoaiRespOutputItem `json:"output"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (aoaiResponsesTranslator) ParseResponse(httpStatus int, body []byte) (Output, error) {
	if httpStatus < 200 || httpStatus >= 300 {
		return Output{}, fmt.Errorf("%w: aoai-responses http %d: %s",
			ErrAdvisorWire, httpStatus, truncateForLog(string(body), 256))
	}
	var resp aoaiRespResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Output{}, fmt.Errorf("%w: aoai-responses decode: %v: %s",
			ErrAdvisorSchema, err, truncateForLog(string(body), 256))
	}
	if resp.Error != nil {
		return Output{}, fmt.Errorf("%w: aoai-responses api error: %s: %s",
			ErrAdvisorSchema, resp.Error.Code, resp.Error.Message)
	}
	for _, item := range resp.Output {
		if item.Type != "function_call" || item.Name != toolName {
			continue
		}
		var out Output
		if err := json.Unmarshal([]byte(item.Arguments), &out); err != nil {
			return Output{}, fmt.Errorf("%w: aoai-responses function_call arguments decode: %v: %s",
				ErrAdvisorSchema, err, truncateForLog(item.Arguments, 256))
		}
		return out, nil
	}
	// No function_call output. Surface what came back so the
	// operator can see why the model declined to invoke the tool.
	textExcerpt := ""
	for _, item := range resp.Output {
		if item.Type == "message" {
			for _, c := range item.Content {
				if c.Text != "" {
					textExcerpt = c.Text
					break
				}
			}
		}
		if textExcerpt != "" {
			break
		}
	}
	return Output{}, fmt.Errorf("%w: aoai-responses output had no function_call for %q (status=%q); model returned text instead of invoking the structured-output tool: %s",
		ErrAdvisorSchema, toolName, resp.Status, truncateForLog(textExcerpt, 256))
}
